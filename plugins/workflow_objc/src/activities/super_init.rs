use binaryninja::{
    binary_view::{BinaryView, BinaryViewBase, BinaryViewExt as _},
    confidence::Conf,
    function::Function,
    medium_level_il::{
        operation::{
            Constant, LiftedCallSsa, LiftedLoadSsa, LiftedSetVarSsa, LiftedSetVarSsaField, Var,
            VarSsa,
        },
        MediumLevelILFunction, MediumLevelILLiftedInstruction, MediumLevelILLiftedInstructionKind,
    },
    rc::Ref,
    types::Type,
    variable::{RegisterValueType, SSAVariable},
    workflow::AnalysisContext,
};
use bstr::{BStr, ByteSlice};

use crate::{
    error::ILLevel,
    metadata::{GlobalState, Selector},
    workflow::Confidence,
    Error,
};

// The `j_` prefix is for stub functions in the shared cache.
// It is added by the shared cache workflow.
const OBJC_MSG_SEND_SUPER_FUNCTIONS: &[&[u8]] = &[
    b"_objc_msgSendSuper2",
    b"j__objc_msgSendSuper2",
    b"_objc_msgSendSuper",
    b"j__objc_msgSendSuper",
];

fn ssa_variable_value_or_load_of_constant_pointer(
    function: &MediumLevelILFunction,
    var: &SSAVariable,
) -> Option<u64> {
    let value = function.ssa_variable_value(var);
    match value.state {
        RegisterValueType::ConstantPointerValue => return Some(value.value as u64),
        RegisterValueType::UndeterminedValue => {}
        _ => return None,
    }

    let def = function.ssa_variable_definition(var)?;
    let MediumLevelILLiftedInstructionKind::SetVarSsa(set_var) = def.lift().kind else {
        return None;
    };

    let MediumLevelILLiftedInstructionKind::LoadSsa(LiftedLoadSsa { src, .. }) = set_var.src.kind
    else {
        return None;
    };

    match src.kind {
        MediumLevelILLiftedInstructionKind::ConstPtr(Constant { constant }) => Some(constant),
        _ => None,
    }
}

/// If `instr` is a constant pointer or is a variable whose value is loaded from a constant pointer,
/// return that pointer address.
fn match_constant_pointer_or_load_of_constant_pointer(
    instr: &MediumLevelILLiftedInstruction,
) -> Option<u64> {
    match instr.kind {
        MediumLevelILLiftedInstructionKind::ConstPtr(Constant { constant }) => Some(constant),
        MediumLevelILLiftedInstructionKind::VarSsa(var) => {
            ssa_variable_value_or_load_of_constant_pointer(&instr.function, &var.src)
        }
        _ => None,
    }
}

#[allow(clippy::struct_field_names)]
struct Call<'a> {
    pub instr: &'a MediumLevelILLiftedInstruction,
    pub call: &'a LiftedCallSsa,
    pub target: Ref<Function>,
}

/// Returns a `Call` if `instr` is a call or tail call to a function whose name appears in `function_names`
fn match_call_to_function_named<'a>(
    instr: &'a MediumLevelILLiftedInstruction,
    view: &'a BinaryView,
    function_names: &'a [&[u8]],
) -> Option<Call<'a>> {
    let (MediumLevelILLiftedInstructionKind::TailcallSsa(ref call)
    | MediumLevelILLiftedInstructionKind::CallSsa(ref call)) = instr.kind
    else {
        return None;
    };

    let MediumLevelILLiftedInstructionKind::ConstPtr(Constant {
        constant: call_target,
    }) = call.dest.kind
    else {
        return None;
    };

    let target_function = view.function_at(&instr.function.function().platform(), call_target)?;
    let function_name = target_function.symbol().full_name();
    if !function_names.contains(&function_name.to_bytes()) {
        return None;
    }

    Some(Call {
        instr,
        call,
        target: target_function,
    })
}

fn class_name_from_symbol_name(symbol_name: &BStr) -> Option<&BStr> {
    // The symbol name for the `objc_class_t` can have different names depending
    // on factors such as being local or external, and whether the reference
    // is from the shared cache or a standalone Mach-O file.
    Some(if symbol_name.starts_with(b"cls_") {
        &symbol_name[4..]
    } else if symbol_name.starts_with(b"clsRef_") {
        &symbol_name[7..]
    } else if symbol_name.starts_with(b"_OBJC_CLASS_$_") {
        &symbol_name[14..]
    } else {
        return None;
    })
}

/// Detect the return type for a call to `objc_msgSendSuper2` where the selector is in the `init` family.
/// Returns `None` if selector is not in the `init` family or the return type cannot be determined.
fn return_type_for_super_init(call: &Call, view: &BinaryView) -> Option<Ref<Type>> {
    // Expecting to see at least `objc_super` and a selector.
    if call.call.params.len() < 2 {
        return None;
    }

    let selector_addr = match_constant_pointer_or_load_of_constant_pointer(&call.call.params[1])?;
    let selector = Selector::from_address(view, selector_addr).ok()?;

    // TODO: This will match `initialize` and `initiate` which are not init methods.
    if !selector.name.starts_with("init") {
        return None;
    }

    let super_param = &call.call.params[0];
    let MediumLevelILLiftedInstructionKind::VarSsa(VarSsa {
        src: super_param_var,
    }) = super_param.kind
    else {
        tracing::debug!(
            "Unhandled super paramater format at {:#0x} {:?}",
            super_param.address,
            super_param
        );
        return None;
    };

    // Parameter is an SSA variable. Find its definitions to find when it was assigned.
    // From there we can determine the values it was assigned.
    let Some(super_param_def) = call
        .instr
        .function
        .ssa_variable_definition(&super_param_var)
    else {
        tracing::debug!("  could not find definition of variable?");
        return None;
    };

    let src = match super_param_def.lift().kind {
        MediumLevelILLiftedInstructionKind::SetVarSsa(LiftedSetVarSsa { src, .. }) => src,
        _ => {
            // The Swift compiler generates code that conditionally assigns to the receiver field of `objc_super`.
            tracing::debug!(
                "Unexpected variable definition kind at {:#0x} {:#x?}",
                super_param_def.address,
                super_param_def
            );
            return None;
        }
    };

    let src_var = match src.kind {
        MediumLevelILLiftedInstructionKind::AddressOf(Var { src: src_var }) => src_var,
        _ => {
            // The Swift compiler generates code that initializes the `objc_super` variable in more varied ways.
            tracing::debug!(
                "  found non-address-of variable definition of `objc_super` variable at {:#0x} {:?}",
                super_param_def.address,
                super_param_def
            );
            return None;
        }
    };

    // `src_var` is a `struct objc_super`. Find constant values assigned to the `super_class` field (second field).
    let super_class_constants: Vec<_> =
        call.instr
            .function
            .variable_definitions(&src_var)
            .into_iter()
            .filter_map(|def| {
                let def = def.lift();
                let src = match def.kind {
                    MediumLevelILLiftedInstructionKind::SetVarAliasedField(
                        LiftedSetVarSsaField { src, offset, .. },
                    ) if offset == view.address_size() as u64 => src,
                    _ => {
                        return None;
                    }
                };

                match src.kind {
                    MediumLevelILLiftedInstructionKind::ConstPtr(Constant { constant }) => {
                        Some(constant)
                    }
                    _ => None,
                }
            })
            .collect();

    // In the common case there are either zero or one assignments to the `super_class` field.
    // If there are zero, that likely means the assigned value was not a constant. Handling
    // that is above my pay grade.
    let &[super_class_ptr] = &super_class_constants[..] else {
        tracing::debug!(
            "Unexpected number of assignments to super class found for {:#0x}: {:#0x?}",
            src.address,
            super_class_constants
        );
        return None;
    };

    let Some(super_class_symbol) = view.symbol_by_address(super_class_ptr) else {
        tracing::debug!("No symbol found for super class at {super_class_ptr:#0x}");
        return None;
    };

    let super_class_symbol_name = super_class_symbol.full_name();
    let Some(class_name) =
        class_name_from_symbol_name(super_class_symbol_name.to_bytes().as_bstr())
    else {
        tracing::debug!(
            "Unable to extract class name from symbol name: {super_class_symbol_name:?}"
        );
        return None;
    };

    let Some(class_type) = view.type_by_name(class_name.to_str_lossy()) else {
        tracing::debug!("No type found for class named {class_name:?}");
        return None;
    };

    Some(Type::pointer(&call.target.arch(), &class_type))
}

/// Adjust the return type of the call represented by `call`.
fn adjust_return_type_of_call(call: &Call<'_>, return_type: &Type) {
    let function = call.instr.function.function();

    // We're changing only the return type, so preserve other aspects of any existing call type adjustment.
    let target_function_type = if let Some(existing_call_type_adjustment) =
        function.call_type_adjustment(call.instr.address, None)
    {
        existing_call_type_adjustment.contents
    } else {
        call.target.function_type()
    };

    // There's nothing to do if the return type is already correct
    if let Some(conf) = target_function_type.return_value() {
        if &*conf.contents == return_type {
            return;
        }
    }

    let adjusted_call_type = target_function_type
        .to_builder()
        .set_child_type(return_type)
        .finalize();

    function.set_auto_call_type_adjustment(
        call.instr.address,
        Conf::new(&*adjusted_call_type, Confidence::SuperInit as u8),
        None,
    );
}

fn process_instruction(instr: &MediumLevelILLiftedInstruction, view: &BinaryView) -> Option<()> {
    let call = match_call_to_function_named(instr, view, OBJC_MSG_SEND_SUPER_FUNCTIONS)?;

    adjust_return_type_of_call(&call, return_type_for_super_init(&call, view)?.as_ref());
    Some(())
}

pub fn process(ac: &AnalysisContext) -> Result<(), Error> {
    let bv = ac.view();
    if GlobalState::should_ignore_view(&bv) {
        return Ok(());
    }

    let mlil = ac.mlil_function().ok_or(Error::MissingIL {
        level: ILLevel::Medium,
        func_start: ac.function().start(),
    })?;
    let mlil_ssa = mlil.ssa_form();

    for block in &mlil_ssa.basic_blocks() {
        for instr in block.iter() {
            process_instruction(&instr.lift(), &bv);
        }
    }

    Ok(())
}
