use binaryninja::{
    binary_view::{BinaryView, BinaryViewBase as _},
    medium_level_il::{
        operation::{Constant, LiftedSetVarSsa, LiftedSetVarSsaField, Var, VarSsa},
        MediumLevelILLiftedInstruction, MediumLevelILLiftedInstructionKind,
    },
    rc::Ref,
    types::Type,
    workflow::AnalysisContext,
};
use bstr::ByteSlice;

use super::util;
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

/// Detect the return type for a call to `objc_msgSendSuper2` where the selector is in the `init` family.
/// Returns `None` if selector is not in the `init` family or the return type cannot be determined.
fn return_type_for_super_init(call: &util::Call, view: &BinaryView) -> Option<Ref<Type>> {
    // Expecting to see at least `objc_super` and a selector.
    if call.call.params.len() < 2 {
        return None;
    }

    let selector_addr =
        util::match_constant_pointer_or_load_of_constant_pointer(&call.call.params[1])?;
    let selector = Selector::from_address(view, selector_addr).ok()?;

    if !selector.is_init_family() {
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
        util::class_name_from_symbol_name(super_class_symbol_name.to_bytes().as_bstr())
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

fn process_instruction(instr: &MediumLevelILLiftedInstruction, view: &BinaryView) -> Option<()> {
    let call = util::match_call_to_function_named(instr, view, OBJC_MSG_SEND_SUPER_FUNCTIONS)?;

    util::adjust_return_type_of_call(
        &call,
        return_type_for_super_init(&call, view)?.as_ref(),
        Confidence::SuperInit as u8,
    );
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
