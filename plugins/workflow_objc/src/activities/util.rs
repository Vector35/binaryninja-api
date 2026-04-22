use binaryninja::{
    binary_view::BinaryView,
    confidence::Conf,
    function::Function,
    medium_level_il::{
        operation::{Constant, LiftedCallSsa, LiftedLoadSsa},
        MediumLevelILFunction, MediumLevelILLiftedInstruction, MediumLevelILLiftedInstructionKind,
    },
    rc::Ref,
    types::Type,
    variable::{RegisterValueType, SSAVariable},
};
use bstr::BStr;

#[allow(clippy::struct_field_names)]
pub struct Call<'a> {
    pub instr: &'a MediumLevelILLiftedInstruction,
    pub call: &'a LiftedCallSsa,
    pub target: Ref<Function>,
}

/// Returns a `Call` if `instr` is a call or tail call to a function whose name appears in `function_names`
pub fn match_call_to_function_named<'a>(
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
pub fn match_constant_pointer_or_load_of_constant_pointer(
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

pub fn class_name_from_symbol_name(symbol_name: &BStr) -> Option<&BStr> {
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

/// Adjust the return type of the call represented by `call`.
pub fn adjust_return_type_of_call(call: &Call<'_>, return_type: &Type, confidence: u8) {
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
        Conf::new(&*adjusted_call_type, confidence),
        None,
    );
}
