use binaryninja::{
    binary_view::BinaryView,
    function::Function,
    low_level_il::{
        expression::{ExpressionHandler as _, LowLevelILExpressionKind},
        function::{LowLevelILFunction, Mutable, NonSSA, SSA},
        instruction::{InstructionHandler as _, LowLevelILInstruction, LowLevelILInstructionKind},
        operation::{CallSsa, Operation},
    },
    variable::PossibleValueSet,
    workflow::AnalysisContext,
};

use crate::{
    error::ILLevel,
    metadata::{GlobalState, Selector},
    Error,
};

mod adjust_call_type;
mod rewrite_to_direct_call;

// Apply all transformations that are specific to calls to `objc_msgSend` and `objc_msgSendSuper2`
// At present these are:
// 1. Call type adjustments
// 2. Rewriting to direct calls, if enabled.
pub fn process(ac: &AnalysisContext) -> Result<(), Error> {
    let bv = ac.view();
    if GlobalState::should_ignore_view(&bv) {
        return Ok(());
    }

    let func_start = ac.function().start();
    let Some(llil) = (unsafe { ac.llil_function() }) else {
        return Err(Error::MissingIL {
            level: ILLevel::Low,
            func_start,
        });
    };

    let Some(ssa) = llil.ssa_form() else {
        return Err(Error::MissingSsaForm {
            level: ILLevel::Low,
            func_start,
        });
    };

    let func = ac.function();
    let mut function_changed = false;
    for block in ssa.basic_blocks().iter() {
        for insn in block.iter() {
            match process_instruction(&bv, &func, &llil, &ssa, &insn) {
                Ok(true) => function_changed = true,
                Ok(_) => {}
                Err(err) => {
                    tracing::error!(
                        "Error processing instruction at {:#x}: {}",
                        insn.address(),
                        err
                    );
                    continue;
                }
            }
        }
    }

    if function_changed {
        // Regenerate SSA form after modifications
        llil.generate_ssa_form();
    }
    Ok(())
}

// Process a single instruction, looking for calls to `objc_msgSend` or `objc_msgSendSuper2`
// Returns `Ok(false)` if the instruction is not a relevant call or if the function was not
// modified. Returns `Ok(true)` to indicate that the function was modified.
fn process_instruction(
    bv: &BinaryView,
    func: &Function,
    llil: &LowLevelILFunction<Mutable, NonSSA>,
    ssa: &LowLevelILFunction<Mutable, SSA>,
    insn: &LowLevelILInstruction<Mutable, SSA>,
) -> Result<bool, &'static str> {
    let call_op = match insn.kind() {
        LowLevelILInstructionKind::CallSsa(op) => op,
        LowLevelILInstructionKind::TailCallSsa(op) => op,
        _ => return Ok(false),
    };

    let target = call_op.target();
    let target_values = target.possible_values();

    // Check if the target is a constant pointer to objc_msgSend
    let call_target = match target_values {
        PossibleValueSet::ConstantValue { value }
        | PossibleValueSet::ConstantPointerValue { value }
        | PossibleValueSet::ImportedAddressValue { value } => value as u64,
        _ => return Ok(false),
    };

    let Some(message_send_type) = call_target_type(bv, call_target) else {
        return Ok(false);
    };

    let Some(selector) = selector_from_call(bv, ssa, &call_op) else {
        return Ok(false);
    };

    let mut function_changed = false;
    if adjust_call_type::process_call(bv, func, ssa, insn, &selector, message_send_type).is_ok() {
        function_changed = true;
    }

    if rewrite_to_direct_call::process_call(bv, llil, insn, &selector, message_send_type).is_ok() {
        function_changed = true;
    }

    Ok(function_changed)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum MessageSendType {
    Normal,
    Super,
}

fn call_target_type(bv: &BinaryView, call_target: u64) -> Option<MessageSendType> {
    let name = bv
        .symbol_by_address(call_target)
        .map(|s| s.raw_name().to_string_lossy().into_owned())?;

    // Strip the `j_` prefix that the shared cache adds to the names of stub functions
    let name = name.strip_prefix("j_").unwrap_or(&name);

    if name == "_objc_msgSend" {
        Some(MessageSendType::Normal)
    } else if name == "_objc_msgSendSuper" || name == "_objc_msgSendSuper2" {
        Some(MessageSendType::Super)
    } else {
        None
    }
}

fn selector_from_call(
    bv: &BinaryView,
    ssa: &LowLevelILFunction<Mutable, SSA>,
    call_op: &Operation<Mutable, SSA, CallSsa>,
) -> Option<Selector> {
    let LowLevelILExpressionKind::CallParamSsa(params) = &call_op.param_expr().kind() else {
        return None;
    };

    let param_exprs = params.param_exprs();
    if param_exprs.is_empty() {
        return None;
    }

    let param_exprs =
        if let LowLevelILExpressionKind::SeparateParamListSsa(params) = &param_exprs[0].kind() {
            params.param_exprs()
        } else {
            param_exprs
        };

    let LowLevelILExpressionKind::RegSsa(reg) = param_exprs.get(1)?.kind() else {
        return None;
    };

    let raw_selector = ssa.get_ssa_register_value(reg.source_reg())?.value as u64;
    if raw_selector == 0 {
        return None;
    }

    Selector::from_address(bv, raw_selector).ok()
}
