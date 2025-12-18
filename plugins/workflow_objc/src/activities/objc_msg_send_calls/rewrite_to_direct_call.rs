use binaryninja::{
    binary_view::BinaryView,
    low_level_il::{
        function::{LowLevelILFunction, Mutable, NonSSA, SSA},
        instruction::{InstructionHandler as _, LowLevelILInstruction, LowLevelILInstructionKind},
    },
};

use super::MessageSendType;
use crate::{
    metadata::{GlobalState, Selector},
    Error,
};

// TODO: This always rewrites to the first known implementation of a given selector.
// This is Not Good as it will pick the wrong target for any common selector.
// In order to do better we need to consider receiver type information.
pub fn process_call(
    bv: &BinaryView,
    llil: &LowLevelILFunction<Mutable, NonSSA>,
    insn: &LowLevelILInstruction<Mutable, SSA>,
    selector: &Selector,
    message_send_type: MessageSendType,
) -> Result<(), Error> {
    if message_send_type == MessageSendType::Super {
        return Ok(());
    }

    let Some(info) =
        GlobalState::analysis_info(bv).filter(|info| info.should_rewrite_to_direct_calls)
    else {
        return Ok(());
    };

    let Some(impl_address) = info.get_selector_impl(bv, selector.addr) else {
        return Ok(());
    };

    // Change the destination expression of the call instruction to point directly to
    // the method implementation.
    let llil_insn = insn.non_ssa_form(llil);
    match llil_insn.kind() {
        LowLevelILInstructionKind::Call(call_op) | LowLevelILInstructionKind::TailCall(call_op) => {
            let dest_expr = call_op.target();
            unsafe {
                llil.replace_expression(dest_expr.index, llil.const_ptr(impl_address));
            }
            Ok(())
        }
        _ => {
            tracing::error!(
                "Unexpected LLIL operation for objc_msgSend call at {:#x}",
                insn.address()
            );
            Err(Error::UnexpectedLlilOperation {
                address: insn.address(),
                expected: "Call or TailCall".to_string(),
            })
        }
    }
}
