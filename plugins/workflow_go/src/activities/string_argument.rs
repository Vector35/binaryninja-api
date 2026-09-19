use binaryninja::binary_view::{AnalysisContext, BinaryView, BinaryViewBase};
use binaryninja::high_level_il::{
    HighLevelILLiftedInstruction as LInstr, HighLevelILLiftedInstructionKind as LK,
    HighLevelILLiftedOperand as LOp,
};
use binaryninja::types::Type;

/// Runs over the HLIL of a golang binary and caps the length of string literals
/// passed as call arguments.
///
/// When a call passes a (const pointer, immediate length) pair, that is a Go
/// string header, so the pointed-to data is redefined as `char[len]` to stop it
/// spilling into the concatenated rodata blob.
pub struct NarrowStringsAction {}

impl NarrowStringsAction {
    /// Apply the workflow
    pub fn apply(ctx: &AnalysisContext) {
        let view = ctx.view();

        let is_go = view
            .query_metadata("go_workflow.is_go")
            .and_then(|m| m.get_boolean())
            .unwrap_or(false);
        if !is_go {
            return;
        }

        let Some(hlil) = ctx.hlil_function(true) else {
            return;
        };

        for block in &hlil.basic_blocks() {
            for instr in block.iter() {
                Self::visit(&instr.lift(), &view);
            }
        }
    }

    /// Recursively find calls and narrow their string arguments.
    fn visit(instr: &LInstr, view: &BinaryView) {
        if let LK::Call(op) | LK::Tailcall(op) = &instr.kind {
            Self::narrow_call(&op.params, view);
        }
        for (_, operand) in instr.operands() {
            match operand {
                LOp::Expr(e) => Self::visit(&e, view),
                LOp::ExprList(list) => list.iter().for_each(|e| Self::visit(e, view)),
                _ => {}
            }
        }
    }

    /// Pair adjacent (ptr, len) constants in a call's params and redefine the
    /// pointed-to data as `char[len]`.
    fn narrow_call(params: &[LInstr], view: &BinaryView) {
        let consts: Vec<Option<u64>> = params
            .iter()
            .map(|p| match &p.kind {
                LK::Const(c) | LK::ConstPtr(c) => Some(c.constant),
                _ => None,
            })
            .collect();

        for w in consts.windows(2) {
            let (Some(ptr), Some(len)) = (w[0], w[1]) else {
                continue;
            };
            if len == 0 || len > 0x8000 || !view.offset_valid(ptr) {
                continue;
            }
            let want = Type::array(&Type::char(), len);
            if let Some(dv) = view.data_variable_at_address(ptr)
                && dv.ty.contents == want
            {
                continue;
            }
            view.define_auto_data_var(ptr, &want);
        }
    }
}
