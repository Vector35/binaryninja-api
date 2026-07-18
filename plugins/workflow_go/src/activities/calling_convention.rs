use binaryninja::architecture::{Architecture, ArchitectureExt, CoreRegister, Register};
use binaryninja::binary_view::AnalysisContext;
use binaryninja::low_level_il::VisitorAction;
use binaryninja::low_level_il::expression::LowLevelILExpressionKind::Load;
use binaryninja::low_level_il::expression::{
    ExpressionHandler, LowLevelILExpression, LowLevelILExpressionKind, ValueExpr,
};
use binaryninja::low_level_il::function::{Mutable, NonSSA};
use binaryninja::low_level_il::instruction::InstructionHandler;
use binaryninja::low_level_il::instruction::LowLevelILInstructionKind;

/// The workflow runs over the functions of a golang binary and applies the correct
/// Go calling convention, so that register-passed arguments are recovered as
/// parameters instead of appearing as spurious register reads.
///
/// Go uses two ABIs: the register-based `ABIInternal` (go1.17+) and the older
/// stack-based `ABI0`. Binary Ninja ships neither, so we register both as custom
/// conventions (`go-abiinternal` / `go-stack`, per architecture) and select one
/// per function.
///
/// The selection works in this way: thunks are skipped (they are just trampolines
/// with no convention of their own); if the function name ends with ".abi0" we
/// apply `go-stack`; otherwise we default to the register-based `go-abiinternal`.
pub struct GoCallingConventionWorkflow {}

impl GoCallingConventionWorkflow {
    /// Apply the workflow
    pub fn apply(ctx: &AnalysisContext) {
        let view = ctx.view();

        // runs this workflow only under golang binaries
        let is_go = view
            .query_metadata("go_workflow.is_go")
            .and_then(|m| m.get_boolean())
            .unwrap_or(false);

        if !is_go {
            return;
        }

        let func = ctx.function();

        unsafe {
            // thunk functions are trampolines for the external functions and for that we
            // do not require to set a specific golang calling convention
            if Self::is_thunk(ctx) {
                return;
            }
        }

        // 1) if the function has a symbol and ends with ".abi0", then we apply the go-stack
        // convention
        let cc_name = match func.defined_symbol() {
            Some(symb)
                if symb
                    .full_name()
                    .to_str()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .ends_with(".abi0") =>
            {
                "go-stack"
            }
            Some(_) => "go-abiinternal",
            _ => match unsafe { Self::reads_args_from_stack(ctx) } {
                true => "go-stack",
                false => "go-abiinternal",
            },
        };

        let arch = func.arch();
        let Some(cc) = arch.calling_convention_by_name(cc_name) else {
            tracing::warn!(
                "go: CC '{cc_name}' not registered on architecture {}",
                arch.name()
            );
            return;
        };

        func.set_auto_calling_convention(Some(&cc));
    }

    /// Heuristic: does the first basic block read an incoming argument from
    /// the stack? A stack-based ABI0 function loads its arguments from `[sp + off]`;
    /// a register-based ABIInternal one receives them in registers.
    ///
    /// Fallback for when the ".abi0" name suffix is missing (stripped binary).
    unsafe fn reads_args_from_stack(ctx: &AnalysisContext) -> bool {
        unsafe {
            let Some(llil) = ctx.llil_function() else {
                return false;
            };
            let blocks = llil.basic_blocks();
            let Some(first) = blocks.iter().next() else {
                return false;
            };

            let arch = ctx.function().arch();
            let Some(sp) = arch.stack_pointer_reg() else {
                return false;
            };

            first.iter().any(|instr| {
                let mut found = false;
                instr.visit_tree(&mut |e| {
                    if let Load(op) = e.kind()
                        && Self::addr_is_stack(&op.source_expr(), sp)
                    {
                        found = true;
                        return VisitorAction::Halt;
                    };
                    VisitorAction::Descend
                });
                found
            })
        }
    }

    /// True if an address expression is `sp` or `sp +/- const`.
    fn addr_is_stack(
        addr: &LowLevelILExpression<Mutable, NonSSA, ValueExpr>,
        sp: CoreRegister,
    ) -> bool {
        match addr.kind() {
            LowLevelILExpressionKind::Reg(op) => op.source_reg().id() == sp.id(),
            LowLevelILExpressionKind::Add(op) | LowLevelILExpressionKind::Sub(op) => {
                Self::side_is_sp(&op.left(), sp) || Self::side_is_sp(&op.right(), sp)
            }
            _ => false,
        }
    }

    fn side_is_sp(e: &LowLevelILExpression<Mutable, NonSSA, ValueExpr>, sp: CoreRegister) -> bool {
        matches!(e.kind(), LowLevelILExpressionKind::Reg(op) if op.source_reg().id() == sp.id())
    }

    /// Check if a specified function at low level is a thunk function. From python source [1], we
    /// define a thunk as a function that has a single basic block and ends with a tail call.
    ///
    /// Returns true if the llil function from the analysis context is a thunk.
    ///
    /// [1]: https://github.com/Vector35/binaryninja-api/blob/5b9a08ec4c061718097d9eb0a40e8a6b9774391d/python/lowlevelil.py#L3667
    unsafe fn is_thunk(ctx: &AnalysisContext) -> bool {
        unsafe {
            let Some(llil) = ctx.llil_function() else {
                return false;
            };

            let blocks = llil.basic_blocks();
            let mut it = blocks.iter();

            // only one basic block
            let (Some(block), None) = (it.next(), it.next()) else {
                return false;
            };

            // grep the last instruction of the basic block
            let Some(last) = block.iter().last() else {
                return false;
            };

            matches!(last.kind(), LowLevelILInstructionKind::TailCall(_))
        }
    }
}
