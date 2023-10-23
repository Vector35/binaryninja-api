use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNGetMediumLevelILIndexForInstruction;
use binaryninjacore_sys::BNMediumLevelILInstruction;

use crate::rc::Ref;

use super::*;

pub struct Instruction<F>
where
    F: FunctionForm,
{
    pub(crate) function: Ref<Function<F>>,
    pub(crate) instr_idx: usize,
}

fn common_info<F>(function: &Function<F>, op: BNMediumLevelILInstruction) -> Option<InstrInfo<F>>
where
    F: FunctionForm,
{
    use binaryninjacore_sys::BNMediumLevelILOperation::*;

    match op.operation {
        MLIL_NOP => InstrInfo::Nop(Operation::new(function, op)).into(),
        MLIL_JUMP | MLIL_RET_HINT => InstrInfo::Jump(Operation::new(function, op)).into(),
        MLIL_JUMP_TO => InstrInfo::JumpTo(Operation::new(function, op)).into(),
        MLIL_RET => InstrInfo::Ret(Operation::new(function, op)).into(),
        MLIL_NORET => InstrInfo::NoRet(Operation::new(function, op)).into(),
        MLIL_IF => InstrInfo::If(Operation::new(function, op)).into(),
        MLIL_GOTO => InstrInfo::Goto(Operation::new(function, op)).into(),
        MLIL_BP => InstrInfo::Bp(Operation::new(function, op)).into(),
        MLIL_TRAP => InstrInfo::Trap(Operation::new(function, op)).into(),
        MLIL_UNDEF => InstrInfo::Undef(Operation::new(function, op)).into(),
        MLIL_UNIMPL => InstrInfo::Unimpl(Operation::new(function, op)).into(),
        _ => None,
    }
}

impl Instruction<NonSSA> {
    pub fn info(&self) -> InstrInfo<NonSSA> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        let expr_idx =
            unsafe { BNGetMediumLevelILIndexForInstruction(self.function.handle, self.instr_idx) };
        let op = unsafe { BNGetMediumLevelILByIndex(self.function.handle, expr_idx) };

        match op.operation {
            MLIL_SET_VAR => InstrInfo::SetVar(Operation::new(&self.function, op)),
            MLIL_SET_VAR_FIELD => InstrInfo::SetVarField(Operation::new(&self.function, op)),
            MLIL_SET_VAR_SPLIT => InstrInfo::SetVarSplit(Operation::new(&self.function, op)),
            MLIL_STORE => InstrInfo::Store(Operation::new(&self.function, op)),
            MLIL_CALL | MLIL_TAILCALL => InstrInfo::Call(Operation::new(&self.function, op)),
            MLIL_CALL_UNTYPED | MLIL_TAILCALL_UNTYPED => {
                InstrInfo::CallUntyped(Operation::new(&self.function, op))
            }
            MLIL_SYSCALL => InstrInfo::Syscall(Operation::new(&self.function, op)),
            MLIL_SYSCALL_UNTYPED => InstrInfo::SyscallUntyped(Operation::new(&self.function, op)),
            MLIL_INTRINSIC => InstrInfo::Intrinsic(Operation::new(&self.function, op)),
            MLIL_STORE_STRUCT => todo!(),
            MLIL_FREE_VAR_SLOT => todo!(),

            _ => common_info(&self.function, op).unwrap_or({
                // Hopefully this is a bare value. If it isn't (expression
                // from wrong function form or similar) it won't really cause
                // any problems as it'll come back as undefined when queried.
                let expr = Expression::new(&self.function, expr_idx);

                let info = unsafe { expr.info_from_op(op) };

                InstrInfo::Value(expr, info)
            }),
        }
    }
}

impl Instruction<SSA> {
    pub fn info(&self) -> InstrInfo<SSA> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        let expr_idx =
            unsafe { BNGetMediumLevelILIndexForInstruction(self.function.handle, self.instr_idx) };
        let op = unsafe { BNGetMediumLevelILByIndex(self.function.handle, expr_idx) };

        match op.operation {
            MLIL_SET_VAR_SSA => InstrInfo::SetVar(Operation::new(&self.function, op)),
            MLIL_SET_VAR_ALIASED => InstrInfo::SetVarAliased(Operation::new(&self.function, op)),
            MLIL_SET_VAR_SSA_FIELD | MLIL_SET_VAR_ALIASED_FIELD | MLIL_VAR_SSA_FIELD => {
                InstrInfo::SetVarField(Operation::new(&self.function, op))
            }
            MLIL_SET_VAR_SPLIT_SSA => InstrInfo::SetVarSplit(Operation::new(&self.function, op)),
            MLIL_VAR_PHI => InstrInfo::VarPhi(Operation::new(&self.function, op)),
            MLIL_MEM_PHI => InstrInfo::MemPhi(Operation::new(&self.function, op)),
            MLIL_STORE_SSA => InstrInfo::Store(Operation::new(&self.function, op)),
            MLIL_CALL_SSA | MLIL_TAILCALL_SSA => {
                InstrInfo::Call(Operation::new(&self.function, op))
            }
            MLIL_CALL_UNTYPED_SSA | MLIL_TAILCALL_UNTYPED_SSA => {
                InstrInfo::CallUntyped(Operation::new(&self.function, op))
            }
            MLIL_SYSCALL_SSA => InstrInfo::Syscall(Operation::new(&self.function, op)),
            MLIL_SYSCALL_UNTYPED_SSA => {
                InstrInfo::SyscallUntyped(Operation::new(&self.function, op))
            }
            MLIL_INTRINSIC_SSA => InstrInfo::Intrinsic(Operation::new(&self.function, op)),
            MLIL_STORE_STRUCT_SSA => todo!(),
            MLIL_FREE_VAR_SLOT_SSA => todo!(),

            _ => common_info(&self.function, op).unwrap_or({
                // Hopefully this is a bare value. If it isn't (expression
                // from wrong function form or similar) it won't really cause
                // any problems as it'll come back as undefined when queried.
                let expr = Expression::new(&self.function, expr_idx);

                let info = unsafe { expr.info_from_op(op) };

                InstrInfo::Value(expr, info)
            }),
        }
    }
}

pub enum InstrInfo<F>
where
    F: FunctionForm,
{
    Nop(Operation<F, operation::NoArgs>),

    SetVar(Operation<F, operation::SetVar>),
    SetVarAliased(Operation<F, operation::SetVarAliased>),
    SetVarField(Operation<F, operation::SetVarField>),
    SetVarSplit(Operation<F, operation::SetVarSplit>),

    VarPhi(Operation<F, operation::VarPhi>),
    MemPhi(Operation<F, operation::MemPhi>),

    Store(Operation<F, operation::Store>),

    Jump(Operation<F, operation::Jump>),
    JumpTo(Operation<F, operation::JumpTo>),

    Call(Operation<F, operation::Call>),
    CallUntyped(Operation<F, operation::CallUntyped>),
    Syscall(Operation<F, operation::Syscall>),
    SyscallUntyped(Operation<F, operation::SyscallUntyped>),

    Ret(Operation<F, operation::Ret>),
    NoRet(Operation<F, operation::NoArgs>),

    If(Operation<F, operation::If>),
    Goto(Operation<F, operation::Goto>),

    Bp(Operation<F, operation::NoArgs>),
    Trap(Operation<F, operation::Trap>),
    Undef(Operation<F, operation::NoArgs>),
    Unimpl(Operation<F, operation::NoArgs>),

    Intrinsic(Operation<F, operation::Intrinsic>),

    Value(Expression<F, ValueExpr>, ExprInfo<F>),
}
