use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNGetMediumLevelILIndexForInstruction;
use binaryninjacore_sys::BNMediumLevelILInstruction;

use super::*;

pub struct Instruction<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) function: &'func Function<A, M, F>,
    pub(crate) instr_idx: usize,
}

fn common_info<'func, A, M, F>(
    function: &'func Function<A, M, F>,
    op: BNMediumLevelILInstruction,
) -> Option<InstrInfo<'func, A, M, F>>
where
    A: 'func + Architecture,
    M: FunctionMutability,
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

impl<'func, A, M, V> Instruction<'func, A, M, NonSSA<V>>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn info(&self) -> InstrInfo<'func, A, M, NonSSA<V>> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        let expr_idx =
            unsafe { BNGetMediumLevelILIndexForInstruction(self.function.handle, self.instr_idx) };
        let op = unsafe { BNGetMediumLevelILByIndex(self.function.handle, expr_idx) };

        match op.operation {
            MLIL_SET_VAR => InstrInfo::SetVar(Operation::new(self.function, op)),
            MLIL_SET_VAR_FIELD => InstrInfo::SetVarField(Operation::new(self.function, op)),
            MLIL_SET_VAR_SPLIT => InstrInfo::SetVarSplit(Operation::new(self.function, op)),
            MLIL_STORE => InstrInfo::Store(Operation::new(self.function, op)),
            MLIL_CALL | MLIL_TAILCALL => InstrInfo::Call(Operation::new(self.function, op)),
            MLIL_CALL_UNTYPED | MLIL_TAILCALL_UNTYPED => {
                InstrInfo::CallUntyped(Operation::new(self.function, op))
            }
            MLIL_SYSCALL => InstrInfo::Syscall(Operation::new(self.function, op)),
            MLIL_SYSCALL_UNTYPED => InstrInfo::SyscallUntyped(Operation::new(self.function, op)),
            MLIL_INTRINSIC => InstrInfo::Intrinsic(Operation::new(self.function, op)),
            MLIL_STORE_STRUCT => todo!(),
            MLIL_FREE_VAR_SLOT => todo!(),

            _ => common_info(&self.function, op).unwrap_or({
                // Hopefully this is a bare value. If it isn't (expression
                // from wrong function form or similar) it won't really cause
                // any problems as it'll come back as undefined when queried.
                let expr = Expression::new(self.function, expr_idx);

                let info = unsafe { expr.info_from_op(op) };

                InstrInfo::Value(expr, info)
            }),
        }
    }
}

impl<'func, A, M> Instruction<'func, A, M, SSA>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn info(&self) -> InstrInfo<'func, A, M, SSA> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        let expr_idx =
            unsafe { BNGetMediumLevelILIndexForInstruction(self.function.handle, self.instr_idx) };
        let op = unsafe { BNGetMediumLevelILByIndex(self.function.handle, expr_idx) };

        match op.operation {
            MLIL_SET_VAR_SSA => InstrInfo::SetVar(Operation::new(self.function, op)),
            MLIL_SET_VAR_ALIASED => InstrInfo::SetVarAliased(Operation::new(self.function, op)),
            MLIL_SET_VAR_SSA_FIELD | MLIL_SET_VAR_ALIASED_FIELD | MLIL_VAR_SSA_FIELD => {
                InstrInfo::SetVarField(Operation::new(self.function, op))
            }
            MLIL_SET_VAR_SPLIT_SSA => InstrInfo::SetVarSplit(Operation::new(self.function, op)),
            MLIL_VAR_PHI => InstrInfo::VarPhi(Operation::new(self.function, op)),
            MLIL_MEM_PHI => InstrInfo::MemPhi(Operation::new(self.function, op)),
            MLIL_STORE_SSA => InstrInfo::Store(Operation::new(self.function, op)),
            MLIL_CALL_SSA | MLIL_TAILCALL_SSA => InstrInfo::Call(Operation::new(self.function, op)),
            MLIL_CALL_UNTYPED_SSA | MLIL_TAILCALL_UNTYPED_SSA => {
                InstrInfo::CallUntyped(Operation::new(self.function, op))
            }
            MLIL_SYSCALL_SSA => InstrInfo::Syscall(Operation::new(self.function, op)),
            MLIL_SYSCALL_UNTYPED_SSA => {
                InstrInfo::SyscallUntyped(Operation::new(self.function, op))
            }
            MLIL_INTRINSIC_SSA => InstrInfo::Intrinsic(Operation::new(self.function, op)),
            MLIL_STORE_STRUCT_SSA => todo!(),
            MLIL_FREE_VAR_SLOT_SSA => todo!(),

            _ => common_info(&self.function, op).unwrap_or({
                // Hopefully this is a bare value. If it isn't (expression
                // from wrong function form or similar) it won't really cause
                // any problems as it'll come back as undefined when queried.
                let expr = Expression::new(self.function, expr_idx);

                let info = unsafe { expr.info_from_op(op) };

                InstrInfo::Value(expr, info)
            }),
        }
    }
}

pub enum InstrInfo<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    Nop(Operation<'func, A, M, F, operation::NoArgs>),

    SetVar(Operation<'func, A, M, F, operation::SetVar>),
    SetVarAliased(Operation<'func, A, M, F, operation::SetVarAliased>),
    SetVarField(Operation<'func, A, M, F, operation::SetVarField>),
    SetVarSplit(Operation<'func, A, M, F, operation::SetVarSplit>),

    VarPhi(Operation<'func, A, M, F, operation::VarPhi>),
    MemPhi(Operation<'func, A, M, F, operation::MemPhi>),

    Store(Operation<'func, A, M, F, operation::Store>),

    Jump(Operation<'func, A, M, F, operation::Jump>),
    JumpTo(Operation<'func, A, M, F, operation::JumpTo>),

    Call(Operation<'func, A, M, F, operation::Call>),
    CallUntyped(Operation<'func, A, M, F, operation::CallUntyped>),
    Syscall(Operation<'func, A, M, F, operation::Syscall>),
    SyscallUntyped(Operation<'func, A, M, F, operation::SyscallUntyped>),

    Ret(Operation<'func, A, M, F, operation::Ret>),
    NoRet(Operation<'func, A, M, F, operation::NoArgs>),

    If(Operation<'func, A, M, F, operation::If>),
    Goto(Operation<'func, A, M, F, operation::Goto>),

    Bp(Operation<'func, A, M, F, operation::NoArgs>),
    Trap(Operation<'func, A, M, F, operation::Trap>),
    Undef(Operation<'func, A, M, F, operation::NoArgs>),
    Unimpl(Operation<'func, A, M, F, operation::NoArgs>),

    Intrinsic(Operation<'func, A, M, F, operation::Intrinsic>),

    Value(
        Expression<'func, A, M, F, ValueExpr>,
        ExprInfo<'func, A, M, F>,
    ),
}
