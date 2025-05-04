// Copyright 2021-2025 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::operation;
use super::operation::Operation;
use super::VisitorAction;
use super::*;
use binaryninjacore_sys::BNGetLowLevelILByIndex;
use binaryninjacore_sys::BNGetLowLevelILIndexForInstruction;
use binaryninjacore_sys::BNLowLevelILInstruction;
use std::fmt::{Debug, Display, Formatter};

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LowLevelInstructionIndex(pub usize);

impl LowLevelInstructionIndex {
    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<usize> for LowLevelInstructionIndex {
    fn from(index: usize) -> Self {
        Self(index)
    }
}

impl From<u64> for LowLevelInstructionIndex {
    fn from(index: u64) -> Self {
        Self(index as usize)
    }
}

impl Display for LowLevelInstructionIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

pub trait InstructionHandler<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn kind(&self) -> InstructionKind<'func, M, F>;

    /// Visit the sub expressions of this instruction.
    ///
    /// NOTE: This does not visit the root expression, i.e. the instruction.
    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, M, F, ValueExpr>) -> VisitorAction;
}

pub struct Instruction<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) function: &'func LowLevelILFunction<M, F>,
    pub index: LowLevelInstructionIndex,
}

impl<'func, M, F> Instruction<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    // TODO: Should we check the instruction count here with BNGetLowLevelILInstructionCount?
    // TODO: If we _can_ then this should become an Option<Self> methinks
    pub fn new(function: &'func LowLevelILFunction<M, F>, index: LowLevelInstructionIndex) -> Self {
        Self { function, index }
    }

    pub fn address(&self) -> u64 {
        self.into_raw().address
    }

    // TODO: Document the difference between the self.index and the expr_idx.
    pub fn expr_idx(&self) -> LowLevelExpressionIndex {
        let idx = unsafe { BNGetLowLevelILIndexForInstruction(self.function.handle, self.index.0) };
        LowLevelExpressionIndex(idx)
    }

    pub fn into_raw(&self) -> BNLowLevelILInstruction {
        unsafe { BNGetLowLevelILByIndex(self.function.handle, self.expr_idx().0) }
    }
}

impl<'func, M, F> Debug for Instruction<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Instruction")
            .field("index", &self.index)
            .field("expr_idx", &self.expr_idx())
            .field("address", &self.address())
            .finish()
    }
}

impl<'func, M> InstructionHandler<'func, M, SSA> for Instruction<'func, M, SSA>
where
    M: FunctionMutability,
{
    fn kind(&self) -> InstructionKind<'func, M, SSA> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let raw_op = self.into_raw();
        #[allow(clippy::match_single_binding)]
        match raw_op.operation {
            // Any invalid ops for Non-Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { InstructionKind::from_raw(self.function, self.expr_idx(), raw_op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, M, SSA, ValueExpr>) -> VisitorAction,
    {
        // Recursively visit sub expressions.
        self.kind().visit_sub_expressions(|e| e.visit_tree(f))
    }
}

impl<'func, M> InstructionHandler<'func, M, NonSSA<LiftedNonSSA>>
    for Instruction<'func, M, NonSSA<LiftedNonSSA>>
where
    M: FunctionMutability,
{
    fn kind(&self) -> InstructionKind<'func, M, NonSSA<LiftedNonSSA>> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let raw_op = self.into_raw();
        #[allow(clippy::match_single_binding)]
        match raw_op.operation {
            // Any invalid ops for Non-Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { InstructionKind::from_raw(self.function, self.expr_idx(), raw_op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, M, NonSSA<LiftedNonSSA>, ValueExpr>) -> VisitorAction,
    {
        // Recursively visit sub expressions.
        self.kind().visit_sub_expressions(|e| e.visit_tree(f))
    }
}

impl<'func, M> InstructionHandler<'func, M, NonSSA<RegularNonSSA>>
    for Instruction<'func, M, NonSSA<RegularNonSSA>>
where
    M: FunctionMutability,
{
    fn kind(&self) -> InstructionKind<'func, M, NonSSA<RegularNonSSA>> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let raw_op = self.into_raw();
        #[allow(clippy::match_single_binding)]
        match raw_op.operation {
            // Any invalid ops for Non-Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { InstructionKind::from_raw(self.function, self.expr_idx(), raw_op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(
            &LowLevelILExpression<'func, M, NonSSA<RegularNonSSA>, ValueExpr>,
        ) -> VisitorAction,
    {
        // Recursively visit sub expressions.
        self.kind().visit_sub_expressions(|e| e.visit_tree(f))
    }
}

#[derive(Debug)]
pub enum InstructionKind<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    Nop(Operation<'func, M, F, operation::NoArgs>),
    SetReg(Operation<'func, M, F, operation::SetReg>),
    SetRegSplit(Operation<'func, M, F, operation::SetRegSplit>),
    SetFlag(Operation<'func, M, F, operation::SetFlag>),
    Store(Operation<'func, M, F, operation::Store>),
    // TODO needs a real op
    Push(Operation<'func, M, F, operation::UnaryOp>),

    RegStackPush(Operation<'func, M, F, operation::RegStackPush>),

    Jump(Operation<'func, M, F, operation::Jump>),
    JumpTo(Operation<'func, M, F, operation::JumpTo>),

    Call(Operation<'func, M, F, operation::Call>),
    TailCall(Operation<'func, M, F, operation::Call>),

    Ret(Operation<'func, M, F, operation::Ret>),
    NoRet(Operation<'func, M, F, operation::NoArgs>),

    If(Operation<'func, M, F, operation::If>),
    Goto(Operation<'func, M, F, operation::Goto>),

    Syscall(Operation<'func, M, F, operation::Syscall>),
    Intrinsic(Operation<'func, M, F, operation::Intrinsic>),
    Bp(Operation<'func, M, F, operation::NoArgs>),
    Trap(Operation<'func, M, F, operation::Trap>),
    Undef(Operation<'func, M, F, operation::NoArgs>),

    /// The instruction is an expression.
    Value(LowLevelILExpression<'func, M, F, ValueExpr>),
}

impl<'func, M, F> InstructionKind<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) unsafe fn from_raw(
        function: &'func LowLevelILFunction<M, F>,
        expr_index: LowLevelExpressionIndex,
        op: BNLowLevelILInstruction,
    ) -> Self {
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        match op.operation {
            LLIL_NOP => InstructionKind::Nop(Operation::new(function, op)),
            LLIL_SET_REG | LLIL_SET_REG_SSA => {
                InstructionKind::SetReg(Operation::new(function, op))
            }
            LLIL_SET_REG_SPLIT | LLIL_SET_REG_SPLIT_SSA => {
                InstructionKind::SetRegSplit(Operation::new(function, op))
            }
            LLIL_SET_FLAG | LLIL_SET_FLAG_SSA => {
                InstructionKind::SetFlag(Operation::new(function, op))
            }
            LLIL_STORE | LLIL_STORE_SSA => InstructionKind::Store(Operation::new(function, op)),
            LLIL_PUSH => InstructionKind::Push(Operation::new(function, op)),

            LLIL_REG_STACK_PUSH => InstructionKind::RegStackPush(Operation::new(function, op)),

            LLIL_JUMP => InstructionKind::Jump(Operation::new(function, op)),
            LLIL_JUMP_TO => InstructionKind::JumpTo(Operation::new(function, op)),

            LLIL_CALL | LLIL_CALL_STACK_ADJUST | LLIL_CALL_SSA => {
                InstructionKind::Call(Operation::new(function, op))
            }
            LLIL_TAILCALL | LLIL_TAILCALL_SSA => {
                InstructionKind::TailCall(Operation::new(function, op))
            }

            LLIL_RET => InstructionKind::Ret(Operation::new(function, op)),
            LLIL_NORET => InstructionKind::NoRet(Operation::new(function, op)),

            LLIL_IF => InstructionKind::If(Operation::new(function, op)),
            LLIL_GOTO => InstructionKind::Goto(Operation::new(function, op)),

            LLIL_SYSCALL | LLIL_SYSCALL_SSA => {
                InstructionKind::Syscall(Operation::new(function, op))
            }
            LLIL_INTRINSIC | LLIL_INTRINSIC_SSA => {
                InstructionKind::Intrinsic(Operation::new(function, op))
            }
            LLIL_BP => InstructionKind::Bp(Operation::new(function, op)),
            LLIL_TRAP => InstructionKind::Trap(Operation::new(function, op)),
            LLIL_UNDEF => InstructionKind::Undef(Operation::new(function, op)),
            _ => InstructionKind::Value(LowLevelILExpression::new(function, expr_index)),
        }
    }

    fn visit_sub_expressions<T>(&self, mut visitor: T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, M, F, ValueExpr>) -> VisitorAction,
    {
        use InstructionKind::*;

        macro_rules! visit {
            ($expr:expr) => {
                if let VisitorAction::Halt = visitor($expr) {
                    return VisitorAction::Halt;
                }
            };
        }

        match self {
            SetReg(ref op) => visit!(&op.source_expr()),
            SetRegSplit(ref op) => visit!(&op.source_expr()),
            SetFlag(ref op) => visit!(&op.source_expr()),
            Store(ref op) => {
                visit!(&op.dest_mem_expr());
                visit!(&op.source_expr());
            }
            Push(ref op) => visit!(&op.operand()),
            RegStackPush(ref op) => visit!(&op.source_expr()),
            Jump(ref op) => visit!(&op.target()),
            JumpTo(ref op) => visit!(&op.target()),
            Call(ref op) | TailCall(ref op) => visit!(&op.target()),
            Ret(ref op) => visit!(&op.target()),
            If(ref op) => visit!(&op.condition()),
            Intrinsic(ref _op) => {
                // TODO: Visit when we support expression lists
            }
            Value(e) => visit!(e),
            // Do not have any sub expressions.
            Nop(_) | NoRet(_) | Goto(_) | Syscall(_) | Bp(_) | Trap(_) | Undef(_) => {}
        }

        VisitorAction::Sibling
    }
}
