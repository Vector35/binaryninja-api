// Copyright 2021-2024 Vector 35 Inc.
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
use crate::architecture::Architecture;
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

// TODO: Probably want to rename this with a LowLevelIL prefix to avoid collisions when we add handlers for other ILs
pub trait InstructionHandler<'func, A, M, F>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn kind(&self) -> LowLevelILInstructionKind<'func, A, M, F>;

    /// Visit the sub expressions of this instruction.
    ///
    /// NOTE: This does not visit the root expression, i.e. the instruction.
    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, A, M, F, ValueExpr>) -> VisitorAction;
}

pub struct LowLevelILInstruction<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) function: &'func LowLevelILFunction<A, M, F>,
    pub index: LowLevelInstructionIndex,
}

impl<'func, A, M, F> LowLevelILInstruction<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    // TODO: Should we check the instruction count here with BNGetLowLevelILInstructionCount?
    // TODO: If we _can_ then this should become an Option<Self> methinks
    pub fn new(
        function: &'func LowLevelILFunction<A, M, F>,
        index: LowLevelInstructionIndex,
    ) -> Self {
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

impl<'func, A, M, F> Debug for LowLevelILInstruction<'func, A, M, F>
where
    A: 'func + Architecture,
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

impl<'func, A, M> InstructionHandler<'func, A, M, SSA> for LowLevelILInstruction<'func, A, M, SSA>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    fn kind(&self) -> LowLevelILInstructionKind<'func, A, M, SSA> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let raw_op = self.into_raw();
        #[allow(clippy::match_single_binding)]
        match raw_op.operation {
            // Any invalid ops for Non-Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe {
                LowLevelILInstructionKind::from_raw(self.function, self.expr_idx(), raw_op)
            },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, A, M, SSA, ValueExpr>) -> VisitorAction,
    {
        // Recursively visit sub expressions.
        self.kind().visit_sub_expressions(|e| e.visit_tree(f))
    }
}

impl<'func, A, M> InstructionHandler<'func, A, M, NonSSA<LiftedNonSSA>>
    for LowLevelILInstruction<'func, A, M, NonSSA<LiftedNonSSA>>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    fn kind(&self) -> LowLevelILInstructionKind<'func, A, M, NonSSA<LiftedNonSSA>> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let raw_op = self.into_raw();
        #[allow(clippy::match_single_binding)]
        match raw_op.operation {
            // Any invalid ops for Non-Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe {
                LowLevelILInstructionKind::from_raw(self.function, self.expr_idx(), raw_op)
            },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(
            &LowLevelILExpression<'func, A, M, NonSSA<LiftedNonSSA>, ValueExpr>,
        ) -> VisitorAction,
    {
        // Recursively visit sub expressions.
        self.kind().visit_sub_expressions(|e| e.visit_tree(f))
    }
}

impl<'func, A, M> InstructionHandler<'func, A, M, NonSSA<RegularNonSSA>>
    for LowLevelILInstruction<'func, A, M, NonSSA<RegularNonSSA>>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    fn kind(&self) -> LowLevelILInstructionKind<'func, A, M, NonSSA<RegularNonSSA>> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let raw_op = self.into_raw();
        #[allow(clippy::match_single_binding)]
        match raw_op.operation {
            // Any invalid ops for Non-Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe {
                LowLevelILInstructionKind::from_raw(self.function, self.expr_idx(), raw_op)
            },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(
            &LowLevelILExpression<'func, A, M, NonSSA<RegularNonSSA>, ValueExpr>,
        ) -> VisitorAction,
    {
        // Recursively visit sub expressions.
        self.kind().visit_sub_expressions(|e| e.visit_tree(f))
    }
}

#[derive(Debug)]
pub enum LowLevelILInstructionKind<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    Nop(Operation<'func, A, M, F, operation::NoArgs>),
    SetReg(Operation<'func, A, M, F, operation::SetReg>),
    SetRegSplit(Operation<'func, A, M, F, operation::SetRegSplit>),
    SetFlag(Operation<'func, A, M, F, operation::SetFlag>),
    Store(Operation<'func, A, M, F, operation::Store>),
    // TODO needs a real op
    Push(Operation<'func, A, M, F, operation::UnaryOp>),

    RegStackPush(Operation<'func, A, M, F, operation::RegStackPush>),

    Jump(Operation<'func, A, M, F, operation::Jump>),
    JumpTo(Operation<'func, A, M, F, operation::JumpTo>),

    Call(Operation<'func, A, M, F, operation::Call>),
    TailCall(Operation<'func, A, M, F, operation::Call>),

    Ret(Operation<'func, A, M, F, operation::Ret>),
    NoRet(Operation<'func, A, M, F, operation::NoArgs>),

    If(Operation<'func, A, M, F, operation::If>),
    Goto(Operation<'func, A, M, F, operation::Goto>),

    Syscall(Operation<'func, A, M, F, operation::Syscall>),
    Intrinsic(Operation<'func, A, M, F, operation::Intrinsic>),
    Bp(Operation<'func, A, M, F, operation::NoArgs>),
    Trap(Operation<'func, A, M, F, operation::Trap>),
    Undef(Operation<'func, A, M, F, operation::NoArgs>),

    /// The instruction is an expression.
    Value(LowLevelILExpression<'func, A, M, F, ValueExpr>),
}

impl<'func, A, M, F> LowLevelILInstructionKind<'func, A, M, F>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) unsafe fn from_raw(
        function: &'func LowLevelILFunction<A, M, F>,
        expr_index: LowLevelExpressionIndex,
        op: BNLowLevelILInstruction,
    ) -> Self {
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        match op.operation {
            LLIL_NOP => LowLevelILInstructionKind::Nop(Operation::new(function, op)),
            LLIL_SET_REG | LLIL_SET_REG_SSA => {
                LowLevelILInstructionKind::SetReg(Operation::new(function, op))
            }
            LLIL_SET_REG_SPLIT | LLIL_SET_REG_SPLIT_SSA => {
                LowLevelILInstructionKind::SetRegSplit(Operation::new(function, op))
            }
            LLIL_SET_FLAG | LLIL_SET_FLAG_SSA => {
                LowLevelILInstructionKind::SetFlag(Operation::new(function, op))
            }
            LLIL_STORE | LLIL_STORE_SSA => {
                LowLevelILInstructionKind::Store(Operation::new(function, op))
            }
            LLIL_PUSH => LowLevelILInstructionKind::Push(Operation::new(function, op)),

            LLIL_REG_STACK_PUSH => {
                LowLevelILInstructionKind::RegStackPush(Operation::new(function, op))
            }

            LLIL_JUMP => LowLevelILInstructionKind::Jump(Operation::new(function, op)),
            LLIL_JUMP_TO => LowLevelILInstructionKind::JumpTo(Operation::new(function, op)),

            LLIL_CALL | LLIL_CALL_STACK_ADJUST | LLIL_CALL_SSA => {
                LowLevelILInstructionKind::Call(Operation::new(function, op))
            }
            LLIL_TAILCALL | LLIL_TAILCALL_SSA => {
                LowLevelILInstructionKind::TailCall(Operation::new(function, op))
            }

            LLIL_RET => LowLevelILInstructionKind::Ret(Operation::new(function, op)),
            LLIL_NORET => LowLevelILInstructionKind::NoRet(Operation::new(function, op)),

            LLIL_IF => LowLevelILInstructionKind::If(Operation::new(function, op)),
            LLIL_GOTO => LowLevelILInstructionKind::Goto(Operation::new(function, op)),

            LLIL_SYSCALL | LLIL_SYSCALL_SSA => {
                LowLevelILInstructionKind::Syscall(Operation::new(function, op))
            }
            LLIL_INTRINSIC | LLIL_INTRINSIC_SSA => {
                LowLevelILInstructionKind::Intrinsic(Operation::new(function, op))
            }
            LLIL_BP => LowLevelILInstructionKind::Bp(Operation::new(function, op)),
            LLIL_TRAP => LowLevelILInstructionKind::Trap(Operation::new(function, op)),
            LLIL_UNDEF => LowLevelILInstructionKind::Undef(Operation::new(function, op)),
            _ => LowLevelILInstructionKind::Value(LowLevelILExpression::new(function, expr_index)),
        }
    }

    fn visit_sub_expressions<T>(&self, mut visitor: T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, A, M, F, ValueExpr>) -> VisitorAction,
    {
        use LowLevelILInstructionKind::*;

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
