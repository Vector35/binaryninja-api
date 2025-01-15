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
use super::*;
use crate::architecture::Architecture;
use binaryninjacore_sys::BNGetLowLevelILByIndex;
use binaryninjacore_sys::BNGetLowLevelILIndexForInstruction;
use binaryninjacore_sys::BNLowLevelILInstruction;
use std::fmt::{Debug, Display, Formatter};

use super::VisitorAction;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstructionIndex(pub usize);

impl InstructionIndex {
    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl Display for InstructionIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

pub trait InstructionHandler<'func, A, M, F>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn info(&self) -> InstrInfo<'func, A, M, F>;

    /// Visit the sub expressions of this instruction.
    ///
    /// NOTE: This does not visit the root expression, i.e. the instruction.
    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, A, M, F, ValueExpr>) -> VisitorAction;
}

pub struct Instruction<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) function: &'func LowLevelILFunction<A, M, F>,
    pub index: InstructionIndex,
}

impl<'func, A, M, F> Instruction<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    // TODO: Should we check the instruction count here with BNGetLowLevelILInstructionCount?
    // TODO: If we _can_ then this should become an Option<Self> methinks
    pub fn new(function: &'func LowLevelILFunction<A, M, F>, index: InstructionIndex) -> Self {
        Self { function, index }
    }

    pub fn address(&self) -> u64 {
        let expr_idx =
            unsafe { BNGetLowLevelILIndexForInstruction(self.function.handle, self.index.0) };
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, expr_idx) };
        op.address
    }
}

impl<'func, A, M, F> Debug for Instruction<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Instruction")
            .field("index", &self.index)
            .field("address", &self.address())
            .finish()
    }
}

impl<'func, A, M> InstructionHandler<'func, A, M, SSA> for Instruction<'func, A, M, SSA>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    fn info(&self) -> InstrInfo<'func, A, M, SSA> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        #[allow(clippy::match_single_binding)]
        match op.operation {
            // Any invalid ops for Non-Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { InstrInfo::from_raw(self.function, self.index, op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, A, M, SSA, ValueExpr>) -> VisitorAction,
    {
        // Recursively visit sub expressions.
        self.info().visit_sub_expressions(|e| e.visit_tree(f))
    }
}

impl<'func, A, M> InstructionHandler<'func, A, M, NonSSA<LiftedNonSSA>>
    for Instruction<'func, A, M, NonSSA<LiftedNonSSA>>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    fn info(&self) -> InstrInfo<'func, A, M, NonSSA<LiftedNonSSA>> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        #[allow(clippy::match_single_binding)]
        match op.operation {
            // Any invalid ops for Non-Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { InstrInfo::from_raw(self.function, self.index, op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, A, M, NonSSA<LiftedNonSSA>, ValueExpr>) -> VisitorAction,
    {
        // Recursively visit sub expressions.
        self.info().visit_sub_expressions(|e| e.visit_tree(f))
    }
}

impl<'func, A, M> InstructionHandler<'func, A, M, NonSSA<RegularNonSSA>>
    for Instruction<'func, A, M, NonSSA<RegularNonSSA>>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    fn info(&self) -> InstrInfo<'func, A, M, NonSSA<RegularNonSSA>> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        #[allow(clippy::match_single_binding)]
        match op.operation {
            // Any invalid ops for Non-Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { InstrInfo::from_raw(self.function, self.index, op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, A, M, NonSSA<RegularNonSSA>, ValueExpr>) -> VisitorAction,
    {
        // Recursively visit sub expressions.
        self.info().visit_sub_expressions(|e| e.visit_tree(f))
    }
}

pub enum InstrInfo<'func, A, M, F>
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
    Value(Expression<'func, A, M, F, ValueExpr>),
}

impl<'func, A, M, F> InstrInfo<'func, A, M, F>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) unsafe fn from_raw(
        function: &'func LowLevelILFunction<A, M, F>,
        index: InstructionIndex,
        op: BNLowLevelILInstruction,
    ) -> Self {
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        match op.operation {
            LLIL_NOP => InstrInfo::Nop(Operation::new(function, op)),
            LLIL_SET_REG | LLIL_SET_REG_SSA => InstrInfo::SetReg(Operation::new(function, op)),
            LLIL_SET_REG_SPLIT | LLIL_SET_REG_SPLIT_SSA => {
                InstrInfo::SetRegSplit(Operation::new(function, op))
            }
            LLIL_SET_FLAG | LLIL_SET_FLAG_SSA => InstrInfo::SetFlag(Operation::new(function, op)),
            LLIL_STORE | LLIL_STORE_SSA => InstrInfo::Store(Operation::new(function, op)),
            LLIL_PUSH => InstrInfo::Push(Operation::new(function, op)),

            LLIL_JUMP => InstrInfo::Jump(Operation::new(function, op)),
            LLIL_JUMP_TO => InstrInfo::JumpTo(Operation::new(function, op)),

            LLIL_CALL | LLIL_CALL_STACK_ADJUST | LLIL_CALL_SSA => {
                InstrInfo::Call(Operation::new(function, op))
            }
            LLIL_TAILCALL | LLIL_TAILCALL_SSA => InstrInfo::TailCall(Operation::new(function, op)),

            LLIL_RET => InstrInfo::Ret(Operation::new(function, op)),
            LLIL_NORET => InstrInfo::NoRet(Operation::new(function, op)),

            LLIL_IF => InstrInfo::If(Operation::new(function, op)),
            LLIL_GOTO => InstrInfo::Goto(Operation::new(function, op)),

            LLIL_SYSCALL | LLIL_SYSCALL_SSA => InstrInfo::Syscall(Operation::new(function, op)),
            LLIL_INTRINSIC | LLIL_INTRINSIC_SSA => {
                InstrInfo::Intrinsic(Operation::new(function, op))
            }
            LLIL_BP => InstrInfo::Bp(Operation::new(function, op)),
            LLIL_TRAP => InstrInfo::Trap(Operation::new(function, op)),
            LLIL_UNDEF => InstrInfo::Undef(Operation::new(function, op)),
            // Could not identify an instruction, therefor must be a value expression.
            // The conversion from instruction index to expression index is safe here.
            _ => InstrInfo::Value(Expression::new(function, ExpressionIndex(index.0))),
        }
    }

    fn visit_sub_expressions<T>(&self, mut visitor: T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, A, M, F, ValueExpr>) -> VisitorAction,
    {
        use InstrInfo::*;

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
            Jump(ref op) => visit!(&op.target()),
            JumpTo(ref op) => visit!(&op.target()),
            Call(ref op) | TailCall(ref op) => visit!(&op.target()),
            Ret(ref op) => visit!(&op.target()),
            If(ref op) => visit!(&op.condition()),
            Intrinsic(ref _op) => {
                // TODO: Visit when we support expression lists
            }
            Value(e) => visit!(e),
            _ => {}
        }

        VisitorAction::Sibling
    }
}
