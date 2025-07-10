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

use crate::basic_block::BasicBlock;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Ref};

use super::block::LowLevelILBlock;
use super::operation;
use super::operation::Operation;
use super::VisitorAction;
use super::*;
use binaryninjacore_sys::BNGetLowLevelILIndexForInstruction;
use binaryninjacore_sys::BNLowLevelILInstruction;
use binaryninjacore_sys::{BNFreeILInstructionList, BNGetLowLevelILByIndex};
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

impl CoreArrayProvider for LowLevelInstructionIndex {
    type Raw = usize;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for LowLevelInstructionIndex {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeILInstructionList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from(*raw)
    }
}

// TODO: Probably want to rename this with a LowLevelIL prefix to avoid collisions when we add handlers for other ILs
pub trait InstructionHandler<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn kind(&self) -> LowLevelILInstructionKind<'func, M, F>;

    /// Visit the sub expressions of this instruction.
    ///
    /// NOTE: This does not visit the root expression, i.e. the instruction.
    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, M, F, ValueExpr>) -> VisitorAction;
}

#[derive(Copy, Clone)]
pub struct LowLevelILInstruction<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) function: &'func LowLevelILFunction<M, F>,
    pub index: LowLevelInstructionIndex,
}

impl<'func, M, F> LowLevelILInstruction<'func, M, F>
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

    /// Returns the [`BasicBlock`] containing the given [`LowLevelILInstruction`].
    pub fn basic_block(&self) -> Option<Ref<BasicBlock<LowLevelILBlock<'func, M, F>>>> {
        // TODO: We might be able to .expect this if we guarantee that self.index is valid.
        self.function.basic_block_containing_index(self.index)
    }
}

impl<'func, M> LowLevelILInstruction<'func, M, NonSSA>
where
    M: FunctionMutability,
{
    pub fn ssa_form(
        &self,
        ssa: &'func LowLevelILFunction<M, SSA>,
    ) -> LowLevelILInstruction<'func, M, SSA> {
        use binaryninjacore_sys::BNGetLowLevelILSSAInstructionIndex;
        let idx = unsafe { BNGetLowLevelILSSAInstructionIndex(self.function.handle, self.index.0) };
        LowLevelILInstruction::new(ssa, LowLevelInstructionIndex(idx))
    }
}

impl<'func, M> LowLevelILInstruction<'func, M, SSA>
where
    M: FunctionMutability,
{
    pub fn non_ssa_form(
        &self,
        non_ssa: &'func LowLevelILFunction<M, NonSSA>,
    ) -> LowLevelILInstruction<'func, M, NonSSA> {
        use binaryninjacore_sys::BNGetLowLevelILNonSSAInstructionIndex;
        let idx =
            unsafe { BNGetLowLevelILNonSSAInstructionIndex(self.function.handle, self.index.0) };
        LowLevelILInstruction::new(non_ssa, LowLevelInstructionIndex(idx))
    }
}

impl<M, F> Debug for LowLevelILInstruction<'_, M, F>
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

impl<'func, M> InstructionHandler<'func, M, SSA> for LowLevelILInstruction<'func, M, SSA>
where
    M: FunctionMutability,
{
    fn kind(&self) -> LowLevelILInstructionKind<'func, M, SSA> {
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
        T: FnMut(&LowLevelILExpression<'func, M, SSA, ValueExpr>) -> VisitorAction,
    {
        // Recursively visit sub expressions.
        self.kind().visit_sub_expressions(|e| e.visit_tree(f))
    }
}

impl<'func, M> InstructionHandler<'func, M, NonSSA> for LowLevelILInstruction<'func, M, NonSSA>
where
    M: FunctionMutability,
{
    fn kind(&self) -> LowLevelILInstructionKind<'func, M, NonSSA> {
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
        T: FnMut(&LowLevelILExpression<'func, M, NonSSA, ValueExpr>) -> VisitorAction,
    {
        // Recursively visit sub expressions.
        self.kind().visit_sub_expressions(|e| e.visit_tree(f))
    }
}

#[derive(Debug)]
pub enum LowLevelILInstructionKind<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    Nop(Operation<'func, M, F, operation::NoArgs>),
    SetReg(Operation<'func, M, F, operation::SetReg>),
    SetRegSsa(Operation<'func, M, F, operation::SetRegSsa>),
    SetRegPartialSsa(Operation<'func, M, F, operation::SetRegPartialSsa>),
    SetRegSplit(Operation<'func, M, F, operation::SetRegSplit>),
    SetRegSplitSsa(Operation<'func, M, F, operation::SetRegSplitSsa>),
    SetFlag(Operation<'func, M, F, operation::SetFlag>),
    SetFlagSsa(Operation<'func, M, F, operation::SetFlagSsa>),
    Store(Operation<'func, M, F, operation::Store>),
    StoreSsa(Operation<'func, M, F, operation::StoreSsa>),
    // TODO needs a real op
    Push(Operation<'func, M, F, operation::UnaryOp>),

    RegStackPush(Operation<'func, M, F, operation::RegStackPush>),

    Jump(Operation<'func, M, F, operation::Jump>),
    JumpTo(Operation<'func, M, F, operation::JumpTo>),

    Call(Operation<'func, M, F, operation::Call>),
    CallSsa(Operation<'func, M, F, operation::CallSsa>),
    TailCall(Operation<'func, M, F, operation::Call>),
    TailCallSsa(Operation<'func, M, F, operation::CallSsa>),

    Ret(Operation<'func, M, F, operation::Ret>),
    NoRet(Operation<'func, M, F, operation::NoArgs>),

    If(Operation<'func, M, F, operation::If>),
    Goto(Operation<'func, M, F, operation::Goto>),

    Syscall(Operation<'func, M, F, operation::Syscall>),
    SyscallSsa(Operation<'func, M, F, operation::SyscallSsa>),
    Intrinsic(Operation<'func, M, F, operation::Intrinsic>),
    Bp(Operation<'func, M, F, operation::NoArgs>),
    Trap(Operation<'func, M, F, operation::Trap>),
    Undef(Operation<'func, M, F, operation::NoArgs>),
    Assert(Operation<'func, M, F, operation::Assert>),
    AssertSsa(Operation<'func, M, F, operation::AssertSsa>),
    ForceVersion(Operation<'func, M, F, operation::ForceVersion>),
    ForceVersionSsa(Operation<'func, M, F, operation::ForceVersionSsa>),

    RegPhi(Operation<'func, M, F, operation::RegPhi>),
    FlagPhi(Operation<'func, M, F, operation::FlagPhi>),
    MemPhi(Operation<'func, M, F, operation::MemPhi>),

    /// The instruction is an expression.
    Value(LowLevelILExpression<'func, M, F, ValueExpr>),
}

impl<'func, M, F> LowLevelILInstructionKind<'func, M, F>
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
            LLIL_NOP => LowLevelILInstructionKind::Nop(Operation::new(function, op, expr_index)),
            LLIL_SET_REG => {
                LowLevelILInstructionKind::SetReg(Operation::new(function, op, expr_index))
            }
            LLIL_SET_REG_SSA => {
                LowLevelILInstructionKind::SetRegSsa(Operation::new(function, op, expr_index))
            }
            LLIL_SET_REG_SSA_PARTIAL => LowLevelILInstructionKind::SetRegPartialSsa(
                Operation::new(function, op, expr_index),
            ),
            LLIL_SET_REG_SPLIT => {
                LowLevelILInstructionKind::SetRegSplit(Operation::new(function, op, expr_index))
            }
            LLIL_SET_REG_SPLIT_SSA => {
                LowLevelILInstructionKind::SetRegSplitSsa(Operation::new(function, op, expr_index))
            }
            LLIL_SET_FLAG => {
                LowLevelILInstructionKind::SetFlag(Operation::new(function, op, expr_index))
            }
            LLIL_SET_FLAG_SSA => {
                LowLevelILInstructionKind::SetFlagSsa(Operation::new(function, op, expr_index))
            }
            LLIL_STORE => {
                LowLevelILInstructionKind::Store(Operation::new(function, op, expr_index))
            }
            LLIL_STORE_SSA => {
                LowLevelILInstructionKind::StoreSsa(Operation::new(function, op, expr_index))
            }
            LLIL_PUSH => LowLevelILInstructionKind::Push(Operation::new(function, op, expr_index)),

            LLIL_REG_STACK_PUSH => {
                LowLevelILInstructionKind::RegStackPush(Operation::new(function, op, expr_index))
            }

            LLIL_JUMP => LowLevelILInstructionKind::Jump(Operation::new(function, op, expr_index)),
            LLIL_JUMP_TO => {
                LowLevelILInstructionKind::JumpTo(Operation::new(function, op, expr_index))
            }

            LLIL_CALL | LLIL_CALL_STACK_ADJUST => {
                LowLevelILInstructionKind::Call(Operation::new(function, op, expr_index))
            }
            LLIL_CALL_SSA => {
                LowLevelILInstructionKind::CallSsa(Operation::new(function, op, expr_index))
            }
            LLIL_TAILCALL => {
                LowLevelILInstructionKind::TailCall(Operation::new(function, op, expr_index))
            }
            LLIL_TAILCALL_SSA => {
                LowLevelILInstructionKind::TailCallSsa(Operation::new(function, op, expr_index))
            }

            LLIL_RET => LowLevelILInstructionKind::Ret(Operation::new(function, op, expr_index)),
            LLIL_NORET => {
                LowLevelILInstructionKind::NoRet(Operation::new(function, op, expr_index))
            }

            LLIL_IF => LowLevelILInstructionKind::If(Operation::new(function, op, expr_index)),
            LLIL_GOTO => LowLevelILInstructionKind::Goto(Operation::new(function, op, expr_index)),

            LLIL_SYSCALL => {
                LowLevelILInstructionKind::Syscall(Operation::new(function, op, expr_index))
            }
            LLIL_SYSCALL_SSA => {
                LowLevelILInstructionKind::SyscallSsa(Operation::new(function, op, expr_index))
            }
            LLIL_INTRINSIC | LLIL_INTRINSIC_SSA => {
                LowLevelILInstructionKind::Intrinsic(Operation::new(function, op, expr_index))
            }
            LLIL_BP => LowLevelILInstructionKind::Bp(Operation::new(function, op, expr_index)),
            LLIL_TRAP => LowLevelILInstructionKind::Trap(Operation::new(function, op, expr_index)),
            LLIL_UNDEF => {
                LowLevelILInstructionKind::Undef(Operation::new(function, op, expr_index))
            }
            LLIL_ASSERT => {
                LowLevelILInstructionKind::Assert(Operation::new(function, op, expr_index))
            }
            LLIL_ASSERT_SSA => {
                LowLevelILInstructionKind::AssertSsa(Operation::new(function, op, expr_index))
            }
            LLIL_FORCE_VER => {
                LowLevelILInstructionKind::ForceVersion(Operation::new(function, op, expr_index))
            }
            LLIL_FORCE_VER_SSA => {
                LowLevelILInstructionKind::ForceVersionSsa(Operation::new(function, op, expr_index))
            }
            LLIL_REG_PHI => {
                LowLevelILInstructionKind::RegPhi(Operation::new(function, op, expr_index))
            }
            LLIL_MEM_PHI => {
                LowLevelILInstructionKind::MemPhi(Operation::new(function, op, expr_index))
            }
            LLIL_FLAG_PHI => {
                LowLevelILInstructionKind::FlagPhi(Operation::new(function, op, expr_index))
            }

            _ => LowLevelILInstructionKind::Value(LowLevelILExpression::new(function, expr_index)),
        }
    }

    fn visit_sub_expressions<T>(&self, mut visitor: T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, M, F, ValueExpr>) -> VisitorAction,
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
            SetRegSsa(ref op) => visit!(&op.source_expr()),
            SetRegPartialSsa(ref op) => visit!(&op.source_expr()),
            SetRegSplit(ref op) => visit!(&op.source_expr()),
            SetRegSplitSsa(ref op) => visit!(&op.source_expr()),
            SetFlag(ref op) => visit!(&op.source_expr()),
            SetFlagSsa(ref op) => visit!(&op.source_expr()),
            Store(ref op) => {
                visit!(&op.dest_expr());
                visit!(&op.source_expr());
            }
            StoreSsa(ref op) => {
                visit!(&op.dest_expr());
                visit!(&op.source_expr());
            }
            Push(ref op) => visit!(&op.operand()),
            RegStackPush(ref op) => visit!(&op.source_expr()),
            Jump(ref op) => visit!(&op.target()),
            JumpTo(ref op) => visit!(&op.target()),
            SyscallSsa(ref op) => {
                visit!(&op.output_expr());
                visit!(&op.param_expr());
                visit!(&op.stack_expr());
            }
            Call(ref op) | TailCall(ref op) => visit!(&op.target()),
            CallSsa(ref op) | TailCallSsa(ref op) => visit!(&op.target()),
            Ret(ref op) => visit!(&op.target()),
            If(ref op) => visit!(&op.condition()),
            Intrinsic(ref _op) => {
                // TODO: Visit when we support expression lists
            }
            Value(e) => visit!(e),
            // Do not have any sub expressions.
            Nop(_) | NoRet(_) | Goto(_) | Syscall(_) | Bp(_) | Trap(_) | Undef(_) | Assert(_)
            | AssertSsa(_) | ForceVersion(_) | ForceVersionSsa(_) | RegPhi(_) | FlagPhi(_)
            | MemPhi(_) => {}
        }

        VisitorAction::Sibling
    }
}
