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

use binaryninjacore_sys::BNGetLowLevelILByIndex;
use binaryninjacore_sys::BNGetLowLevelILIndexForInstruction;
use binaryninjacore_sys::BNLowLevelILInstruction;

use super::operation;
use super::operation::Operation;
use super::*;

use crate::architecture::Architecture;

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
    op: BNLowLevelILInstruction,
) -> Option<InstrInfo<'func, A, M, F>>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    use binaryninjacore_sys::BNLowLevelILOperation::*;

    match op.operation {
        LLIL_NOP => InstrInfo::Nop(Operation::new(function, op)).into(),
        LLIL_JUMP => InstrInfo::Jump(Operation::new(function, op)).into(),
        LLIL_JUMP_TO => InstrInfo::JumpTo(Operation::new(function, op)).into(),
        LLIL_RET => InstrInfo::Ret(Operation::new(function, op)).into(),
        LLIL_NORET => InstrInfo::NoRet(Operation::new(function, op)).into(),
        LLIL_IF => InstrInfo::If(Operation::new(function, op)).into(),
        LLIL_GOTO => InstrInfo::Goto(Operation::new(function, op)).into(),
        LLIL_BP => InstrInfo::Bp(Operation::new(function, op)).into(),
        LLIL_TRAP => InstrInfo::Trap(Operation::new(function, op)).into(),
        LLIL_UNDEF => InstrInfo::Undef(Operation::new(function, op)).into(),
        _ => None,
    }
}

use super::VisitorAction;

macro_rules! visit {
    ($f:expr, $($e:expr),*) => {
        if let VisitorAction::Halt = $f($($e,)*) {
            return VisitorAction::Halt;
        }
    }
}

fn common_visit<'func, A, M, F, CB>(info: &InstrInfo<'func, A, M, F>, f: &mut CB) -> VisitorAction
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    CB: FnMut(&Expression<'func, A, M, F, ValueExpr>) -> VisitorAction,
{
    use self::InstrInfo::*;

    match *info {
        Jump(ref op) => visit!(f, &op.target()),
        JumpTo(ref op) => visit!(f, &op.target()),
        Ret(ref op) => visit!(f, &op.target()),
        If(ref op) => visit!(f, &op.condition()),
        Value(ref e, _) => visit!(f, e),
        _ => {}
    };

    VisitorAction::Sibling
}

impl<'func, A, M, V> Instruction<'func, A, M, NonSSA<V>>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn address(&self) -> u64 {
        let expr_idx =
            unsafe { BNGetLowLevelILIndexForInstruction(self.function.handle, self.instr_idx) };
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, expr_idx) };
        op.address
    }

    pub fn info(&self) -> InstrInfo<'func, A, M, NonSSA<V>> {
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        let expr_idx =
            unsafe { BNGetLowLevelILIndexForInstruction(self.function.handle, self.instr_idx) };
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, expr_idx) };

        match op.operation {
            LLIL_SET_REG => InstrInfo::SetReg(Operation::new(self.function, op)),
            LLIL_SET_REG_SPLIT => InstrInfo::SetRegSplit(Operation::new(self.function, op)),
            LLIL_SET_FLAG => InstrInfo::SetFlag(Operation::new(self.function, op)),
            LLIL_STORE => InstrInfo::Store(Operation::new(self.function, op)),
            LLIL_PUSH => InstrInfo::Push(Operation::new(self.function, op)),
            LLIL_CALL | LLIL_CALL_STACK_ADJUST => {
                InstrInfo::Call(Operation::new(self.function, op))
            }
            LLIL_TAILCALL => InstrInfo::TailCall(Operation::new(self.function, op)),
            LLIL_SYSCALL => InstrInfo::Syscall(Operation::new(self.function, op)),
            LLIL_INTRINSIC => InstrInfo::Intrinsic(Operation::new(self.function, op)),
            _ => {
                common_info(self.function, op).unwrap_or_else(|| {
                    // Hopefully this is a bare value. If it isn't (expression
                    // from wrong function form or similar) it won't really cause
                    // any problems as it'll come back as undefined when queried.
                    let expr = Expression::new(self.function, expr_idx);

                    let info = unsafe { expr.info_from_op(op) };

                    InstrInfo::Value(expr, info)
                })
            }
        }
    }

    pub fn visit_tree<F>(&self, f: &mut F) -> VisitorAction
    where
        F: FnMut(
            &Expression<'func, A, M, NonSSA<V>, ValueExpr>,
            &ExprInfo<'func, A, M, NonSSA<V>>,
        ) -> VisitorAction,
    {
        use self::InstrInfo::*;
        let info = self.info();

        let fb = &mut |e: &Expression<'func, A, M, NonSSA<V>, ValueExpr>| e.visit_tree(f);

        match info {
            SetReg(ref op) => visit!(fb, &op.source_expr()),
            SetRegSplit(ref op) => visit!(fb, &op.source_expr()),
            SetFlag(ref op) => visit!(fb, &op.source_expr()),
            Store(ref op) => {
                visit!(fb, &op.dest_mem_expr());
                visit!(fb, &op.source_expr());
            }
            Push(ref op) => visit!(fb, &op.operand()),
            Call(ref op) | TailCall(ref op) => visit!(fb, &op.target()),
            Intrinsic(ref _op) => {
                // TODO: Use this when we support expression lists
                // for expr in op.source_exprs() {
                //     visit!(fb, expr);
                // }
            }
            _ => visit!(common_visit, &info, fb),
        }

        VisitorAction::Sibling
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
    Push(Operation<'func, A, M, F, operation::UnaryOp>), // TODO needs a real op

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

    Value(
        Expression<'func, A, M, F, ValueExpr>,
        ExprInfo<'func, A, M, F>,
    ),
}
