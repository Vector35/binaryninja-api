// Copyright 2021 Vector 35 Inc.
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

use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNGetMediumLevelILIndexForInstruction;
use binaryninjacore_sys::BNMediumLevelILInstruction;

use std::marker::PhantomData;

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
        MLIL_JUMP => InstrInfo::Jump(Operation::new(function, op)).into(),
        MLIL_JUMP_TO => InstrInfo::JumpTo(Operation::new(function, op)).into(),
        MLIL_RET => InstrInfo::Ret(Operation::new(function, op)).into(),
        MLIL_NORET => InstrInfo::NoRet(Operation::new(function, op)).into(),
        MLIL_IF => InstrInfo::If(Operation::new(function, op)).into(),
        MLIL_GOTO => InstrInfo::Goto(Operation::new(function, op)).into(),
        MLIL_BP => InstrInfo::Bp(Operation::new(function, op)).into(),
        MLIL_TRAP => InstrInfo::Trap(Operation::new(function, op)).into(),
        MLIL_UNDEF => InstrInfo::Undef(Operation::new(function, op)).into(),
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
    pub fn operation(&self) -> binaryninjacore_sys::BNMediumLevelILOperation {
        let expr_idx =
            unsafe { BNGetMediumLevelILIndexForInstruction(self.function.handle, self.instr_idx) };
        unsafe { BNGetMediumLevelILByIndex(self.function.handle, expr_idx) }.operation
    }

    pub fn info(&self) -> InstrInfo<'func, A, M, NonSSA<V>> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        let expr_idx =
            unsafe { BNGetMediumLevelILIndexForInstruction(self.function.handle, self.instr_idx) };
        let op = unsafe { BNGetMediumLevelILByIndex(self.function.handle, expr_idx) };

        match op.operation {
            MLIL_STORE => InstrInfo::Store(Operation::new(self.function, op)),
            MLIL_PUSH => InstrInfo::Push(Operation::new(self.function, op)),
            MLIL_SYSCALL => InstrInfo::Syscall(Operation::new(self.function, op)),
            _ => {
                common_info(self.function, op).unwrap_or_else(|| {
                    // Hopefully this is a bare value. If it isn't (expression
                    // from wrong function form or similar) it won't really cause
                    // any problems as it'll come back as undefined when queried.
                    let expr = Expression {
                        function: self.function,
                        expr_idx: expr_idx,
                        _ty: PhantomData,
                    };

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
            Store(ref op) => {
                visit!(fb, &op.dest_mem_expr());
                visit!(fb, &op.source_expr());
            }
            Push(ref op) => visit!(fb, &op.operand()),
            Call(ref op) => visit!(fb, &op.target()),
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
    Store(Operation<'func, A, M, F, operation::Store>),
    Push(Operation<'func, A, M, F, operation::UnaryOp>), // TODO needs a real op

    Jump(Operation<'func, A, M, F, operation::Jump>),
    JumpTo(Operation<'func, A, M, F, operation::JumpTo>),

    Call(Operation<'func, A, M, F, operation::Call>),

    Ret(Operation<'func, A, M, F, operation::Ret>),
    NoRet(Operation<'func, A, M, F, operation::NoArgs>),

    If(Operation<'func, A, M, F, operation::If>),
    Goto(Operation<'func, A, M, F, operation::Goto>),

    Syscall(Operation<'func, A, M, F, operation::Syscall>),
    Bp(Operation<'func, A, M, F, operation::NoArgs>),
    Trap(Operation<'func, A, M, F, operation::Trap>),
    Undef(Operation<'func, A, M, F, operation::NoArgs>),

    Value(
        Expression<'func, A, M, F, ValueExpr>,
        ExprInfo<'func, A, M, F>,
    ),
}
