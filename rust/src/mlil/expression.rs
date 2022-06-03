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
use binaryninjacore_sys::BNMediumLevelILInstruction;

use std::fmt;
use std::marker::PhantomData;

use super::operation;
use super::operation::Operation;
use super::*;

use crate::architecture::Architecture;
use crate::architecture::RegisterInfo;

// used as a marker for Expressions that can produce a value
#[derive(Copy, Clone, Debug)]
pub struct ValueExpr;

// used as a marker for Expressions that can not produce a value
#[derive(Copy, Clone, Debug)]
pub struct VoidExpr;

pub trait ExpressionResultType: 'static {}

impl ExpressionResultType for ValueExpr {}

impl ExpressionResultType for VoidExpr {}

pub struct Expression<'func, A, M, F, R>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    pub(crate) function: &'func Function<A, M, F>,
    pub(crate) expr_idx: usize,

    // tag the 'return' type of this expression
    pub(crate) _ty: PhantomData<R>,
}

impl<'func, A, M, F, R> Expression<'func, A, M, F, R>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    pub fn index(&self) -> usize {
        self.expr_idx
    }
}

impl<'func, A, M, V> fmt::Debug for Expression<'func, A, M, NonSSA<V>, ValueExpr>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let op_info = self.info();
        write!(f, "<expr {}: {:?}>", self.expr_idx, op_info)
    }
}

fn common_info<'func, A, M, F>(
    function: &'func Function<A, M, F>,
    op: BNMediumLevelILInstruction,
) -> ExprInfo<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    use binaryninjacore_sys::BNMediumLevelILOperation::*;

    match op.operation {
        MLIL_CONST => ExprInfo::Const(Operation::new(function, op)),
        MLIL_CONST_PTR => ExprInfo::ConstPtr(Operation::new(function, op)),

        MLIL_ADD => ExprInfo::Add(Operation::new(function, op)),
        MLIL_ADC => ExprInfo::Adc(Operation::new(function, op)),
        MLIL_SUB => ExprInfo::Sub(Operation::new(function, op)),
        MLIL_SBB => ExprInfo::Sbb(Operation::new(function, op)),
        MLIL_AND => ExprInfo::And(Operation::new(function, op)),
        MLIL_OR => ExprInfo::Or(Operation::new(function, op)),
        MLIL_XOR => ExprInfo::Xor(Operation::new(function, op)),
        MLIL_LSL => ExprInfo::Lsl(Operation::new(function, op)),
        MLIL_LSR => ExprInfo::Lsr(Operation::new(function, op)),
        MLIL_ASR => ExprInfo::Asr(Operation::new(function, op)),
        MLIL_ROL => ExprInfo::Rol(Operation::new(function, op)),
        MLIL_RLC => ExprInfo::Rlc(Operation::new(function, op)),
        MLIL_ROR => ExprInfo::Ror(Operation::new(function, op)),
        MLIL_RRC => ExprInfo::Rrc(Operation::new(function, op)),
        MLIL_MUL => ExprInfo::Mul(Operation::new(function, op)),

        MLIL_MULU_DP => ExprInfo::MuluDp(Operation::new(function, op)),
        MLIL_MULS_DP => ExprInfo::MulsDp(Operation::new(function, op)),

        MLIL_DIVU => ExprInfo::Divu(Operation::new(function, op)),
        MLIL_DIVS => ExprInfo::Divs(Operation::new(function, op)),

        MLIL_DIVU_DP => ExprInfo::DivuDp(Operation::new(function, op)),
        MLIL_DIVS_DP => ExprInfo::DivsDp(Operation::new(function, op)),

        MLIL_MODU => ExprInfo::Modu(Operation::new(function, op)),
        MLIL_MODS => ExprInfo::Mods(Operation::new(function, op)),

        MLIL_MODU_DP => ExprInfo::ModuDp(Operation::new(function, op)),
        MLIL_MODS_DP => ExprInfo::ModsDp(Operation::new(function, op)),

        MLIL_NEG => ExprInfo::Neg(Operation::new(function, op)),
        MLIL_NOT => ExprInfo::Not(Operation::new(function, op)),

        MLIL_SX => ExprInfo::Sx(Operation::new(function, op)),
        MLIL_ZX => ExprInfo::Zx(Operation::new(function, op)),
        MLIL_LOW_PART => ExprInfo::LowPart(Operation::new(function, op)),

        MLIL_CMP_E => ExprInfo::CmpE(Operation::new(function, op)),
        MLIL_CMP_NE => ExprInfo::CmpNe(Operation::new(function, op)),
        MLIL_CMP_SLT => ExprInfo::CmpSlt(Operation::new(function, op)),
        MLIL_CMP_ULT => ExprInfo::CmpUlt(Operation::new(function, op)),
        MLIL_CMP_SLE => ExprInfo::CmpSle(Operation::new(function, op)),
        MLIL_CMP_ULE => ExprInfo::CmpUle(Operation::new(function, op)),
        MLIL_CMP_SGE => ExprInfo::CmpSge(Operation::new(function, op)),
        MLIL_CMP_UGE => ExprInfo::CmpUge(Operation::new(function, op)),
        MLIL_CMP_SGT => ExprInfo::CmpSgt(Operation::new(function, op)),
        MLIL_CMP_UGT => ExprInfo::CmpUgt(Operation::new(function, op)),

        MLIL_BOOL_TO_INT => ExprInfo::BoolToInt(Operation::new(function, op)),

        MLIL_UNIMPL => ExprInfo::Unimpl(Operation::new(function, op)),
        MLIL_UNIMPL_MEM => ExprInfo::UnimplMem(Operation::new(function, op)),

        // TODO TEST_BIT ADD_OVERFLOW
        _ => {
            #[cfg(debug_assertions)]
            {
                error!(
                    "Got unexpected operation {:?} in value expr at 0x{:x}",
                    op.operation, op.address
                );
            }

            ExprInfo::Undef(Operation::new(function, op))
        }
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

fn common_visit<'func, A, M, F, CB>(info: &ExprInfo<'func, A, M, F>, f: &mut CB) -> VisitorAction
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    CB: FnMut(&Expression<'func, A, M, F, ValueExpr>) -> VisitorAction,
{
    use self::ExprInfo::*;

    match *info {
        CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
        | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op) | CmpUgt(ref op) => {
            visit!(f, &op.left());
            visit!(f, &op.right());
        }

        Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => {
            visit!(f, &op.left());
            visit!(f, &op.right());
            visit!(f, &op.carry());
        }

        Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
        | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op) | MulsDp(ref op)
        | MuluDp(ref op) | Divu(ref op) | Divs(ref op) | Modu(ref op) | Mods(ref op) => {
            visit!(f, &op.left());
            visit!(f, &op.right());
        }

        DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => {
            visit!(f, &op.high());
            visit!(f, &op.low());
            visit!(f, &op.right());
        }

        Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
        | BoolToInt(ref op) => {
            visit!(f, &op.operand());
        }

        UnimplMem(ref op) => {
            visit!(f, &op.mem_expr());
        }

        _ => {}
    };

    VisitorAction::Sibling
}

impl<'func, A, M, V> Expression<'func, A, M, NonSSA<V>, ValueExpr>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub(crate) unsafe fn info_from_op(
        &self,
        op: BNMediumLevelILInstruction,
    ) -> ExprInfo<'func, A, M, NonSSA<V>> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        match op.operation {
            MLIL_LOAD => ExprInfo::Load(Operation::new(self.function, op)),
            _ => common_info(self.function, op),
        }
    }

    pub fn info(&self) -> ExprInfo<'func, A, M, NonSSA<V>> {
        unsafe {
            let op = BNGetMediumLevelILByIndex(self.function.handle, self.expr_idx);
            self.info_from_op(op)
        }
    }

    pub fn visit_tree<F>(&self, f: &mut F) -> VisitorAction
    where
        F: FnMut(&Self, &ExprInfo<'func, A, M, NonSSA<V>>) -> VisitorAction,
    {
        use self::ExprInfo::*;

        let info = self.info();

        match f(self, &info) {
            VisitorAction::Descend => {}
            action => return action,
        };

        match info {
            Load(ref op) => visit!(Self::visit_tree, &op.source_mem_expr(), f),
            _ => {
                let mut fb = |e: &Self| e.visit_tree(f);
                visit!(common_visit, &info, &mut fb);
            }
        };

        VisitorAction::Sibling
    }
}

impl<'func, A, M> Expression<'func, A, M, SSA, ValueExpr>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub(crate) unsafe fn info_from_op(
        &self,
        op: BNMediumLevelILInstruction,
    ) -> ExprInfo<'func, A, M, SSA> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        match op.operation {
            MLIL_LOAD_SSA => ExprInfo::Load(Operation::new(self.function, op)),
            _ => common_info(self.function, op),
        }
    }

    pub fn info(&self) -> ExprInfo<'func, A, M, SSA> {
        unsafe {
            let op = BNGetMediumLevelILByIndex(self.function.handle, self.expr_idx);
            self.info_from_op(op)
        }
    }

    pub fn visit_tree<F>(&self, f: &mut F) -> VisitorAction
    where
        F: FnMut(&Self, &ExprInfo<'func, A, M, SSA>) -> VisitorAction,
    {
        use self::ExprInfo::*;

        let info = self.info();

        match f(self, &info) {
            VisitorAction::Descend => {}
            action => return action,
        };

        match info {
            // TODO ssa
            Load(ref _op) => {} //visit!(Self::visit_tree, &op.source_mem_expr(), f),
            _ => {
                let mut fb = |e: &Self| e.visit_tree(f);
                visit!(common_visit, &info, &mut fb);
            }
        };

        VisitorAction::Sibling
    }
}

impl<'func, A, F> Expression<'func, A, Finalized, F, ValueExpr>
where
    A: 'func + Architecture,
    F: FunctionForm,
{
    // TODO possible values
}

pub enum ExprInfo<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    Load(Operation<'func, A, M, F, operation::Load>),
    Const(Operation<'func, A, M, F, operation::Const>),
    ConstPtr(Operation<'func, A, M, F, operation::Const>),

    Add(Operation<'func, A, M, F, operation::BinaryOp>),
    Adc(Operation<'func, A, M, F, operation::BinaryOpCarry>),
    Sub(Operation<'func, A, M, F, operation::BinaryOp>),
    Sbb(Operation<'func, A, M, F, operation::BinaryOpCarry>),
    And(Operation<'func, A, M, F, operation::BinaryOp>),
    Or(Operation<'func, A, M, F, operation::BinaryOp>),
    Xor(Operation<'func, A, M, F, operation::BinaryOp>),
    Lsl(Operation<'func, A, M, F, operation::BinaryOp>),
    Lsr(Operation<'func, A, M, F, operation::BinaryOp>),
    Asr(Operation<'func, A, M, F, operation::BinaryOp>),
    Rol(Operation<'func, A, M, F, operation::BinaryOp>),
    Rlc(Operation<'func, A, M, F, operation::BinaryOpCarry>),
    Ror(Operation<'func, A, M, F, operation::BinaryOp>),
    Rrc(Operation<'func, A, M, F, operation::BinaryOpCarry>),
    Mul(Operation<'func, A, M, F, operation::BinaryOp>),

    MulsDp(Operation<'func, A, M, F, operation::BinaryOp>),
    MuluDp(Operation<'func, A, M, F, operation::BinaryOp>),

    Divu(Operation<'func, A, M, F, operation::BinaryOp>),
    Divs(Operation<'func, A, M, F, operation::BinaryOp>),

    DivuDp(Operation<'func, A, M, F, operation::DoublePrecDivOp>),
    DivsDp(Operation<'func, A, M, F, operation::DoublePrecDivOp>),

    Modu(Operation<'func, A, M, F, operation::BinaryOp>),
    Mods(Operation<'func, A, M, F, operation::BinaryOp>),

    ModuDp(Operation<'func, A, M, F, operation::DoublePrecDivOp>),
    ModsDp(Operation<'func, A, M, F, operation::DoublePrecDivOp>),

    Neg(Operation<'func, A, M, F, operation::UnaryOp>),
    Not(Operation<'func, A, M, F, operation::UnaryOp>),
    Sx(Operation<'func, A, M, F, operation::UnaryOp>),
    Zx(Operation<'func, A, M, F, operation::UnaryOp>),
    LowPart(Operation<'func, A, M, F, operation::UnaryOp>),

    CmpE(Operation<'func, A, M, F, operation::Condition>),
    CmpNe(Operation<'func, A, M, F, operation::Condition>),
    CmpSlt(Operation<'func, A, M, F, operation::Condition>),
    CmpUlt(Operation<'func, A, M, F, operation::Condition>),
    CmpSle(Operation<'func, A, M, F, operation::Condition>),
    CmpUle(Operation<'func, A, M, F, operation::Condition>),
    CmpSge(Operation<'func, A, M, F, operation::Condition>),
    CmpUge(Operation<'func, A, M, F, operation::Condition>),
    CmpSgt(Operation<'func, A, M, F, operation::Condition>),
    CmpUgt(Operation<'func, A, M, F, operation::Condition>),

    //TestBit(Operation<'func, A, M, F, operation::TestBit>), // TODO
    BoolToInt(Operation<'func, A, M, F, operation::UnaryOp>),

    // TODO ADD_OVERFLOW
    Unimpl(Operation<'func, A, M, F, operation::NoArgs>),
    UnimplMem(Operation<'func, A, M, F, operation::UnimplMem>),

    Undef(Operation<'func, A, M, F, operation::NoArgs>),
}

impl<'func, A, M, F> ExprInfo<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    /// Returns the size of the result of this expression
    ///
    /// If the expression is malformed or is `Unimpl` there
    /// is no meaningful size associated with the result.
    pub fn size(&self) -> Option<usize> {
        use self::ExprInfo::*;

        match *self {
            Undef(..) | Unimpl(..) => None,

            CmpE(..) | CmpNe(..) | CmpSlt(..) | CmpUlt(..) | CmpSle(..) | CmpUle(..)
            | CmpSge(..) | CmpUge(..) | CmpSgt(..) | CmpUgt(..) => Some(0),

            _ => Some(self.raw_struct().size),
            //TestBit(Operation<'func, A, M, F, operation::TestBit>), // TODO
        }
    }

    pub fn address(&self) -> u64 {
        self.raw_struct().address
    }

    pub fn as_cmp_op(&self) -> Option<&Operation<'func, A, M, F, operation::Condition>> {
        use self::ExprInfo::*;

        match *self {
            CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
            | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op)
            | CmpUgt(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_binary_op(&self) -> Option<&Operation<'func, A, M, F, operation::BinaryOp>> {
        use self::ExprInfo::*;

        match *self {
            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op) | Modu(ref op)
            | Mods(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_binary_op_carry(
        &self,
    ) -> Option<&Operation<'func, A, M, F, operation::BinaryOpCarry>> {
        use self::ExprInfo::*;

        match *self {
            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_double_prec_div_op(
        &self,
    ) -> Option<&Operation<'func, A, M, F, operation::DoublePrecDivOp>> {
        use self::ExprInfo::*;

        match *self {
            DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_unary_op(&self) -> Option<&Operation<'func, A, M, F, operation::UnaryOp>> {
        use self::ExprInfo::*;

        match *self {
            Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
            | BoolToInt(ref op) => Some(op),
            _ => None,
        }
    }

    pub(crate) fn raw_struct(&self) -> &BNMediumLevelILInstruction {
        use self::ExprInfo::*;

        match *self {
            Undef(ref op) => &op.op,

            Unimpl(ref op) => &op.op,

            CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
            | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op)
            | CmpUgt(ref op) => &op.op,

            Load(ref op) => &op.op,

            Const(ref op) | ConstPtr(ref op) => &op.op,

            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => &op.op,

            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op) | Modu(ref op)
            | Mods(ref op) => &op.op,

            DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => &op.op,

            Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
            | BoolToInt(ref op) => &op.op,

            UnimplMem(ref op) => &op.op,
            //TestBit(Operation<'func, A, M, F, operation::TestBit>), // TODO
        }
    }
}

impl<'func, A, M, V> fmt::Debug for ExprInfo<'func, A, M, NonSSA<V>>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ExprInfo::*;

        match *self {
            Undef(..) => f.write_str("undefined"),

            Unimpl(..) => f.write_str("unimplemented"),

            CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
            | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op)
            | CmpUgt(ref op) => {
                let left = op.left();
                let right = op.right();

                write!(
                    f,
                    "{:?}({}, {:?}, {:?})",
                    op.op.operation,
                    op.size(),
                    left,
                    right
                )
            }

            Load(ref op) => {
                let source = op.source_mem_expr();
                let size = op.size();

                write!(f, "[{:?}].{}", source, size)
            }

            Const(ref op) | ConstPtr(ref op) => write!(f, "0x{:x}", op.value()),

            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => {
                let left = op.left();
                let right = op.right();
                let carry = op.carry();

                write!(
                    f,
                    "{:?}({}, {:?}, {:?}, carry: {:?})",
                    op.op.operation,
                    op.size(),
                    left,
                    right,
                    carry
                )
            }

            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op) | Modu(ref op)
            | Mods(ref op) => {
                let left = op.left();
                let right = op.right();

                write!(
                    f,
                    "{:?}({}, {:?}, {:?})",
                    op.op.operation,
                    op.size(),
                    left,
                    right
                )
            }

            DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => {
                let high = op.high();
                let low = op.low();
                let right = op.right();

                write!(
                    f,
                    "{:?}({}, {:?}:{:?},{:?})",
                    op.op.operation,
                    op.size(),
                    high,
                    low,
                    right
                )
            }

            Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
            | BoolToInt(ref op) => write!(
                f,
                "{:?}({}, {:?})",
                op.op.operation,
                op.size(),
                op.operand()
            ),

            UnimplMem(ref op) => write!(f, "unimplemented_mem({:?})", op.mem_expr()),
            //TestBit(Operation<'func, A, M, F, operation::TestBit>), // TODO
        }
    }
}
