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
use binaryninjacore_sys::BNLowLevelILInstruction;

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
    pub(crate) fn new(function: &'func Function<A, M, F>, expr_idx: usize) -> Self {
        Self {
            function,
            expr_idx,
            _ty: PhantomData,
        }
    }

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
    op: BNLowLevelILInstruction,
) -> ExprInfo<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    use binaryninjacore_sys::BNLowLevelILOperation::*;

    match op.operation {
        LLIL_CONST => ExprInfo::Const(Operation::new(function, op)),
        LLIL_CONST_PTR => ExprInfo::ConstPtr(Operation::new(function, op)),

        LLIL_EXTERN_PTR => ExprInfo::ExternPtr(Operation::new(function, op)),

        LLIL_ADD => ExprInfo::Add(Operation::new(function, op)),
        LLIL_ADC => ExprInfo::Adc(Operation::new(function, op)),
        LLIL_SUB => ExprInfo::Sub(Operation::new(function, op)),
        LLIL_SBB => ExprInfo::Sbb(Operation::new(function, op)),
        LLIL_AND => ExprInfo::And(Operation::new(function, op)),
        LLIL_OR => ExprInfo::Or(Operation::new(function, op)),
        LLIL_XOR => ExprInfo::Xor(Operation::new(function, op)),
        LLIL_LSL => ExprInfo::Lsl(Operation::new(function, op)),
        LLIL_LSR => ExprInfo::Lsr(Operation::new(function, op)),
        LLIL_ASR => ExprInfo::Asr(Operation::new(function, op)),
        LLIL_ROL => ExprInfo::Rol(Operation::new(function, op)),
        LLIL_RLC => ExprInfo::Rlc(Operation::new(function, op)),
        LLIL_ROR => ExprInfo::Ror(Operation::new(function, op)),
        LLIL_RRC => ExprInfo::Rrc(Operation::new(function, op)),
        LLIL_MUL => ExprInfo::Mul(Operation::new(function, op)),

        LLIL_MULU_DP => ExprInfo::MuluDp(Operation::new(function, op)),
        LLIL_MULS_DP => ExprInfo::MulsDp(Operation::new(function, op)),

        LLIL_DIVU => ExprInfo::Divu(Operation::new(function, op)),
        LLIL_DIVS => ExprInfo::Divs(Operation::new(function, op)),

        LLIL_DIVU_DP => ExprInfo::DivuDp(Operation::new(function, op)),
        LLIL_DIVS_DP => ExprInfo::DivsDp(Operation::new(function, op)),

        LLIL_MODU => ExprInfo::Modu(Operation::new(function, op)),
        LLIL_MODS => ExprInfo::Mods(Operation::new(function, op)),

        LLIL_MODU_DP => ExprInfo::ModuDp(Operation::new(function, op)),
        LLIL_MODS_DP => ExprInfo::ModsDp(Operation::new(function, op)),

        LLIL_NEG => ExprInfo::Neg(Operation::new(function, op)),
        LLIL_NOT => ExprInfo::Not(Operation::new(function, op)),

        LLIL_SX => ExprInfo::Sx(Operation::new(function, op)),
        LLIL_ZX => ExprInfo::Zx(Operation::new(function, op)),
        LLIL_LOW_PART => ExprInfo::LowPart(Operation::new(function, op)),

        LLIL_REG_SPLIT => ExprInfo::RegSplit(Operation::new(function, op)),

        LLIL_CMP_E => ExprInfo::CmpE(Operation::new(function, op)),
        LLIL_CMP_NE => ExprInfo::CmpNe(Operation::new(function, op)),
        LLIL_CMP_SLT => ExprInfo::CmpSlt(Operation::new(function, op)),
        LLIL_CMP_ULT => ExprInfo::CmpUlt(Operation::new(function, op)),
        LLIL_CMP_SLE => ExprInfo::CmpSle(Operation::new(function, op)),
        LLIL_CMP_ULE => ExprInfo::CmpUle(Operation::new(function, op)),
        LLIL_CMP_SGE => ExprInfo::CmpSge(Operation::new(function, op)),
        LLIL_CMP_UGE => ExprInfo::CmpUge(Operation::new(function, op)),
        LLIL_CMP_SGT => ExprInfo::CmpSgt(Operation::new(function, op)),
        LLIL_CMP_UGT => ExprInfo::CmpUgt(Operation::new(function, op)),

        LLIL_BOOL_TO_INT => ExprInfo::BoolToInt(Operation::new(function, op)),

        LLIL_FADD => ExprInfo::Fadd(Operation::new(function, op)),
        LLIL_FSUB => ExprInfo::Fsub(Operation::new(function, op)),
        LLIL_FMUL => ExprInfo::Fmul(Operation::new(function, op)),
        LLIL_FDIV => ExprInfo::Fdiv(Operation::new(function, op)),

        LLIL_FSQRT => ExprInfo::Fsqrt(Operation::new(function, op)),
        LLIL_FNEG => ExprInfo::Fneg(Operation::new(function, op)),
        LLIL_FABS => ExprInfo::Fabs(Operation::new(function, op)),
        LLIL_FLOAT_TO_INT => ExprInfo::FloatToInt(Operation::new(function, op)),
        LLIL_INT_TO_FLOAT => ExprInfo::IntToFloat(Operation::new(function, op)),
        LLIL_FLOAT_CONV => ExprInfo::FloatConv(Operation::new(function, op)),
        LLIL_ROUND_TO_INT => ExprInfo::RoundToInt(Operation::new(function, op)),
        LLIL_FLOOR => ExprInfo::Floor(Operation::new(function, op)),
        LLIL_CEIL => ExprInfo::Ceil(Operation::new(function, op)),
        LLIL_FTRUNC => ExprInfo::Ftrunc(Operation::new(function, op)),

        LLIL_FCMP_E => ExprInfo::FcmpE(Operation::new(function, op)),
        LLIL_FCMP_NE => ExprInfo::FcmpNE(Operation::new(function, op)),
        LLIL_FCMP_LT => ExprInfo::FcmpLT(Operation::new(function, op)),
        LLIL_FCMP_LE => ExprInfo::FcmpLE(Operation::new(function, op)),
        LLIL_FCMP_GT => ExprInfo::FcmpGT(Operation::new(function, op)),
        LLIL_FCMP_GE => ExprInfo::FcmpGE(Operation::new(function, op)),
        LLIL_FCMP_O => ExprInfo::FcmpO(Operation::new(function, op)),
        LLIL_FCMP_UO => ExprInfo::FcmpUO(Operation::new(function, op)),

        LLIL_UNIMPL => ExprInfo::Unimpl(Operation::new(function, op)),
        LLIL_UNIMPL_MEM => ExprInfo::UnimplMem(Operation::new(function, op)),

        // TODO TEST_BIT ADD_OVERFLOW LLIL_REG_STACK_PUSH LLIL_REG_STACK_POP
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
        | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op) | CmpUgt(ref op)
        | FcmpE(ref op) | FcmpNE(ref op) | FcmpLT(ref op) | FcmpLE(ref op) | FcmpGE(ref op)
        | FcmpGT(ref op) | FcmpO(ref op) | FcmpUO(ref op) => {
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
        | MuluDp(ref op) | Divu(ref op) | Divs(ref op) | Modu(ref op) | Mods(ref op)
        | Fadd(ref op) | Fsub(ref op) | Fmul(ref op) | Fdiv(ref op) => {
            visit!(f, &op.left());
            visit!(f, &op.right());
        }

        DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => {
            visit!(f, &op.high());
            visit!(f, &op.low());
            visit!(f, &op.right());
        }

        Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
        | BoolToInt(ref op) | Fsqrt(ref op) | Fneg(ref op) | Fabs(ref op) | FloatToInt(ref op)
        | IntToFloat(ref op) | FloatConv(ref op) | RoundToInt(ref op) | Floor(ref op)
        | Ceil(ref op) | Ftrunc(ref op) => {
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
        op: BNLowLevelILInstruction,
    ) -> ExprInfo<'func, A, M, NonSSA<V>> {
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        match op.operation {
            LLIL_LOAD => ExprInfo::Load(Operation::new(self.function, op)),
            LLIL_POP => ExprInfo::Pop(Operation::new(self.function, op)),
            LLIL_REG => ExprInfo::Reg(Operation::new(self.function, op)),
            LLIL_REG_SPLIT => ExprInfo::RegSplit(Operation::new(self.function, op)),
            LLIL_FLAG => ExprInfo::Flag(Operation::new(self.function, op)),
            LLIL_FLAG_BIT => ExprInfo::FlagBit(Operation::new(self.function, op)),
            LLIL_FLAG_COND => ExprInfo::FlagCond(Operation::new(self.function, op)), // TODO lifted only
            LLIL_FLAG_GROUP => ExprInfo::FlagGroup(Operation::new(self.function, op)), // TODO lifted only
            _ => common_info(self.function, op),
        }
    }

    pub fn info(&self) -> ExprInfo<'func, A, M, NonSSA<V>> {
        unsafe {
            let op = BNGetLowLevelILByIndex(self.function.handle, self.expr_idx);
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
        op: BNLowLevelILInstruction,
    ) -> ExprInfo<'func, A, M, SSA> {
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        match op.operation {
            LLIL_LOAD_SSA => ExprInfo::Load(Operation::new(self.function, op)),
            LLIL_REG_SSA | LLIL_REG_SSA_PARTIAL => ExprInfo::Reg(Operation::new(self.function, op)),
            LLIL_REG_SPLIT_SSA => ExprInfo::RegSplit(Operation::new(self.function, op)),
            LLIL_FLAG_SSA => ExprInfo::Flag(Operation::new(self.function, op)),
            LLIL_FLAG_BIT_SSA => ExprInfo::FlagBit(Operation::new(self.function, op)),
            _ => common_info(self.function, op),
        }
    }

    pub fn info(&self) -> ExprInfo<'func, A, M, SSA> {
        unsafe {
            let op = BNGetLowLevelILByIndex(self.function.handle, self.expr_idx);
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
    Pop(Operation<'func, A, M, F, operation::Pop>),
    Reg(Operation<'func, A, M, F, operation::Reg>),
    RegSplit(Operation<'func, A, M, F, operation::RegSplit>),
    Const(Operation<'func, A, M, F, operation::Const>),
    ConstPtr(Operation<'func, A, M, F, operation::Const>),
    Flag(Operation<'func, A, M, F, operation::Flag>),
    FlagBit(Operation<'func, A, M, F, operation::FlagBit>),
    ExternPtr(Operation<'func, A, M, F, operation::Extern>),

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

    FlagCond(Operation<'func, A, M, F, operation::FlagCond>),
    FlagGroup(Operation<'func, A, M, F, operation::FlagGroup>),

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

    Fadd(Operation<'func, A, M, F, operation::BinaryOp>),
    Fsub(Operation<'func, A, M, F, operation::BinaryOp>),
    Fmul(Operation<'func, A, M, F, operation::BinaryOp>),
    Fdiv(Operation<'func, A, M, F, operation::BinaryOp>),
    Fsqrt(Operation<'func, A, M, F, operation::UnaryOp>),
    Fneg(Operation<'func, A, M, F, operation::UnaryOp>),
    Fabs(Operation<'func, A, M, F, operation::UnaryOp>),
    FloatToInt(Operation<'func, A, M, F, operation::UnaryOp>),
    IntToFloat(Operation<'func, A, M, F, operation::UnaryOp>),
    FloatConv(Operation<'func, A, M, F, operation::UnaryOp>),
    RoundToInt(Operation<'func, A, M, F, operation::UnaryOp>),
    Floor(Operation<'func, A, M, F, operation::UnaryOp>),
    Ceil(Operation<'func, A, M, F, operation::UnaryOp>),
    Ftrunc(Operation<'func, A, M, F, operation::UnaryOp>),

    FcmpE(Operation<'func, A, M, F, operation::Condition>),
    FcmpNE(Operation<'func, A, M, F, operation::Condition>),
    FcmpLT(Operation<'func, A, M, F, operation::Condition>),
    FcmpLE(Operation<'func, A, M, F, operation::Condition>),
    FcmpGE(Operation<'func, A, M, F, operation::Condition>),
    FcmpGT(Operation<'func, A, M, F, operation::Condition>),
    FcmpO(Operation<'func, A, M, F, operation::Condition>),
    FcmpUO(Operation<'func, A, M, F, operation::Condition>),

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

            FlagCond(..) | FlagGroup(..) | CmpE(..) | CmpNe(..) | CmpSlt(..) | CmpUlt(..)
            | CmpSle(..) | CmpUle(..) | CmpSge(..) | CmpUge(..) | CmpSgt(..) | CmpUgt(..) => {
                Some(0)
            }

            _ => Some(self.raw_struct().size),
            //TestBit(Operation<'func, A, M, F, operation::TestBit>), // TODO
        }
    }

    pub fn address(&self) -> u64 {
        self.raw_struct().address
    }

    /// Determines if the expressions represent the same operation
    ///
    /// It does not examine the operands for equality.
    pub fn is_same_op_as(&self, other: &Self) -> bool {
        use self::ExprInfo::*;

        match (self, other) {
            (&Reg(..), &Reg(..)) => true,
            _ => self.raw_struct().operation == other.raw_struct().operation,
        }
    }

    pub fn as_cmp_op(&self) -> Option<&Operation<'func, A, M, F, operation::Condition>> {
        use self::ExprInfo::*;

        match *self {
            CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
            | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op)
            | CmpUgt(ref op) | FcmpE(ref op) | FcmpNE(ref op) | FcmpLT(ref op) | FcmpLE(ref op)
            | FcmpGE(ref op) | FcmpGT(ref op) | FcmpO(ref op) | FcmpUO(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_binary_op(&self) -> Option<&Operation<'func, A, M, F, operation::BinaryOp>> {
        use self::ExprInfo::*;

        match *self {
            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op) | Modu(ref op)
            | Mods(ref op) | Fadd(ref op) | Fsub(ref op) | Fmul(ref op) | Fdiv(ref op) => Some(op),
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
            | BoolToInt(ref op) | Fsqrt(ref op) | Fneg(ref op) | Fabs(ref op)
            | FloatToInt(ref op) | IntToFloat(ref op) | FloatConv(ref op) | RoundToInt(ref op)
            | Floor(ref op) | Ceil(ref op) | Ftrunc(ref op) => Some(op),
            _ => None,
        }
    }

    pub(crate) fn raw_struct(&self) -> &BNLowLevelILInstruction {
        use self::ExprInfo::*;

        match *self {
            Undef(ref op) => &op.op,

            Unimpl(ref op) => &op.op,

            FlagCond(ref op) => &op.op,
            FlagGroup(ref op) => &op.op,

            CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
            | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op)
            | CmpUgt(ref op) | FcmpE(ref op) | FcmpNE(ref op) | FcmpLT(ref op) | FcmpLE(ref op)
            | FcmpGE(ref op) | FcmpGT(ref op) | FcmpO(ref op) | FcmpUO(ref op) => &op.op,

            Load(ref op) => &op.op,

            Pop(ref op) => &op.op,

            Reg(ref op) => &op.op,

            RegSplit(ref op) => &op.op,

            Flag(ref op) => &op.op,

            FlagBit(ref op) => &op.op,

            Const(ref op) | ConstPtr(ref op) => &op.op,

            ExternPtr(ref op) => &op.op,

            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => &op.op,

            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op) | Modu(ref op)
            | Mods(ref op) | Fadd(ref op) | Fsub(ref op) | Fmul(ref op) | Fdiv(ref op) => &op.op,

            DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => &op.op,

            Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
            | BoolToInt(ref op) | Fsqrt(ref op) | Fneg(ref op) | Fabs(ref op)
            | FloatToInt(ref op) | IntToFloat(ref op) | FloatConv(ref op) | RoundToInt(ref op)
            | Floor(ref op) | Ceil(ref op) | Ftrunc(ref op) => &op.op,

            UnimplMem(ref op) => &op.op,
            //TestBit(Operation<'func, A, M, F, operation::TestBit>), // TODO
        }
    }
}

impl<'func, A> ExprInfo<'func, A, Mutable, NonSSA<LiftedNonSSA>>
where
    A: 'func + Architecture,
{
    pub fn flag_write(&self) -> Option<A::FlagWrite> {
        use self::ExprInfo::*;

        match *self {
            Undef(ref _op) => None,

            Unimpl(ref _op) => None,

            FlagCond(ref _op) => None,
            FlagGroup(ref _op) => None,

            CmpE(ref _op) | CmpNe(ref _op) | CmpSlt(ref _op) | CmpUlt(ref _op)
            | CmpSle(ref _op) | CmpUle(ref _op) | CmpSge(ref _op) | CmpUge(ref _op)
            | CmpSgt(ref _op) | CmpUgt(ref _op) | FcmpE(ref _op) | FcmpNE(ref _op)
            | FcmpLT(ref _op) | FcmpLE(ref _op) | FcmpGE(ref _op) | FcmpGT(ref _op)
            | FcmpO(ref _op) | FcmpUO(ref _op) => None,

            Load(ref op) => op.flag_write(),

            Pop(ref op) => op.flag_write(),

            Reg(ref op) => op.flag_write(),

            RegSplit(ref op) => op.flag_write(),

            Flag(ref op) => op.flag_write(),

            FlagBit(ref op) => op.flag_write(),

            Const(ref op) | ConstPtr(ref op) => op.flag_write(),

            ExternPtr(ref op) => op.flag_write(),

            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => op.flag_write(),

            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op) | Modu(ref op)
            | Mods(ref op) | Fadd(ref op) | Fsub(ref op) | Fmul(ref op) | Fdiv(ref op) => {
                op.flag_write()
            }

            DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => op.flag_write(),

            Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
            | BoolToInt(ref op) | Fsqrt(ref op) | Fneg(ref op) | Fabs(ref op)
            | FloatToInt(ref op) | IntToFloat(ref op) | FloatConv(ref op) | RoundToInt(ref op)
            | Floor(ref op) | Ceil(ref op) | Ftrunc(ref op) => op.flag_write(),

            UnimplMem(ref op) => op.flag_write(),
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

            FlagCond(..) => f.write_str("some_flag_cond"),
            FlagGroup(..) => f.write_str("some_flag_group"),

            CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
            | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op)
            | CmpUgt(ref op) | FcmpE(ref op) | FcmpNE(ref op) | FcmpLT(ref op) | FcmpLE(ref op)
            | FcmpGE(ref op) | FcmpGT(ref op) | FcmpO(ref op) | FcmpUO(ref op) => {
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

            Pop(ref op) => write!(f, "pop.{}", op.size()),

            Reg(ref op) => {
                let reg = op.source_reg();
                let size = op.size();

                let size = match reg {
                    Register::Temp(_) => Some(size),
                    Register::ArchReg(ref r) if r.info().size() != size => Some(size),
                    _ => None,
                };

                match size {
                    Some(s) => write!(f, "{:?}.{}", reg, s),
                    _ => write!(f, "{:?}", reg),
                }
            }

            RegSplit(ref op) => {
                let low_reg = op.low_reg();
                let high_reg = op.high_reg();
                let size = op.size();

                let low_size = match low_reg {
                    Register::Temp(_) => Some(size),
                    Register::ArchReg(ref r) if r.info().size() != size => Some(size),
                    _ => None,
                };

                let high_size = match high_reg {
                    Register::Temp(_) => Some(size),
                    Register::ArchReg(ref r) if r.info().size() != size => Some(size),
                    _ => None,
                };

                match (low_size, high_size) {
                    (Some(ls), Some(hs)) => write!(f, "{:?}.{}:{:?}.{}", high_reg, hs, low_reg, ls),
                    (Some(ls), None) => write!(f, "{:?}:{:?}.{}", high_reg, low_reg, ls),
                    (None, Some(hs)) => write!(f, "{:?}.{}:{:?}", high_reg, hs, low_reg),
                    _ => write!(f, "{:?}:{:?}", high_reg, low_reg),
                }
            }

            Flag(ref _op) => write!(f, "flag"), // TODO

            FlagBit(ref _op) => write!(f, "flag_bit"), // TODO

            Const(ref op) | ConstPtr(ref op) => write!(f, "0x{:x}", op.value()),

            ExternPtr(ref op) => write!(f, "0x{:x}", op.value()),

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
            | Mods(ref op) | Fadd(ref op) | Fsub(ref op) | Fmul(ref op) | Fdiv(ref op) => {
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
            | BoolToInt(ref op) | Fsqrt(ref op) | Fneg(ref op) | Fabs(ref op)
            | FloatToInt(ref op) | IntToFloat(ref op) | FloatConv(ref op) | RoundToInt(ref op)
            | Floor(ref op) | Ceil(ref op) | Ftrunc(ref op) => write!(
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
