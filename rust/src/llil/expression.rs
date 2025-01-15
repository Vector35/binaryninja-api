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

use super::operation;
use super::operation::Operation;
use super::VisitorAction;
use super::*;
use crate::architecture::Architecture;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

/// Used as a marker for an [`Expression`] that **can** produce a value.
#[derive(Copy, Clone, Debug)]
pub struct ValueExpr;

/// Used as a marker for an [`Expression`] that can **not** produce a value.
#[derive(Copy, Clone, Debug)]
pub struct VoidExpr;

pub trait ExpressionResultType: 'static {}
impl ExpressionResultType for ValueExpr {}
impl ExpressionResultType for VoidExpr {}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpressionIndex(pub usize);

impl Display for ExpressionIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

pub trait ExpressionHandler<'func, A, M, F>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn info(&self) -> ExprInfo<'func, A, M, F>;

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, A, M, F, ValueExpr>) -> VisitorAction;
}

pub struct Expression<'func, A, M, F, R>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    pub(crate) function: &'func LowLevelILFunction<A, M, F>,
    pub index: ExpressionIndex,

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
    pub(crate) fn new(
        function: &'func LowLevelILFunction<A, M, F>,
        index: ExpressionIndex,
    ) -> Self {
        // TODO: Validate expression here?
        Self {
            function,
            index,
            _ty: PhantomData,
        }
    }
}

impl<'func, A, M, F, R> fmt::Debug for Expression<'func, A, M, F, R>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("Expression")
            .field("index", &self.index)
            .finish()
    }
}

impl<'func, A, M> ExpressionHandler<'func, A, M, SSA> for Expression<'func, A, M, SSA, ValueExpr>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    fn info(&self) -> ExprInfo<'func, A, M, SSA> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        #[allow(clippy::match_single_binding)]
        match op.operation {
            // Any invalid ops for SSA will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { ExprInfo::from_raw(self.function, op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, A, M, SSA, ValueExpr>) -> VisitorAction,
    {
        // First visit the current expression.
        let info = self.info();
        match f(self) {
            VisitorAction::Descend => {}
            action => return action,
        }
        // Recursively visit sub expressions.
        info.visit_sub_expressions(|e| e.visit_tree(f))
    }
}

impl<'func, A, M> ExpressionHandler<'func, A, M, NonSSA<LiftedNonSSA>>
    for Expression<'func, A, M, NonSSA<LiftedNonSSA>, ValueExpr>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    fn info(&self) -> ExprInfo<'func, A, M, NonSSA<LiftedNonSSA>> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        #[allow(clippy::match_single_binding)]
        match op.operation {
            // Any invalid ops for Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { ExprInfo::from_raw(self.function, op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, A, M, NonSSA<LiftedNonSSA>, ValueExpr>) -> VisitorAction,
    {
        // First visit the current expression.
        let info = self.info();
        match f(self) {
            VisitorAction::Descend => {}
            action => return action,
        }
        // Recursively visit sub expressions.
        info.visit_sub_expressions(|e| e.visit_tree(f))
    }
}

impl<'func, A, M> ExpressionHandler<'func, A, M, NonSSA<RegularNonSSA>>
    for Expression<'func, A, M, NonSSA<RegularNonSSA>, ValueExpr>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    fn info(&self) -> ExprInfo<'func, A, M, NonSSA<RegularNonSSA>> {
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        match op.operation {
            // Any invalid ops for Non-Lifted IL will be checked here.
            LLIL_FLAG_COND => unreachable!("LLIL_FLAG_COND is only valid in Lifted IL"),
            LLIL_FLAG_GROUP => unreachable!("LLIL_FLAG_GROUP is only valid in Lifted IL"),
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { ExprInfo::from_raw(self.function, op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, A, M, NonSSA<RegularNonSSA>, ValueExpr>) -> VisitorAction,
    {
        // First visit the current expression.
        let info = self.info();
        match f(self) {
            VisitorAction::Descend => {}
            action => return action,
        }
        // Recursively visit sub expressions.
        info.visit_sub_expressions(|e| e.visit_tree(f))
    }
}

impl<'func, A, F> Expression<'func, A, Finalized, F, ValueExpr>
where
    A: 'func + Architecture,
    F: FunctionForm,
{
    // TODO possible values
}

#[derive(Debug)]
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

    // Valid only in Lifted IL
    FlagCond(Operation<'func, A, M, NonSSA<LiftedNonSSA>, operation::FlagCond>),
    // Valid only in Lifted IL
    FlagGroup(Operation<'func, A, M, NonSSA<LiftedNonSSA>, operation::FlagGroup>),

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
    // TODO: Document what "unchecked" means and how to consume this safely.
    pub(crate) unsafe fn from_raw(
        function: &'func LowLevelILFunction<A, M, F>,
        op: BNLowLevelILInstruction,
    ) -> Self {
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        match op.operation {
            LLIL_LOAD | LLIL_LOAD_SSA => ExprInfo::Load(Operation::new(function, op)),
            LLIL_POP => ExprInfo::Pop(Operation::new(function, op)),
            LLIL_REG | LLIL_REG_SSA | LLIL_REG_SSA_PARTIAL => {
                ExprInfo::Reg(Operation::new(function, op))
            }
            LLIL_REG_SPLIT | LLIL_REG_SPLIT_SSA => ExprInfo::RegSplit(Operation::new(function, op)),
            LLIL_CONST => ExprInfo::Const(Operation::new(function, op)),
            LLIL_CONST_PTR => ExprInfo::ConstPtr(Operation::new(function, op)),
            LLIL_FLAG | LLIL_FLAG_SSA => ExprInfo::Flag(Operation::new(function, op)),
            LLIL_FLAG_BIT | LLIL_FLAG_BIT_SSA => ExprInfo::FlagBit(Operation::new(function, op)),
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
                log::error!(
                    "Got unexpected operation {:?} in value expr at 0x{:x}",
                    op.operation,
                    op.address
                );

                ExprInfo::Undef(Operation::new(function, op))
            }
        }
    }

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

    pub fn visit_sub_expressions<T>(&self, mut visitor: T) -> VisitorAction
    where
        T: FnMut(Expression<'func, A, M, F, ValueExpr>) -> VisitorAction,
    {
        use ExprInfo::*;

        macro_rules! visit {
            ($expr:expr) => {
                if let VisitorAction::Halt = visitor($expr) {
                    return VisitorAction::Halt;
                }
            };
        }

        match self {
            CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
            | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op)
            | CmpUgt(ref op) | FcmpE(ref op) | FcmpNE(ref op) | FcmpLT(ref op) | FcmpLE(ref op)
            | FcmpGE(ref op) | FcmpGT(ref op) | FcmpO(ref op) | FcmpUO(ref op) => {
                visit!(op.left());
                visit!(op.right());
            }
            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => {
                visit!(op.left());
                visit!(op.right());
                visit!(op.carry());
            }
            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op) | Modu(ref op)
            | Mods(ref op) | Fadd(ref op) | Fsub(ref op) | Fmul(ref op) | Fdiv(ref op) => {
                visit!(op.left());
                visit!(op.right());
            }
            DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => {
                visit!(op.high());
                visit!(op.low());
                visit!(op.right());
            }
            Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
            | BoolToInt(ref op) | Fsqrt(ref op) | Fneg(ref op) | Fabs(ref op)
            | FloatToInt(ref op) | IntToFloat(ref op) | FloatConv(ref op) | RoundToInt(ref op)
            | Floor(ref op) | Ceil(ref op) | Ftrunc(ref op) => {
                visit!(op.operand());
            }
            UnimplMem(ref op) => {
                visit!(op.mem_expr());
            }
            _ => {}
        }

        VisitorAction::Sibling
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
