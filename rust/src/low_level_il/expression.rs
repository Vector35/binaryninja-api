// Copyright 2021-2026 Vector 35 Inc.
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

use binaryninjacore_sys::BNLowLevelILInstruction;
use binaryninjacore_sys::{
    BNGetLowLevelILByIndex, BNGetLowLevelILExprValue, BNGetLowLevelILPossibleExprValues,
};

use super::operation;
use super::operation::Operation;
use super::VisitorAction;
use super::*;
use crate::architecture::CoreFlagWrite;
use crate::variable::{PossibleValueSet, RegisterValue};
use crate::DataFlowQueryOption;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;

/// Used as a marker for an [`LowLevelILExpression`] that **can** produce a value.
#[derive(Copy, Clone, Debug)]
pub struct ValueExpr;

/// Used as a marker for an [`LowLevelILExpression`] that can **not** produce a value.
#[derive(Copy, Clone, Debug)]
pub struct VoidExpr;

pub trait ExpressionResultType: 'static + Debug {}
impl ExpressionResultType for ValueExpr {}
impl ExpressionResultType for VoidExpr {}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LowLevelExpressionIndex(pub usize);

impl Display for LowLevelExpressionIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

// TODO: Probably want to rename this with a LowLevelIL prefix to avoid collisions when we add handlers for other ILs
pub trait ExpressionHandler<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn kind(&self) -> LowLevelILExpressionKind<'func, M, F>;

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, M, F, ValueExpr>) -> VisitorAction;
}

#[derive(Copy)]
pub struct LowLevelILExpression<'func, M, F, R>
where
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    pub(crate) function: &'func LowLevelILFunction<M, F>,
    pub index: LowLevelExpressionIndex,

    // tag the 'return' type of this expression
    pub(crate) _ty: PhantomData<R>,
}

impl<M, F, R> Clone for LowLevelILExpression<'_, M, F, R>
where
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    fn clone(&self) -> Self {
        Self {
            function: self.function,
            index: self.index,
            _ty: PhantomData,
        }
    }
}

impl<'func, M, F, R> LowLevelILExpression<'func, M, F, R>
where
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    pub fn new(function: &'func LowLevelILFunction<M, F>, index: LowLevelExpressionIndex) -> Self {
        // TODO: Validate expression here?
        Self {
            function,
            index,
            _ty: PhantomData,
        }
    }
}

impl<M, F, R> Debug for LowLevelILExpression<'_, M, F, R>
where
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        let kind = LowLevelILExpressionKind::from_raw(self.function, op, self.index);
        kind.fmt(f)
    }
}

impl<M, R> LowLevelILExpression<'_, M, SSA, R>
where
    M: FunctionMutability,
    R: ExpressionResultType,
{
    pub fn non_ssa_form<'func>(
        &self,
        non_ssa: &'func LowLevelILFunction<M, NonSSA>,
    ) -> LowLevelILExpression<'func, M, NonSSA, R> {
        use binaryninjacore_sys::BNGetLowLevelILNonSSAExprIndex;
        let idx = unsafe { BNGetLowLevelILNonSSAExprIndex(self.function.handle, self.index.0) };
        LowLevelILExpression::new(non_ssa, LowLevelExpressionIndex(idx))
    }
}

impl<M, R> LowLevelILExpression<'_, M, NonSSA, R>
where
    M: FunctionMutability,
    R: ExpressionResultType,
{
    pub fn ssa_form<'func>(
        &self,
        ssa: &'func LowLevelILFunction<M, SSA>,
    ) -> LowLevelILExpression<'func, M, SSA, R> {
        use binaryninjacore_sys::BNGetLowLevelILSSAExprIndex;
        let idx = unsafe { BNGetLowLevelILSSAExprIndex(self.function.handle, self.index.0) };
        LowLevelILExpression::new(ssa, LowLevelExpressionIndex(idx))
    }
}

impl<'func, M> ExpressionHandler<'func, M, SSA> for LowLevelILExpression<'func, M, SSA, ValueExpr>
where
    M: FunctionMutability,
{
    fn kind(&self) -> LowLevelILExpressionKind<'func, M, SSA> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        #[allow(clippy::match_single_binding)]
        match op.operation {
            // Any invalid ops for SSA will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => LowLevelILExpressionKind::from_raw(self.function, op, self.index),
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, M, SSA, ValueExpr>) -> VisitorAction,
    {
        // Visit the current expression.
        match f(self) {
            VisitorAction::Descend => {
                // Recursively visit sub expressions.
                self.kind().visit_sub_expressions(|e| e.visit_tree(f))
            }
            action => action,
        }
    }
}

impl<'func, M> ExpressionHandler<'func, M, NonSSA>
    for LowLevelILExpression<'func, M, NonSSA, ValueExpr>
where
    M: FunctionMutability,
{
    fn kind(&self) -> LowLevelILExpressionKind<'func, M, NonSSA> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        #[allow(clippy::match_single_binding)]
        match op.operation {
            // Any invalid ops for Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => LowLevelILExpressionKind::from_raw(self.function, op, self.index),
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, M, NonSSA, ValueExpr>) -> VisitorAction,
    {
        // Visit the current expression.
        match f(self) {
            VisitorAction::Descend => {
                // Recursively visit sub expressions.
                self.kind().visit_sub_expressions(|e| e.visit_tree(f))
            }
            action => action,
        }
    }
}

impl<M, F> LowLevelILExpression<'_, M, F, ValueExpr>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    /// Value of expression if constant or a known value.
    ///
    /// NOTE: If a value is expressed but not concrete, use [`LowLevelILExpression::possible_values`].
    pub fn value(&self) -> RegisterValue {
        let value = unsafe { BNGetLowLevelILExprValue(self.function.handle, self.index.0) };
        RegisterValue::from(value)
    }

    /// Possible values of expression using path-sensitive static data flow analysis
    pub fn possible_values(&self) -> PossibleValueSet {
        self.possible_values_with_opts(&[])
    }

    /// Possible values of expression using path-sensitive static data flow analysis
    pub fn possible_values_with_opts(&self, options: &[DataFlowQueryOption]) -> PossibleValueSet {
        let value = unsafe {
            BNGetLowLevelILPossibleExprValues(
                self.function.handle,
                self.index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_core_raw(value)
    }

    // TODO: Possible register, stack and flag values.
}

// BEGIN GENERATED llil-expression-kind: from api/il, do not edit
#[derive(Debug)]
pub enum LowLevelILExpressionKind<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    Load(Operation<'func, M, F, operation::Load>),
    Pop(Operation<'func, M, F, operation::Pop>),
    Reg(Operation<'func, M, F, operation::Reg>),
    RegSplit(Operation<'func, M, F, operation::RegSplit>),
    RegStackRel(Operation<'func, M, F, operation::RegStackRel>),
    RegStackPop(Operation<'func, M, F, operation::RegStackPop>),
    Const(Operation<'func, M, F, operation::Const>),
    ConstPtr(Operation<'func, M, F, operation::Const>),
    ExternPtr(Operation<'func, M, F, operation::Extern>),
    FloatConst(Operation<'func, M, F, operation::FloatConst>),
    Flag(Operation<'func, M, F, operation::Flag>),
    FlagBit(Operation<'func, M, F, operation::FlagBit>),
    Add(Operation<'func, M, F, operation::BinaryOp>),
    Adc(Operation<'func, M, F, operation::BinaryOpCarry>),
    Sub(Operation<'func, M, F, operation::BinaryOp>),
    Sbb(Operation<'func, M, F, operation::BinaryOpCarry>),
    And(Operation<'func, M, F, operation::BinaryOp>),
    Or(Operation<'func, M, F, operation::BinaryOp>),
    Xor(Operation<'func, M, F, operation::BinaryOp>),
    Lsl(Operation<'func, M, F, operation::BinaryOp>),
    Lsr(Operation<'func, M, F, operation::BinaryOp>),
    Asr(Operation<'func, M, F, operation::BinaryOp>),
    Rol(Operation<'func, M, F, operation::BinaryOp>),
    Rlc(Operation<'func, M, F, operation::BinaryOpCarry>),
    Ror(Operation<'func, M, F, operation::BinaryOp>),
    Rrc(Operation<'func, M, F, operation::BinaryOpCarry>),
    Mul(Operation<'func, M, F, operation::BinaryOp>),
    MuluDp(Operation<'func, M, F, operation::BinaryOp>),
    MulsDp(Operation<'func, M, F, operation::BinaryOp>),
    Divu(Operation<'func, M, F, operation::BinaryOp>),
    DivuDp(Operation<'func, M, F, operation::BinaryOp>),
    Divs(Operation<'func, M, F, operation::BinaryOp>),
    DivsDp(Operation<'func, M, F, operation::BinaryOp>),
    Modu(Operation<'func, M, F, operation::BinaryOp>),
    ModuDp(Operation<'func, M, F, operation::BinaryOp>),
    Mods(Operation<'func, M, F, operation::BinaryOp>),
    ModsDp(Operation<'func, M, F, operation::BinaryOp>),
    Neg(Operation<'func, M, F, operation::UnaryOp>),
    Not(Operation<'func, M, F, operation::UnaryOp>),
    Sx(Operation<'func, M, F, operation::UnaryOp>),
    Zx(Operation<'func, M, F, operation::UnaryOp>),
    LowPart(Operation<'func, M, F, operation::UnaryOp>),
    FlagCond(Operation<'func, M, F, operation::FlagCond>),
    FlagGroup(Operation<'func, M, F, operation::FlagGroup>),
    CmpE(Operation<'func, M, F, operation::Condition>),
    CmpNe(Operation<'func, M, F, operation::Condition>),
    CmpSlt(Operation<'func, M, F, operation::Condition>),
    CmpUlt(Operation<'func, M, F, operation::Condition>),
    CmpSle(Operation<'func, M, F, operation::Condition>),
    CmpUle(Operation<'func, M, F, operation::Condition>),
    CmpSge(Operation<'func, M, F, operation::Condition>),
    CmpUge(Operation<'func, M, F, operation::Condition>),
    CmpSgt(Operation<'func, M, F, operation::Condition>),
    CmpUgt(Operation<'func, M, F, operation::Condition>),
    TestBit(Operation<'func, M, F, operation::BinaryOp>),
    BoolToInt(Operation<'func, M, F, operation::UnaryOp>),
    AddOverflow(Operation<'func, M, F, operation::BinaryOp>),
    Undef(Operation<'func, M, F, operation::NoArgs>),
    Unimpl(Operation<'func, M, F, operation::NoArgs>),
    UnimplMem(Operation<'func, M, F, operation::UnimplMem>),
    Fadd(Operation<'func, M, F, operation::BinaryOp>),
    Fsub(Operation<'func, M, F, operation::BinaryOp>),
    Fmul(Operation<'func, M, F, operation::BinaryOp>),
    Fdiv(Operation<'func, M, F, operation::BinaryOp>),
    Fsqrt(Operation<'func, M, F, operation::UnaryOp>),
    Fneg(Operation<'func, M, F, operation::UnaryOp>),
    Fabs(Operation<'func, M, F, operation::UnaryOp>),
    FloatToInt(Operation<'func, M, F, operation::UnaryOp>),
    IntToFloat(Operation<'func, M, F, operation::UnaryOp>),
    FloatConv(Operation<'func, M, F, operation::UnaryOp>),
    RoundToInt(Operation<'func, M, F, operation::UnaryOp>),
    Floor(Operation<'func, M, F, operation::UnaryOp>),
    Ceil(Operation<'func, M, F, operation::UnaryOp>),
    Ftrunc(Operation<'func, M, F, operation::UnaryOp>),
    FcmpE(Operation<'func, M, F, operation::Condition>),
    FcmpNE(Operation<'func, M, F, operation::Condition>),
    FcmpLT(Operation<'func, M, F, operation::Condition>),
    FcmpLE(Operation<'func, M, F, operation::Condition>),
    FcmpGE(Operation<'func, M, F, operation::Condition>),
    FcmpGT(Operation<'func, M, F, operation::Condition>),
    FcmpO(Operation<'func, M, F, operation::Condition>),
    FcmpUO(Operation<'func, M, F, operation::Condition>),
    RegSplitDestSsa(Operation<'func, M, F, operation::RegSplitDestSsa>),
    RegStackDestSsa(Operation<'func, M, F, operation::RegStackDestSsa>),
    RegSsa(Operation<'func, M, F, operation::RegSsa>),
    RegPartialSsa(Operation<'func, M, F, operation::RegPartialSsa>),
    RegSplitSsa(Operation<'func, M, F, operation::RegSplitSsa>),
    RegStackRelSsa(Operation<'func, M, F, operation::RegStackRelSsa>),
    RegStackAbsSsa(Operation<'func, M, F, operation::RegStackAbsSsa>),
    CallParamSsa(Operation<'func, M, F, operation::CallParamSsa>),
    CallStackSsa(Operation<'func, M, F, operation::CallStackSsa>),
    CallOutputSsa(Operation<'func, M, F, operation::CallOutputSsa>),
    SeparateParamListSsa(Operation<'func, M, F, operation::SeparateParamListSsa>),
    SharedParamSlotSsa(Operation<'func, M, F, operation::SharedParamSlotSsa>),
    MemoryIntrinsicOutputSsa(Operation<'func, M, F, operation::MemoryIntrinsicOutputSsa>),
    LoadSsa(Operation<'func, M, F, operation::LoadSsa>),
    Bswap(Operation<'func, M, F, operation::UnaryOp>),
    Popcnt(Operation<'func, M, F, operation::UnaryOp>),
    Clz(Operation<'func, M, F, operation::UnaryOp>),
    Ctz(Operation<'func, M, F, operation::UnaryOp>),
    Rbit(Operation<'func, M, F, operation::UnaryOp>),
    Cls(Operation<'func, M, F, operation::UnaryOp>),
    MinSigned(Operation<'func, M, F, operation::BinaryOp>),
    MaxSigned(Operation<'func, M, F, operation::BinaryOp>),
    MinUnsigned(Operation<'func, M, F, operation::BinaryOp>),
    MaxUnsigned(Operation<'func, M, F, operation::BinaryOp>),
    Abs(Operation<'func, M, F, operation::UnaryOp>),
}

impl<'func, M, F> LowLevelILExpressionKind<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) fn from_raw(
        function: &'func LowLevelILFunction<M, F>,
        op: BNLowLevelILInstruction,
        index: LowLevelExpressionIndex,
    ) -> Self {
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        match op.operation {
            LLIL_LOAD => LowLevelILExpressionKind::Load(Operation::new(function, op, index)),
            LLIL_POP => LowLevelILExpressionKind::Pop(Operation::new(function, op, index)),
            LLIL_REG => LowLevelILExpressionKind::Reg(Operation::new(function, op, index)),
            LLIL_REG_SPLIT => {
                LowLevelILExpressionKind::RegSplit(Operation::new(function, op, index))
            }
            LLIL_REG_STACK_REL => {
                LowLevelILExpressionKind::RegStackRel(Operation::new(function, op, index))
            }
            LLIL_REG_STACK_POP => {
                LowLevelILExpressionKind::RegStackPop(Operation::new(function, op, index))
            }
            LLIL_CONST => LowLevelILExpressionKind::Const(Operation::new(function, op, index)),
            LLIL_CONST_PTR => {
                LowLevelILExpressionKind::ConstPtr(Operation::new(function, op, index))
            }
            LLIL_EXTERN_PTR => {
                LowLevelILExpressionKind::ExternPtr(Operation::new(function, op, index))
            }
            LLIL_FLOAT_CONST => {
                LowLevelILExpressionKind::FloatConst(Operation::new(function, op, index))
            }
            LLIL_FLAG | LLIL_FLAG_SSA => {
                LowLevelILExpressionKind::Flag(Operation::new(function, op, index))
            }
            LLIL_FLAG_BIT | LLIL_FLAG_BIT_SSA => {
                LowLevelILExpressionKind::FlagBit(Operation::new(function, op, index))
            }
            LLIL_ADD => LowLevelILExpressionKind::Add(Operation::new(function, op, index)),
            LLIL_ADC => LowLevelILExpressionKind::Adc(Operation::new(function, op, index)),
            LLIL_SUB => LowLevelILExpressionKind::Sub(Operation::new(function, op, index)),
            LLIL_SBB => LowLevelILExpressionKind::Sbb(Operation::new(function, op, index)),
            LLIL_AND => LowLevelILExpressionKind::And(Operation::new(function, op, index)),
            LLIL_OR => LowLevelILExpressionKind::Or(Operation::new(function, op, index)),
            LLIL_XOR => LowLevelILExpressionKind::Xor(Operation::new(function, op, index)),
            LLIL_LSL => LowLevelILExpressionKind::Lsl(Operation::new(function, op, index)),
            LLIL_LSR => LowLevelILExpressionKind::Lsr(Operation::new(function, op, index)),
            LLIL_ASR => LowLevelILExpressionKind::Asr(Operation::new(function, op, index)),
            LLIL_ROL => LowLevelILExpressionKind::Rol(Operation::new(function, op, index)),
            LLIL_RLC => LowLevelILExpressionKind::Rlc(Operation::new(function, op, index)),
            LLIL_ROR => LowLevelILExpressionKind::Ror(Operation::new(function, op, index)),
            LLIL_RRC => LowLevelILExpressionKind::Rrc(Operation::new(function, op, index)),
            LLIL_MUL => LowLevelILExpressionKind::Mul(Operation::new(function, op, index)),
            LLIL_MULU_DP => LowLevelILExpressionKind::MuluDp(Operation::new(function, op, index)),
            LLIL_MULS_DP => LowLevelILExpressionKind::MulsDp(Operation::new(function, op, index)),
            LLIL_DIVU => LowLevelILExpressionKind::Divu(Operation::new(function, op, index)),
            LLIL_DIVU_DP => LowLevelILExpressionKind::DivuDp(Operation::new(function, op, index)),
            LLIL_DIVS => LowLevelILExpressionKind::Divs(Operation::new(function, op, index)),
            LLIL_DIVS_DP => LowLevelILExpressionKind::DivsDp(Operation::new(function, op, index)),
            LLIL_MODU => LowLevelILExpressionKind::Modu(Operation::new(function, op, index)),
            LLIL_MODU_DP => LowLevelILExpressionKind::ModuDp(Operation::new(function, op, index)),
            LLIL_MODS => LowLevelILExpressionKind::Mods(Operation::new(function, op, index)),
            LLIL_MODS_DP => LowLevelILExpressionKind::ModsDp(Operation::new(function, op, index)),
            LLIL_NEG => LowLevelILExpressionKind::Neg(Operation::new(function, op, index)),
            LLIL_NOT => LowLevelILExpressionKind::Not(Operation::new(function, op, index)),
            LLIL_SX => LowLevelILExpressionKind::Sx(Operation::new(function, op, index)),
            LLIL_ZX => LowLevelILExpressionKind::Zx(Operation::new(function, op, index)),
            LLIL_LOW_PART => LowLevelILExpressionKind::LowPart(Operation::new(function, op, index)),
            LLIL_FLAG_COND => {
                LowLevelILExpressionKind::FlagCond(Operation::new(function, op, index))
            }
            LLIL_FLAG_GROUP => {
                LowLevelILExpressionKind::FlagGroup(Operation::new(function, op, index))
            }
            LLIL_CMP_E => LowLevelILExpressionKind::CmpE(Operation::new(function, op, index)),
            LLIL_CMP_NE => LowLevelILExpressionKind::CmpNe(Operation::new(function, op, index)),
            LLIL_CMP_SLT => LowLevelILExpressionKind::CmpSlt(Operation::new(function, op, index)),
            LLIL_CMP_ULT => LowLevelILExpressionKind::CmpUlt(Operation::new(function, op, index)),
            LLIL_CMP_SLE => LowLevelILExpressionKind::CmpSle(Operation::new(function, op, index)),
            LLIL_CMP_ULE => LowLevelILExpressionKind::CmpUle(Operation::new(function, op, index)),
            LLIL_CMP_SGE => LowLevelILExpressionKind::CmpSge(Operation::new(function, op, index)),
            LLIL_CMP_UGE => LowLevelILExpressionKind::CmpUge(Operation::new(function, op, index)),
            LLIL_CMP_SGT => LowLevelILExpressionKind::CmpSgt(Operation::new(function, op, index)),
            LLIL_CMP_UGT => LowLevelILExpressionKind::CmpUgt(Operation::new(function, op, index)),
            LLIL_TEST_BIT => LowLevelILExpressionKind::TestBit(Operation::new(function, op, index)),
            LLIL_BOOL_TO_INT => {
                LowLevelILExpressionKind::BoolToInt(Operation::new(function, op, index))
            }
            LLIL_ADD_OVERFLOW => {
                LowLevelILExpressionKind::AddOverflow(Operation::new(function, op, index))
            }
            LLIL_UNDEF => LowLevelILExpressionKind::Undef(Operation::new(function, op, index)),
            LLIL_UNIMPL => LowLevelILExpressionKind::Unimpl(Operation::new(function, op, index)),
            LLIL_UNIMPL_MEM => {
                LowLevelILExpressionKind::UnimplMem(Operation::new(function, op, index))
            }
            LLIL_FADD => LowLevelILExpressionKind::Fadd(Operation::new(function, op, index)),
            LLIL_FSUB => LowLevelILExpressionKind::Fsub(Operation::new(function, op, index)),
            LLIL_FMUL => LowLevelILExpressionKind::Fmul(Operation::new(function, op, index)),
            LLIL_FDIV => LowLevelILExpressionKind::Fdiv(Operation::new(function, op, index)),
            LLIL_FSQRT => LowLevelILExpressionKind::Fsqrt(Operation::new(function, op, index)),
            LLIL_FNEG => LowLevelILExpressionKind::Fneg(Operation::new(function, op, index)),
            LLIL_FABS => LowLevelILExpressionKind::Fabs(Operation::new(function, op, index)),
            LLIL_FLOAT_TO_INT => {
                LowLevelILExpressionKind::FloatToInt(Operation::new(function, op, index))
            }
            LLIL_INT_TO_FLOAT => {
                LowLevelILExpressionKind::IntToFloat(Operation::new(function, op, index))
            }
            LLIL_FLOAT_CONV => {
                LowLevelILExpressionKind::FloatConv(Operation::new(function, op, index))
            }
            LLIL_ROUND_TO_INT => {
                LowLevelILExpressionKind::RoundToInt(Operation::new(function, op, index))
            }
            LLIL_FLOOR => LowLevelILExpressionKind::Floor(Operation::new(function, op, index)),
            LLIL_CEIL => LowLevelILExpressionKind::Ceil(Operation::new(function, op, index)),
            LLIL_FTRUNC => LowLevelILExpressionKind::Ftrunc(Operation::new(function, op, index)),
            LLIL_FCMP_E => LowLevelILExpressionKind::FcmpE(Operation::new(function, op, index)),
            LLIL_FCMP_NE => LowLevelILExpressionKind::FcmpNE(Operation::new(function, op, index)),
            LLIL_FCMP_LT => LowLevelILExpressionKind::FcmpLT(Operation::new(function, op, index)),
            LLIL_FCMP_LE => LowLevelILExpressionKind::FcmpLE(Operation::new(function, op, index)),
            LLIL_FCMP_GE => LowLevelILExpressionKind::FcmpGE(Operation::new(function, op, index)),
            LLIL_FCMP_GT => LowLevelILExpressionKind::FcmpGT(Operation::new(function, op, index)),
            LLIL_FCMP_O => LowLevelILExpressionKind::FcmpO(Operation::new(function, op, index)),
            LLIL_FCMP_UO => LowLevelILExpressionKind::FcmpUO(Operation::new(function, op, index)),
            LLIL_REG_SPLIT_DEST_SSA => {
                LowLevelILExpressionKind::RegSplitDestSsa(Operation::new(function, op, index))
            }
            LLIL_REG_STACK_DEST_SSA => {
                LowLevelILExpressionKind::RegStackDestSsa(Operation::new(function, op, index))
            }
            LLIL_REG_SSA => LowLevelILExpressionKind::RegSsa(Operation::new(function, op, index)),
            LLIL_REG_SSA_PARTIAL => {
                LowLevelILExpressionKind::RegPartialSsa(Operation::new(function, op, index))
            }
            LLIL_REG_SPLIT_SSA => {
                LowLevelILExpressionKind::RegSplitSsa(Operation::new(function, op, index))
            }
            LLIL_REG_STACK_REL_SSA => {
                LowLevelILExpressionKind::RegStackRelSsa(Operation::new(function, op, index))
            }
            LLIL_REG_STACK_ABS_SSA => {
                LowLevelILExpressionKind::RegStackAbsSsa(Operation::new(function, op, index))
            }
            LLIL_CALL_PARAM => {
                LowLevelILExpressionKind::CallParamSsa(Operation::new(function, op, index))
            }
            LLIL_CALL_STACK_SSA => {
                LowLevelILExpressionKind::CallStackSsa(Operation::new(function, op, index))
            }
            LLIL_CALL_OUTPUT_SSA => {
                LowLevelILExpressionKind::CallOutputSsa(Operation::new(function, op, index))
            }
            LLIL_SEPARATE_PARAM_LIST_SSA => {
                LowLevelILExpressionKind::SeparateParamListSsa(Operation::new(function, op, index))
            }
            LLIL_SHARED_PARAM_SLOT_SSA => {
                LowLevelILExpressionKind::SharedParamSlotSsa(Operation::new(function, op, index))
            }
            LLIL_MEMORY_INTRINSIC_OUTPUT_SSA => LowLevelILExpressionKind::MemoryIntrinsicOutputSsa(
                Operation::new(function, op, index),
            ),
            LLIL_LOAD_SSA => LowLevelILExpressionKind::LoadSsa(Operation::new(function, op, index)),
            LLIL_BSWAP => LowLevelILExpressionKind::Bswap(Operation::new(function, op, index)),
            LLIL_POPCNT => LowLevelILExpressionKind::Popcnt(Operation::new(function, op, index)),
            LLIL_CLZ => LowLevelILExpressionKind::Clz(Operation::new(function, op, index)),
            LLIL_CTZ => LowLevelILExpressionKind::Ctz(Operation::new(function, op, index)),
            LLIL_RBIT => LowLevelILExpressionKind::Rbit(Operation::new(function, op, index)),
            LLIL_CLS => LowLevelILExpressionKind::Cls(Operation::new(function, op, index)),
            LLIL_MINS => LowLevelILExpressionKind::MinSigned(Operation::new(function, op, index)),
            LLIL_MAXS => LowLevelILExpressionKind::MaxSigned(Operation::new(function, op, index)),
            LLIL_MINU => LowLevelILExpressionKind::MinUnsigned(Operation::new(function, op, index)),
            LLIL_MAXU => LowLevelILExpressionKind::MaxUnsigned(Operation::new(function, op, index)),
            LLIL_ABS => LowLevelILExpressionKind::Abs(Operation::new(function, op, index)),
            _ => {
                tracing::error!(
                    "Got unexpected operation {:?} in value expr at 0x{:x}",
                    op.operation,
                    op.address
                );

                LowLevelILExpressionKind::Undef(Operation::new(function, op, index))
            }
        }
    }

    /// Returns the size of the operation in bytes
    ///
    /// If the expression is malformed or is `Unimpl` there
    /// is no meaningful size associated with the result.
    pub fn size(&self) -> Option<usize> {
        use self::LowLevelILExpressionKind::*;

        match *self {
            Undef(..) | Unimpl(..) => None,
            Flag(..)
            | FlagCond(..)
            | FlagGroup(..)
            | SeparateParamListSsa(..)
            | SharedParamSlotSsa(..) => Some(0),
            _ => Some(self.raw_struct().size),
        }
    }

    pub fn address(&self) -> u64 {
        self.raw_struct().address
    }

    /// Determines if the expressions represent the same operation
    ///
    /// It does not examine the operands for equality.
    pub fn is_same_op_as(&self, other: &Self) -> bool {
        self.raw_struct().operation == other.raw_struct().operation
    }

    pub fn as_binary_op(&self) -> Option<&Operation<'func, M, F, operation::BinaryOp>> {
        use self::LowLevelILExpressionKind::*;

        match *self {
            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MuluDp(ref op) | MulsDp(ref op) | Divu(ref op) | DivuDp(ref op) | Divs(ref op)
            | DivsDp(ref op) | Modu(ref op) | ModuDp(ref op) | Mods(ref op) | ModsDp(ref op)
            | TestBit(ref op) | AddOverflow(ref op) | Fadd(ref op) | Fsub(ref op)
            | Fmul(ref op) | Fdiv(ref op) | MinSigned(ref op) | MaxSigned(ref op)
            | MinUnsigned(ref op) | MaxUnsigned(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_binary_op_carry(&self) -> Option<&Operation<'func, M, F, operation::BinaryOpCarry>> {
        use self::LowLevelILExpressionKind::*;

        match *self {
            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_cmp_op(&self) -> Option<&Operation<'func, M, F, operation::Condition>> {
        use self::LowLevelILExpressionKind::*;

        match *self {
            CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
            | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op)
            | CmpUgt(ref op) | FcmpE(ref op) | FcmpNE(ref op) | FcmpLT(ref op) | FcmpLE(ref op)
            | FcmpGE(ref op) | FcmpGT(ref op) | FcmpO(ref op) | FcmpUO(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_unary_op(&self) -> Option<&Operation<'func, M, F, operation::UnaryOp>> {
        use self::LowLevelILExpressionKind::*;

        match *self {
            Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
            | BoolToInt(ref op) | Fsqrt(ref op) | Fneg(ref op) | Fabs(ref op)
            | FloatToInt(ref op) | IntToFloat(ref op) | FloatConv(ref op) | RoundToInt(ref op)
            | Floor(ref op) | Ceil(ref op) | Ftrunc(ref op) | Bswap(ref op) | Popcnt(ref op)
            | Clz(ref op) | Ctz(ref op) | Rbit(ref op) | Cls(ref op) | Abs(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn visit_sub_expressions<T>(&self, mut visitor: T) -> VisitorAction
    where
        T: FnMut(LowLevelILExpression<'func, M, F, ValueExpr>) -> VisitorAction,
    {
        use LowLevelILExpressionKind::*;

        macro_rules! visit {
            ($expr:expr) => {
                if let VisitorAction::Halt = visitor($expr) {
                    return VisitorAction::Halt;
                }
            };
        }

        match self {
            Load(ref op) => visit!(op.source_expr()),
            RegStackRel(ref op) => visit!(op.source_expr()),
            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MuluDp(ref op) | MulsDp(ref op) | Divu(ref op) | DivuDp(ref op) | Divs(ref op)
            | DivsDp(ref op) | Modu(ref op) | ModuDp(ref op) | Mods(ref op) | ModsDp(ref op)
            | TestBit(ref op) | AddOverflow(ref op) | Fadd(ref op) | Fsub(ref op)
            | Fmul(ref op) | Fdiv(ref op) | MinSigned(ref op) | MaxSigned(ref op)
            | MinUnsigned(ref op) | MaxUnsigned(ref op) => {
                visit!(op.left());
                visit!(op.right());
            }
            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => {
                visit!(op.left());
                visit!(op.right());
                visit!(op.carry());
            }
            Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
            | BoolToInt(ref op) | Fsqrt(ref op) | Fneg(ref op) | Fabs(ref op)
            | FloatToInt(ref op) | IntToFloat(ref op) | FloatConv(ref op) | RoundToInt(ref op)
            | Floor(ref op) | Ceil(ref op) | Ftrunc(ref op) | Bswap(ref op) | Popcnt(ref op)
            | Clz(ref op) | Ctz(ref op) | Rbit(ref op) | Cls(ref op) | Abs(ref op) => {
                visit!(op.operand())
            }
            CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
            | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op)
            | CmpUgt(ref op) | FcmpE(ref op) | FcmpNE(ref op) | FcmpLT(ref op) | FcmpLE(ref op)
            | FcmpGE(ref op) | FcmpGT(ref op) | FcmpO(ref op) | FcmpUO(ref op) => {
                visit!(op.left());
                visit!(op.right());
            }
            UnimplMem(ref op) => visit!(op.mem_expr()),
            RegStackRelSsa(ref op) => {
                visit!(op.source_expr());
                visit!(op.top_expr());
            }
            CallParamSsa(ref op) => {
                for expr in op.param_exprs() {
                    visit!(expr);
                }
            }
            SeparateParamListSsa(ref op) => {
                for expr in op.param_exprs() {
                    visit!(expr);
                }
            }
            SharedParamSlotSsa(ref op) => {
                for expr in op.param_exprs() {
                    visit!(expr);
                }
            }
            LoadSsa(ref op) => visit!(op.source_expr()),
            // Do not have any sub expressions.
            Pop(_)
            | Reg(_)
            | RegSplit(_)
            | RegStackPop(_)
            | Const(_)
            | ConstPtr(_)
            | ExternPtr(_)
            | FloatConst(_)
            | Flag(_)
            | FlagBit(_)
            | FlagCond(_)
            | FlagGroup(_)
            | Undef(_)
            | Unimpl(_)
            | RegSplitDestSsa(_)
            | RegStackDestSsa(_)
            | RegSsa(_)
            | RegPartialSsa(_)
            | RegSplitSsa(_)
            | RegStackAbsSsa(_)
            | CallStackSsa(_)
            | CallOutputSsa(_)
            | MemoryIntrinsicOutputSsa(_) => {}
        }

        VisitorAction::Sibling
    }

    pub(crate) fn raw_struct(&self) -> &BNLowLevelILInstruction {
        use self::LowLevelILExpressionKind::*;

        match *self {
            Load(ref op) => &op.op,
            Pop(ref op) => &op.op,
            Reg(ref op) => &op.op,
            RegSplit(ref op) => &op.op,
            RegStackRel(ref op) => &op.op,
            RegStackPop(ref op) => &op.op,
            Const(ref op) => &op.op,
            ConstPtr(ref op) => &op.op,
            ExternPtr(ref op) => &op.op,
            FloatConst(ref op) => &op.op,
            Flag(ref op) => &op.op,
            FlagBit(ref op) => &op.op,
            Add(ref op) => &op.op,
            Adc(ref op) => &op.op,
            Sub(ref op) => &op.op,
            Sbb(ref op) => &op.op,
            And(ref op) => &op.op,
            Or(ref op) => &op.op,
            Xor(ref op) => &op.op,
            Lsl(ref op) => &op.op,
            Lsr(ref op) => &op.op,
            Asr(ref op) => &op.op,
            Rol(ref op) => &op.op,
            Rlc(ref op) => &op.op,
            Ror(ref op) => &op.op,
            Rrc(ref op) => &op.op,
            Mul(ref op) => &op.op,
            MuluDp(ref op) => &op.op,
            MulsDp(ref op) => &op.op,
            Divu(ref op) => &op.op,
            DivuDp(ref op) => &op.op,
            Divs(ref op) => &op.op,
            DivsDp(ref op) => &op.op,
            Modu(ref op) => &op.op,
            ModuDp(ref op) => &op.op,
            Mods(ref op) => &op.op,
            ModsDp(ref op) => &op.op,
            Neg(ref op) => &op.op,
            Not(ref op) => &op.op,
            Sx(ref op) => &op.op,
            Zx(ref op) => &op.op,
            LowPart(ref op) => &op.op,
            FlagCond(ref op) => &op.op,
            FlagGroup(ref op) => &op.op,
            CmpE(ref op) => &op.op,
            CmpNe(ref op) => &op.op,
            CmpSlt(ref op) => &op.op,
            CmpUlt(ref op) => &op.op,
            CmpSle(ref op) => &op.op,
            CmpUle(ref op) => &op.op,
            CmpSge(ref op) => &op.op,
            CmpUge(ref op) => &op.op,
            CmpSgt(ref op) => &op.op,
            CmpUgt(ref op) => &op.op,
            TestBit(ref op) => &op.op,
            BoolToInt(ref op) => &op.op,
            AddOverflow(ref op) => &op.op,
            Undef(ref op) => &op.op,
            Unimpl(ref op) => &op.op,
            UnimplMem(ref op) => &op.op,
            Fadd(ref op) => &op.op,
            Fsub(ref op) => &op.op,
            Fmul(ref op) => &op.op,
            Fdiv(ref op) => &op.op,
            Fsqrt(ref op) => &op.op,
            Fneg(ref op) => &op.op,
            Fabs(ref op) => &op.op,
            FloatToInt(ref op) => &op.op,
            IntToFloat(ref op) => &op.op,
            FloatConv(ref op) => &op.op,
            RoundToInt(ref op) => &op.op,
            Floor(ref op) => &op.op,
            Ceil(ref op) => &op.op,
            Ftrunc(ref op) => &op.op,
            FcmpE(ref op) => &op.op,
            FcmpNE(ref op) => &op.op,
            FcmpLT(ref op) => &op.op,
            FcmpLE(ref op) => &op.op,
            FcmpGE(ref op) => &op.op,
            FcmpGT(ref op) => &op.op,
            FcmpO(ref op) => &op.op,
            FcmpUO(ref op) => &op.op,
            RegSplitDestSsa(ref op) => &op.op,
            RegStackDestSsa(ref op) => &op.op,
            RegSsa(ref op) => &op.op,
            RegPartialSsa(ref op) => &op.op,
            RegSplitSsa(ref op) => &op.op,
            RegStackRelSsa(ref op) => &op.op,
            RegStackAbsSsa(ref op) => &op.op,
            CallParamSsa(ref op) => &op.op,
            CallStackSsa(ref op) => &op.op,
            CallOutputSsa(ref op) => &op.op,
            SeparateParamListSsa(ref op) => &op.op,
            SharedParamSlotSsa(ref op) => &op.op,
            MemoryIntrinsicOutputSsa(ref op) => &op.op,
            LoadSsa(ref op) => &op.op,
            Bswap(ref op) => &op.op,
            Popcnt(ref op) => &op.op,
            Clz(ref op) => &op.op,
            Ctz(ref op) => &op.op,
            Rbit(ref op) => &op.op,
            Cls(ref op) => &op.op,
            MinSigned(ref op) => &op.op,
            MaxSigned(ref op) => &op.op,
            MinUnsigned(ref op) => &op.op,
            MaxUnsigned(ref op) => &op.op,
            Abs(ref op) => &op.op,
        }
    }
}

impl LowLevelILExpressionKind<'_, Mutable, NonSSA> {
    pub fn flag_write(&self) -> Option<CoreFlagWrite> {
        use self::LowLevelILExpressionKind::*;

        match *self {
            Load(ref op) => op.flag_write(),
            Pop(ref op) => op.flag_write(),
            Reg(ref op) => op.flag_write(),
            RegSplit(ref op) => op.flag_write(),
            RegStackRel(ref op) => op.flag_write(),
            RegStackPop(ref op) => op.flag_write(),
            Const(ref op) | ConstPtr(ref op) => op.flag_write(),
            ExternPtr(ref op) => op.flag_write(),
            FloatConst(ref op) => op.flag_write(),
            Flag(ref op) => op.flag_write(),
            FlagBit(ref op) => op.flag_write(),
            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MuluDp(ref op) | MulsDp(ref op) | Divu(ref op) | DivuDp(ref op) | Divs(ref op)
            | DivsDp(ref op) | Modu(ref op) | ModuDp(ref op) | Mods(ref op) | ModsDp(ref op)
            | TestBit(ref op) | AddOverflow(ref op) | Fadd(ref op) | Fsub(ref op)
            | Fmul(ref op) | Fdiv(ref op) | MinSigned(ref op) | MaxSigned(ref op)
            | MinUnsigned(ref op) | MaxUnsigned(ref op) => op.flag_write(),
            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => op.flag_write(),
            Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
            | BoolToInt(ref op) | Fsqrt(ref op) | Fneg(ref op) | Fabs(ref op)
            | FloatToInt(ref op) | IntToFloat(ref op) | FloatConv(ref op) | RoundToInt(ref op)
            | Floor(ref op) | Ceil(ref op) | Ftrunc(ref op) | Bswap(ref op) | Popcnt(ref op)
            | Clz(ref op) | Ctz(ref op) | Rbit(ref op) | Cls(ref op) | Abs(ref op) => {
                op.flag_write()
            }
            FlagCond(ref op) => op.flag_write(),
            FlagGroup(ref op) => op.flag_write(),
            CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
            | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op)
            | CmpUgt(ref op) | FcmpE(ref op) | FcmpNE(ref op) | FcmpLT(ref op) | FcmpLE(ref op)
            | FcmpGE(ref op) | FcmpGT(ref op) | FcmpO(ref op) | FcmpUO(ref op) => op.flag_write(),
            Undef(ref op) | Unimpl(ref op) => op.flag_write(),
            UnimplMem(ref op) => op.flag_write(),
            RegSplitDestSsa(ref op) => op.flag_write(),
            RegStackDestSsa(ref op) => op.flag_write(),
            RegSsa(ref op) => op.flag_write(),
            RegPartialSsa(ref op) => op.flag_write(),
            RegSplitSsa(ref op) => op.flag_write(),
            RegStackRelSsa(ref op) => op.flag_write(),
            RegStackAbsSsa(ref op) => op.flag_write(),
            CallParamSsa(ref op) => op.flag_write(),
            CallStackSsa(ref op) => op.flag_write(),
            CallOutputSsa(ref op) => op.flag_write(),
            SeparateParamListSsa(ref op) => op.flag_write(),
            SharedParamSlotSsa(ref op) => op.flag_write(),
            MemoryIntrinsicOutputSsa(ref op) => op.flag_write(),
            LoadSsa(ref op) => op.flag_write(),
        }
    }
}
// END GENERATED llil-expression-kind
