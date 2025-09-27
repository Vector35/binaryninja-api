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

#[derive(Debug)]
pub enum LowLevelILExpressionKind<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    Load(Operation<'func, M, F, operation::Load>),
    LoadSsa(Operation<'func, M, F, operation::LoadSsa>),
    Pop(Operation<'func, M, F, operation::Pop>),
    Reg(Operation<'func, M, F, operation::Reg>),
    RegSsa(Operation<'func, M, F, operation::RegSsa>),
    RegPartialSsa(Operation<'func, M, F, operation::RegPartialSsa>),
    RegSplit(Operation<'func, M, F, operation::RegSplit>),
    RegSplitSsa(Operation<'func, M, F, operation::RegSplitSsa>),
    Const(Operation<'func, M, F, operation::Const>),
    ConstPtr(Operation<'func, M, F, operation::Const>),
    Flag(Operation<'func, M, F, operation::Flag>),
    FlagBit(Operation<'func, M, F, operation::FlagBit>),
    ExternPtr(Operation<'func, M, F, operation::Extern>),

    RegStackPop(Operation<'func, M, F, operation::RegStackPop>),
    RegStackFreeReg(Operation<'func, M, F, operation::RegStackPop>),

    CallOutputSsa(Operation<'func, M, F, operation::CallOutputSsa>),
    CallParamSsa(Operation<'func, M, F, operation::CallParamSsa>),
    CallStackSsa(Operation<'func, M, F, operation::CallStackSsa>),

    Add(Operation<'func, M, F, operation::BinaryOp>),
    AddOverflow(Operation<'func, M, F, operation::BinaryOp>),
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

    MulsDp(Operation<'func, M, F, operation::BinaryOp>),
    MuluDp(Operation<'func, M, F, operation::BinaryOp>),

    Divu(Operation<'func, M, F, operation::BinaryOp>),
    Divs(Operation<'func, M, F, operation::BinaryOp>),

    DivuDp(Operation<'func, M, F, operation::BinaryOp>),
    DivsDp(Operation<'func, M, F, operation::BinaryOp>),

    Modu(Operation<'func, M, F, operation::BinaryOp>),
    Mods(Operation<'func, M, F, operation::BinaryOp>),

    ModuDp(Operation<'func, M, F, operation::BinaryOp>),
    ModsDp(Operation<'func, M, F, operation::BinaryOp>),

    Neg(Operation<'func, M, F, operation::UnaryOp>),
    Not(Operation<'func, M, F, operation::UnaryOp>),
    Sx(Operation<'func, M, F, operation::UnaryOp>),
    Zx(Operation<'func, M, F, operation::UnaryOp>),
    LowPart(Operation<'func, M, F, operation::UnaryOp>),

    // Valid only in Lifted IL
    FlagCond(Operation<'func, M, F, operation::FlagCond>),
    // Valid only in Lifted IL
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

    FloatConst(Operation<'func, M, F, operation::FloatConst>),

    FcmpE(Operation<'func, M, F, operation::Condition>),
    FcmpNE(Operation<'func, M, F, operation::Condition>),
    FcmpLT(Operation<'func, M, F, operation::Condition>),
    FcmpLE(Operation<'func, M, F, operation::Condition>),
    FcmpGE(Operation<'func, M, F, operation::Condition>),
    FcmpGT(Operation<'func, M, F, operation::Condition>),
    FcmpO(Operation<'func, M, F, operation::Condition>),
    FcmpUO(Operation<'func, M, F, operation::Condition>),

    SeparateParamListSsa(Operation<'func, M, F, operation::SeparateParamListSsa>),

    Unimpl(Operation<'func, M, F, operation::NoArgs>),
    UnimplMem(Operation<'func, M, F, operation::UnimplMem>),

    Undef(Operation<'func, M, F, operation::NoArgs>),
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
            LLIL_LOAD_SSA => LowLevelILExpressionKind::LoadSsa(Operation::new(function, op, index)),
            LLIL_POP => LowLevelILExpressionKind::Pop(Operation::new(function, op, index)),
            LLIL_REG => LowLevelILExpressionKind::Reg(Operation::new(function, op, index)),
            LLIL_REG_SSA => LowLevelILExpressionKind::RegSsa(Operation::new(function, op, index)),
            LLIL_REG_SSA_PARTIAL => {
                LowLevelILExpressionKind::RegPartialSsa(Operation::new(function, op, index))
            }
            LLIL_REG_SPLIT => {
                LowLevelILExpressionKind::RegSplit(Operation::new(function, op, index))
            }
            LLIL_REG_SPLIT_SSA => {
                LowLevelILExpressionKind::RegSplitSsa(Operation::new(function, op, index))
            }
            LLIL_CONST => LowLevelILExpressionKind::Const(Operation::new(function, op, index)),
            LLIL_CONST_PTR => {
                LowLevelILExpressionKind::ConstPtr(Operation::new(function, op, index))
            }
            LLIL_FLAG | LLIL_FLAG_SSA => {
                LowLevelILExpressionKind::Flag(Operation::new(function, op, index))
            }
            LLIL_FLAG_GROUP => {
                LowLevelILExpressionKind::FlagGroup(Operation::new(function, op, index))
            }
            LLIL_FLAG_COND => {
                LowLevelILExpressionKind::FlagCond(Operation::new(function, op, index))
            }
            LLIL_FLAG_BIT | LLIL_FLAG_BIT_SSA => {
                LowLevelILExpressionKind::FlagBit(Operation::new(function, op, index))
            }
            LLIL_EXTERN_PTR => {
                LowLevelILExpressionKind::ExternPtr(Operation::new(function, op, index))
            }

            LLIL_REG_STACK_POP => {
                LowLevelILExpressionKind::RegStackPop(Operation::new(function, op, index))
            }
            LLIL_REG_STACK_FREE_REG => {
                LowLevelILExpressionKind::RegStackFreeReg(Operation::new(function, op, index))
            }

            LLIL_CALL_OUTPUT_SSA => {
                LowLevelILExpressionKind::CallOutputSsa(Operation::new(function, op, index))
            }
            LLIL_CALL_PARAM => {
                LowLevelILExpressionKind::CallParamSsa(Operation::new(function, op, index))
            }
            LLIL_CALL_STACK_SSA => {
                LowLevelILExpressionKind::CallStackSsa(Operation::new(function, op, index))
            }

            LLIL_ADD => LowLevelILExpressionKind::Add(Operation::new(function, op, index)),
            LLIL_ADD_OVERFLOW => {
                LowLevelILExpressionKind::AddOverflow(Operation::new(function, op, index))
            }
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
            LLIL_DIVS => LowLevelILExpressionKind::Divs(Operation::new(function, op, index)),

            LLIL_DIVU_DP => LowLevelILExpressionKind::DivuDp(Operation::new(function, op, index)),
            LLIL_DIVS_DP => LowLevelILExpressionKind::DivsDp(Operation::new(function, op, index)),

            LLIL_MODU => LowLevelILExpressionKind::Modu(Operation::new(function, op, index)),
            LLIL_MODS => LowLevelILExpressionKind::Mods(Operation::new(function, op, index)),

            LLIL_MODU_DP => LowLevelILExpressionKind::ModuDp(Operation::new(function, op, index)),
            LLIL_MODS_DP => LowLevelILExpressionKind::ModsDp(Operation::new(function, op, index)),

            LLIL_NEG => LowLevelILExpressionKind::Neg(Operation::new(function, op, index)),
            LLIL_NOT => LowLevelILExpressionKind::Not(Operation::new(function, op, index)),

            LLIL_SX => LowLevelILExpressionKind::Sx(Operation::new(function, op, index)),
            LLIL_ZX => LowLevelILExpressionKind::Zx(Operation::new(function, op, index)),
            LLIL_LOW_PART => LowLevelILExpressionKind::LowPart(Operation::new(function, op, index)),

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
            LLIL_FCMP_GT => LowLevelILExpressionKind::FcmpGT(Operation::new(function, op, index)),
            LLIL_FCMP_GE => LowLevelILExpressionKind::FcmpGE(Operation::new(function, op, index)),
            LLIL_FCMP_O => LowLevelILExpressionKind::FcmpO(Operation::new(function, op, index)),
            LLIL_FCMP_UO => LowLevelILExpressionKind::FcmpUO(Operation::new(function, op, index)),

            LLIL_FLOAT_CONST => {
                LowLevelILExpressionKind::FloatConst(Operation::new(function, op, index))
            }

            LLIL_SEPARATE_PARAM_LIST_SSA => {
                LowLevelILExpressionKind::SeparateParamListSsa(Operation::new(function, op, index))
            }

            LLIL_UNDEF => LowLevelILExpressionKind::Undef(Operation::new(function, op, index)),

            LLIL_UNIMPL => LowLevelILExpressionKind::Unimpl(Operation::new(function, op, index)),
            LLIL_UNIMPL_MEM => {
                LowLevelILExpressionKind::UnimplMem(Operation::new(function, op, index))
            }

            _ => {
                // #[cfg(debug_assertions)]
                log::error!(
                    "Got unexpected operation {:?} in value expr at 0x{:x}",
                    op.operation,
                    op.address
                );

                LowLevelILExpressionKind::Undef(Operation::new(function, op, index))
            }
        }
    }

    /// Returns the size of the result of this expression
    ///
    /// If the expression is malformed or is `Unimpl` there
    /// is no meaningful size associated with the result.
    pub fn size(&self) -> Option<usize> {
        use self::LowLevelILExpressionKind::*;

        match *self {
            Undef(..) | Unimpl(..) => None,

            FlagCond(..) | FlagGroup(..) | CmpE(..) | CmpNe(..) | CmpSlt(..) | CmpUlt(..)
            | CmpSle(..) | CmpUle(..) | CmpSge(..) | CmpUge(..) | CmpSgt(..) | CmpUgt(..) => {
                Some(0)
            }

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
        use self::LowLevelILExpressionKind::*;

        match (self, other) {
            (&Reg(..), &Reg(..)) => true,
            _ => self.raw_struct().operation == other.raw_struct().operation,
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

    pub fn as_binary_op(&self) -> Option<&Operation<'func, M, F, operation::BinaryOp>> {
        use self::LowLevelILExpressionKind::*;

        match *self {
            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op) | Modu(ref op)
            | Mods(ref op) | Fadd(ref op) | Fsub(ref op) | Fmul(ref op) | Fdiv(ref op)
            | DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => Some(op),
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

    pub fn as_unary_op(&self) -> Option<&Operation<'func, M, F, operation::UnaryOp>> {
        use self::LowLevelILExpressionKind::*;

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
            Add(ref op) | AddOverflow(ref op) | Sub(ref op) | And(ref op) | Or(ref op)
            | Xor(ref op) | Lsl(ref op) | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op)
            | Mul(ref op) | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op)
            | Modu(ref op) | Mods(ref op) | Fadd(ref op) | Fsub(ref op) | Fmul(ref op)
            | DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) | Fdiv(ref op)
            | TestBit(ref op) => {
                visit!(op.left());
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
            Load(ref op) => {
                visit!(op.source_expr());
            }
            LoadSsa(ref op) => {
                visit!(op.source_expr());
            }
            CallParamSsa(ref op) => {
                for param_expr in op.param_exprs() {
                    visit!(param_expr);
                }
            }
            SeparateParamListSsa(ref op) => {
                for param_expr in op.param_exprs() {
                    visit!(param_expr);
                }
            }
            // Do not have any sub expressions.
            Pop(_) | Reg(_) | RegSsa(_) | RegPartialSsa(_) | RegSplit(_) | RegSplitSsa(_)
            | Const(_) | ConstPtr(_) | Flag(_) | FlagBit(_) | ExternPtr(_) | FlagCond(_)
            | FlagGroup(_) | Unimpl(_) | Undef(_) | RegStackPop(_) | RegStackFreeReg(_)
            | CallOutputSsa(_) | CallStackSsa(_) | FloatConst(_) => {}
        }

        VisitorAction::Sibling
    }

    pub(crate) fn raw_struct(&self) -> &BNLowLevelILInstruction {
        use self::LowLevelILExpressionKind::*;

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

            LoadSsa(ref op) => &op.op,

            Pop(ref op) => &op.op,

            Reg(ref op) => &op.op,

            RegSsa(ref op) => &op.op,

            RegPartialSsa(ref op) => &op.op,

            RegSplit(ref op) => &op.op,

            RegSplitSsa(ref op) => &op.op,

            Flag(ref op) => &op.op,

            FlagBit(ref op) => &op.op,

            Const(ref op) | ConstPtr(ref op) => &op.op,

            FloatConst(ref op) => &op.op,

            ExternPtr(ref op) => &op.op,

            RegStackPop(ref op) => &op.op,
            RegStackFreeReg(ref op) => &op.op,

            CallOutputSsa(ref op) => &op.op,
            CallParamSsa(ref op) => &op.op,
            CallStackSsa(ref op) => &op.op,

            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => &op.op,

            Add(ref op) | AddOverflow(ref op) | Sub(ref op) | And(ref op) | Or(ref op)
            | Xor(ref op) | Lsl(ref op) | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op)
            | Mul(ref op) | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op)
            | Modu(ref op) | Mods(ref op) | Fadd(ref op) | Fsub(ref op) | Fmul(ref op)
            | Fdiv(ref op) | TestBit(ref op) => &op.op,

            DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => &op.op,

            Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
            | BoolToInt(ref op) | Fsqrt(ref op) | Fneg(ref op) | Fabs(ref op)
            | FloatToInt(ref op) | IntToFloat(ref op) | FloatConv(ref op) | RoundToInt(ref op)
            | Floor(ref op) | Ceil(ref op) | Ftrunc(ref op) => &op.op,

            SeparateParamListSsa(ref op) => &op.op,

            UnimplMem(ref op) => &op.op,
        }
    }
}

impl LowLevelILExpressionKind<'_, Mutable, NonSSA> {
    pub fn flag_write(&self) -> Option<CoreFlagWrite> {
        use self::LowLevelILExpressionKind::*;

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

            LoadSsa(ref op) => op.flag_write(),

            Pop(ref op) => op.flag_write(),

            Reg(ref op) => op.flag_write(),

            RegSsa(ref op) => op.flag_write(),

            RegPartialSsa(ref op) => op.flag_write(),

            RegSplit(ref op) => op.flag_write(),

            RegSplitSsa(ref op) => op.flag_write(),

            Flag(ref op) => op.flag_write(),

            FlagBit(ref op) => op.flag_write(),

            Const(ref op) | ConstPtr(ref op) => op.flag_write(),

            FloatConst(ref op) => op.flag_write(),

            ExternPtr(ref op) => op.flag_write(),

            RegStackPop(ref op) => op.flag_write(),
            RegStackFreeReg(ref op) => op.flag_write(),

            CallOutputSsa(ref op) => op.flag_write(),
            CallParamSsa(ref op) => op.flag_write(),
            CallStackSsa(ref op) => op.flag_write(),

            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => op.flag_write(),

            Add(ref op) | AddOverflow(ref op) | Sub(ref op) | And(ref op) | Or(ref op)
            | Xor(ref op) | Lsl(ref op) | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op)
            | Mul(ref op) | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op)
            | Modu(ref op) | Mods(ref op) | Fadd(ref op) | Fsub(ref op) | Fmul(ref op)
            | Fdiv(ref op) | TestBit(ref op) => op.flag_write(),

            DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => op.flag_write(),

            Neg(ref op) | Not(ref op) | Sx(ref op) | Zx(ref op) | LowPart(ref op)
            | BoolToInt(ref op) | Fsqrt(ref op) | Fneg(ref op) | Fabs(ref op)
            | FloatToInt(ref op) | IntToFloat(ref op) | FloatConv(ref op) | RoundToInt(ref op)
            | Floor(ref op) | Ceil(ref op) | Ftrunc(ref op) => op.flag_write(),

            SeparateParamListSsa(ref op) => op.flag_write(),

            UnimplMem(ref op) => op.flag_write(),
        }
    }
}
