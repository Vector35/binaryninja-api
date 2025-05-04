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

use binaryninjacore_sys::BNGetLowLevelILByIndex;
use binaryninjacore_sys::BNLowLevelILInstruction;

use super::operation;
use super::operation::Operation;
use super::VisitorAction;
use super::*;
use crate::architecture::CoreFlagWrite;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;

/// Used as a marker for an [`Expression`] that **can** produce a value.
#[derive(Copy, Clone, Debug)]
pub struct ValueExpr;

/// Used as a marker for an [`Expression`] that can **not** produce a value.
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
    fn kind(&self) -> ExpressionKind<'func, M, F>;

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, M, F, ValueExpr>) -> VisitorAction;
}

pub struct Expression<'func, M, F, R>
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

impl<'func, M, F, R> Expression<'func, M, F, R>
where
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    pub(crate) fn new(
        function: &'func LowLevelILFunction<M, F>,
        index: LowLevelExpressionIndex,
    ) -> Self {
        // TODO: Validate expression here?
        Self {
            function,
            index,
            _ty: PhantomData,
        }
    }
}

impl<'func, M, F, R> fmt::Debug for Expression<'func, M, F, R>
where
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        // SAFETY: This is safe we are not exposing the expression kind to the caller.
        let kind = unsafe { ExpressionKind::from_raw(self.function, op) };
        kind.fmt(f)
    }
}

impl<'func, M> ExpressionHandler<'func, M, SSA> for Expression<'func, M, SSA, ValueExpr>
where
    M: FunctionMutability,
{
    fn kind(&self) -> ExpressionKind<'func, M, SSA> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        #[allow(clippy::match_single_binding)]
        match op.operation {
            // Any invalid ops for SSA will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { ExpressionKind::from_raw(self.function, op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, M, SSA, ValueExpr>) -> VisitorAction,
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

impl<'func, M> ExpressionHandler<'func, M, NonSSA<LiftedNonSSA>>
    for Expression<'func, M, NonSSA<LiftedNonSSA>, ValueExpr>
where
    M: FunctionMutability,
{
    fn kind(&self) -> ExpressionKind<'func, M, NonSSA<LiftedNonSSA>> {
        #[allow(unused_imports)]
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        #[allow(clippy::match_single_binding)]
        match op.operation {
            // Any invalid ops for Lifted IL will be checked here.
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { ExpressionKind::from_raw(self.function, op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, M, NonSSA<LiftedNonSSA>, ValueExpr>) -> VisitorAction,
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

impl<'func, M> ExpressionHandler<'func, M, NonSSA<RegularNonSSA>>
    for Expression<'func, M, NonSSA<RegularNonSSA>, ValueExpr>
where
    M: FunctionMutability,
{
    fn kind(&self) -> ExpressionKind<'func, M, NonSSA<RegularNonSSA>> {
        use binaryninjacore_sys::BNLowLevelILOperation::*;
        let op = unsafe { BNGetLowLevelILByIndex(self.function.handle, self.index.0) };
        match op.operation {
            // Any invalid ops for Non-Lifted IL will be checked here.
            LLIL_FLAG_COND => unreachable!("LLIL_FLAG_COND is only valid in Lifted IL"),
            LLIL_FLAG_GROUP => unreachable!("LLIL_FLAG_GROUP is only valid in Lifted IL"),
            // SAFETY: We have checked for illegal operations.
            _ => unsafe { ExpressionKind::from_raw(self.function, op) },
        }
    }

    fn visit_tree<T>(&self, f: &mut T) -> VisitorAction
    where
        T: FnMut(&Expression<'func, M, NonSSA<RegularNonSSA>, ValueExpr>) -> VisitorAction,
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

impl<'func, F> Expression<'func, Finalized, F, ValueExpr>
where
    F: FunctionForm,
{
    // TODO possible values
}

#[derive(Debug)]
pub enum ExpressionKind<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    Load(Operation<'func, M, F, operation::Load>),
    Pop(Operation<'func, M, F, operation::Pop>),
    Reg(Operation<'func, M, F, operation::Reg>),
    RegSplit(Operation<'func, M, F, operation::RegSplit>),
    Const(Operation<'func, M, F, operation::Const>),
    ConstPtr(Operation<'func, M, F, operation::Const>),
    Flag(Operation<'func, M, F, operation::Flag>),
    FlagBit(Operation<'func, M, F, operation::FlagBit>),
    ExternPtr(Operation<'func, M, F, operation::Extern>),

    RegStackPop(Operation<'func, M, F, operation::RegStackPop>),

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

    MulsDp(Operation<'func, M, F, operation::BinaryOp>),
    MuluDp(Operation<'func, M, F, operation::BinaryOp>),

    Divu(Operation<'func, M, F, operation::BinaryOp>),
    Divs(Operation<'func, M, F, operation::BinaryOp>),

    DivuDp(Operation<'func, M, F, operation::DoublePrecDivOp>),
    DivsDp(Operation<'func, M, F, operation::DoublePrecDivOp>),

    Modu(Operation<'func, M, F, operation::BinaryOp>),
    Mods(Operation<'func, M, F, operation::BinaryOp>),

    ModuDp(Operation<'func, M, F, operation::DoublePrecDivOp>),
    ModsDp(Operation<'func, M, F, operation::DoublePrecDivOp>),

    Neg(Operation<'func, M, F, operation::UnaryOp>),
    Not(Operation<'func, M, F, operation::UnaryOp>),
    Sx(Operation<'func, M, F, operation::UnaryOp>),
    Zx(Operation<'func, M, F, operation::UnaryOp>),
    LowPart(Operation<'func, M, F, operation::UnaryOp>),

    // Valid only in Lifted IL
    FlagCond(Operation<'func, M, NonSSA<LiftedNonSSA>, operation::FlagCond>),
    // Valid only in Lifted IL
    FlagGroup(Operation<'func, M, NonSSA<LiftedNonSSA>, operation::FlagGroup>),

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

    //TestBit(Operation<'func, M, F, operation::TestBit>), // TODO
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

    FcmpE(Operation<'func, M, F, operation::Condition>),
    FcmpNE(Operation<'func, M, F, operation::Condition>),
    FcmpLT(Operation<'func, M, F, operation::Condition>),
    FcmpLE(Operation<'func, M, F, operation::Condition>),
    FcmpGE(Operation<'func, M, F, operation::Condition>),
    FcmpGT(Operation<'func, M, F, operation::Condition>),
    FcmpO(Operation<'func, M, F, operation::Condition>),
    FcmpUO(Operation<'func, M, F, operation::Condition>),

    // TODO ADD_OVERFLOW
    Unimpl(Operation<'func, M, F, operation::NoArgs>),
    UnimplMem(Operation<'func, M, F, operation::UnimplMem>),

    Undef(Operation<'func, M, F, operation::NoArgs>),
}

impl<'func, M, F> ExpressionKind<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    // TODO: Document what "unchecked" means and how to consume this safely.
    pub(crate) unsafe fn from_raw(
        function: &'func LowLevelILFunction<M, F>,
        op: BNLowLevelILInstruction,
    ) -> Self {
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        match op.operation {
            LLIL_LOAD | LLIL_LOAD_SSA => ExpressionKind::Load(Operation::new(function, op)),
            LLIL_POP => ExpressionKind::Pop(Operation::new(function, op)),
            LLIL_REG | LLIL_REG_SSA | LLIL_REG_SSA_PARTIAL => {
                ExpressionKind::Reg(Operation::new(function, op))
            }
            LLIL_REG_SPLIT | LLIL_REG_SPLIT_SSA => {
                ExpressionKind::RegSplit(Operation::new(function, op))
            }
            LLIL_CONST => ExpressionKind::Const(Operation::new(function, op)),
            LLIL_CONST_PTR => ExpressionKind::ConstPtr(Operation::new(function, op)),
            LLIL_FLAG | LLIL_FLAG_SSA => ExpressionKind::Flag(Operation::new(function, op)),
            LLIL_FLAG_BIT | LLIL_FLAG_BIT_SSA => {
                ExpressionKind::FlagBit(Operation::new(function, op))
            }
            LLIL_EXTERN_PTR => ExpressionKind::ExternPtr(Operation::new(function, op)),

            LLIL_REG_STACK_POP => ExpressionKind::RegStackPop(Operation::new(function, op)),

            LLIL_ADD => ExpressionKind::Add(Operation::new(function, op)),
            LLIL_ADC => ExpressionKind::Adc(Operation::new(function, op)),
            LLIL_SUB => ExpressionKind::Sub(Operation::new(function, op)),
            LLIL_SBB => ExpressionKind::Sbb(Operation::new(function, op)),
            LLIL_AND => ExpressionKind::And(Operation::new(function, op)),
            LLIL_OR => ExpressionKind::Or(Operation::new(function, op)),
            LLIL_XOR => ExpressionKind::Xor(Operation::new(function, op)),
            LLIL_LSL => ExpressionKind::Lsl(Operation::new(function, op)),
            LLIL_LSR => ExpressionKind::Lsr(Operation::new(function, op)),
            LLIL_ASR => ExpressionKind::Asr(Operation::new(function, op)),
            LLIL_ROL => ExpressionKind::Rol(Operation::new(function, op)),
            LLIL_RLC => ExpressionKind::Rlc(Operation::new(function, op)),
            LLIL_ROR => ExpressionKind::Ror(Operation::new(function, op)),
            LLIL_RRC => ExpressionKind::Rrc(Operation::new(function, op)),
            LLIL_MUL => ExpressionKind::Mul(Operation::new(function, op)),

            LLIL_MULU_DP => ExpressionKind::MuluDp(Operation::new(function, op)),
            LLIL_MULS_DP => ExpressionKind::MulsDp(Operation::new(function, op)),

            LLIL_DIVU => ExpressionKind::Divu(Operation::new(function, op)),
            LLIL_DIVS => ExpressionKind::Divs(Operation::new(function, op)),

            LLIL_DIVU_DP => ExpressionKind::DivuDp(Operation::new(function, op)),
            LLIL_DIVS_DP => ExpressionKind::DivsDp(Operation::new(function, op)),

            LLIL_MODU => ExpressionKind::Modu(Operation::new(function, op)),
            LLIL_MODS => ExpressionKind::Mods(Operation::new(function, op)),

            LLIL_MODU_DP => ExpressionKind::ModuDp(Operation::new(function, op)),
            LLIL_MODS_DP => ExpressionKind::ModsDp(Operation::new(function, op)),

            LLIL_NEG => ExpressionKind::Neg(Operation::new(function, op)),
            LLIL_NOT => ExpressionKind::Not(Operation::new(function, op)),

            LLIL_SX => ExpressionKind::Sx(Operation::new(function, op)),
            LLIL_ZX => ExpressionKind::Zx(Operation::new(function, op)),
            LLIL_LOW_PART => ExpressionKind::LowPart(Operation::new(function, op)),

            LLIL_CMP_E => ExpressionKind::CmpE(Operation::new(function, op)),
            LLIL_CMP_NE => ExpressionKind::CmpNe(Operation::new(function, op)),
            LLIL_CMP_SLT => ExpressionKind::CmpSlt(Operation::new(function, op)),
            LLIL_CMP_ULT => ExpressionKind::CmpUlt(Operation::new(function, op)),
            LLIL_CMP_SLE => ExpressionKind::CmpSle(Operation::new(function, op)),
            LLIL_CMP_ULE => ExpressionKind::CmpUle(Operation::new(function, op)),
            LLIL_CMP_SGE => ExpressionKind::CmpSge(Operation::new(function, op)),
            LLIL_CMP_UGE => ExpressionKind::CmpUge(Operation::new(function, op)),
            LLIL_CMP_SGT => ExpressionKind::CmpSgt(Operation::new(function, op)),
            LLIL_CMP_UGT => ExpressionKind::CmpUgt(Operation::new(function, op)),

            LLIL_BOOL_TO_INT => ExpressionKind::BoolToInt(Operation::new(function, op)),

            LLIL_FADD => ExpressionKind::Fadd(Operation::new(function, op)),
            LLIL_FSUB => ExpressionKind::Fsub(Operation::new(function, op)),
            LLIL_FMUL => ExpressionKind::Fmul(Operation::new(function, op)),
            LLIL_FDIV => ExpressionKind::Fdiv(Operation::new(function, op)),

            LLIL_FSQRT => ExpressionKind::Fsqrt(Operation::new(function, op)),
            LLIL_FNEG => ExpressionKind::Fneg(Operation::new(function, op)),
            LLIL_FABS => ExpressionKind::Fabs(Operation::new(function, op)),
            LLIL_FLOAT_TO_INT => ExpressionKind::FloatToInt(Operation::new(function, op)),
            LLIL_INT_TO_FLOAT => ExpressionKind::IntToFloat(Operation::new(function, op)),
            LLIL_FLOAT_CONV => ExpressionKind::FloatConv(Operation::new(function, op)),
            LLIL_ROUND_TO_INT => ExpressionKind::RoundToInt(Operation::new(function, op)),
            LLIL_FLOOR => ExpressionKind::Floor(Operation::new(function, op)),
            LLIL_CEIL => ExpressionKind::Ceil(Operation::new(function, op)),
            LLIL_FTRUNC => ExpressionKind::Ftrunc(Operation::new(function, op)),

            LLIL_FCMP_E => ExpressionKind::FcmpE(Operation::new(function, op)),
            LLIL_FCMP_NE => ExpressionKind::FcmpNE(Operation::new(function, op)),
            LLIL_FCMP_LT => ExpressionKind::FcmpLT(Operation::new(function, op)),
            LLIL_FCMP_LE => ExpressionKind::FcmpLE(Operation::new(function, op)),
            LLIL_FCMP_GT => ExpressionKind::FcmpGT(Operation::new(function, op)),
            LLIL_FCMP_GE => ExpressionKind::FcmpGE(Operation::new(function, op)),
            LLIL_FCMP_O => ExpressionKind::FcmpO(Operation::new(function, op)),
            LLIL_FCMP_UO => ExpressionKind::FcmpUO(Operation::new(function, op)),

            LLIL_UNIMPL => ExpressionKind::Unimpl(Operation::new(function, op)),
            LLIL_UNIMPL_MEM => ExpressionKind::UnimplMem(Operation::new(function, op)),

            // TODO TEST_BIT ADD_OVERFLOW LLIL_REG_STACK_PUSH LLIL_REG_STACK_POP
            _ => {
                #[cfg(debug_assertions)]
                log::error!(
                    "Got unexpected operation {:?} in value expr at 0x{:x}",
                    op.operation,
                    op.address
                );

                ExpressionKind::Undef(Operation::new(function, op))
            }
        }
    }

    /// Returns the size of the result of this expression
    ///
    /// If the expression is malformed or is `Unimpl` there
    /// is no meaningful size associated with the result.
    pub fn size(&self) -> Option<usize> {
        use self::ExpressionKind::*;

        match *self {
            Undef(..) | Unimpl(..) => None,

            FlagCond(..) | FlagGroup(..) | CmpE(..) | CmpNe(..) | CmpSlt(..) | CmpUlt(..)
            | CmpSle(..) | CmpUle(..) | CmpSge(..) | CmpUge(..) | CmpSgt(..) | CmpUgt(..) => {
                Some(0)
            }

            _ => Some(self.raw_struct().size),
            //TestBit(Operation<'func, M, F, operation::TestBit>), // TODO
        }
    }

    pub fn address(&self) -> u64 {
        self.raw_struct().address
    }

    /// Determines if the expressions represent the same operation
    ///
    /// It does not examine the operands for equality.
    pub fn is_same_op_as(&self, other: &Self) -> bool {
        use self::ExpressionKind::*;

        match (self, other) {
            (&Reg(..), &Reg(..)) => true,
            _ => self.raw_struct().operation == other.raw_struct().operation,
        }
    }

    pub fn as_cmp_op(&self) -> Option<&Operation<'func, M, F, operation::Condition>> {
        use self::ExpressionKind::*;

        match *self {
            CmpE(ref op) | CmpNe(ref op) | CmpSlt(ref op) | CmpUlt(ref op) | CmpSle(ref op)
            | CmpUle(ref op) | CmpSge(ref op) | CmpUge(ref op) | CmpSgt(ref op)
            | CmpUgt(ref op) | FcmpE(ref op) | FcmpNE(ref op) | FcmpLT(ref op) | FcmpLE(ref op)
            | FcmpGE(ref op) | FcmpGT(ref op) | FcmpO(ref op) | FcmpUO(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_binary_op(&self) -> Option<&Operation<'func, M, F, operation::BinaryOp>> {
        use self::ExpressionKind::*;

        match *self {
            Add(ref op) | Sub(ref op) | And(ref op) | Or(ref op) | Xor(ref op) | Lsl(ref op)
            | Lsr(ref op) | Asr(ref op) | Rol(ref op) | Ror(ref op) | Mul(ref op)
            | MulsDp(ref op) | MuluDp(ref op) | Divu(ref op) | Divs(ref op) | Modu(ref op)
            | Mods(ref op) | Fadd(ref op) | Fsub(ref op) | Fmul(ref op) | Fdiv(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_binary_op_carry(&self) -> Option<&Operation<'func, M, F, operation::BinaryOpCarry>> {
        use self::ExpressionKind::*;

        match *self {
            Adc(ref op) | Sbb(ref op) | Rlc(ref op) | Rrc(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_double_prec_div_op(
        &self,
    ) -> Option<&Operation<'func, M, F, operation::DoublePrecDivOp>> {
        use self::ExpressionKind::*;

        match *self {
            DivuDp(ref op) | DivsDp(ref op) | ModuDp(ref op) | ModsDp(ref op) => Some(op),
            _ => None,
        }
    }

    pub fn as_unary_op(&self) -> Option<&Operation<'func, M, F, operation::UnaryOp>> {
        use self::ExpressionKind::*;

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
        T: FnMut(Expression<'func, M, F, ValueExpr>) -> VisitorAction,
    {
        use ExpressionKind::*;

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
            Load(ref op) => {
                visit!(op.source_mem_expr());
            }
            // Do not have any sub expressions.
            Pop(_) | Reg(_) | RegSplit(_) | Const(_) | ConstPtr(_) | Flag(_) | FlagBit(_)
            | ExternPtr(_) | FlagCond(_) | FlagGroup(_) | Unimpl(_) | Undef(_) | RegStackPop(_) => {
            }
        }

        VisitorAction::Sibling
    }

    pub(crate) fn raw_struct(&self) -> &BNLowLevelILInstruction {
        use self::ExpressionKind::*;

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

            RegStackPop(ref op) => &op.op,

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
            //TestBit(Operation<'func, M, F, operation::TestBit>), // TODO
        }
    }
}

impl<'func> ExpressionKind<'func, Mutable, NonSSA<LiftedNonSSA>> {
    pub fn flag_write(&self) -> Option<CoreFlagWrite> {
        use self::ExpressionKind::*;

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

            RegStackPop(ref op) => op.flag_write(),

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
            //TestBit(Operation<'func, M, F, operation::TestBit>), // TODO
        }
    }
}
