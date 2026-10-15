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

use std::marker::PhantomData;

use binaryninjacore_sys::{
    BNAddLowLevelILLabelForAddress, BNLowLevelILClearIndirectBranches, BNLowLevelILLabel,
    BNLowLevelILOperation, BNRegisterOrConstant, BNSetLowLevelILExprAttributes,
};

use super::*;
use crate::architecture::{Architecture, FlagWriteId, IntrinsicId, RegisterId};
use crate::architecture::{CoreRegister, Register as ArchReg};
use crate::architecture::{
    Flag, FlagClass, FlagCondition, FlagGroup, FlagRole, FlagWrite, Intrinsic,
};
use crate::basic_block::BasicBlock;
use crate::function::{Location, NativeBlock};

pub trait LiftableLowLevelIL<'func> {
    type Result: ExpressionResultType;

    fn lift(
        il: &'func LowLevelILMutableFunction,
        expr: Self,
    ) -> LowLevelILMutableExpression<'func, Self::Result>;
}

pub trait LiftableLowLevelILWithSize<'func>: LiftableLowLevelIL<'func, Result = ValueExpr> {
    fn lift_with_size(
        il: &'func LowLevelILMutableFunction,
        expr: Self,
        size: usize,
    ) -> LowLevelILMutableExpression<'func, ValueExpr>;
}

#[derive(Copy, Clone)]
pub enum LowLevelILRegisterOrConstant<R: ArchReg> {
    Register(usize, LowLevelILRegisterKind<R>),
    Constant(usize, u64),
}

impl<R: ArchReg> From<LowLevelILRegisterOrConstant<R>> for BNRegisterOrConstant {
    fn from(value: LowLevelILRegisterOrConstant<R>) -> Self {
        match value {
            LowLevelILRegisterOrConstant::Register(_, r) => Self {
                constant: false,
                reg: r.id().0,
                value: 0,
            },
            LowLevelILRegisterOrConstant::Constant(_, value) => Self {
                constant: true,
                reg: 0,
                value,
            },
        }
    }
}

#[derive(Clone)]
pub enum LowLevelILFlagWriteOp<R: ArchReg> {
    SetReg(usize, LowLevelILRegisterOrConstant<R>),
    SetRegSplit(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),

    Sub(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Add(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),

    Load(usize, LowLevelILRegisterOrConstant<R>),

    Push(usize, LowLevelILRegisterOrConstant<R>),
    Neg(usize, LowLevelILRegisterOrConstant<R>),
    Not(usize, LowLevelILRegisterOrConstant<R>),
    Bswap(usize, LowLevelILRegisterOrConstant<R>),
    Popcnt(usize, LowLevelILRegisterOrConstant<R>),
    Clz(usize, LowLevelILRegisterOrConstant<R>),
    Ctz(usize, LowLevelILRegisterOrConstant<R>),
    Rbit(usize, LowLevelILRegisterOrConstant<R>),
    Cls(usize, LowLevelILRegisterOrConstant<R>),
    Abs(usize, LowLevelILRegisterOrConstant<R>),
    Sx(usize, LowLevelILRegisterOrConstant<R>),
    Zx(usize, LowLevelILRegisterOrConstant<R>),
    LowPart(usize, LowLevelILRegisterOrConstant<R>),
    BoolToInt(usize, LowLevelILRegisterOrConstant<R>),
    FloatToInt(usize, LowLevelILRegisterOrConstant<R>),
    Fsqrt(usize, LowLevelILRegisterOrConstant<R>),
    Fneg(usize, LowLevelILRegisterOrConstant<R>),
    Fabs(usize, LowLevelILRegisterOrConstant<R>),
    IntToFloat(usize, LowLevelILRegisterOrConstant<R>),
    FloatConv(usize, LowLevelILRegisterOrConstant<R>),
    RoundToInt(usize, LowLevelILRegisterOrConstant<R>),
    Floor(usize, LowLevelILRegisterOrConstant<R>),
    Ceil(usize, LowLevelILRegisterOrConstant<R>),
    Ftrunc(usize, LowLevelILRegisterOrConstant<R>),

    Store(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),

    And(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Or(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Xor(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Lsl(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Lsr(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Asr(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Rol(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Ror(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Mul(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    MuluDp(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    MulsDp(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Divu(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Divs(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Modu(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Mods(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    MinSigned(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    MaxSigned(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    MinUnsigned(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    MaxUnsigned(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    DivuDp(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    DivsDp(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    ModuDp(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    ModsDp(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),

    TestBit(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    AddOverflow(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    CmpE(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    CmpNe(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    CmpSlt(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    CmpUlt(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    CmpSle(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    CmpUle(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    CmpSge(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    CmpUge(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    CmpSgt(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    CmpUgt(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),

    Fadd(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Fsub(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Fmul(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Fdiv(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    FcmpE(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    FcmpNE(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    FcmpLT(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    FcmpLE(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    FcmpGE(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    FcmpGT(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    FcmpO(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    FcmpUO(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),

    Adc(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Sbb(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Rlc(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),
    Rrc(
        usize,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
        LowLevelILRegisterOrConstant<R>,
    ),

    Pop(usize),

    /// Core doesn't pass each parameter's width, so the parameters carry the intrinsic's size, which is usually 0.
    Intrinsic(usize, IntrinsicId, Vec<LowLevelILRegisterOrConstant<R>>),
}

impl<R: ArchReg> LowLevelILFlagWriteOp<R> {
    pub(crate) fn from_op<A>(
        arch: &A,
        size: usize,
        op: BNLowLevelILOperation,
        operands: &[BNRegisterOrConstant],
    ) -> Option<Self>
    where
        A: Architecture<Register = R>,
        R: ArchReg<InfoType = A::RegisterInfo>,
    {
        use self::LowLevelILFlagWriteOp::*;
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        fn build_op<A, R>(
            arch: &A,
            size: usize,
            operand: &BNRegisterOrConstant,
        ) -> LowLevelILRegisterOrConstant<R>
        where
            A: Architecture<Register = R>,
            R: ArchReg<InfoType = A::RegisterInfo>,
        {
            if operand.constant {
                LowLevelILRegisterOrConstant::Constant(size, operand.value)
            } else {
                let raw_id = RegisterId(operand.reg);
                let il_reg =
                    LowLevelILRegisterKind::from_raw(arch, raw_id).expect("Bad register ID");
                LowLevelILRegisterOrConstant::Register(size, il_reg)
            }
        }

        macro_rules! op {
            ($x:ident, $($ops:expr),*) => {
                ( $x(size, $( build_op(arch, size, &operands[$ops]), )* ) )
            };
        }

        Some(match (operands.len(), op) {
            (1, LLIL_SET_REG) => op!(SetReg, 0),
            (2, LLIL_SET_REG_SPLIT) => op!(SetRegSplit, 0, 1),

            (2, LLIL_SUB) => op!(Sub, 0, 1),
            (2, LLIL_ADD) => op!(Add, 0, 1),

            (1, LLIL_LOAD) => op!(Load, 0),

            (1, LLIL_PUSH) => op!(Push, 0),
            (1, LLIL_NEG) => op!(Neg, 0),
            (1, LLIL_NOT) => op!(Not, 0),
            (1, LLIL_BSWAP) => op!(Bswap, 0),
            (1, LLIL_POPCNT) => op!(Popcnt, 0),
            (1, LLIL_CLZ) => op!(Clz, 0),
            (1, LLIL_CTZ) => op!(Ctz, 0),
            (1, LLIL_RBIT) => op!(Rbit, 0),
            (1, LLIL_CLS) => op!(Cls, 0),
            (1, LLIL_ABS) => op!(Abs, 0),
            (1, LLIL_SX) => op!(Sx, 0),
            (1, LLIL_ZX) => op!(Zx, 0),
            (1, LLIL_LOW_PART) => op!(LowPart, 0),
            (1, LLIL_BOOL_TO_INT) => op!(BoolToInt, 0),
            (1, LLIL_FLOAT_TO_INT) => op!(FloatToInt, 0),
            (1, LLIL_FSQRT) => op!(Fsqrt, 0),
            (1, LLIL_FNEG) => op!(Fneg, 0),
            (1, LLIL_FABS) => op!(Fabs, 0),
            (1, LLIL_INT_TO_FLOAT) => op!(IntToFloat, 0),
            (1, LLIL_FLOAT_CONV) => op!(FloatConv, 0),
            (1, LLIL_ROUND_TO_INT) => op!(RoundToInt, 0),
            (1, LLIL_FLOOR) => op!(Floor, 0),
            (1, LLIL_CEIL) => op!(Ceil, 0),
            (1, LLIL_FTRUNC) => op!(Ftrunc, 0),

            (2, LLIL_STORE) => op!(Store, 0, 1),

            (2, LLIL_AND) => op!(And, 0, 1),
            (2, LLIL_OR) => op!(Or, 0, 1),
            (2, LLIL_XOR) => op!(Xor, 0, 1),
            (2, LLIL_LSL) => op!(Lsl, 0, 1),
            (2, LLIL_LSR) => op!(Lsr, 0, 1),
            (2, LLIL_ASR) => op!(Asr, 0, 1),
            (2, LLIL_ROL) => op!(Rol, 0, 1),
            (2, LLIL_ROR) => op!(Ror, 0, 1),
            (2, LLIL_MUL) => op!(Mul, 0, 1),
            (2, LLIL_MULU_DP) => op!(MuluDp, 0, 1),
            (2, LLIL_MULS_DP) => op!(MulsDp, 0, 1),
            (2, LLIL_DIVU) => op!(Divu, 0, 1),
            (2, LLIL_DIVS) => op!(Divs, 0, 1),
            (2, LLIL_MODU) => op!(Modu, 0, 1),
            (2, LLIL_MODS) => op!(Mods, 0, 1),
            (2, LLIL_MINS) => op!(MinSigned, 0, 1),
            (2, LLIL_MAXS) => op!(MaxSigned, 0, 1),
            (2, LLIL_MINU) => op!(MinUnsigned, 0, 1),
            (2, LLIL_MAXU) => op!(MaxUnsigned, 0, 1),
            (2, LLIL_DIVU_DP) => op!(DivuDp, 0, 1),
            (2, LLIL_DIVS_DP) => op!(DivsDp, 0, 1),
            (2, LLIL_MODU_DP) => op!(ModuDp, 0, 1),
            (2, LLIL_MODS_DP) => op!(ModsDp, 0, 1),

            (2, LLIL_TEST_BIT) => op!(TestBit, 0, 1),
            (2, LLIL_ADD_OVERFLOW) => op!(AddOverflow, 0, 1),
            (2, LLIL_CMP_E) => op!(CmpE, 0, 1),
            (2, LLIL_CMP_NE) => op!(CmpNe, 0, 1),
            (2, LLIL_CMP_SLT) => op!(CmpSlt, 0, 1),
            (2, LLIL_CMP_ULT) => op!(CmpUlt, 0, 1),
            (2, LLIL_CMP_SLE) => op!(CmpSle, 0, 1),
            (2, LLIL_CMP_ULE) => op!(CmpUle, 0, 1),
            (2, LLIL_CMP_SGE) => op!(CmpSge, 0, 1),
            (2, LLIL_CMP_UGE) => op!(CmpUge, 0, 1),
            (2, LLIL_CMP_SGT) => op!(CmpSgt, 0, 1),
            (2, LLIL_CMP_UGT) => op!(CmpUgt, 0, 1),

            (2, LLIL_FADD) => op!(Fadd, 0, 1),
            (2, LLIL_FSUB) => op!(Fsub, 0, 1),
            (2, LLIL_FMUL) => op!(Fmul, 0, 1),
            (2, LLIL_FDIV) => op!(Fdiv, 0, 1),
            (2, LLIL_FCMP_E) => op!(FcmpE, 0, 1),
            (2, LLIL_FCMP_NE) => op!(FcmpNE, 0, 1),
            (2, LLIL_FCMP_LT) => op!(FcmpLT, 0, 1),
            (2, LLIL_FCMP_LE) => op!(FcmpLE, 0, 1),
            (2, LLIL_FCMP_GE) => op!(FcmpGE, 0, 1),
            (2, LLIL_FCMP_GT) => op!(FcmpGT, 0, 1),
            (2, LLIL_FCMP_O) => op!(FcmpO, 0, 1),
            (2, LLIL_FCMP_UO) => op!(FcmpUO, 0, 1),

            (3, LLIL_ADC) => op!(Adc, 0, 1, 2),
            (3, LLIL_SBB) => op!(Sbb, 0, 1, 2),
            (3, LLIL_RLC) => op!(Rlc, 0, 1, 2),
            (3, LLIL_RRC) => op!(Rrc, 0, 1, 2),

            (0, LLIL_POP) => op!(Pop,),

            // Core passes the intrinsic as a constant, followed by each parameter.
            (n, LLIL_INTRINSIC) if n >= 1 && operands[0].constant => Intrinsic(
                size,
                IntrinsicId(operands[0].value as u32),
                operands[1..]
                    .iter()
                    .map(|operand| build_op(arch, size, operand))
                    .collect(),
            ),

            _ => return None,
        })
    }

    pub(crate) fn size_and_op(&self) -> (usize, BNLowLevelILOperation) {
        use self::LowLevelILFlagWriteOp::*;
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        match *self {
            SetReg(size, ..) => (size, LLIL_SET_REG),
            SetRegSplit(size, ..) => (size, LLIL_SET_REG_SPLIT),

            Sub(size, ..) => (size, LLIL_SUB),
            Add(size, ..) => (size, LLIL_ADD),

            Load(size, ..) => (size, LLIL_LOAD),

            Push(size, ..) => (size, LLIL_PUSH),
            Neg(size, ..) => (size, LLIL_NEG),
            Not(size, ..) => (size, LLIL_NOT),
            Bswap(size, ..) => (size, LLIL_BSWAP),
            Popcnt(size, ..) => (size, LLIL_POPCNT),
            Clz(size, ..) => (size, LLIL_CLZ),
            Ctz(size, ..) => (size, LLIL_CTZ),
            Rbit(size, ..) => (size, LLIL_RBIT),
            Cls(size, ..) => (size, LLIL_CLS),
            Abs(size, ..) => (size, LLIL_ABS),
            Sx(size, ..) => (size, LLIL_SX),
            Zx(size, ..) => (size, LLIL_ZX),
            LowPart(size, ..) => (size, LLIL_LOW_PART),
            BoolToInt(size, ..) => (size, LLIL_BOOL_TO_INT),
            FloatToInt(size, ..) => (size, LLIL_FLOAT_TO_INT),
            Fsqrt(size, ..) => (size, LLIL_FSQRT),
            Fneg(size, ..) => (size, LLIL_FNEG),
            Fabs(size, ..) => (size, LLIL_FABS),
            IntToFloat(size, ..) => (size, LLIL_INT_TO_FLOAT),
            FloatConv(size, ..) => (size, LLIL_FLOAT_CONV),
            RoundToInt(size, ..) => (size, LLIL_ROUND_TO_INT),
            Floor(size, ..) => (size, LLIL_FLOOR),
            Ceil(size, ..) => (size, LLIL_CEIL),
            Ftrunc(size, ..) => (size, LLIL_FTRUNC),

            Store(size, ..) => (size, LLIL_STORE),

            And(size, ..) => (size, LLIL_AND),
            Or(size, ..) => (size, LLIL_OR),
            Xor(size, ..) => (size, LLIL_XOR),
            Lsl(size, ..) => (size, LLIL_LSL),
            Lsr(size, ..) => (size, LLIL_LSR),
            Asr(size, ..) => (size, LLIL_ASR),
            Rol(size, ..) => (size, LLIL_ROL),
            Ror(size, ..) => (size, LLIL_ROR),
            Mul(size, ..) => (size, LLIL_MUL),
            MuluDp(size, ..) => (size, LLIL_MULU_DP),
            MulsDp(size, ..) => (size, LLIL_MULS_DP),
            Divu(size, ..) => (size, LLIL_DIVU),
            Divs(size, ..) => (size, LLIL_DIVS),
            Modu(size, ..) => (size, LLIL_MODU),
            Mods(size, ..) => (size, LLIL_MODS),
            MinSigned(size, ..) => (size, LLIL_MINS),
            MaxSigned(size, ..) => (size, LLIL_MAXS),
            MinUnsigned(size, ..) => (size, LLIL_MINU),
            MaxUnsigned(size, ..) => (size, LLIL_MAXU),
            DivuDp(size, ..) => (size, LLIL_DIVU_DP),
            DivsDp(size, ..) => (size, LLIL_DIVS_DP),
            ModuDp(size, ..) => (size, LLIL_MODU_DP),
            ModsDp(size, ..) => (size, LLIL_MODS_DP),

            TestBit(size, ..) => (size, LLIL_TEST_BIT),
            AddOverflow(size, ..) => (size, LLIL_ADD_OVERFLOW),
            CmpE(size, ..) => (size, LLIL_CMP_E),
            CmpNe(size, ..) => (size, LLIL_CMP_NE),
            CmpSlt(size, ..) => (size, LLIL_CMP_SLT),
            CmpUlt(size, ..) => (size, LLIL_CMP_ULT),
            CmpSle(size, ..) => (size, LLIL_CMP_SLE),
            CmpUle(size, ..) => (size, LLIL_CMP_ULE),
            CmpSge(size, ..) => (size, LLIL_CMP_SGE),
            CmpUge(size, ..) => (size, LLIL_CMP_UGE),
            CmpSgt(size, ..) => (size, LLIL_CMP_SGT),
            CmpUgt(size, ..) => (size, LLIL_CMP_UGT),

            Fadd(size, ..) => (size, LLIL_FADD),
            Fsub(size, ..) => (size, LLIL_FSUB),
            Fmul(size, ..) => (size, LLIL_FMUL),
            Fdiv(size, ..) => (size, LLIL_FDIV),
            FcmpE(size, ..) => (size, LLIL_FCMP_E),
            FcmpNE(size, ..) => (size, LLIL_FCMP_NE),
            FcmpLT(size, ..) => (size, LLIL_FCMP_LT),
            FcmpLE(size, ..) => (size, LLIL_FCMP_LE),
            FcmpGE(size, ..) => (size, LLIL_FCMP_GE),
            FcmpGT(size, ..) => (size, LLIL_FCMP_GT),
            FcmpO(size, ..) => (size, LLIL_FCMP_O),
            FcmpUO(size, ..) => (size, LLIL_FCMP_UO),

            Adc(size, ..) => (size, LLIL_ADC),
            Sbb(size, ..) => (size, LLIL_SBB),
            Rlc(size, ..) => (size, LLIL_RLC),
            Rrc(size, ..) => (size, LLIL_RRC),

            Pop(size) => (size, LLIL_POP),

            Intrinsic(size, ..) => (size, LLIL_INTRINSIC),
        }
    }

    pub(crate) fn raw_operands(&self) -> Vec<BNRegisterOrConstant> {
        use self::LowLevelILFlagWriteOp::*;

        match *self {
            Pop(_) => Vec::new(),

            SetReg(_, op0)
            | Load(_, op0)
            | Push(_, op0)
            | Neg(_, op0)
            | Not(_, op0)
            | Bswap(_, op0)
            | Popcnt(_, op0)
            | Clz(_, op0)
            | Ctz(_, op0)
            | Rbit(_, op0)
            | Cls(_, op0)
            | Abs(_, op0)
            | Sx(_, op0)
            | Zx(_, op0)
            | LowPart(_, op0)
            | BoolToInt(_, op0)
            | FloatToInt(_, op0)
            | Fsqrt(_, op0)
            | Fneg(_, op0)
            | Fabs(_, op0)
            | IntToFloat(_, op0)
            | FloatConv(_, op0)
            | RoundToInt(_, op0)
            | Floor(_, op0)
            | Ceil(_, op0)
            | Ftrunc(_, op0) => vec![op0.into()],

            SetRegSplit(_, op0, op1)
            | Sub(_, op0, op1)
            | Add(_, op0, op1)
            | Store(_, op0, op1)
            | And(_, op0, op1)
            | Or(_, op0, op1)
            | Xor(_, op0, op1)
            | Lsl(_, op0, op1)
            | Lsr(_, op0, op1)
            | Asr(_, op0, op1)
            | Rol(_, op0, op1)
            | Ror(_, op0, op1)
            | Mul(_, op0, op1)
            | MuluDp(_, op0, op1)
            | MulsDp(_, op0, op1)
            | Divu(_, op0, op1)
            | Divs(_, op0, op1)
            | Modu(_, op0, op1)
            | Mods(_, op0, op1)
            | MinSigned(_, op0, op1)
            | MaxSigned(_, op0, op1)
            | MinUnsigned(_, op0, op1)
            | MaxUnsigned(_, op0, op1)
            | DivuDp(_, op0, op1)
            | DivsDp(_, op0, op1)
            | ModuDp(_, op0, op1)
            | ModsDp(_, op0, op1)
            | TestBit(_, op0, op1)
            | AddOverflow(_, op0, op1)
            | CmpE(_, op0, op1)
            | CmpNe(_, op0, op1)
            | CmpSlt(_, op0, op1)
            | CmpUlt(_, op0, op1)
            | CmpSle(_, op0, op1)
            | CmpUle(_, op0, op1)
            | CmpSge(_, op0, op1)
            | CmpUge(_, op0, op1)
            | CmpSgt(_, op0, op1)
            | CmpUgt(_, op0, op1)
            | Fadd(_, op0, op1)
            | Fsub(_, op0, op1)
            | Fmul(_, op0, op1)
            | Fdiv(_, op0, op1)
            | FcmpE(_, op0, op1)
            | FcmpNE(_, op0, op1)
            | FcmpLT(_, op0, op1)
            | FcmpLE(_, op0, op1)
            | FcmpGE(_, op0, op1)
            | FcmpGT(_, op0, op1)
            | FcmpO(_, op0, op1)
            | FcmpUO(_, op0, op1) => vec![op0.into(), op1.into()],

            Adc(_, op0, op1, op2)
            | Sbb(_, op0, op1, op2)
            | Rlc(_, op0, op1, op2)
            | Rrc(_, op0, op1, op2) => vec![op0.into(), op1.into(), op2.into()],

            Intrinsic(_, id, ref params) => {
                let id = BNRegisterOrConstant {
                    constant: true,
                    reg: 0,
                    value: id.0 as u64,
                };
                std::iter::once(id)
                    .chain(params.iter().map(|&param| param.into()))
                    .collect()
            }
        }
    }
}

pub fn get_default_flag_write_llil<'func, A>(
    arch: &A,
    role: FlagRole,
    op: LowLevelILFlagWriteOp<A::Register>,
    il: &'func LowLevelILMutableFunction,
) -> LowLevelILMutableExpression<'func, ValueExpr>
where
    A: 'func + Architecture,
{
    let (size, operation) = op.size_and_op();
    let mut operands = op.raw_operands();

    let expr_idx = unsafe {
        use binaryninjacore_sys::BNGetDefaultArchitectureFlagWriteLowLevelIL;
        BNGetDefaultArchitectureFlagWriteLowLevelIL(
            arch.as_ref().handle,
            operation,
            size,
            role,
            operands.as_mut_ptr(),
            operands.len(),
            il.handle,
        )
    };

    LowLevelILExpression::new(il, LowLevelExpressionIndex(expr_idx))
}

pub fn get_default_flag_cond_llil<'func, A>(
    arch: &A,
    cond: FlagCondition,
    class: Option<A::FlagClass>,
    il: &'func LowLevelILMutableFunction,
) -> LowLevelILMutableExpression<'func, ValueExpr>
where
    A: 'func + Architecture,
{
    use binaryninjacore_sys::BNGetDefaultArchitectureFlagConditionLowLevelIL;
    let class_id = class.map(|c| c.id().0).unwrap_or(0);

    unsafe {
        let expr_idx = BNGetDefaultArchitectureFlagConditionLowLevelIL(
            arch.as_ref().handle,
            cond,
            class_id,
            il.handle,
        );

        LowLevelILExpression::new(il, LowLevelExpressionIndex(expr_idx))
    }
}

macro_rules! prim_int_lifter {
    ($x:ty) => {
        impl<'a> LiftableLowLevelIL<'a> for $x {
            type Result = ValueExpr;

            fn lift(il: &'a LowLevelILMutableFunction, val: Self)
                -> LowLevelILMutableExpression<'a, Self::Result>
            {
                il.const_int(std::mem::size_of::<Self>(), val as i64 as u64)
            }
        }

        impl<'a> LiftableLowLevelILWithSize<'a> for $x {
            fn lift_with_size(il: &'a LowLevelILMutableFunction, val: Self, size: usize)
                -> LowLevelILMutableExpression<'a, ValueExpr>
            {
                let raw = val as i64;

                #[cfg(debug_assertions)]
                {
                    let is_safe = match raw.overflowing_shr(size as u32 * 8) {
                        (_, true) => true,
                        (res, false) => [-1, 0].contains(&res),
                    };

                    if !is_safe {
                        tracing::error!("il @ {:x} attempted to lift constant 0x{:x} as {} byte expr (won't fit!)",
                               il.current_address(), val, size);
                    }
                }

                il.const_int(size, raw as u64)
            }
        }
    }
}

prim_int_lifter!(i8);
prim_int_lifter!(i16);
prim_int_lifter!(i32);
prim_int_lifter!(i64);

prim_int_lifter!(u8);
prim_int_lifter!(u16);
prim_int_lifter!(u32);
prim_int_lifter!(u64);

impl<'a, R> LiftableLowLevelIL<'a> for LowLevelILRegisterKind<R>
where
    R: LiftableLowLevelIL<'a, Result = ValueExpr> + Into<LowLevelILRegisterKind<R>> + ArchReg,
{
    type Result = ValueExpr;

    fn lift(
        il: &'a LowLevelILMutableFunction,
        reg: Self,
    ) -> LowLevelILMutableExpression<'a, Self::Result> {
        match reg {
            LowLevelILRegisterKind::Arch(r) => R::lift(il, r),
            LowLevelILRegisterKind::Temp(t) => il.reg(
                il.arch().default_integer_size(),
                LowLevelILRegisterKind::Temp::<R>(t),
            ),
        }
    }
}

impl<'a, R> LiftableLowLevelILWithSize<'a> for LowLevelILRegisterKind<R>
where
    R: LiftableLowLevelILWithSize<'a> + Into<LowLevelILRegisterKind<R>> + ArchReg,
{
    fn lift_with_size(
        il: &'a LowLevelILMutableFunction,
        reg: Self,
        size: usize,
    ) -> LowLevelILMutableExpression<'a, ValueExpr> {
        match reg {
            LowLevelILRegisterKind::Arch(r) => R::lift_with_size(il, r, size),
            LowLevelILRegisterKind::Temp(t) => il.reg(size, LowLevelILRegisterKind::<R>::Temp(t)),
        }
    }
}

impl<'a, R> LiftableLowLevelIL<'a> for LowLevelILRegisterOrConstant<R>
where
    R: LiftableLowLevelILWithSize<'a, Result = ValueExpr>
        + Into<LowLevelILRegisterKind<R>>
        + ArchReg,
{
    type Result = ValueExpr;

    fn lift(
        il: &'a LowLevelILMutableFunction,
        reg: Self,
    ) -> LowLevelILMutableExpression<'a, Self::Result> {
        match reg {
            LowLevelILRegisterOrConstant::Register(size, r) => {
                LowLevelILRegisterKind::<R>::lift_with_size(il, r, size)
            }
            LowLevelILRegisterOrConstant::Constant(size, value) => {
                u64::lift_with_size(il, value, size)
            }
        }
    }
}

impl<'a, R> LiftableLowLevelILWithSize<'a> for LowLevelILRegisterOrConstant<R>
where
    R: LiftableLowLevelILWithSize<'a> + Into<LowLevelILRegisterKind<R>> + ArchReg,
{
    fn lift_with_size(
        il: &'a LowLevelILMutableFunction,
        reg: Self,
        size: usize,
    ) -> LowLevelILMutableExpression<'a, ValueExpr> {
        // TODO ensure requested size is compatible with size of this constant
        match reg {
            LowLevelILRegisterOrConstant::Register(_, r) => {
                LowLevelILRegisterKind::<R>::lift_with_size(il, r, size)
            }
            LowLevelILRegisterOrConstant::Constant(_, value) => {
                u64::lift_with_size(il, value, size)
            }
        }
    }
}

impl<'a, R> LiftableLowLevelIL<'a> for LowLevelILExpression<'a, Mutable, NonSSA, R>
where
    R: ExpressionResultType,
{
    type Result = R;

    fn lift(
        il: &'a LowLevelILMutableFunction,
        expr: Self,
    ) -> LowLevelILMutableExpression<'a, Self::Result> {
        debug_assert!(expr.function.handle == il.handle);
        expr
    }
}

impl<'a> LiftableLowLevelILWithSize<'a> for LowLevelILExpression<'a, Mutable, NonSSA, ValueExpr> {
    fn lift_with_size(
        il: &'a LowLevelILMutableFunction,
        expr: Self,
        _size: usize,
    ) -> LowLevelILMutableExpression<'a, Self::Result> {
        #[cfg(debug_assertions)]
        {
            use binaryninjacore_sys::BNGetLowLevelILByIndex;

            let instr = unsafe { BNGetLowLevelILByIndex(il.handle, expr.index.0) };
            if let Some(width) = result_width(instr.operation, instr.size) {
                if width != _size {
                    tracing::warn!(
                        "il @ {:x} attempted to lift {} byte expression as {} bytes",
                        il.current_address(),
                        width,
                        _size
                    );
                }
            }
        }

        LiftableLowLevelIL::lift(il, expr)
    }
}

impl<R> LowLevelILExpression<'_, Mutable, NonSSA, R>
where
    R: ExpressionResultType,
{
    pub fn with_source_operand(self, op: u32) -> Self {
        use binaryninjacore_sys::BNLowLevelILSetExprSourceOperand;
        unsafe { BNLowLevelILSetExprSourceOperand(self.function.handle, self.index.0, op) }
        self
    }

    pub fn append(self) {
        self.function.add_instruction(self);
    }
}

pub struct ExpressionBuilder<'func, R>
where
    R: ExpressionResultType,
{
    function: &'func LowLevelILFunction<Mutable, NonSSA>,
    op: BNLowLevelILOperation,
    size: usize,
    flag_write: FlagWriteId,
    op1: u64,
    op2: u64,
    op3: u64,
    op4: u64,
    _ty: PhantomData<R>,
}

impl<'a, R> ExpressionBuilder<'a, R>
where
    R: ExpressionResultType,
{
    pub fn from_expr(expr: LowLevelILExpression<'a, Mutable, NonSSA, R>) -> Self {
        use binaryninjacore_sys::BNGetLowLevelILByIndex;

        let instr = unsafe { BNGetLowLevelILByIndex(expr.function.handle, expr.index.0) };

        ExpressionBuilder {
            function: expr.function,
            op: instr.operation,
            size: instr.size,
            flag_write: FlagWriteId(instr.flags),
            op1: instr.operands[0],
            op2: instr.operands[1],
            op3: instr.operands[2],
            op4: instr.operands[3],
            _ty: PhantomData,
        }
    }

    pub fn with_flag_write(mut self, flag_write: impl FlagWrite) -> Self {
        // TODO verify valid id
        self.flag_write = flag_write.id();
        self
    }

    pub fn build(self) -> LowLevelILExpression<'a, Mutable, NonSSA, R> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;

        let expr_idx = unsafe {
            BNLowLevelILAddExpr(
                self.function.handle,
                self.op,
                self.size,
                self.flag_write.0,
                self.op1,
                self.op2,
                self.op3,
                self.op4,
            )
        };

        LowLevelILExpression::new(self.function, LowLevelExpressionIndex(expr_idx))
    }

    pub fn with_source_operand(self, op: u32) -> LowLevelILExpression<'a, Mutable, NonSSA, R> {
        self.build().with_source_operand(op)
    }

    pub fn append(self) {
        let expr = self.build();
        expr.function.add_instruction(expr);
    }
}

impl<'a, R> LiftableLowLevelIL<'a> for ExpressionBuilder<'a, R>
where
    R: ExpressionResultType,
{
    type Result = R;

    fn lift(
        il: &'a LowLevelILMutableFunction,
        expr: Self,
    ) -> LowLevelILMutableExpression<'a, Self::Result> {
        debug_assert!(expr.function.handle == il.handle);

        expr.build()
    }
}

impl<'a> LiftableLowLevelILWithSize<'a> for ExpressionBuilder<'a, ValueExpr> {
    fn lift_with_size(
        il: &'a LowLevelILMutableFunction,
        expr: Self,
        _size: usize,
    ) -> LowLevelILMutableExpression<'a, ValueExpr> {
        #[cfg(debug_assertions)]
        {
            if let Some(width) = result_width(expr.op, expr.size) {
                if width != _size {
                    tracing::warn!(
                        "il @ {:x} attempted to lift {} byte expression builder as {} bytes",
                        il.current_address(),
                        width,
                        _size
                    );
                }
            }
        }

        LiftableLowLevelIL::lift(il, expr)
    }
}

impl LowLevelILMutableFunction {
    pub const NO_INPUTS: [ExpressionBuilder<'static, ValueExpr>; 0] = [];
    pub const NO_OUTPUTS: [LowLevelILRegisterKind<CoreRegister>; 0] = [];

    pub fn expression<'a, E: LiftableLowLevelIL<'a>>(
        &'a self,
        expr: E,
    ) -> LowLevelILExpression<'a, Mutable, NonSSA, E::Result> {
        E::lift(self, expr)
    }

    pub fn add_instruction<'a, E: LiftableLowLevelIL<'a>>(&'a self, expr: E) {
        let expr = self.expression(expr);

        unsafe {
            use binaryninjacore_sys::BNLowLevelILAddInstruction;
            BNLowLevelILAddInstruction(self.handle, expr.index.0);
        }
    }

    pub unsafe fn replace_expression<'a, E: LiftableLowLevelIL<'a>>(
        &'a self,
        replaced_expr_index: LowLevelExpressionIndex,
        replacement: E,
    ) -> bool {
        use binaryninjacore_sys::BNReplaceLowLevelILExpr;
        if replaced_expr_index.0 >= self.expression_count() {
            // Invalid expression index, cant replace expression.
            return false;
        }
        let expr = self.expression(replacement);
        BNReplaceLowLevelILExpr(self.handle, replaced_expr_index.0, expr.index.0);
        true
    }

    pub fn const_int(&self, size: usize, val: u64) -> LowLevelILMutableExpression<'_, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CONST;

        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_CONST, size, 0, val, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn const_ptr_sized(
        &self,
        size: usize,
        val: u64,
    ) -> LowLevelILMutableExpression<'_, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CONST_PTR;

        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_CONST_PTR, size, 0, val, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn const_ptr(&self, val: u64) -> LowLevelILMutableExpression<'_, ValueExpr> {
        self.const_ptr_sized(self.arch().address_size(), val)
    }

    pub fn trap(&self, val: u64) -> LowLevelILExpression<'_, Mutable, NonSSA, VoidExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_TRAP;

        let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, LLIL_TRAP, 0, 0, val, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    // TODO: LLIL_JUMP_TO

    pub fn if_expr<'a: 'b, 'b, C>(
        &'a self,
        cond: C,
        true_label: &'b mut LowLevelILLabel,
        false_label: &'b mut LowLevelILLabel,
    ) -> LowLevelILExpression<'a, Mutable, NonSSA, VoidExpr>
    where
        C: LiftableLowLevelIL<'b, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILIf;

        let cond = C::lift(self, cond);

        let mut raw_true_label = BNLowLevelILLabel::from(*true_label);
        let mut raw_false_label = BNLowLevelILLabel::from(*false_label);
        let expr_idx = unsafe {
            BNLowLevelILIf(
                self.handle,
                cond.index.0 as u64,
                &mut raw_true_label,
                &mut raw_false_label,
            )
        };

        // Update the labels after they have been resolved.
        let mut new_true_label = LowLevelILLabel::from(raw_true_label);
        let mut new_false_label = LowLevelILLabel::from(raw_false_label);
        if let Some(location) = true_label.location {
            new_true_label.location = Some(location);
            self.update_label_map_for_label(&new_true_label);
        }
        if let Some(location) = false_label.location {
            new_false_label.location = Some(location);
            self.update_label_map_for_label(&new_false_label);
        }
        *true_label = new_true_label;
        *false_label = new_false_label;

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    // TODO: Wtf are these lifetimes??
    pub fn goto<'a: 'b, 'b>(
        &'a self,
        label: &'b mut LowLevelILLabel,
    ) -> LowLevelILExpression<'a, Mutable, NonSSA, VoidExpr> {
        use binaryninjacore_sys::BNLowLevelILGoto;

        let mut raw_label = BNLowLevelILLabel::from(*label);
        let expr_idx = unsafe { BNLowLevelILGoto(self.handle, &mut raw_label) };

        // Update the labels after they have been resolved.
        let mut new_label = LowLevelILLabel::from(raw_label);
        if let Some(location) = label.location {
            new_label.location = Some(location);
            self.update_label_map_for_label(&new_label);
        }
        *label = new_label;

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn reg<R: ArchReg, LR: Into<LowLevelILRegisterKind<R>>>(
        &self,
        size: usize,
        reg: LR,
    ) -> LowLevelILMutableExpression<'_, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_REG;

        // TODO verify valid id
        let reg = reg.into().id();

        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_REG, size, 0, reg.0 as u64, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn reg_split<R: ArchReg, LR: Into<LowLevelILRegisterKind<R>>>(
        &self,
        size: usize,
        hi_reg: LR,
        lo_reg: LR,
    ) -> LowLevelILMutableExpression<'_, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_REG_SPLIT;

        // TODO verify valid id
        let hi_reg = hi_reg.into().id();
        let lo_reg = lo_reg.into().id();

        let expr_idx = unsafe {
            BNLowLevelILAddExpr(
                self.handle,
                LLIL_REG_SPLIT,
                size,
                0,
                hi_reg.0 as u64,
                lo_reg.0 as u64,
                0,
                0,
            )
        };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn set_reg<'a, R, LR, E>(
        &'a self,
        size: usize,
        dest_reg: LR,
        expr: E,
    ) -> ExpressionBuilder<'a, VoidExpr>
    where
        R: ArchReg,
        LR: Into<LowLevelILRegisterKind<R>>,
        E: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_SET_REG;

        // TODO verify valid id
        let dest_reg = dest_reg.into().id();

        let expr = E::lift_with_size(self, expr, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_SET_REG,
            size,
            // TODO: Make these optional?
            flag_write: FlagWriteId(0),
            op1: dest_reg.0 as u64,
            op2: expr.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    pub fn set_reg_split<'a, R, LR, E>(
        &'a self,
        size: usize,
        hi_reg: LR,
        lo_reg: LR,
        expr: E,
    ) -> ExpressionBuilder<'a, VoidExpr>
    where
        R: ArchReg,
        LR: Into<LowLevelILRegisterKind<R>>,
        E: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_SET_REG_SPLIT;

        // TODO verify valid id
        let hi_reg = hi_reg.into().id();
        let lo_reg = lo_reg.into().id();

        let expr = E::lift_with_size(self, expr, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_SET_REG_SPLIT,
            size,
            flag_write: FlagWriteId(0),
            op1: hi_reg.0 as u64,
            op2: lo_reg.0 as u64,
            op3: expr.index.0 as u64,
            op4: 0,
            _ty: PhantomData,
        }
    }

    pub fn flag(&self, flag: impl Flag) -> LowLevelILMutableExpression<'_, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLAG;

        // TODO verify valid id
        let expr_idx = unsafe {
            BNLowLevelILAddExpr(self.handle, LLIL_FLAG, 0, 0, flag.id().0 as u64, 0, 0, 0)
        };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn flag_cond(&self, cond: FlagCondition) -> LowLevelILMutableExpression<'_, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLAG_COND;

        // TODO verify valid id
        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_FLAG_COND, 0, 0, cond as u64, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn flag_group(&self, group: impl FlagGroup) -> LowLevelILMutableExpression<'_, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLAG_GROUP;

        // TODO verify valid id
        let expr_idx = unsafe {
            BNLowLevelILAddExpr(
                self.handle,
                LLIL_FLAG_GROUP,
                0,
                0,
                group.id().0 as u64,
                0,
                0,
                0,
            )
        };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn set_flag<'a, E>(
        &'a self,
        dest_flag: impl Flag,
        expr: E,
    ) -> ExpressionBuilder<'a, VoidExpr>
    where
        E: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_SET_FLAG;

        // TODO verify valid id

        let expr = E::lift_with_size(self, expr, 0);

        ExpressionBuilder {
            function: self,
            op: LLIL_SET_FLAG,
            size: 0,
            flag_write: FlagWriteId(0),
            op1: dest_flag.id().0 as u64,
            op2: expr.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /*
     * TODO
    FlagBit(usize, Flag<A>, u64),
    */

    // TODO: Reposition arguments.
    pub fn intrinsic<'a, R, O, P>(
        &'a self,
        outputs: impl IntoIterator<Item = O>,
        intrinsic: impl Intrinsic,
        inputs: impl IntoIterator<Item = P>,
    ) -> ExpressionBuilder<'a, VoidExpr>
    where
        R: ArchReg,
        O: Into<LowLevelILRegisterKind<R>>,
        P: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::{LLIL_CALL_PARAM, LLIL_INTRINSIC};
        use binaryninjacore_sys::{BNLowLevelILAddExpr, BNLowLevelILAddOperandList};

        let mut outputs: Vec<u64> = outputs
            .into_iter()
            .map(|output| output.into().id().0 as u64)
            .collect();
        let output_expr_idx =
            unsafe { BNLowLevelILAddOperandList(self.handle, outputs.as_mut_ptr(), outputs.len()) };

        let mut inputs: Vec<u64> = inputs
            .into_iter()
            .map(|input| {
                let input = P::lift(self, input);
                input.index.0 as u64
            })
            .collect();
        let input_list_expr_idx =
            unsafe { BNLowLevelILAddOperandList(self.handle, inputs.as_mut_ptr(), inputs.len()) };
        let input_expr_idx = unsafe {
            BNLowLevelILAddExpr(
                self.handle,
                LLIL_CALL_PARAM,
                0,
                0,
                inputs.len() as u64,
                input_list_expr_idx as u64,
                0,
                0,
            )
        };

        ExpressionBuilder {
            function: self,
            op: LLIL_INTRINSIC,
            size: 0,
            flag_write: FlagWriteId(0),
            op1: outputs.len() as u64,
            op2: output_expr_idx as u64,
            op3: intrinsic.id().0 as u64,
            op4: input_expr_idx as u64,
            _ty: PhantomData,
        }
    }

    pub fn current_address(&self) -> u64 {
        use binaryninjacore_sys::BNLowLevelILGetCurrentAddress;
        unsafe { BNLowLevelILGetCurrentAddress(self.handle) }
    }

    pub fn set_current_address<L: Into<Location>>(&self, loc: L) {
        use binaryninjacore_sys::BNLowLevelILSetCurrentAddress;

        let loc: Location = loc.into();
        let arch = loc.arch.unwrap_or_else(|| *self.arch().as_ref());

        unsafe {
            BNLowLevelILSetCurrentAddress(self.handle, arch.handle, loc.addr);
        }
    }

    pub fn set_current_source_block(&self, source: &BasicBlock<NativeBlock>) {
        use binaryninjacore_sys::BNLowLevelILSetCurrentSourceBlock;
        unsafe {
            BNLowLevelILSetCurrentSourceBlock(self.handle, source.handle);
        }
    }

    pub fn label_for_address<L: Into<Location>>(&self, loc: L) -> Option<LowLevelILLabel> {
        use binaryninjacore_sys::BNGetLowLevelILLabelForAddress;

        let loc: Location = loc.into();
        let arch = loc.arch.unwrap_or_else(|| *self.arch().as_ref());
        let raw_label =
            unsafe { BNGetLowLevelILLabelForAddress(self.handle, arch.handle, loc.addr) };
        match raw_label.is_null() {
            false => {
                let mut label = unsafe { LowLevelILLabel::from(*raw_label) };
                // Set the location so that calls to [Self::update_label_map_for_label] will update the label map.
                label.location = Some(loc);
                Some(label)
            }
            true => None,
        }
    }

    /// Call this after updating the label through an il operation or via [`Self::mark_label`].
    fn update_label_map_for_label(&self, label: &LowLevelILLabel) {
        use binaryninjacore_sys::BNGetLowLevelILLabelForAddress;

        // Only need to update the label if there is an associated address.
        if let Some(loc) = label.location {
            let arch = loc.arch.unwrap_or_else(|| *self.arch().as_ref());
            // Add the label into the label map
            unsafe { BNAddLowLevelILLabelForAddress(self.handle, arch.handle, loc.addr) };
            // Retrieve a pointer to the label in the map
            let raw_label =
                unsafe { BNGetLowLevelILLabelForAddress(self.handle, arch.handle, loc.addr) };
            // We should always have a valid label here
            assert!(!raw_label.is_null(), "Failed to add label for address!");
            // Update the label in the map with `label`
            unsafe { *raw_label = label.into() };
        }
    }

    pub fn mark_label(&self, label: &mut LowLevelILLabel) {
        use binaryninjacore_sys::BNLowLevelILMarkLabel;

        let mut raw_label = BNLowLevelILLabel::from(*label);
        unsafe { BNLowLevelILMarkLabel(self.handle, &mut raw_label) };
        let mut new_label = LowLevelILLabel::from(raw_label);
        if let Some(location) = label.location {
            new_label.location = Some(location);
            self.update_label_map_for_label(&new_label);
        }
        *label = new_label;
    }

    pub fn set_expr_attributes(
        &self,
        expr: LowLevelExpressionIndex,
        value: &ILInstructionAttributeSet,
    ) {
        let mut result = 0u32;
        for flag in value {
            result |= flag.value();
        }

        unsafe {
            BNSetLowLevelILExprAttributes(self.handle, expr.0, result);
        }
    }

    pub fn clear_indirect_branches(&self) {
        unsafe { BNLowLevelILClearIndirectBranches(self.handle) };
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct LowLevelILLabel {
    /// Used to update the label map if the label is associated with a location.
    pub location: Option<Location>,
    pub resolved: bool,
    // TODO: This expr_ref is not actually a valid one sometimes...
    // TODO: We should make these non public and only accessible if resolved is true.
    pub expr_ref: LowLevelExpressionIndex,
    // TODO: If this is 7 this label is not valid.
    pub operand: usize,
}

impl LowLevelILLabel {
    pub fn new() -> Self {
        use binaryninjacore_sys::BNLowLevelILInitLabel;

        let mut raw_label = BNLowLevelILLabel::default();
        unsafe { BNLowLevelILInitLabel(&mut raw_label) };
        raw_label.into()
    }
}

impl From<BNLowLevelILLabel> for LowLevelILLabel {
    fn from(value: BNLowLevelILLabel) -> Self {
        Self {
            location: None,
            resolved: value.resolved,
            expr_ref: LowLevelExpressionIndex(value.ref_),
            operand: value.operand,
        }
    }
}

impl From<LowLevelILLabel> for BNLowLevelILLabel {
    fn from(value: LowLevelILLabel) -> Self {
        Self {
            resolved: value.resolved,
            ref_: value.expr_ref.0,
            operand: value.operand,
        }
    }
}

impl From<&LowLevelILLabel> for BNLowLevelILLabel {
    fn from(value: &LowLevelILLabel) -> Self {
        Self::from(*value)
    }
}

impl Default for LowLevelILLabel {
    fn default() -> Self {
        Self::new()
    }
}

// BEGIN GENERATED llil-lifters: from api/il, do not edit
/// The width of the value an expression produces given its size field, or `None` where its width
/// isn't tied to its size.
#[cfg(debug_assertions)]
pub(crate) fn result_width(op: BNLowLevelILOperation, size: usize) -> Option<usize> {
    use binaryninjacore_sys::BNLowLevelILOperation::*;

    match op {
        LLIL_LOAD
        | LLIL_POP
        | LLIL_REG
        | LLIL_REG_STACK_REL
        | LLIL_REG_STACK_POP
        | LLIL_CONST
        | LLIL_CONST_PTR
        | LLIL_EXTERN_PTR
        | LLIL_FLOAT_CONST
        | LLIL_FLAG_BIT
        | LLIL_ADD
        | LLIL_ADC
        | LLIL_SUB
        | LLIL_SBB
        | LLIL_AND
        | LLIL_OR
        | LLIL_XOR
        | LLIL_LSL
        | LLIL_LSR
        | LLIL_ASR
        | LLIL_ROL
        | LLIL_RLC
        | LLIL_ROR
        | LLIL_RRC
        | LLIL_MUL
        | LLIL_DIVU
        | LLIL_DIVU_DP
        | LLIL_DIVS
        | LLIL_DIVS_DP
        | LLIL_MODU
        | LLIL_MODU_DP
        | LLIL_MODS
        | LLIL_MODS_DP
        | LLIL_NEG
        | LLIL_NOT
        | LLIL_SX
        | LLIL_ZX
        | LLIL_LOW_PART
        | LLIL_BOOL_TO_INT
        | LLIL_UNIMPL_MEM
        | LLIL_FADD
        | LLIL_FSUB
        | LLIL_FMUL
        | LLIL_FDIV
        | LLIL_FSQRT
        | LLIL_FNEG
        | LLIL_FABS
        | LLIL_FLOAT_TO_INT
        | LLIL_INT_TO_FLOAT
        | LLIL_FLOAT_CONV
        | LLIL_ROUND_TO_INT
        | LLIL_FLOOR
        | LLIL_CEIL
        | LLIL_FTRUNC
        | LLIL_REG_SSA
        | LLIL_REG_SSA_PARTIAL
        | LLIL_REG_STACK_REL_SSA
        | LLIL_REG_STACK_ABS_SSA
        | LLIL_FLAG_BIT_SSA
        | LLIL_LOAD_SSA
        | LLIL_BSWAP
        | LLIL_POPCNT
        | LLIL_CLZ
        | LLIL_CTZ
        | LLIL_RBIT
        | LLIL_CLS
        | LLIL_MINS
        | LLIL_MAXS
        | LLIL_MINU
        | LLIL_MAXU
        | LLIL_ABS => Some(size),
        LLIL_REG_SPLIT | LLIL_MULU_DP | LLIL_MULS_DP | LLIL_REG_SPLIT_SSA => Some(size * 2),
        LLIL_FLAG | LLIL_FLAG_COND | LLIL_FLAG_GROUP | LLIL_CMP_E | LLIL_CMP_NE | LLIL_CMP_SLT
        | LLIL_CMP_ULT | LLIL_CMP_SLE | LLIL_CMP_ULE | LLIL_CMP_SGE | LLIL_CMP_UGE
        | LLIL_CMP_SGT | LLIL_CMP_UGT | LLIL_TEST_BIT | LLIL_ADD_OVERFLOW | LLIL_FCMP_E
        | LLIL_FCMP_NE | LLIL_FCMP_LT | LLIL_FCMP_LE | LLIL_FCMP_GE | LLIL_FCMP_GT
        | LLIL_FCMP_O | LLIL_FCMP_UO | LLIL_FLAG_SSA => Some(0),
        _ => None,
    }
}

impl LowLevelILMutableFunction {
    /// Does nothing.
    ///
    /// Returns the expression `nop`.
    pub fn nop(&self) -> LowLevelILExpression<'_, Mutable, NonSSA, VoidExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_NOP;

        let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, LLIL_NOP, 0, 0, 0, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    /// Reads `size` bytes from memory at `src`.
    ///
    /// Returns the expression `[src].<size> {<flags>}`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn load<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_LOAD;

        let src = Src::lift(self, src);

        ExpressionBuilder {
            function: self,
            op: LLIL_LOAD,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Writes the `size` bytes of `src` to memory at `dest`.
    ///
    /// Returns the expression `[dest].<size> = src {<flags>}`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn store<'a, Dest, Src>(
        &'a self,
        size: usize,
        dest: Dest,
        src: Src,
    ) -> ExpressionBuilder<'a, VoidExpr>
    where
        Dest: LiftableLowLevelIL<'a, Result = ValueExpr>,
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_STORE;

        let dest = Dest::lift(self, dest);
        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_STORE,
            size,
            flag_write: FlagWriteId(0),
            op1: dest.index.0 as u64,
            op2: src.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Writes `src` to the stack, adjusting the stack pointer by `size`.
    ///
    /// Returns the expression `push.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn push<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, VoidExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_PUSH;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_PUSH,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Reads `size` bytes from the stack, adjusting the stack pointer by `size`.
    ///
    /// Returns the expression `pop.<size>{<flags>}`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn pop(&self, size: usize) -> ExpressionBuilder<'_, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_POP;

        ExpressionBuilder {
            function: self,
            op: LLIL_POP,
            size,
            flag_write: FlagWriteId(0),
            op1: 0,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Adds `left` and `right`. Without flags, renders as `left + right`.
    ///
    /// Returns the expression `add.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn add<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_ADD;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_ADD,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Adds `left`, `right` and the carry `carry`.
    ///
    /// Returns the expression `adc.<size>{<flags>}(left, right, carry)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn adc<'a, Left, Right, Carry>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
        carry: Carry,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
        Carry: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_ADC;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);
        let carry = Carry::lift_with_size(self, carry, 0);

        ExpressionBuilder {
            function: self,
            op: LLIL_ADC,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: carry.index.0 as u64,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Subtracts `right` from `left`. Without flags, renders as `left - right`.
    ///
    /// Returns the expression `sub.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn sub<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_SUB;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_SUB,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Subtracts `right` and the borrow `carry` from `left`.
    ///
    /// Returns the expression `sbb.<size>{<flags>}(left, right, carry)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn sbb<'a, Left, Right, Carry>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
        carry: Carry,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
        Carry: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_SBB;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);
        let carry = Carry::lift_with_size(self, carry, 0);

        ExpressionBuilder {
            function: self,
            op: LLIL_SBB,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: carry.index.0 as u64,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The bitwise and of `left` and `right`. Without flags, renders as `left & right`, or as
    /// `left && right` when `size` is 0.
    ///
    /// Returns the expression `and.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn and<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_AND;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_AND,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The bitwise or of `left` and `right`. Without flags, renders as `left | right`, or as
    /// `left || right` when `size` is 0.
    ///
    /// Returns the expression `or.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn or<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_OR;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_OR,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The bitwise exclusive or of `left` and `right`. Without flags, renders as `left ^ right`.
    ///
    /// Returns the expression `xor.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn xor<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_XOR;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_XOR,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Shifts `left` left by `right` bits. Without flags, renders as `left << right`.
    ///
    /// Returns the expression `lsl.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn lsl<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_LSL;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_LSL,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Shifts `left` logically right by `right` bits. Without flags, renders as `left u>> right`.
    ///
    /// Returns the expression `lsr.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn lsr<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_LSR;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_LSR,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Shifts `left` arithmetically right by `right` bits. Without flags, renders as `left s>> right`.
    ///
    /// Returns the expression `asr.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn asr<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_ASR;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_ASR,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Rotates `left` left by `right` bits.
    ///
    /// Returns the expression `rol.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn rol<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_ROL;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_ROL,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Rotates `left` left by `right` bits through the carry `carry`.
    ///
    /// Returns the expression `rlc.<size>{<flags>}(left, right, carry)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn rlc<'a, Left, Right, Carry>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
        carry: Carry,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
        Carry: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_RLC;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);
        let carry = Carry::lift_with_size(self, carry, 0);

        ExpressionBuilder {
            function: self,
            op: LLIL_RLC,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: carry.index.0 as u64,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Rotates `left` right by `right` bits.
    ///
    /// Returns the expression `ror.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn ror<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_ROR;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_ROR,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Rotates `left` right by `right` bits through the carry `carry`.
    ///
    /// Returns the expression `rrc.<size>{<flags>}(left, right, carry)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn rrc<'a, Left, Right, Carry>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
        carry: Carry,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
        Carry: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_RRC;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);
        let carry = Carry::lift_with_size(self, carry, 0);

        ExpressionBuilder {
            function: self,
            op: LLIL_RRC,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: carry.index.0 as u64,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Multiplies `left` by `right`. The operands and the result are all `size` bytes, so the upper half of
    /// the product is discarded. Without flags, renders as `left * right`.
    ///
    /// Returns the expression `mul.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn mul<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_MUL;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_MUL,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Multiplies `left` by `right` as unsigned integers. The operands are `size` bytes and the result is
    /// `2 * size` bytes. The expression's size, which it renders with, is still `size`.
    ///
    /// Returns the expression `mulu.dp.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn mulu_dp<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_MULU_DP;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_MULU_DP,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Multiplies `left` by `right` as signed integers. The operands are `size` bytes and the result is
    /// `2 * size` bytes. The expression's size, which it renders with, is still `size`.
    ///
    /// Returns the expression `muls.dp.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn muls_dp<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_MULS_DP;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_MULS_DP,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Divides `left` by `right` as unsigned integers.
    ///
    /// Returns the expression `divu.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn divu<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_DIVU;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_DIVU,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Divides `left` by `right` as unsigned integers. `left` is `2 * size` bytes, and `right` and the
    /// result are `size` bytes.
    ///
    /// Returns the expression `divu.dp.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn divu_dp<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_DIVU_DP;

        let left = Left::lift_with_size(self, left, size * 2);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_DIVU_DP,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Divides `left` by `right` as signed integers.
    ///
    /// Returns the expression `divs.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn divs<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_DIVS;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_DIVS,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Divides `left` by `right` as signed integers. `left` is `2 * size` bytes, and `right` and the result
    /// are `size` bytes.
    ///
    /// Returns the expression `divs.dp.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn divs_dp<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_DIVS_DP;

        let left = Left::lift_with_size(self, left, size * 2);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_DIVS_DP,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The remainder of dividing `left` by `right` as unsigned integers.
    ///
    /// Returns the expression `modu.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn modu<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_MODU;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_MODU,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The remainder of dividing `left` by `right` as unsigned integers. `left` is `2 * size` bytes, and
    /// `right` and the result are `size` bytes.
    ///
    /// Returns the expression `modu.dp.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn modu_dp<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_MODU_DP;

        let left = Left::lift_with_size(self, left, size * 2);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_MODU_DP,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The remainder of dividing `left` by `right` as signed integers.
    ///
    /// Returns the expression `mods.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn mods<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_MODS;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_MODS,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The remainder of dividing `left` by `right` as signed integers. `left` is `2 * size` bytes, and
    /// `right` and the result are `size` bytes.
    ///
    /// Returns the expression `mods.dp.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn mods_dp<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_MODS_DP;

        let left = Left::lift_with_size(self, left, size * 2);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_MODS_DP,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Negates `src` as a two's complement integer.
    ///
    /// Returns the expression `neg.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn neg<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_NEG;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_NEG,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Inverts the bits of `src`.
    ///
    /// Returns the expression `not.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn not<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_NOT;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_NOT,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Sign-extends `src` to `size` bytes.
    ///
    /// Returns the expression `sx.<size>(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn sx<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_SX;

        let src = Src::lift(self, src);

        ExpressionBuilder {
            function: self,
            op: LLIL_SX,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Zero-extends `src` to `size` bytes.
    ///
    /// Returns the expression `zx.<size>(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn zx<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_ZX;

        let src = Src::lift(self, src);

        ExpressionBuilder {
            function: self,
            op: LLIL_ZX,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Truncates `src` to its low `size` bytes.
    ///
    /// Returns the expression `(src).<size>`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn low_part<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_LOW_PART;

        let src = Src::lift(self, src);

        ExpressionBuilder {
            function: self,
            op: LLIL_LOW_PART,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Jumps to `dest`.
    ///
    /// Returns the expression `jump(dest)`.
    pub fn jump<'a, Dest>(
        &'a self,
        dest: Dest,
    ) -> LowLevelILExpression<'a, Mutable, NonSSA, VoidExpr>
    where
        Dest: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_JUMP;

        let dest = Dest::lift(self, dest);

        let expr_idx = unsafe {
            BNLowLevelILAddExpr(self.handle, LLIL_JUMP, 0, 0, dest.index.0 as u64, 0, 0, 0)
        };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    /// Calls `dest`. On architectures without a link register, this pushes the address of the next
    /// instruction onto the stack, then jumps to `dest`.
    ///
    /// Returns the expression `call(dest)`.
    pub fn call<'a, Dest>(
        &'a self,
        dest: Dest,
    ) -> LowLevelILExpression<'a, Mutable, NonSSA, VoidExpr>
    where
        Dest: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CALL;

        let dest = Dest::lift(self, dest);

        let expr_idx = unsafe {
            BNLowLevelILAddExpr(self.handle, LLIL_CALL, 0, 0, dest.index.0 as u64, 0, 0, 0)
        };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    /// Jumps to `dest` as a tail call.
    ///
    /// Returns the expression `<return> tailcall(dest)`.
    pub fn tailcall<'a, Dest>(
        &'a self,
        dest: Dest,
    ) -> LowLevelILExpression<'a, Mutable, NonSSA, VoidExpr>
    where
        Dest: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_TAILCALL;

        let dest = Dest::lift(self, dest);

        let expr_idx = unsafe {
            BNLowLevelILAddExpr(
                self.handle,
                LLIL_TAILCALL,
                0,
                0,
                dest.index.0 as u64,
                0,
                0,
                0,
            )
        };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    /// Returns from the function by jumping to `dest`.
    ///
    /// Returns the expression `<return> jump(dest)`.
    pub fn ret<'a, Dest>(
        &'a self,
        dest: Dest,
    ) -> LowLevelILExpression<'a, Mutable, NonSSA, VoidExpr>
    where
        Dest: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_RET;

        let dest = Dest::lift(self, dest);

        let expr_idx = unsafe {
            BNLowLevelILAddExpr(self.handle, LLIL_RET, 0, 0, dest.index.0 as u64, 0, 0, 0)
        };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    /// Marks a point that execution doesn't pass, such as after a call that doesn't return.
    ///
    /// Returns the expression `noreturn`.
    pub fn no_ret(&self) -> LowLevelILExpression<'_, Mutable, NonSSA, VoidExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_NORET;

        let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, LLIL_NORET, 0, 0, 0, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    /// Tests whether `left` equals `right`.
    ///
    /// Returns the expression `left == right`.
    pub fn cmp_e<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CMP_E;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CMP_E,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` doesn't equal `right`.
    ///
    /// Returns the expression `left != right`.
    pub fn cmp_ne<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CMP_NE;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CMP_NE,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is less than `right` as signed integers.
    ///
    /// Returns the expression `left s< right`.
    pub fn cmp_slt<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CMP_SLT;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CMP_SLT,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is less than `right` as unsigned integers.
    ///
    /// Returns the expression `left u< right`.
    pub fn cmp_ult<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CMP_ULT;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CMP_ULT,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is less than or equal to `right` as signed integers.
    ///
    /// Returns the expression `left s<= right`.
    pub fn cmp_sle<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CMP_SLE;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CMP_SLE,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is less than or equal to `right` as unsigned integers.
    ///
    /// Returns the expression `left u<= right`.
    pub fn cmp_ule<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CMP_ULE;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CMP_ULE,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is greater than or equal to `right` as signed integers.
    ///
    /// Returns the expression `left s>= right`.
    pub fn cmp_sge<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CMP_SGE;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CMP_SGE,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is greater than or equal to `right` as unsigned integers.
    ///
    /// Returns the expression `left u>= right`.
    pub fn cmp_uge<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CMP_UGE;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CMP_UGE,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is greater than `right` as signed integers.
    ///
    /// Returns the expression `left s> right`.
    pub fn cmp_sgt<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CMP_SGT;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CMP_SGT,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is greater than `right` as unsigned integers.
    ///
    /// Returns the expression `left u> right`.
    pub fn cmp_ugt<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CMP_UGT;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CMP_UGT,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether bit `right` of `left` is set.
    ///
    /// Returns the expression `test_bit(left, right)`.
    pub fn test_bit<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_TEST_BIT;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_TEST_BIT,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Converts `src` to the integer 1 if it's true, or 0 if it's false.
    ///
    /// Returns the expression `src ? 1 : 0`.
    pub fn bool_to_int<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_BOOL_TO_INT;

        let src = Src::lift(self, src);

        ExpressionBuilder {
            function: self,
            op: LLIL_BOOL_TO_INT,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    pub fn add_overflow<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_ADD_OVERFLOW;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_ADD_OVERFLOW,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Makes a system call.
    ///
    /// Returns the expression `syscall`.
    pub fn syscall(&self) -> LowLevelILExpression<'_, Mutable, NonSSA, VoidExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_SYSCALL;

        let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, LLIL_SYSCALL, 0, 0, 0, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    /// A processor breakpoint.
    ///
    /// Returns the expression `breakpoint`.
    pub fn bp(&self) -> LowLevelILExpression<'_, Mutable, NonSSA, VoidExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_BP;

        let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, LLIL_BP, 0, 0, 0, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    /// An undefined value or operation. As a statement, it ends the basic block and leaves its outgoing
    /// edges undetermined.
    ///
    /// Returns the expression `undefined`.
    pub fn undefined(&self) -> LowLevelILExpression<'_, Mutable, NonSSA, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_UNDEF;

        let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, LLIL_UNDEF, 0, 0, 0, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    /// An unimplemented instruction or value.
    ///
    /// Returns the expression `unimplemented`.
    pub fn unimplemented(&self) -> LowLevelILExpression<'_, Mutable, NonSSA, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_UNIMPL;

        let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, LLIL_UNIMPL, 0, 0, 0, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    /// A value that can't be known at analysis time, such as a flag that depends on runtime state. It
    /// doesn't produce the warning an unimplemented expression does.
    ///
    /// Returns the expression `unknown`.
    pub fn unknown(&self) -> LowLevelILExpression<'_, Mutable, NonSSA, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_UNIMPL;

        let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, LLIL_UNIMPL, 0, 0, 1, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    /// A reference to `size` bytes of memory at `src`, for an unimplemented operation.
    ///
    /// Returns the expression `unimplemented([src].<size>)`.
    pub fn unimplemented_mem<'a, Src>(
        &'a self,
        size: usize,
        src: Src,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_UNIMPL_MEM;

        let src = Src::lift(self, src);

        ExpressionBuilder {
            function: self,
            op: LLIL_UNIMPL_MEM,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// A reference to `size` bytes of memory at `src`, whose value can't be known at analysis time. It
    /// doesn't produce the warning an unimplemented expression does.
    ///
    /// Returns the expression `unknown([src].<size>)`.
    pub fn unknown_mem<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_UNIMPL_MEM;

        let src = Src::lift(self, src);

        ExpressionBuilder {
            function: self,
            op: LLIL_UNIMPL_MEM,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 1,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Adds `left` and `right` as floating point values. Without flags, renders as `left f+ right`.
    ///
    /// Returns the expression `fadd.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn fadd<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FADD;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FADD,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Subtracts `right` from `left` as floating point values. Without flags, renders as `left f- right`.
    ///
    /// Returns the expression `fsub.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn fsub<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FSUB;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FSUB,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Multiplies `left` by `right` as floating point values. Without flags, renders as `left f* right`.
    ///
    /// Returns the expression `fmul.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn fmul<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FMUL;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FMUL,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Divides `left` by `right` as floating point values. Without flags, renders as `left f/ right`.
    ///
    /// Returns the expression `fdiv.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn fdiv<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FDIV;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FDIV,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The square root of the floating point value `src`.
    ///
    /// Returns the expression `sqrt{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn fsqrt<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FSQRT;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FSQRT,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Negates the floating point value `src`.
    ///
    /// Returns the expression `fneg{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn fneg<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FNEG;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FNEG,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The absolute value of the floating point value `src`.
    ///
    /// Returns the expression `fabs{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn fabs<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FABS;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FABS,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Converts the floating point value `src` to an integer.
    ///
    /// Returns the expression `int.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn float_to_int<'a, Src>(
        &'a self,
        size: usize,
        src: Src,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLOAT_TO_INT;

        let src = Src::lift(self, src);

        ExpressionBuilder {
            function: self,
            op: LLIL_FLOAT_TO_INT,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Converts the integer `src` to a floating point value.
    ///
    /// Returns the expression `float.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn int_to_float<'a, Src>(
        &'a self,
        size: usize,
        src: Src,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_INT_TO_FLOAT;

        let src = Src::lift(self, src);

        ExpressionBuilder {
            function: self,
            op: LLIL_INT_TO_FLOAT,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Converts the floating point value `src` to a floating point value of `size` bytes.
    ///
    /// Returns the expression `fconvert.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn float_conv<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelIL<'a, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLOAT_CONV;

        let src = Src::lift(self, src);

        ExpressionBuilder {
            function: self,
            op: LLIL_FLOAT_CONV,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Rounds the floating point value `src` to the nearest integral value.
    ///
    /// Returns the expression `roundint.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn round_to_int<'a, Src>(
        &'a self,
        size: usize,
        src: Src,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_ROUND_TO_INT;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_ROUND_TO_INT,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Rounds the floating point value `src` to an integral value, towards negative infinity.
    ///
    /// Returns the expression `floor.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn floor<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLOOR;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FLOOR,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Rounds the floating point value `src` to an integral value, towards positive infinity.
    ///
    /// Returns the expression `ceil.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn ceil<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CEIL;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CEIL,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Rounds the floating point value `src` to an integral value, towards zero.
    ///
    /// Returns the expression `ftrunc.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn ftrunc<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FTRUNC;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FTRUNC,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` equals `right` as floating point values.
    ///
    /// Returns the expression `left f== right`.
    pub fn fcmp_e<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FCMP_E;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FCMP_E,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` doesn't equal `right` as floating point values.
    ///
    /// Returns the expression `left f!= right`.
    pub fn fcmp_ne<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FCMP_NE;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FCMP_NE,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is less than `right` as floating point values.
    ///
    /// Returns the expression `left f< right`.
    pub fn fcmp_lt<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FCMP_LT;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FCMP_LT,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is less than or equal to `right` as floating point values.
    ///
    /// Returns the expression `left f<= right`.
    pub fn fcmp_le<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FCMP_LE;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FCMP_LE,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is greater than or equal to `right` as floating point values.
    ///
    /// Returns the expression `left f>= right`.
    pub fn fcmp_ge<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FCMP_GE;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FCMP_GE,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` is greater than `right` as floating point values.
    ///
    /// Returns the expression `left f> right`.
    pub fn fcmp_gt<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FCMP_GT;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FCMP_GT,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` and `right` are ordered, which they are when neither is NaN.
    ///
    /// Returns the expression `is_ordered.<size>(left, right)`.
    pub fn fcmp_o<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FCMP_O;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FCMP_O,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Tests whether `left` and `right` are unordered, which they are when either is NaN.
    ///
    /// Returns the expression `is_unordered.<size>(left, right)`.
    pub fn fcmp_uo<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FCMP_UO;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_FCMP_UO,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Reverses the byte order of `src`.
    ///
    /// Returns the expression `bswap.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn bswap<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_BSWAP;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_BSWAP,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Counts the set bits in `src`.
    ///
    /// Returns the expression `popcnt.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn popcnt<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_POPCNT;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_POPCNT,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Counts the leading zero bits in `src`. The result is `8 * size` when `src` is zero.
    ///
    /// Returns the expression `clz.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn clz<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CLZ;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CLZ,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Counts the trailing zero bits in `src`. The result is `8 * size` when `src` is zero.
    ///
    /// Returns the expression `ctz.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn ctz<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CTZ;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CTZ,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Reverses the bit order of `src`.
    ///
    /// Returns the expression `rbit.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn rbit<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_RBIT;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_RBIT,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// Counts the bits below the sign bit of `src` that match it.
    ///
    /// Returns the expression `cls.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn cls<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CLS;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_CLS,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The smaller of `left` and `right` as signed integers.
    ///
    /// Returns the expression `mins.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn min_signed<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_MINS;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_MINS,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The larger of `left` and `right` as signed integers.
    ///
    /// Returns the expression `maxs.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn max_signed<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_MAXS;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_MAXS,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The smaller of `left` and `right` as unsigned integers.
    ///
    /// Returns the expression `minu.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn min_unsigned<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_MINU;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_MINU,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The larger of `left` and `right` as unsigned integers.
    ///
    /// Returns the expression `maxu.<size>{<flags>}(left, right)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn max_unsigned<'a, Left, Right>(
        &'a self,
        size: usize,
        left: Left,
        right: Right,
    ) -> ExpressionBuilder<'a, ValueExpr>
    where
        Left: LiftableLowLevelILWithSize<'a>,
        Right: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_MAXU;

        let left = Left::lift_with_size(self, left, size);
        let right = Right::lift_with_size(self, right, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_MAXU,
            size,
            flag_write: FlagWriteId(0),
            op1: left.index.0 as u64,
            op2: right.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    /// The absolute value of `src` as a signed integer.
    ///
    /// Returns the expression `abs.<size>{<flags>}(src)`.
    ///
    /// Set its flag write type with [`ExpressionBuilder::with_flag_write`].
    pub fn abs<'a, Src>(&'a self, size: usize, src: Src) -> ExpressionBuilder<'a, ValueExpr>
    where
        Src: LiftableLowLevelILWithSize<'a>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_ABS;

        let src = Src::lift_with_size(self, src, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_ABS,
            size,
            flag_write: FlagWriteId(0),
            op1: src.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }
}
// END GENERATED llil-lifters
