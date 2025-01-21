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

use std::marker::PhantomData;

use binaryninjacore_sys::{BNAddLowLevelILLabelForAddress, BNLowLevelILOperation};
use binaryninjacore_sys::{BNLowLevelILLabel, BNRegisterOrConstant};

use super::*;
use crate::architecture::Register as ArchReg;
use crate::architecture::{Architecture, FlagWriteId, RegisterId};
use crate::architecture::{
    Flag, FlagClass, FlagCondition, FlagGroup, FlagRole, FlagWrite, Intrinsic,
};
use crate::function::Location;

pub trait LiftableLowLevelIL<'func, A: 'func + Architecture> {
    type Result: ExpressionResultType;

    fn lift(
        il: &'func MutableLiftedILFunction<A>,
        expr: Self,
    ) -> MutableLiftedILExpr<'func, A, Self::Result>;
}

pub trait LiftableLowLevelILWithSize<'func, A: 'func + Architecture>:
    LiftableLowLevelIL<'func, A, Result = ValueExpr>
{
    fn lift_with_size(
        il: &'func MutableLiftedILFunction<A>,
        expr: Self,
        size: usize,
    ) -> MutableLiftedILExpr<'func, A, ValueExpr>;
}

#[derive(Copy, Clone)]
pub enum LowLevelILRegisterOrConstant<R: ArchReg> {
    Register(usize, LowLevelILRegister<R>),
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

// TODO flesh way out
#[derive(Copy, Clone)]
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
    Sx(usize, LowLevelILRegisterOrConstant<R>),
    Zx(usize, LowLevelILRegisterOrConstant<R>),
    LowPart(usize, LowLevelILRegisterOrConstant<R>),
    BoolToInt(usize, LowLevelILRegisterOrConstant<R>),
    FloatToInt(usize, LowLevelILRegisterOrConstant<R>),

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
    // TODO: floating point stuff, llil comparison ops that set flags, intrinsics
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
                let il_reg = if 0x8000_0000 & operand.reg == 0 {
                    LowLevelILRegister::ArchReg(
                        arch.register_from_id(RegisterId(operand.reg)).unwrap(),
                    )
                } else {
                    LowLevelILRegister::Temp(operand.reg)
                };

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
            (1, LLIL_SX) => op!(Sx, 0),
            (1, LLIL_ZX) => op!(Zx, 0),
            (1, LLIL_LOW_PART) => op!(LowPart, 0),
            (1, LLIL_BOOL_TO_INT) => op!(BoolToInt, 0),
            (1, LLIL_FLOAT_TO_INT) => op!(FloatToInt, 0),

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
            (2, LLIL_DIVU_DP) => op!(DivuDp, 0, 1),
            (2, LLIL_DIVS_DP) => op!(DivsDp, 0, 1),
            (2, LLIL_MODU_DP) => op!(ModuDp, 0, 1),
            (2, LLIL_MODS_DP) => op!(ModsDp, 0, 1),

            (2, LLIL_TEST_BIT) => op!(TestBit, 0, 1),
            (2, LLIL_ADD_OVERFLOW) => op!(AddOverflow, 0, 1),

            (3, LLIL_ADC) => op!(Adc, 0, 1, 2),
            (3, LLIL_SBB) => op!(Sbb, 0, 1, 2),
            (3, LLIL_RLC) => op!(Rlc, 0, 1, 2),
            (3, LLIL_RRC) => op!(Rrc, 0, 1, 2),

            (0, LLIL_POP) => op!(Pop,),

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
            Sx(size, ..) => (size, LLIL_SX),
            Zx(size, ..) => (size, LLIL_ZX),
            LowPart(size, ..) => (size, LLIL_LOW_PART),
            BoolToInt(size, ..) => (size, LLIL_BOOL_TO_INT),
            FloatToInt(size, ..) => (size, LLIL_FLOAT_TO_INT),

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
            DivuDp(size, ..) => (size, LLIL_DIVU_DP),
            DivsDp(size, ..) => (size, LLIL_DIVS_DP),
            ModuDp(size, ..) => (size, LLIL_MODU_DP),
            ModsDp(size, ..) => (size, LLIL_MODS_DP),

            TestBit(size, ..) => (size, LLIL_TEST_BIT),
            AddOverflow(size, ..) => (size, LLIL_ADD_OVERFLOW),

            Adc(size, ..) => (size, LLIL_ADC),
            Sbb(size, ..) => (size, LLIL_SBB),
            Rlc(size, ..) => (size, LLIL_RLC),
            Rrc(size, ..) => (size, LLIL_RRC),

            Pop(size) => (size, LLIL_POP),
        }
    }

    pub(crate) fn raw_operands(&self) -> (usize, [BNRegisterOrConstant; 5]) {
        use self::LowLevelILFlagWriteOp::*;

        let mut operands: [BNRegisterOrConstant; 5] = [BNRegisterOrConstant::default(); 5];

        let count = match *self {
            Pop(_) => 0,

            SetReg(_, op0)
            | Load(_, op0)
            | Push(_, op0)
            | Neg(_, op0)
            | Not(_, op0)
            | Sx(_, op0)
            | Zx(_, op0)
            | LowPart(_, op0)
            | BoolToInt(_, op0)
            | FloatToInt(_, op0) => {
                operands[0] = op0.into();
                1
            }

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
            | DivuDp(_, op0, op1)
            | DivsDp(_, op0, op1)
            | ModuDp(_, op0, op1)
            | ModsDp(_, op0, op1)
            | TestBit(_, op0, op1)
            | AddOverflow(_, op0, op1) => {
                operands[0] = op0.into();
                operands[1] = op1.into();
                2
            }

            Adc(_, op0, op1, op2)
            | Sbb(_, op0, op1, op2)
            | Rlc(_, op0, op1, op2)
            | Rrc(_, op0, op1, op2) => {
                operands[0] = op0.into();
                operands[1] = op1.into();
                operands[2] = op2.into();
                3
            }
        };

        (count, operands)
    }
}

pub fn get_default_flag_write_llil<'func, A>(
    arch: &A,
    role: FlagRole,
    op: LowLevelILFlagWriteOp<A::Register>,
    il: &'func MutableLiftedILFunction<A>,
) -> MutableLiftedILExpr<'func, A, ValueExpr>
where
    A: 'func + Architecture,
{
    let (size, operation) = op.size_and_op();
    let (count, operands) = op.raw_operands();

    let expr_idx = unsafe {
        use binaryninjacore_sys::BNGetDefaultArchitectureFlagWriteLowLevelIL;
        BNGetDefaultArchitectureFlagWriteLowLevelIL(
            arch.as_ref().handle,
            operation,
            size,
            role,
            operands.as_ptr() as *mut _,
            count,
            il.handle,
        )
    };

    LowLevelILExpression::new(il, LowLevelExpressionIndex(expr_idx))
}

pub fn get_default_flag_cond_llil<'func, A>(
    arch: &A,
    cond: FlagCondition,
    class: Option<A::FlagClass>,
    il: &'func MutableLiftedILFunction<A>,
) -> MutableLiftedILExpr<'func, A, ValueExpr>
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
        impl<'a, A: 'a + Architecture> LiftableLowLevelIL<'a, A> for $x {
            type Result = ValueExpr;

            fn lift(il: &'a MutableLiftedILFunction<A>, val: Self)
                -> MutableLiftedILExpr<'a, A, Self::Result>
            {
                il.const_int(std::mem::size_of::<Self>(), val as i64 as u64)
            }
        }

        impl<'a, A: 'a + Architecture> LiftableLowLevelILWithSize<'a, A> for $x {
            fn lift_with_size(il: &'a MutableLiftedILFunction<A>, val: Self, size: usize)
                -> MutableLiftedILExpr<'a, A, ValueExpr>
            {
                let raw = val as i64;

                #[cfg(debug_assertions)]
                {
                    let is_safe = match raw.overflowing_shr(size as u32 * 8) {
                        (_, true) => true,
                        (res, false) => [-1, 0].contains(&res),
                    };

                    if !is_safe {
                        log::error!("il @ {:x} attempted to lift constant 0x{:x} as {} byte expr (won't fit!)",
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

impl<'a, R: ArchReg, A: 'a + Architecture> LiftableLowLevelIL<'a, A> for LowLevelILRegister<R>
where
    R: LiftableLowLevelIL<'a, A, Result = ValueExpr> + Into<LowLevelILRegister<R>>,
{
    type Result = ValueExpr;

    fn lift(
        il: &'a MutableLiftedILFunction<A>,
        reg: Self,
    ) -> MutableLiftedILExpr<'a, A, Self::Result> {
        match reg {
            LowLevelILRegister::ArchReg(r) => R::lift(il, r),
            LowLevelILRegister::Temp(t) => il.reg(
                il.arch().default_integer_size(),
                LowLevelILRegister::Temp(t),
            ),
        }
    }
}

impl<'a, R: ArchReg, A: 'a + Architecture> LiftableLowLevelILWithSize<'a, A>
    for LowLevelILRegister<R>
where
    R: LiftableLowLevelILWithSize<'a, A> + Into<LowLevelILRegister<R>>,
{
    fn lift_with_size(
        il: &'a MutableLiftedILFunction<A>,
        reg: Self,
        size: usize,
    ) -> MutableLiftedILExpr<'a, A, ValueExpr> {
        match reg {
            LowLevelILRegister::ArchReg(r) => R::lift_with_size(il, r, size),
            LowLevelILRegister::Temp(t) => il.reg(size, LowLevelILRegister::Temp(t)),
        }
    }
}

impl<'a, R: ArchReg, A: 'a + Architecture> LiftableLowLevelIL<'a, A>
    for LowLevelILRegisterOrConstant<R>
where
    R: LiftableLowLevelILWithSize<'a, A, Result = ValueExpr> + Into<LowLevelILRegister<R>>,
{
    type Result = ValueExpr;

    fn lift(
        il: &'a MutableLiftedILFunction<A>,
        reg: Self,
    ) -> MutableLiftedILExpr<'a, A, Self::Result> {
        match reg {
            LowLevelILRegisterOrConstant::Register(size, r) => {
                LowLevelILRegister::<R>::lift_with_size(il, r, size)
            }
            LowLevelILRegisterOrConstant::Constant(size, value) => {
                u64::lift_with_size(il, value, size)
            }
        }
    }
}

impl<'a, R: ArchReg, A: 'a + Architecture> LiftableLowLevelILWithSize<'a, A>
    for LowLevelILRegisterOrConstant<R>
where
    R: LiftableLowLevelILWithSize<'a, A> + Into<LowLevelILRegister<R>>,
{
    fn lift_with_size(
        il: &'a MutableLiftedILFunction<A>,
        reg: Self,
        size: usize,
    ) -> MutableLiftedILExpr<'a, A, ValueExpr> {
        // TODO ensure requested size is compatible with size of this constant
        match reg {
            LowLevelILRegisterOrConstant::Register(_, r) => {
                LowLevelILRegister::<R>::lift_with_size(il, r, size)
            }
            LowLevelILRegisterOrConstant::Constant(_, value) => {
                u64::lift_with_size(il, value, size)
            }
        }
    }
}

impl<'a, A, R> LiftableLowLevelIL<'a, A>
    for LowLevelILExpression<'a, A, Mutable, NonSSA<LiftedNonSSA>, R>
where
    A: 'a + Architecture,
    R: ExpressionResultType,
{
    type Result = R;

    fn lift(
        il: &'a MutableLiftedILFunction<A>,
        expr: Self,
    ) -> MutableLiftedILExpr<'a, A, Self::Result> {
        debug_assert!(expr.function.handle == il.handle);
        expr
    }
}

impl<'a, A: 'a + Architecture> LiftableLowLevelILWithSize<'a, A>
    for LowLevelILExpression<'a, A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr>
{
    fn lift_with_size(
        il: &'a MutableLiftedILFunction<A>,
        expr: Self,
        _size: usize,
    ) -> MutableLiftedILExpr<'a, A, Self::Result> {
        #[cfg(debug_assertions)]
        {
            use crate::low_level_il::ExpressionHandler;
            if let Some(expr_size) = expr.kind().size() {
                if expr_size != _size {
                    log::warn!(
                        "il @ {:x} attempted to lift {} byte expression as {} bytes",
                        il.current_address(),
                        expr_size,
                        _size
                    );
                }
            }
        }

        LiftableLowLevelIL::lift(il, expr)
    }
}

impl<'func, A, R> LowLevelILExpression<'func, A, Mutable, NonSSA<LiftedNonSSA>, R>
where
    A: 'func + Architecture,
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

pub struct ExpressionBuilder<'func, A, R>
where
    A: 'func + Architecture,
    R: ExpressionResultType,
{
    function: &'func LowLevelILFunction<A, Mutable, NonSSA<LiftedNonSSA>>,
    op: BNLowLevelILOperation,
    size: usize,
    flag_write: FlagWriteId,
    op1: u64,
    op2: u64,
    op3: u64,
    op4: u64,
    _ty: PhantomData<R>,
}

impl<'a, A, R> ExpressionBuilder<'a, A, R>
where
    A: 'a + Architecture,
    R: ExpressionResultType,
{
    pub fn from_expr(expr: LowLevelILExpression<'a, A, Mutable, NonSSA<LiftedNonSSA>, R>) -> Self {
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

    pub fn with_flag_write(mut self, flag_write: A::FlagWrite) -> Self {
        // TODO verify valid id
        self.flag_write = flag_write.id();
        self
    }

    pub fn build(self) -> LowLevelILExpression<'a, A, Mutable, NonSSA<LiftedNonSSA>, R> {
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

    pub fn with_source_operand(
        self,
        op: u32,
    ) -> LowLevelILExpression<'a, A, Mutable, NonSSA<LiftedNonSSA>, R> {
        self.build().with_source_operand(op)
    }

    pub fn append(self) {
        let expr = self.build();
        expr.function.add_instruction(expr);
    }
}

impl<'a, A, R> LiftableLowLevelIL<'a, A> for ExpressionBuilder<'a, A, R>
where
    A: 'a + Architecture,
    R: ExpressionResultType,
{
    type Result = R;

    fn lift(
        il: &'a MutableLiftedILFunction<A>,
        expr: Self,
    ) -> MutableLiftedILExpr<'a, A, Self::Result> {
        debug_assert!(expr.function.handle == il.handle);

        expr.build()
    }
}

impl<'a, A> LiftableLowLevelILWithSize<'a, A> for ExpressionBuilder<'a, A, ValueExpr>
where
    A: 'a + Architecture,
{
    fn lift_with_size(
        il: &'a MutableLiftedILFunction<A>,
        expr: Self,
        _size: usize,
    ) -> MutableLiftedILExpr<'a, A, ValueExpr> {
        #[cfg(debug_assertions)]
        {
            use binaryninjacore_sys::BNLowLevelILOperation::{LLIL_UNIMPL, LLIL_UNIMPL_MEM};

            if expr.size != _size && ![LLIL_UNIMPL, LLIL_UNIMPL_MEM].contains(&expr.op) {
                log::warn!(
                    "il @ {:x} attempted to lift {} byte expression builder as {} bytes",
                    il.current_address(),
                    expr.size,
                    _size
                );
            }
        }

        LiftableLowLevelIL::lift(il, expr)
    }
}

macro_rules! no_arg_lifter {
    ($name:ident, $op:ident, $result:ty) => {
        pub fn $name(&self) -> LowLevelILExpression<A, Mutable, NonSSA<LiftedNonSSA>, $result> {
            use binaryninjacore_sys::BNLowLevelILAddExpr;
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, $op, 0, 0, 0, 0, 0, 0) };

            LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
        }
    };
}

macro_rules! sized_no_arg_lifter {
    ($name:ident, $op:ident, $result:ty) => {
        pub fn $name(&self, size: usize) -> ExpressionBuilder<A, $result> {
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            ExpressionBuilder {
                function: self,
                op: $op,
                size,
                flag_write: FlagWriteId(0),
                op1: 0,
                op2: 0,
                op3: 0,
                op4: 0,
                _ty: PhantomData,
            }
        }
    };
}

macro_rules! unsized_unary_op_lifter {
    ($name:ident, $op:ident, $result:ty) => {
        pub fn $name<'a, E>(
            &'a self,
            expr: E,
        ) -> LowLevelILExpression<'a, A, Mutable, NonSSA<LiftedNonSSA>, $result>
        where
            E: LiftableLowLevelIL<'a, A, Result = ValueExpr>,
        {
            use binaryninjacore_sys::BNLowLevelILAddExpr;
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let expr = E::lift(self, expr);

            let expr_idx = unsafe {
                BNLowLevelILAddExpr(self.handle, $op, 0, 0, expr.index.0 as u64, 0, 0, 0)
            };

            LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
        }
    };
}

macro_rules! sized_unary_op_lifter {
    ($name:ident, $op:ident, $result:ty) => {
        pub fn $name<'a, E>(&'a self, size: usize, expr: E) -> ExpressionBuilder<'a, A, $result>
        where
            E: LiftableLowLevelILWithSize<'a, A>,
        {
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let expr = E::lift_with_size(self, expr, size);

            ExpressionBuilder {
                function: self,
                op: $op,
                size,
                flag_write: FlagWriteId(0),
                op1: expr.index.0 as u64,
                op2: 0,
                op3: 0,
                op4: 0,
                _ty: PhantomData,
            }
        }
    };
}

macro_rules! size_changing_unary_op_lifter {
    ($name:ident, $op:ident, $result:ty) => {
        pub fn $name<'a, E>(&'a self, size: usize, expr: E) -> ExpressionBuilder<'a, A, $result>
        where
            E: LiftableLowLevelILWithSize<'a, A>,
        {
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let expr = E::lift(self, expr);

            ExpressionBuilder {
                function: self,
                op: $op,
                size,
                flag_write: FlagWriteId(0),
                op1: expr.index.0 as u64,
                op2: 0,
                op3: 0,
                op4: 0,
                _ty: PhantomData,
            }
        }
    };
}

macro_rules! binary_op_lifter {
    ($name:ident, $op:ident) => {
        pub fn $name<'a, L, R>(
            &'a self,
            size: usize,
            left: L,
            right: R,
        ) -> ExpressionBuilder<'a, A, ValueExpr>
        where
            L: LiftableLowLevelILWithSize<'a, A>,
            R: LiftableLowLevelILWithSize<'a, A>,
        {
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let left = L::lift_with_size(self, left, size);
            let right = R::lift_with_size(self, right, size);

            ExpressionBuilder {
                function: self,
                op: $op,
                size,
                flag_write: FlagWriteId(0),
                op1: left.index.0 as u64,
                op2: right.index.0 as u64,
                op3: 0,
                op4: 0,
                _ty: PhantomData,
            }
        }
    };
}

macro_rules! binary_op_carry_lifter {
    ($name:ident, $op:ident) => {
        pub fn $name<'a, L, R, C>(
            &'a self,
            size: usize,
            left: L,
            right: R,
            carry: C,
        ) -> ExpressionBuilder<'a, A, ValueExpr>
        where
            L: LiftableLowLevelILWithSize<'a, A>,
            R: LiftableLowLevelILWithSize<'a, A>,
            C: LiftableLowLevelILWithSize<'a, A>,
        {
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let left = L::lift_with_size(self, left, size);
            let right = R::lift_with_size(self, right, size);
            let carry = C::lift_with_size(self, carry, 0);

            ExpressionBuilder {
                function: self,
                op: $op,
                size,
                flag_write: FlagWriteId(0),
                op1: left.index.0 as u64,
                op2: right.index.0 as u64,
                op3: carry.index.0 as u64,
                op4: 0,
                _ty: PhantomData,
            }
        }
    };
}

impl<A> LowLevelILFunction<A, Mutable, NonSSA<LiftedNonSSA>>
where
    A: Architecture,
{
    pub const NO_INPUTS: [ExpressionBuilder<'static, A, ValueExpr>; 0] = [];
    pub const NO_OUTPUTS: [LowLevelILRegister<A::Register>; 0] = [];

    pub fn expression<'a, E: LiftableLowLevelIL<'a, A>>(
        &'a self,
        expr: E,
    ) -> LowLevelILExpression<'a, A, Mutable, NonSSA<LiftedNonSSA>, E::Result> {
        E::lift(self, expr)
    }

    pub fn add_instruction<'a, E: LiftableLowLevelIL<'a, A>>(&'a self, expr: E) {
        let expr = self.expression(expr);

        unsafe {
            use binaryninjacore_sys::BNLowLevelILAddInstruction;
            BNLowLevelILAddInstruction(self.handle, expr.index.0);
        }
    }

    pub unsafe fn replace_expression<'a, E: LiftableLowLevelIL<'a, A>>(
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

    pub fn const_int(
        &self,
        size: usize,
        val: u64,
    ) -> LowLevelILExpression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
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
    ) -> LowLevelILExpression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CONST_PTR;

        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_CONST_PTR, size, 0, val, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn const_ptr(
        &self,
        val: u64,
    ) -> LowLevelILExpression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        self.const_ptr_sized(self.arch().address_size(), val)
    }

    pub fn trap(
        &self,
        val: u64,
    ) -> LowLevelILExpression<A, Mutable, NonSSA<LiftedNonSSA>, VoidExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_TRAP;

        let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, LLIL_TRAP, 0, 0, val, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    no_arg_lifter!(unimplemented, LLIL_UNIMPL, ValueExpr);
    no_arg_lifter!(undefined, LLIL_UNDEF, VoidExpr);
    no_arg_lifter!(nop, LLIL_NOP, VoidExpr);

    no_arg_lifter!(no_ret, LLIL_NORET, VoidExpr);
    no_arg_lifter!(syscall, LLIL_SYSCALL, VoidExpr);
    no_arg_lifter!(bp, LLIL_BP, VoidExpr);

    unsized_unary_op_lifter!(call, LLIL_CALL, VoidExpr);
    unsized_unary_op_lifter!(ret, LLIL_RET, VoidExpr);
    unsized_unary_op_lifter!(jump, LLIL_JUMP, VoidExpr);
    // TODO: LLIL_JUMP_TO

    pub fn if_expr<'a: 'b, 'b, C>(
        &'a self,
        cond: C,
        true_label: &'b mut LowLevelILLabel,
        false_label: &'b mut LowLevelILLabel,
    ) -> LowLevelILExpression<'a, A, Mutable, NonSSA<LiftedNonSSA>, VoidExpr>
    where
        C: LiftableLowLevelIL<'b, A, Result = ValueExpr>,
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
    ) -> LowLevelILExpression<'a, A, Mutable, NonSSA<LiftedNonSSA>, VoidExpr> {
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

    pub fn reg<R: Into<LowLevelILRegister<A::Register>>>(
        &self,
        size: usize,
        reg: R,
    ) -> LowLevelILExpression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_REG;

        // TODO verify valid id
        let reg = reg.into().id();

        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_REG, size, 0, reg.0 as u64, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn reg_split<
        H: Into<LowLevelILRegister<A::Register>>,
        L: Into<LowLevelILRegister<A::Register>>,
    >(
        &self,
        size: usize,
        hi_reg: H,
        lo_reg: L,
    ) -> LowLevelILExpression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
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

    pub fn set_reg<'a, R, E>(
        &'a self,
        size: usize,
        dest_reg: R,
        expr: E,
    ) -> ExpressionBuilder<'a, A, VoidExpr>
    where
        R: Into<LowLevelILRegister<A::Register>>,
        E: LiftableLowLevelILWithSize<'a, A>,
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

    pub fn set_reg_split<'a, H, L, E>(
        &'a self,
        size: usize,
        hi_reg: H,
        lo_reg: L,
        expr: E,
    ) -> ExpressionBuilder<'a, A, VoidExpr>
    where
        H: Into<LowLevelILRegister<A::Register>>,
        L: Into<LowLevelILRegister<A::Register>>,
        E: LiftableLowLevelILWithSize<'a, A>,
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
            // TODO: Make these optional?
            flag_write: FlagWriteId(0),
            op1: hi_reg.0 as u64,
            op2: lo_reg.0 as u64,
            op3: expr.index.0 as u64,
            op4: 0,
            _ty: PhantomData,
        }
    }

    pub fn flag(
        &self,
        flag: A::Flag,
    ) -> LowLevelILExpression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLAG;

        // TODO verify valid id
        let expr_idx = unsafe {
            BNLowLevelILAddExpr(self.handle, LLIL_FLAG, 0, 0, flag.id().0 as u64, 0, 0, 0)
        };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn flag_cond(
        &self,
        cond: FlagCondition,
    ) -> LowLevelILExpression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLAG_COND;

        // TODO verify valid id
        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_FLAG_COND, 0, 0, cond as u64, 0, 0, 0) };

        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))
    }

    pub fn flag_group(
        &self,
        group: A::FlagGroup,
    ) -> LowLevelILExpression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
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
        dest_flag: A::Flag,
        expr: E,
    ) -> ExpressionBuilder<'a, A, VoidExpr>
    where
        E: LiftableLowLevelILWithSize<'a, A>,
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

    pub fn load<'a, E>(&'a self, size: usize, source_mem: E) -> ExpressionBuilder<'a, A, ValueExpr>
    where
        E: LiftableLowLevelIL<'a, A, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_LOAD;

        let expr = E::lift(self, source_mem);

        ExpressionBuilder {
            function: self,
            op: LLIL_LOAD,
            size,
            flag_write: FlagWriteId(0),
            op1: expr.index.0 as u64,
            op2: 0,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    pub fn store<'a, D, V>(
        &'a self,
        size: usize,
        dest_mem: D,
        value: V,
    ) -> ExpressionBuilder<'a, A, VoidExpr>
    where
        D: LiftableLowLevelIL<'a, A, Result = ValueExpr>,
        V: LiftableLowLevelILWithSize<'a, A>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_STORE;

        let dest_mem = D::lift(self, dest_mem);
        let value = V::lift_with_size(self, value, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_STORE,
            size,
            flag_write: FlagWriteId(0),
            op1: dest_mem.index.0 as u64,
            op2: value.index.0 as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    pub fn intrinsic<'a, O, OL, I, P, PL>(
        &'a self,
        outputs: OL,
        intrinsic: I,
        inputs: PL,
    ) -> ExpressionBuilder<'a, A, VoidExpr>
    where
        O: Into<LowLevelILRegister<A::Register>>,
        OL: IntoIterator<Item = O>,
        I: Into<A::Intrinsic>,
        P: LiftableLowLevelIL<'a, A, Result = ValueExpr>,
        PL: IntoIterator<Item = P>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::{LLIL_CALL_PARAM, LLIL_INTRINSIC};
        use binaryninjacore_sys::{BNLowLevelILAddExpr, BNLowLevelILAddOperandList};

        let mut outputs: Vec<u64> = outputs
            .into_iter()
            .map(|output| output.into().id().0 as u64)
            .collect();
        let output_expr_idx =
            unsafe { BNLowLevelILAddOperandList(self.handle, outputs.as_mut_ptr(), outputs.len()) };

        let intrinsic: A::Intrinsic = intrinsic.into();

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

    sized_unary_op_lifter!(push, LLIL_PUSH, VoidExpr);
    sized_no_arg_lifter!(pop, LLIL_POP, ValueExpr);

    size_changing_unary_op_lifter!(unimplemented_mem, LLIL_UNIMPL_MEM, ValueExpr);

    sized_unary_op_lifter!(neg, LLIL_NEG, ValueExpr);
    sized_unary_op_lifter!(not, LLIL_NOT, ValueExpr);

    size_changing_unary_op_lifter!(sx, LLIL_SX, ValueExpr);
    size_changing_unary_op_lifter!(zx, LLIL_ZX, ValueExpr);
    size_changing_unary_op_lifter!(low_part, LLIL_LOW_PART, ValueExpr);

    binary_op_lifter!(add, LLIL_ADD);
    binary_op_lifter!(add_overflow, LLIL_ADD_OVERFLOW);
    binary_op_lifter!(sub, LLIL_SUB);
    binary_op_lifter!(and, LLIL_AND);
    binary_op_lifter!(or, LLIL_OR);
    binary_op_lifter!(xor, LLIL_XOR);
    binary_op_lifter!(lsl, LLIL_LSL);
    binary_op_lifter!(lsr, LLIL_LSR);
    binary_op_lifter!(asr, LLIL_ASR);

    binary_op_lifter!(rol, LLIL_ROL);
    binary_op_lifter!(rlc, LLIL_RLC);
    binary_op_lifter!(ror, LLIL_ROR);
    binary_op_lifter!(rrc, LLIL_RRC);
    binary_op_lifter!(mul, LLIL_MUL);
    binary_op_lifter!(muls_dp, LLIL_MULS_DP);
    binary_op_lifter!(mulu_dp, LLIL_MULU_DP);
    binary_op_lifter!(divs, LLIL_DIVS);
    binary_op_lifter!(divu, LLIL_DIVU);
    binary_op_lifter!(mods, LLIL_MODS);
    binary_op_lifter!(modu, LLIL_MODU);

    binary_op_carry_lifter!(adc, LLIL_ADC);
    binary_op_carry_lifter!(sbb, LLIL_SBB);

    /*
    DivsDp(usize, Expr, Expr, Expr, Option<A::FlagWrite>),
    DivuDp(usize, Expr, Expr, Expr, Option<A::FlagWrite>),
    ModsDp(usize, Expr, Expr, Expr, Option<A::FlagWrite>),
    ModuDp(usize, Expr, Expr, Expr, Option<A::FlagWrite>),
    */

    // FlagCond(u32), // TODO

    binary_op_lifter!(cmp_e, LLIL_CMP_E);
    binary_op_lifter!(cmp_ne, LLIL_CMP_NE);
    binary_op_lifter!(cmp_slt, LLIL_CMP_SLT);
    binary_op_lifter!(cmp_ult, LLIL_CMP_ULT);
    binary_op_lifter!(cmp_sle, LLIL_CMP_SLE);
    binary_op_lifter!(cmp_ule, LLIL_CMP_ULE);
    binary_op_lifter!(cmp_sge, LLIL_CMP_SGE);
    binary_op_lifter!(cmp_uge, LLIL_CMP_UGE);
    binary_op_lifter!(cmp_sgt, LLIL_CMP_SGT);
    binary_op_lifter!(cmp_ugt, LLIL_CMP_UGT);
    binary_op_lifter!(test_bit, LLIL_TEST_BIT);

    // TODO no flags
    size_changing_unary_op_lifter!(bool_to_int, LLIL_BOOL_TO_INT, ValueExpr);

    binary_op_lifter!(fadd, LLIL_FADD);
    binary_op_lifter!(fsub, LLIL_FSUB);
    binary_op_lifter!(fmul, LLIL_FMUL);
    binary_op_lifter!(fdiv, LLIL_FDIV);
    sized_unary_op_lifter!(fsqrt, LLIL_FSQRT, ValueExpr);
    sized_unary_op_lifter!(fneg, LLIL_FNEG, ValueExpr);
    sized_unary_op_lifter!(fabs, LLIL_FABS, ValueExpr);
    sized_unary_op_lifter!(float_to_int, LLIL_FLOAT_TO_INT, ValueExpr);
    sized_unary_op_lifter!(int_to_float, LLIL_INT_TO_FLOAT, ValueExpr);
    sized_unary_op_lifter!(float_conv, LLIL_FLOAT_CONV, ValueExpr);
    sized_unary_op_lifter!(round_to_int, LLIL_ROUND_TO_INT, ValueExpr);
    sized_unary_op_lifter!(floor, LLIL_FLOOR, ValueExpr);
    sized_unary_op_lifter!(ceil, LLIL_CEIL, ValueExpr);
    sized_unary_op_lifter!(ftrunc, LLIL_FTRUNC, ValueExpr);
    binary_op_lifter!(fcmp_e, LLIL_FCMP_E);
    binary_op_lifter!(fcmp_ne, LLIL_FCMP_NE);
    binary_op_lifter!(fcmp_lt, LLIL_FCMP_LT);
    binary_op_lifter!(fcmp_le, LLIL_FCMP_LE);
    binary_op_lifter!(fcmp_ge, LLIL_FCMP_GE);
    binary_op_lifter!(fcmp_gt, LLIL_FCMP_GT);
    binary_op_lifter!(fcmp_o, LLIL_FCMP_O);
    binary_op_lifter!(fcmp_uo, LLIL_FCMP_UO);

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
