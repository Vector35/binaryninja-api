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

use std::marker::PhantomData;
use std::{mem, ptr};

use crate::architecture::Register as ArchReg;
use crate::architecture::{Architecture, InstructionContext};
use crate::architecture::{Flag, FlagClass, FlagCondition, FlagGroup, FlagRole, FlagWrite};
use crate::basicblock::{BasicBlock, BlockContext};
use crate::rc::Ref;

use super::*;

pub trait Liftable<'func, A: 'func + Architecture> {
    type Result: ExpressionResultType;

    fn lift(
        il: &'func Function<A, Mutable, NonSSA<LiftedNonSSA>>,
        expr: Self,
    ) -> Expression<'func, A, Mutable, NonSSA<LiftedNonSSA>, Self::Result>;
}

pub trait LiftableWithSize<'func, A: 'func + Architecture>:
    Liftable<'func, A, Result = ValueExpr>
{
    fn lift_with_size(
        il: &'func Function<A, Mutable, NonSSA<LiftedNonSSA>>,
        expr: Self,
        size: usize,
    ) -> Expression<'func, A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr>;
}

use binaryninjacore_sys::BNRegisterOrConstant;

#[derive(Copy, Clone)]
pub enum RegisterOrConstant<R: ArchReg> {
    Register(usize, Register<R>),
    Constant(usize, u64),
}

impl<R: ArchReg> RegisterOrConstant<R> {
    pub(crate) fn into_api(self) -> BNRegisterOrConstant {
        match self {
            RegisterOrConstant::Register(_, r) => BNRegisterOrConstant {
                constant: false,
                reg: r.id(),
                value: 0,
            },
            RegisterOrConstant::Constant(_, value) => BNRegisterOrConstant {
                constant: true,
                reg: 0,
                value: value,
            },
        }
    }
}

// TODO flesh way out
#[derive(Copy, Clone)]
pub enum FlagWriteOp<R: ArchReg> {
    SetReg(usize, RegisterOrConstant<R>),
    SetRegSplit(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),

    Sub(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Add(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),

    Load(usize, RegisterOrConstant<R>),

    Push(usize, RegisterOrConstant<R>),
    Neg(usize, RegisterOrConstant<R>),
    Not(usize, RegisterOrConstant<R>),
    Sx(usize, RegisterOrConstant<R>),
    Zx(usize, RegisterOrConstant<R>),
    LowPart(usize, RegisterOrConstant<R>),
    BoolToInt(usize, RegisterOrConstant<R>),
    FloatToInt(usize, RegisterOrConstant<R>),

    Store(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),

    And(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Or(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Xor(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Lsl(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Lsr(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Asr(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Rol(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Ror(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Mul(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    MuluDp(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    MulsDp(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Divu(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Divs(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Modu(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    Mods(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    DivuDp(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    DivsDp(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    ModuDp(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    ModsDp(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),

    TestBit(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),
    AddOverflow(usize, RegisterOrConstant<R>, RegisterOrConstant<R>),

    Adc(
        usize,
        RegisterOrConstant<R>,
        RegisterOrConstant<R>,
        RegisterOrConstant<R>,
    ),
    Sbb(
        usize,
        RegisterOrConstant<R>,
        RegisterOrConstant<R>,
        RegisterOrConstant<R>,
    ),
    Rlc(
        usize,
        RegisterOrConstant<R>,
        RegisterOrConstant<R>,
        RegisterOrConstant<R>,
    ),
    Rrc(
        usize,
        RegisterOrConstant<R>,
        RegisterOrConstant<R>,
        RegisterOrConstant<R>,
    ),

    Pop(usize),
    // TODO: floating point stuff, llil comparison ops that set flags, intrinsics
}

impl<R: ArchReg> FlagWriteOp<R> {
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
        use self::FlagWriteOp::*;
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        fn build_op<A, R>(
            arch: &A,
            size: usize,
            operand: &BNRegisterOrConstant,
        ) -> RegisterOrConstant<R>
        where
            A: Architecture<Register = R>,
            R: ArchReg<InfoType = A::RegisterInfo>,
        {
            if operand.constant {
                RegisterOrConstant::Constant(size, operand.value)
            } else {
                let il_reg = if 0x8000_0000 & operand.reg == 0 {
                    Register::ArchReg(arch.register_from_id(operand.reg).unwrap())
                } else {
                    Register::Temp(operand.reg)
                };

                RegisterOrConstant::Register(size, il_reg)
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
        use self::FlagWriteOp::*;
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

    pub(crate) fn api_operands(&self) -> (usize, [BNRegisterOrConstant; 5]) {
        use self::FlagWriteOp::*;

        let mut operands: [BNRegisterOrConstant; 5] = unsafe { mem::zeroed() };

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
                operands[0] = op0.into_api();
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
                operands[0] = op0.into_api();
                operands[1] = op1.into_api();
                2
            }

            Adc(_, op0, op1, op2)
            | Sbb(_, op0, op1, op2)
            | Rlc(_, op0, op1, op2)
            | Rrc(_, op0, op1, op2) => {
                operands[0] = op0.into_api();
                operands[1] = op1.into_api();
                operands[2] = op2.into_api();
                3
            }
        };

        (count, operands)
    }
}

pub fn get_default_flag_write_llil<'func, A>(
    arch: &A,
    role: FlagRole,
    op: FlagWriteOp<A::Register>,
    il: &'func Lifter<A>,
) -> LiftedExpr<'func, A>
where
    A: 'func + Architecture,
{
    let (size, operation) = op.size_and_op();
    let (count, operands) = op.api_operands();

    let expr_idx = unsafe {
        use binaryninjacore_sys::BNGetDefaultArchitectureFlagWriteLowLevelIL;
        BNGetDefaultArchitectureFlagWriteLowLevelIL(
            arch.as_ref().0,
            operation,
            size,
            role,
            operands.as_ptr() as *mut _,
            count,
            il.handle,
        )
    };

    Expression {
        function: il,
        expr_idx: expr_idx,
        _ty: PhantomData,
    }
}

pub fn get_default_flag_cond_llil<'func, A>(
    arch: &A,
    cond: FlagCondition,
    class: Option<A::FlagClass>,
    il: &'func Lifter<A>,
) -> LiftedExpr<'func, A>
where
    A: 'func + Architecture,
{
    use binaryninjacore_sys::BNGetDefaultArchitectureFlagConditionLowLevelIL;

    let handle = arch.as_ref();
    let class_id = class.map(|c| c.id()).unwrap_or(0);

    unsafe {
        let expr_idx =
            BNGetDefaultArchitectureFlagConditionLowLevelIL(handle.0, cond, class_id, il.handle);

        Expression {
            function: il,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }
}

pub fn get_default_block_llil<A, C: BlockContext>(
    arch: &A,
    block: BasicBlock<C>,
    ctxt: Option<&mut InstructionContext>,
    il: &mut Lifter<A>,
) -> bool
where
    A: Architecture,
{
    use binaryninjacore_sys::BNGetDefaultArchitectureBlockLowLevelIL;

    let handle = arch.as_ref();
    let ctxt_ptr = ctxt.map_or(ptr::null_mut(), |c| &mut c.0 as *mut _);

    unsafe { BNGetDefaultArchitectureBlockLowLevelIL(handle.0, block.handle, ctxt_ptr, il.handle) }
}

pub fn get_default_function_llil<A, C: BlockContext>(
    arch: &A,
    func: Ref<crate::function::Function>,
    blocks: Vec<BasicBlock<C>>,
    ctxt: Option<&mut InstructionContext>,
    il: &mut Lifter<A>,
) -> bool
where
    A: Architecture,
{
    use binaryninjacore_sys::BNGetDefaultArchitectureFunctionLowLevelIL;

    let handle = arch.as_ref();
    let mut blocks = blocks
        .into_iter()
        .map(|block| block.handle)
        .collect::<Vec<_>>();
    let ctxt_ptr = ctxt.map_or(ptr::null_mut(), |c| &mut c.0 as *mut _);

    unsafe {
        BNGetDefaultArchitectureFunctionLowLevelIL(
            handle.0,
            func.handle,
            blocks.as_mut_ptr(),
            blocks.len(),
            ctxt_ptr,
            il.handle,
        )
    }
}

macro_rules! prim_int_lifter {
    ($x:ty) => {
        impl<'a, A: 'a + Architecture> Liftable<'a, A> for $x {
            type Result = ValueExpr;

            fn lift(il: &'a Function<A, Mutable, NonSSA<LiftedNonSSA>>, val: Self)
                -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, Self::Result>
            {
                il.const_int(mem::size_of::<Self>(), val as i64 as u64)
            }
        }

        impl<'a, A: 'a + Architecture> LiftableWithSize<'a, A> for $x {
            fn lift_with_size(il: &'a Function<A, Mutable, NonSSA<LiftedNonSSA>>, val: Self, size: usize)
                -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr>
            {
                let raw = val as i64;

                #[cfg(debug_assertions)]
                {
                    let is_safe = match raw.overflowing_shr(size as u32 * 8) {
                        (_, true) => true,
                        (res, false) => [-1, 0].contains(&res),
                    };

                    if !is_safe {
                        error!("il @ {:x} attempted to lift constant 0x{:x} as {} byte expr (won't fit!)",
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

impl<'a, R: ArchReg, A: 'a + Architecture> Liftable<'a, A> for Register<R>
where
    R: Liftable<'a, A, Result = ValueExpr> + Into<Register<R>>,
{
    type Result = ValueExpr;

    fn lift(
        il: &'a Function<A, Mutable, NonSSA<LiftedNonSSA>>,
        reg: Self,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, Self::Result> {
        match reg {
            Register::ArchReg(r) => R::lift(il, r),
            Register::Temp(t) => il.reg(il.arch().default_integer_size(), Register::Temp(t)),
        }
    }
}

impl<'a, R: ArchReg, A: 'a + Architecture> LiftableWithSize<'a, A> for Register<R>
where
    R: LiftableWithSize<'a, A> + Into<Register<R>>,
{
    fn lift_with_size(
        il: &'a Function<A, Mutable, NonSSA<LiftedNonSSA>>,
        reg: Self,
        size: usize,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        match reg {
            Register::ArchReg(r) => R::lift_with_size(il, r, size),
            Register::Temp(t) => il.reg(size, Register::Temp(t)),
        }
    }
}

impl<'a, R: ArchReg, A: 'a + Architecture> Liftable<'a, A> for RegisterOrConstant<R>
where
    R: LiftableWithSize<'a, A, Result = ValueExpr> + Into<Register<R>>,
{
    type Result = ValueExpr;

    fn lift(
        il: &'a Function<A, Mutable, NonSSA<LiftedNonSSA>>,
        reg: Self,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, Self::Result> {
        match reg {
            RegisterOrConstant::Register(size, r) => Register::<R>::lift_with_size(il, r, size),
            RegisterOrConstant::Constant(size, value) => u64::lift_with_size(il, value, size),
        }
    }
}

impl<'a, R: ArchReg, A: 'a + Architecture> LiftableWithSize<'a, A> for RegisterOrConstant<R>
where
    R: LiftableWithSize<'a, A> + Into<Register<R>>,
{
    fn lift_with_size(
        il: &'a Function<A, Mutable, NonSSA<LiftedNonSSA>>,
        reg: Self,
        size: usize,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        // TODO ensure requested size is compatible with size of this constant
        match reg {
            RegisterOrConstant::Register(_, r) => Register::<R>::lift_with_size(il, r, size),
            RegisterOrConstant::Constant(_, value) => u64::lift_with_size(il, value, size),
        }
    }
}

impl<'a, A, R> Liftable<'a, A> for Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, R>
where
    A: 'a + Architecture,
    R: ExpressionResultType,
{
    type Result = R;

    fn lift(
        il: &'a Function<A, Mutable, NonSSA<LiftedNonSSA>>,
        expr: Self,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, Self::Result> {
        debug_assert!(expr.function.handle == il.handle);
        expr
    }
}

impl<'a, A: 'a + Architecture> LiftableWithSize<'a, A>
    for Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr>
{
    fn lift_with_size(
        il: &'a Function<A, Mutable, NonSSA<LiftedNonSSA>>,
        expr: Self,
        _size: usize,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, Self::Result> {
        #[cfg(debug_assertions)]
        {
            if let Some(expr_size) = expr.info().size() {
                if expr_size != _size {
                    warn!(
                        "il @ {:x} attempted to lift {} byte expression as {} bytes",
                        il.current_address(),
                        expr_size,
                        _size
                    );
                }
            }
        }

        Liftable::lift(il, expr)
    }
}

impl<'func, A, R> Expression<'func, A, Mutable, NonSSA<LiftedNonSSA>, R>
where
    A: 'func + Architecture,
    R: ExpressionResultType,
{
    pub fn with_source_operand(self, op: u32) -> Self {
        use binaryninjacore_sys::BNLowLevelILSetExprSourceOperand;

        unsafe { BNLowLevelILSetExprSourceOperand(self.function.handle, self.expr_idx, op) }

        self
    }

    pub fn append(self) {
        let il = self.function;
        il.instruction(self);
    }
}

use binaryninjacore_sys::BNLowLevelILOperation;
pub struct ExpressionBuilder<'func, A, R>
where
    A: 'func + Architecture,
    R: ExpressionResultType,
{
    function: &'func Function<A, Mutable, NonSSA<LiftedNonSSA>>,
    op: BNLowLevelILOperation,
    size: usize,
    flags: u32,
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
    pub fn with_flag_write(mut self, flag_write: A::FlagWrite) -> Self {
        // TODO verify valid id
        self.flags = flag_write.id();
        self
    }

    pub fn into_expr(self) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, R> {
        self.into()
    }

    pub fn with_source_operand(
        self,
        op: u32,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, R> {
        let expr = self.into_expr();
        expr.with_source_operand(op)
    }

    pub fn append(self) {
        let expr = self.into_expr();
        let il = expr.function;

        il.instruction(expr);
    }
}

impl<'a, A, R> Into<Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, R>>
    for ExpressionBuilder<'a, A, R>
where
    A: 'a + Architecture,
    R: ExpressionResultType,
{
    fn into(self) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, R> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;

        let expr_idx = unsafe {
            BNLowLevelILAddExpr(
                self.function.handle,
                self.op,
                self.size,
                self.flags,
                self.op1,
                self.op2,
                self.op3,
                self.op4,
            )
        };

        Expression {
            function: self.function,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }
}

impl<'a, A, R> Liftable<'a, A> for ExpressionBuilder<'a, A, R>
where
    A: 'a + Architecture,
    R: ExpressionResultType,
{
    type Result = R;

    fn lift(
        il: &'a Function<A, Mutable, NonSSA<LiftedNonSSA>>,
        expr: Self,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, Self::Result> {
        debug_assert!(expr.function.handle == il.handle);

        expr.into()
    }
}

impl<'a, A> LiftableWithSize<'a, A> for ExpressionBuilder<'a, A, ValueExpr>
where
    A: 'a + Architecture,
{
    fn lift_with_size(
        il: &'a Function<A, Mutable, NonSSA<LiftedNonSSA>>,
        expr: Self,
        _size: usize,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        #[cfg(debug_assertions)]
        {
            use binaryninjacore_sys::BNLowLevelILOperation::{LLIL_UNIMPL, LLIL_UNIMPL_MEM};

            if expr.size != _size && ![LLIL_UNIMPL, LLIL_UNIMPL_MEM].contains(&expr.op) {
                warn!(
                    "il @ {:x} attempted to lift {} byte expression builder as {} bytes",
                    il.current_address(),
                    expr.size,
                    _size
                );
            }
        }

        Liftable::lift(il, expr)
    }
}

macro_rules! no_arg_lifter {
    ($name:ident, $op:ident, $result:ty) => {
        pub fn $name(&self) -> Expression<A, Mutable, NonSSA<LiftedNonSSA>, $result> {
            use binaryninjacore_sys::BNLowLevelILAddExpr;
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, $op, 0, 0, 0, 0, 0, 0) };

            Expression {
                function: self,
                expr_idx: expr_idx,
                _ty: PhantomData,
            }
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
                size: size,
                flags: 0,
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
        ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, $result>
        where
            E: Liftable<'a, A, Result = ValueExpr>,
        {
            use binaryninjacore_sys::BNLowLevelILAddExpr;
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let expr = E::lift(self, expr);

            let expr_idx = unsafe {
                BNLowLevelILAddExpr(self.handle, $op, 0, 0, expr.expr_idx as u64, 0, 0, 0)
            };

            Expression {
                function: self,
                expr_idx: expr_idx,
                _ty: PhantomData,
            }
        }
    };
}

macro_rules! sized_unary_op_lifter {
    ($name:ident, $op:ident, $result:ty) => {
        pub fn $name<'a, E>(&'a self, size: usize, expr: E) -> ExpressionBuilder<'a, A, $result>
        where
            E: LiftableWithSize<'a, A>,
        {
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let expr = E::lift_with_size(self, expr, size);

            ExpressionBuilder {
                function: self,
                op: $op,
                size: size,
                flags: 0,
                op1: expr.expr_idx as u64,
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
            E: LiftableWithSize<'a, A>,
        {
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let expr = E::lift(self, expr);

            ExpressionBuilder {
                function: self,
                op: $op,
                size: size,
                flags: 0,
                op1: expr.expr_idx as u64,
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
            L: LiftableWithSize<'a, A>,
            R: LiftableWithSize<'a, A>,
        {
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let left = L::lift_with_size(self, left, size);
            let right = R::lift_with_size(self, right, size);

            ExpressionBuilder {
                function: self,
                op: $op,
                size: size,
                flags: 0,
                op1: left.expr_idx as u64,
                op2: right.expr_idx as u64,
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
            L: LiftableWithSize<'a, A>,
            R: LiftableWithSize<'a, A>,
            C: LiftableWithSize<'a, A>,
        {
            use binaryninjacore_sys::BNLowLevelILOperation::$op;

            let left = L::lift_with_size(self, left, size);
            let right = R::lift_with_size(self, right, size);
            let carry = C::lift_with_size(self, carry, 1); // TODO 0?

            ExpressionBuilder {
                function: self,
                op: $op,
                size: size,
                flags: 0,
                op1: left.expr_idx as u64,
                op2: right.expr_idx as u64,
                op3: carry.expr_idx as u64,
                op4: 0,
                _ty: PhantomData,
            }
        }
    };
}

impl<A> Function<A, Mutable, NonSSA<LiftedNonSSA>>
where
    A: Architecture,
{
    pub fn expression<'a, E: Liftable<'a, A>>(
        &'a self,
        expr: E,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, E::Result> {
        E::lift(self, expr)
    }

    pub fn instruction<'a, E: Liftable<'a, A>>(&'a self, expr: E) {
        let expr = self.expression(expr);

        unsafe {
            use binaryninjacore_sys::BNLowLevelILAddInstruction;
            BNLowLevelILAddInstruction(self.handle, expr.expr_idx);
        }
    }

    pub unsafe fn replace_expression<'a, E: Liftable<'a, A>>(
        &'a self,
        replaced_expr_index: usize,
        replacement: E,
    ) {
        use binaryninjacore_sys::BNGetLowLevelILExprCount;
        use binaryninjacore_sys::BNReplaceLowLevelILExpr;

        if replaced_expr_index >= BNGetLowLevelILExprCount(self.handle) {
            panic!(
                "bad expr idx used: {} exceeds function bounds",
                replaced_expr_index
            );
        }

        let expr = self.expression(replacement);
        BNReplaceLowLevelILExpr(self.handle, replaced_expr_index, expr.expr_idx);
    }

    pub fn const_int(
        &self,
        size: usize,
        val: u64,
    ) -> Expression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CONST;

        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_CONST, size, 0, val, 0, 0, 0) };

        Expression {
            function: self,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }

    pub fn const_ptr_sized(
        &self,
        size: usize,
        val: u64,
    ) -> Expression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CONST_PTR;

        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_CONST_PTR, size, 0, val, 0, 0, 0) };

        Expression {
            function: self,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }

    pub fn const_ptr(&self, val: u64) -> Expression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        self.const_ptr_sized(self.arch().address_size(), val)
    }

    pub fn trap(&self, val: u64) -> Expression<A, Mutable, NonSSA<LiftedNonSSA>, VoidExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_TRAP;

        let expr_idx = unsafe { BNLowLevelILAddExpr(self.handle, LLIL_TRAP, 0, 0, val, 0, 0, 0) };

        Expression {
            function: self,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
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
    // JumpTo TODO

    pub fn if_expr<'a: 'b, 'b, C>(
        &'a self,
        cond: C,
        t: &'b Label,
        f: &'b Label,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, VoidExpr>
    where
        C: Liftable<'b, A, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILIf;

        let cond = C::lift(self, cond);

        let expr_idx = unsafe {
            BNLowLevelILIf(
                self.handle,
                cond.expr_idx as u64,
                &t.0 as *const _ as *mut _,
                &f.0 as *const _ as *mut _,
            )
        };

        Expression {
            function: self,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }

    pub fn goto<'a: 'b, 'b>(
        &'a self,
        l: &'b Label,
    ) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, VoidExpr> {
        use binaryninjacore_sys::BNLowLevelILGoto;

        let expr_idx = unsafe { BNLowLevelILGoto(self.handle, &l.0 as *const _ as *mut _) };

        Expression {
            function: self,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }

    pub fn reg<R: Into<Register<A::Register>>>(
        &self,
        size: usize,
        reg: R,
    ) -> Expression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_REG;

        // TODO verify valid id
        let reg = match reg.into() {
            Register::ArchReg(r) => r.id(),
            Register::Temp(r) => 0x8000_0000 | r,
        };

        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_REG, size, 0, reg as u64, 0, 0, 0) };

        Expression {
            function: self,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }

    pub fn set_reg<'a, R, E>(
        &'a self,
        size: usize,
        dest_reg: R,
        expr: E,
    ) -> ExpressionBuilder<'a, A, VoidExpr>
    where
        R: Into<Register<A::Register>>,
        E: LiftableWithSize<'a, A>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_SET_REG;

        // TODO verify valid id
        let dest_reg = match dest_reg.into() {
            Register::ArchReg(r) => r.id(),
            Register::Temp(r) => 0x8000_0000 | r,
        };

        let expr = E::lift_with_size(self, expr, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_SET_REG,
            size: size,
            flags: 0,
            op1: dest_reg as u64,
            op2: expr.expr_idx as u64,
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
        H: Into<Register<A::Register>>,
        L: Into<Register<A::Register>>,
        E: LiftableWithSize<'a, A>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_SET_REG_SPLIT;

        // TODO verify valid id
        let hi_reg = match hi_reg.into() {
            Register::ArchReg(r) => r.id(),
            Register::Temp(r) => 0x8000_0000 | r,
        };

        // TODO verify valid id
        let lo_reg = match lo_reg.into() {
            Register::ArchReg(r) => r.id(),
            Register::Temp(r) => 0x8000_0000 | r,
        };

        let expr = E::lift_with_size(self, expr, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_SET_REG_SPLIT,
            size: size,
            flags: 0,
            op1: hi_reg as u64,
            op2: lo_reg as u64,
            op3: expr.expr_idx as u64,
            op4: 0,
            _ty: PhantomData,
        }
    }

    pub fn flag(&self, flag: A::Flag) -> Expression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLAG;

        // TODO verify valid id
        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_FLAG, 0, 0, flag.id() as u64, 0, 0, 0) };

        Expression {
            function: self,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }

    pub fn flag_cond(
        &self,
        cond: FlagCondition,
    ) -> Expression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLAG_COND;

        // TODO verify valid id
        let expr_idx =
            unsafe { BNLowLevelILAddExpr(self.handle, LLIL_FLAG_COND, 0, 0, cond as u64, 0, 0, 0) };

        Expression {
            function: self,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }

    pub fn flag_group(
        &self,
        group: A::FlagGroup,
    ) -> Expression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        use binaryninjacore_sys::BNLowLevelILAddExpr;
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLAG_GROUP;

        // TODO verify valid id
        let expr_idx = unsafe {
            BNLowLevelILAddExpr(
                self.handle,
                LLIL_FLAG_GROUP,
                0,
                0,
                group.id() as u64,
                0,
                0,
                0,
            )
        };

        Expression {
            function: self,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }

    pub fn set_flag<'a, E>(
        &'a self,
        dest_flag: A::Flag,
        expr: E,
    ) -> ExpressionBuilder<'a, A, VoidExpr>
    where
        E: LiftableWithSize<'a, A>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_SET_FLAG;

        // TODO verify valid id

        let expr = E::lift_with_size(self, expr, 0);

        ExpressionBuilder {
            function: self,
            op: LLIL_SET_FLAG,
            size: 0,
            flags: 0,
            op1: dest_flag.id() as u64,
            op2: expr.expr_idx as u64,
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
        E: Liftable<'a, A, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_LOAD;

        let expr = E::lift(self, source_mem);

        ExpressionBuilder {
            function: self,
            op: LLIL_LOAD,
            size: size,
            flags: 0,
            op1: expr.expr_idx as u64,
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
        D: Liftable<'a, A, Result = ValueExpr>,
        V: LiftableWithSize<'a, A>,
    {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_STORE;

        let dest_mem = D::lift(self, dest_mem);
        let value = V::lift_with_size(self, value, size);

        ExpressionBuilder {
            function: self,
            op: LLIL_STORE,
            size: size,
            flags: 0,
            op1: dest_mem.expr_idx as u64,
            op2: value.expr_idx as u64,
            op3: 0,
            op4: 0,
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

    pub fn current_address(&self) -> u64 {
        use binaryninjacore_sys::BNLowLevelILGetCurrentAddress;
        unsafe { BNLowLevelILGetCurrentAddress(self.handle) }
    }

    pub fn set_current_address<L: Into<Location>>(&self, loc: L) {
        use binaryninjacore_sys::BNLowLevelILSetCurrentAddress;

        let loc: Location = loc.into();
        let arch = loc.arch.unwrap_or_else(|| *self.arch().as_ref());

        unsafe {
            BNLowLevelILSetCurrentAddress(self.handle, arch.0, loc.addr);
        }
    }

    pub fn label_for_address<L: Into<Location>>(&self, loc: L) -> Option<&Label> {
        use binaryninjacore_sys::BNGetLowLevelILLabelForAddress;

        let loc: Location = loc.into();
        let arch = loc.arch.unwrap_or_else(|| *self.arch().as_ref());

        let res = unsafe { BNGetLowLevelILLabelForAddress(self.handle, arch.0, loc.addr) };

        if res.is_null() {
            None
        } else {
            Some(unsafe { &*(res as *mut Label) })
        }
    }

    pub fn mark_label(&self, label: &mut Label) {
        use binaryninjacore_sys::BNLowLevelILMarkLabel;

        unsafe {
            BNLowLevelILMarkLabel(self.handle, &mut label.0 as *mut _);
        }
    }
}

use binaryninjacore_sys::BNLowLevelILLabel;

#[repr(C)]
pub struct Label(BNLowLevelILLabel);
impl Label {
    pub fn new() -> Self {
        use binaryninjacore_sys::BNLowLevelILInitLabel;

        unsafe {
            // This is one instance where it'd be easy to use mem::MaybeUninit, but *shrug* this is easier
            let mut res = Label(mem::zeroed());
            BNLowLevelILInitLabel(&mut res.0 as *mut _);
            res
        }
    }
}
