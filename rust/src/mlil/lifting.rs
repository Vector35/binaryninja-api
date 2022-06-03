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
use std::mem;

use crate::architecture::Architecture;
use crate::architecture::Register as ArchReg;

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
            Register::Temp(t) => todo!(),
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
            Register::Temp(t) => todo!(),
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

use binaryninjacore_sys::BNMediumLevelILOperation;

pub struct ExpressionBuilder<'func, A, R>
where
    A: 'func + Architecture,
    R: ExpressionResultType,
{
    function: &'func Function<A, Mutable, NonSSA<LiftedNonSSA>>,
    op: BNMediumLevelILOperation,
    size: usize,
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
    pub fn into_expr(self) -> Expression<'a, A, Mutable, NonSSA<LiftedNonSSA>, R> {
        self.into()
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
        use binaryninjacore_sys::BNMediumLevelILAddExpr;

        let expr_idx = unsafe {
            BNMediumLevelILAddExpr(
                self.function.handle,
                self.op,
                self.size,
                self.op1,
                self.op2,
                self.op3,
                self.op4,
                0,
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
            use binaryninjacore_sys::BNMediumLevelILOperation::{MLIL_UNIMPL, MLIL_UNIMPL_MEM};

            if expr.size != _size && ![MLIL_UNIMPL, MLIL_UNIMPL_MEM].contains(&expr.op) {
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
            use binaryninjacore_sys::BNMediumLevelILAddExpr;
            use binaryninjacore_sys::BNMediumLevelILOperation::$op;

            let expr_idx = unsafe { BNMediumLevelILAddExpr(self.handle, $op, 0, 0, 0, 0, 0, 0) };

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
            use binaryninjacore_sys::BNMediumLevelILOperation::$op;

            ExpressionBuilder {
                function: self,
                op: $op,
                size: size,
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
            use binaryninjacore_sys::BNMediumLevelILAddExpr;
            use binaryninjacore_sys::BNMediumLevelILOperation::$op;

            let expr = E::lift(self, expr);

            let expr_idx = unsafe {
                BNMediumLevelILAddExpr(self.handle, $op, 0, 0, expr.expr_idx as u64, 0, 0, 0)
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
            use binaryninjacore_sys::BNMediumLevelILOperation::$op;

            let expr = E::lift_with_size(self, expr, size);

            ExpressionBuilder {
                function: self,
                op: $op,
                size: size,
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
            use binaryninjacore_sys::BNMediumLevelILOperation::$op;

            let expr = E::lift(self, expr);

            ExpressionBuilder {
                function: self,
                op: $op,
                size: size,
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
            use binaryninjacore_sys::BNMediumLevelILOperation::$op;

            let left = L::lift_with_size(self, left, size);
            let right = R::lift_with_size(self, right, size);

            ExpressionBuilder {
                function: self,
                op: $op,
                size: size,
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
            use binaryninjacore_sys::BNMediumLevelILOperation::$op;

            let left = L::lift_with_size(self, left, size);
            let right = R::lift_with_size(self, right, size);
            let carry = C::lift_with_size(self, carry, 1); // TODO 0?

            ExpressionBuilder {
                function: self,
                op: $op,
                size: size,
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
            use binaryninjacore_sys::BNMediumLevelILAddInstruction;
            BNMediumLevelILAddInstruction(self.handle, expr.expr_idx);
        }
    }

    pub unsafe fn replace_expression<'a, E: Liftable<'a, A>>(
        &'a self,
        replaced_expr_index: usize,
        replacement: E,
    ) {
        use binaryninjacore_sys::BNGetMediumLevelILExprCount;
        use binaryninjacore_sys::BNReplaceMediumLevelILExpr;

        if replaced_expr_index >= BNGetMediumLevelILExprCount(self.handle) {
            panic!(
                "bad expr idx used: {} exceeds function bounds",
                replaced_expr_index
            );
        }

        let expr = self.expression(replacement);
        BNReplaceMediumLevelILExpr(self.handle, replaced_expr_index, expr.expr_idx);
    }

    pub fn const_int(
        &self,
        size: usize,
        val: u64,
    ) -> Expression<A, Mutable, NonSSA<LiftedNonSSA>, ValueExpr> {
        use binaryninjacore_sys::BNMediumLevelILAddExpr;
        use binaryninjacore_sys::BNMediumLevelILOperation::MLIL_CONST;

        let expr_idx =
            unsafe { BNMediumLevelILAddExpr(self.handle, MLIL_CONST, size, 0, val, 0, 0, 0) };

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
        use binaryninjacore_sys::BNMediumLevelILAddExpr;
        use binaryninjacore_sys::BNMediumLevelILOperation::MLIL_CONST_PTR;

        let expr_idx =
            unsafe { BNMediumLevelILAddExpr(self.handle, MLIL_CONST_PTR, size, 0, val, 0, 0, 0) };

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
        use binaryninjacore_sys::BNMediumLevelILAddExpr;
        use binaryninjacore_sys::BNMediumLevelILOperation::MLIL_TRAP;

        let expr_idx =
            unsafe { BNMediumLevelILAddExpr(self.handle, MLIL_TRAP, 0, 0, val, 0, 0, 0) };

        Expression {
            function: self,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }

    no_arg_lifter!(unimplemented, MLIL_UNIMPL, ValueExpr);
    no_arg_lifter!(undefined, MLIL_UNDEF, VoidExpr);
    no_arg_lifter!(nop, MLIL_NOP, VoidExpr);

    no_arg_lifter!(no_ret, MLIL_NORET, VoidExpr);
    no_arg_lifter!(syscall, MLIL_SYSCALL, VoidExpr);
    no_arg_lifter!(bp, MLIL_BP, VoidExpr);

    unsized_unary_op_lifter!(call, MLIL_CALL, VoidExpr);
    unsized_unary_op_lifter!(ret, MLIL_RET, VoidExpr);
    unsized_unary_op_lifter!(jump, MLIL_JUMP, VoidExpr);
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
        use binaryninjacore_sys::BNMediumLevelILIf;

        let cond = C::lift(self, cond);

        let expr_idx = unsafe {
            BNMediumLevelILIf(
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
        use binaryninjacore_sys::BNMediumLevelILGoto;

        let expr_idx = unsafe { BNMediumLevelILGoto(self.handle, &l.0 as *const _ as *mut _) };

        Expression {
            function: self,
            expr_idx: expr_idx,
            _ty: PhantomData,
        }
    }

    pub fn load<'a, E>(&'a self, size: usize, source_mem: E) -> ExpressionBuilder<'a, A, ValueExpr>
    where
        E: Liftable<'a, A, Result = ValueExpr>,
    {
        use binaryninjacore_sys::BNMediumLevelILOperation::MLIL_LOAD;

        let expr = E::lift(self, source_mem);

        ExpressionBuilder {
            function: self,
            op: MLIL_LOAD,
            size: size,
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
        use binaryninjacore_sys::BNMediumLevelILOperation::MLIL_STORE;

        let dest_mem = D::lift(self, dest_mem);
        let value = V::lift_with_size(self, value, size);

        ExpressionBuilder {
            function: self,
            op: MLIL_STORE,
            size: size,
            op1: dest_mem.expr_idx as u64,
            op2: value.expr_idx as u64,
            op3: 0,
            op4: 0,
            _ty: PhantomData,
        }
    }

    size_changing_unary_op_lifter!(unimplemented_mem, MLIL_UNIMPL_MEM, ValueExpr);

    sized_unary_op_lifter!(neg, MLIL_NEG, ValueExpr);
    sized_unary_op_lifter!(not, MLIL_NOT, ValueExpr);

    size_changing_unary_op_lifter!(sx, MLIL_SX, ValueExpr);
    size_changing_unary_op_lifter!(zx, MLIL_ZX, ValueExpr);
    size_changing_unary_op_lifter!(low_part, MLIL_LOW_PART, ValueExpr);

    binary_op_lifter!(add, MLIL_ADD);
    binary_op_lifter!(add_overflow, MLIL_ADD_OVERFLOW);
    binary_op_lifter!(sub, MLIL_SUB);
    binary_op_lifter!(and, MLIL_AND);
    binary_op_lifter!(or, MLIL_OR);
    binary_op_lifter!(xor, MLIL_XOR);
    binary_op_lifter!(lsl, MLIL_LSL);
    binary_op_lifter!(lsr, MLIL_LSR);
    binary_op_lifter!(asr, MLIL_ASR);

    binary_op_lifter!(rol, MLIL_ROL);
    binary_op_lifter!(rlc, MLIL_RLC);
    binary_op_lifter!(ror, MLIL_ROR);
    binary_op_lifter!(rrc, MLIL_RRC);
    binary_op_lifter!(mul, MLIL_MUL);
    binary_op_lifter!(muls_dp, MLIL_MULS_DP);
    binary_op_lifter!(mulu_dp, MLIL_MULU_DP);
    binary_op_lifter!(divs, MLIL_DIVS);
    binary_op_lifter!(divu, MLIL_DIVU);
    binary_op_lifter!(mods, MLIL_MODS);
    binary_op_lifter!(modu, MLIL_MODU);

    binary_op_carry_lifter!(adc, MLIL_ADC);
    binary_op_carry_lifter!(sbb, MLIL_SBB);

    binary_op_lifter!(cmp_e, MLIL_CMP_E);
    binary_op_lifter!(cmp_ne, MLIL_CMP_NE);
    binary_op_lifter!(cmp_slt, MLIL_CMP_SLT);
    binary_op_lifter!(cmp_ult, MLIL_CMP_ULT);
    binary_op_lifter!(cmp_sle, MLIL_CMP_SLE);
    binary_op_lifter!(cmp_ule, MLIL_CMP_ULE);
    binary_op_lifter!(cmp_sge, MLIL_CMP_SGE);
    binary_op_lifter!(cmp_uge, MLIL_CMP_UGE);
    binary_op_lifter!(cmp_sgt, MLIL_CMP_SGT);
    binary_op_lifter!(cmp_ugt, MLIL_CMP_UGT);
    binary_op_lifter!(test_bit, MLIL_TEST_BIT);

    size_changing_unary_op_lifter!(bool_to_int, MLIL_BOOL_TO_INT, ValueExpr);

    pub fn current_address(&self) -> u64 {
        use binaryninjacore_sys::BNMediumLevelILGetCurrentAddress;
        unsafe { BNMediumLevelILGetCurrentAddress(self.handle) }
    }

    pub fn set_current_address<L: Into<Location>>(&self, loc: L) {
        use binaryninjacore_sys::BNMediumLevelILSetCurrentAddress;

        let loc: Location = loc.into();
        let arch = loc.arch.unwrap_or_else(|| *self.arch().as_ref());

        unsafe {
            BNMediumLevelILSetCurrentAddress(self.handle, arch.0, loc.addr);
        }
    }

    pub fn mark_label(&self, label: &mut Label) {
        use binaryninjacore_sys::BNMediumLevelILMarkLabel;

        unsafe {
            BNMediumLevelILMarkLabel(self.handle, &mut label.0 as *mut _);
        }
    }
}

use binaryninjacore_sys::BNMediumLevelILLabel;

#[repr(C)]
pub struct Label(BNMediumLevelILLabel);

impl Label {
    pub fn new() -> Self {
        use binaryninjacore_sys::BNMediumLevelILInitLabel;

        unsafe {
            // This is one instance where it'd be easy to use mem::MaybeUninit, but *shrug* this is easier
            let mut res = Label(mem::zeroed());
            BNMediumLevelILInitLabel(&mut res.0 as *mut _);
            res
        }
    }
}
