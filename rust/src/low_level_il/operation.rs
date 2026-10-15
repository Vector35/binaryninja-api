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

use binaryninjacore_sys::{
    BNGetCachedLowLevelILPossibleValueSet, BNLowLevelILFreeOperandList, BNLowLevelILGetOperandList,
    BNLowLevelILInstruction,
};

use super::*;
use crate::architecture::{CoreArchitecture, CoreFlagClass, FlagClassId, FlagCondition};
use crate::architecture::{
    CoreFlag, CoreFlagGroup, CoreFlagWrite, CoreIntrinsic, CoreRegister, CoreRegisterStack,
    FlagGroupId, FlagId, FlagWriteId, IntrinsicId, RegisterStackId,
};
use crate::variable::PossibleValueSet;
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::mem;

pub struct Operation<'func, M, F, O>
where
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    pub(crate) function: &'func LowLevelILFunction<M, F>,
    pub(crate) op: BNLowLevelILInstruction,
    pub(crate) expr_idx: LowLevelExpressionIndex,
    _args: PhantomData<O>,
}

impl<'func, M, F, O> Operation<'func, M, F, O>
where
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    pub(crate) fn new(
        function: &'func LowLevelILFunction<M, F>,
        op: BNLowLevelILInstruction,
        expr_idx: LowLevelExpressionIndex,
    ) -> Self {
        Self {
            function,
            op,
            expr_idx,
            _args: PhantomData,
        }
    }

    pub fn address(&self) -> u64 {
        self.op.address
    }

    fn get_operand_list(&self, operand_idx: usize) -> Vec<u64> {
        let mut count = 0;
        let raw_list_ptr = unsafe {
            BNLowLevelILGetOperandList(
                self.function.handle,
                self.expr_idx.0,
                operand_idx,
                &mut count,
            )
        };
        assert!(!raw_list_ptr.is_null());
        let list = unsafe { std::slice::from_raw_parts(raw_list_ptr, count).to_vec() };
        unsafe { BNLowLevelILFreeOperandList(raw_list_ptr) };
        list
    }

    /// Get the raw operand from the operand list.
    ///
    /// This has no type information associated with it. It's up to the caller to know what the correct type of the
    /// underlying u64 should be.
    ///
    /// # Panic
    /// `idx` must be less than 4. This is to protect against an out of bounds access.
    ///
    /// # Safety
    /// Even if `idx` is valid, it may index to an uninitialized or unused value. Make sure you index into an operand that
    /// you know should be initialized properly.
    pub unsafe fn get_operand(&self, idx: usize) -> u64 {
        assert!(idx < 4);
        self.op.operands[idx]
    }
}

impl<M, O> Operation<'_, M, NonSSA, O>
where
    M: FunctionMutability,
    O: OperationArguments,
{
    /// Get the [`CoreFlagWrite`] for the operation.
    ///
    /// NOTE: This is only expected to be present for lifted IL.
    pub fn flag_write(&self) -> Option<CoreFlagWrite> {
        match self.op.flags {
            0 => None,
            id => self.function.arch().flag_write_from_id(FlagWriteId(id)),
        }
    }
}

impl<'func, M, F, O> Operation<'func, M, F, O>
where
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    /// Get operand `sub_operand_idx` of the subexpression at `operand_idx`.
    fn get_sub_operand(&self, operand_idx: usize, sub_operand_idx: usize) -> u64 {
        use binaryninjacore_sys::BNGetLowLevelILByIndex;

        let sub = unsafe {
            BNGetLowLevelILByIndex(self.function.handle, self.op.operands[operand_idx] as usize)
        };
        sub.operands[sub_operand_idx]
    }

    /// Get the operand list at `sub_operand_idx` of the subexpression at `operand_idx`.
    fn get_sub_operand_list(&self, operand_idx: usize, sub_operand_idx: usize) -> Vec<u64> {
        let mut count = 0;
        let raw_list_ptr = unsafe {
            BNLowLevelILGetOperandList(
                self.function.handle,
                self.op.operands[operand_idx] as usize,
                sub_operand_idx,
                &mut count,
            )
        };
        assert!(!raw_list_ptr.is_null());
        let list = unsafe { std::slice::from_raw_parts(raw_list_ptr, count).to_vec() };
        unsafe { BNLowLevelILFreeOperandList(raw_list_ptr) };
        list
    }
}

// LLIL_NOP, LLIL_NORET, LLIL_BP, LLIL_UNDEF, LLIL_UNIMPL
pub struct NoArgs;

impl<M, F> Operation<'_, M, F, NoArgs>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    /// Returns `true` if this is an `LLIL_UNIMPL` for a value that can't be known at analysis time
    /// rather than an unimplemented instruction.
    pub fn unknown(&self) -> bool {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_UNIMPL;
        self.op.operation == LLIL_UNIMPL && self.op.operands[0] != 0
    }
}

impl<M, F> Debug for Operation<'_, M, F, NoArgs>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoArgs").finish()
    }
}

// LLIL_INTRINSIC, LLIL_INTRINSIC_SSA
pub struct Intrinsic;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IntrinsicOutput {
    Reg(CoreRegister),
    Flag(CoreFlag),
}

impl IntrinsicOutput {
    /// Decodes a register or flag id, where bit 32 marks a flag.
    fn from_raw(arch: &CoreArchitecture, raw: u64) -> Self {
        if raw & (1 << 32) != 0 {
            arch.flag_from_id(FlagId((raw & 0xffffffff) as u32))
                .expect("Invalid core flag ID")
                .into()
        } else {
            arch.register_from_id(RegisterId((raw & 0xffffffff) as u32))
                .expect("Invalid register ID")
                .into()
        }
    }
}

impl From<CoreRegister> for IntrinsicOutput {
    fn from(value: CoreRegister) -> Self {
        Self::Reg(value)
    }
}

impl From<CoreFlag> for IntrinsicOutput {
    fn from(value: CoreFlag) -> Self {
        Self::Flag(value)
    }
}

/// An intrinsic output in SSA form.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SSAIntrinsicOutput {
    pub output: IntrinsicOutput,
    pub version: u32,
}

impl<'func, M, F> Operation<'func, M, F, Intrinsic>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn intrinsic(&self) -> Option<CoreIntrinsic> {
        let raw_id = self.op.operands[2] as u32;
        self.function.arch().intrinsic_from_id(IntrinsicId(raw_id))
    }

    /// Get the output list.
    pub fn outputs(&self) -> Vec<IntrinsicOutput> {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_INTRINSIC_SSA;
        let arch = self.function.arch();
        let list = self.get_operand_list(0);
        // In SSA form each output is followed by its version.
        let step = if self.op.operation == LLIL_INTRINSIC_SSA {
            2
        } else {
            1
        };
        list.iter()
            .step_by(step)
            .map(|&raw| IntrinsicOutput::from_raw(&arch, raw))
            .collect()
    }

    /// Get the output list with versions, or `None` if this isn't an `LLIL_INTRINSIC_SSA`.
    pub fn ssa_outputs(&self) -> Option<Vec<SSAIntrinsicOutput>> {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_INTRINSIC_SSA;
        if self.op.operation != LLIL_INTRINSIC_SSA {
            return None;
        }
        let arch = self.function.arch();
        let list = self.get_operand_list(0);
        Some(
            list.as_chunks::<2>()
                .0
                .iter()
                .map(|pair| SSAIntrinsicOutput {
                    output: IntrinsicOutput::from_raw(&arch, pair[0]),
                    version: pair[1] as u32,
                })
                .collect(),
        )
    }

    /// Get the input list for the intrinsic.
    ///
    /// This will just be a CallParamSsa expression.
    #[inline]
    pub fn inputs(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[3] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, Intrinsic>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use crate::architecture::Intrinsic;
        f.debug_struct("Intrinsic")
            .field("address", &self.address())
            .field(
                "intrinsic",
                &self.intrinsic().expect("Valid intrinsic").name(),
            )
            .field("outputs", &self.outputs())
            .field("inputs", &self.inputs())
            .finish()
    }
}

// LLIL_CALL, LLIL_CALL_STACK_ADJUST, LLIL_TAILCALL
pub struct Call;

impl<'func, M, F> Operation<'func, M, F, Call>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn stack_adjust(&self) -> Option<u64> {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CALL_STACK_ADJUST;
        if self.op.operation == LLIL_CALL_STACK_ADJUST {
            Some(self.op.operands[1])
        } else {
            None
        }
    }

    /// Get how far the call moves the top of each register stack, or `None` if this isn't an
    /// `LLIL_CALL_STACK_ADJUST`.
    pub fn register_stack_adjustments(&self) -> Option<HashMap<CoreRegisterStack, i32>> {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_CALL_STACK_ADJUST;
        if self.op.operation != LLIL_CALL_STACK_ADJUST {
            return None;
        }
        let arch = self.function.arch();
        let list = self.get_operand_list(2);
        Some(
            list.as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    let reg_stack = arch
                        .register_stack_from_id(RegisterStackId(pair[0] as u32))
                        .expect("Bad register stack ID");
                    (reg_stack, pair[1] as u32 as i32)
                })
                .collect(),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, Call>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call")
            .field("target", &self.target())
            .field("stack_adjust", &self.stack_adjust())
            .field(
                "register_stack_adjustments",
                &self.register_stack_adjustments(),
            )
            .finish()
    }
}

// LLIL_FLAG, LLIL_FLAG_SSA
pub struct Flag;

impl<M, F> Operation<'_, M, F, Flag>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn source_flag(&self) -> CoreFlag {
        self.function
            .arch()
            .flag_from_id(FlagId(self.op.operands[0] as u32))
            .expect("Bad flag ID")
    }

    /// Get the flag with its SSA version, or `None` if this isn't an `LLIL_FLAG_SSA`.
    pub fn ssa_source_flag(&self) -> Option<LowLevelILSSAFlag<CoreFlag>> {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLAG_SSA;
        if self.op.operation != LLIL_FLAG_SSA {
            return None;
        }
        Some(LowLevelILSSAFlag::new(
            self.source_flag(),
            self.op.operands[1] as u32,
        ))
    }
}

impl<M, F> Debug for Operation<'_, M, F, Flag>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flag")
            .field("source_flag", &self.source_flag())
            .field("ssa_source_flag", &self.ssa_source_flag())
            .finish()
    }
}

// LLIL_FLAG_BIT, LLIL_FLAG_BIT_SSA
pub struct FlagBit;

impl<M, F> Operation<'_, M, F, FlagBit>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn source_flag(&self) -> CoreFlag {
        self.function
            .arch()
            .flag_from_id(FlagId(self.op.operands[0] as u32))
            .expect("Bad flag ID")
    }

    /// Get the flag with its SSA version, or `None` if this isn't an `LLIL_FLAG_BIT_SSA`.
    pub fn ssa_source_flag(&self) -> Option<LowLevelILSSAFlag<CoreFlag>> {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLAG_BIT_SSA;
        if self.op.operation != LLIL_FLAG_BIT_SSA {
            return None;
        }
        Some(LowLevelILSSAFlag::new(
            self.source_flag(),
            self.op.operands[1] as u32,
        ))
    }

    /// Get the index of the result bit that holds the flag.
    pub fn bit_index(&self) -> u64 {
        use binaryninjacore_sys::BNLowLevelILOperation::LLIL_FLAG_BIT_SSA;
        // In SSA form the flag's version comes before the bit.
        if self.op.operation == LLIL_FLAG_BIT_SSA {
            self.op.operands[2]
        } else {
            self.op.operands[1]
        }
    }
}

impl<M, F> Debug for Operation<'_, M, F, FlagBit>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagBit")
            .field("source_flag", &self.source_flag())
            .field("ssa_source_flag", &self.ssa_source_flag())
            .field("bit_index", &self.bit_index())
            .finish()
    }
}

impl<M, F> Operation<'_, M, F, Const>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn value(&self) -> u64 {
        #[cfg(debug_assertions)]
        {
            let raw = self.op.operands[0] as i64;

            let is_safe = match raw.overflowing_shr(self.op.size as u32 * 8) {
                (_, true) => true,
                (res, false) => [-1, 0].contains(&res),
            };

            if !is_safe {
                tracing::error!(
                    "il expr @ {:x} contains constant 0x{:x} as {} byte value (doesn't fit!)",
                    self.op.address,
                    self.op.operands[0],
                    self.op.size
                );
            }
        }

        let mask: u64 = if self.op.size == 0 {
            1
        } else if self.op.size < mem::size_of::<u64>() {
            let m = -1i64 << (self.op.size * 8);
            !m as u64
        } else {
            (-1i64) as u64
        };

        self.op.operands[0] & mask
    }
}

impl<M, F> Operation<'_, M, F, Extern>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn value(&self) -> u64 {
        #[cfg(debug_assertions)]
        {
            let raw = self.op.operands[0] as i64;

            let is_safe = match raw.overflowing_shr(self.op.size as u32 * 8) {
                (_, true) => true,
                (res, false) => [-1, 0].contains(&res),
            };

            if !is_safe {
                tracing::error!(
                    "il expr @ {:x} contains extern 0x{:x} as {} byte value (doesn't fit!)",
                    self.op.address,
                    self.op.operands[0],
                    self.op.size
                );
            }
        }

        let mut mask = -1i64 as u64;

        if self.op.size < mem::size_of::<u64>() {
            mask <<= self.op.size * 8;
            mask = !mask;
        }

        self.op.operands[0] & mask
    }
}

impl<M, F> Operation<'_, M, F, FloatConst>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn float_value(&self) -> f64 {
        let raw_bits = self.raw_value();
        match self.op.size {
            4 => {
                // For f32, take the lower 32 bits and convert to f32
                let bits32 = (raw_bits & 0xFFFFFFFF) as u32;
                f32::from_bits(bits32) as f64
            }
            8 => {
                // For f64, use all 64 bits
                f64::from_bits(raw_bits)
            }
            _ => {
                // Log error for unexpected sizes
                tracing::error!(
                    "il expr @ {:x} has invalid float size {} (expected 4 or 8 bytes)",
                    self.op.address,
                    self.op.size
                );
                f64::NAN
            }
        }
    }
}

impl<M, F> Operation<'_, M, F, SetRegPartialSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        let full_raw_id = RegisterId(self.op.operands[0] as u32);
        let version = self.op.operands[1] as u32;
        let partial_raw_id = RegisterId(self.op.operands[2] as u32);
        let full_reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), full_raw_id)
            .expect("Bad register ID");
        let partial_reg =
            CoreRegister::new(self.function.arch(), partial_raw_id).expect("Bad register ID");
        LowLevelILSSARegisterKind::new_partial(full_reg_kind, version, partial_reg)
    }
}

impl<M, F> Operation<'_, M, F, RegPartialSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn source_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        let full_raw_id = RegisterId(self.op.operands[0] as u32);
        let version = self.op.operands[1] as u32;
        let partial_raw_id = RegisterId(self.op.operands[2] as u32);
        let full_reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), full_raw_id)
            .expect("Bad register ID");
        let partial_reg =
            CoreRegister::new(self.function.arch(), partial_raw_id).expect("Bad register ID");
        LowLevelILSSARegisterKind::new_partial(full_reg_kind, version, partial_reg)
    }
}

// BEGIN GENERATED llil-operations: from api/il, do not edit
// LLIL_SET_REG
pub struct SetReg;

impl<'func, M, F> Operation<'func, M, F, SetReg>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[0] as u32),
        )
        .expect("Bad register ID")
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, SetReg>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetReg")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_reg", &self.dest_reg())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_SET_REG_SPLIT
pub struct SetRegSplit;

impl<'func, M, F> Operation<'func, M, F, SetRegSplit>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg_high(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[0] as u32),
        )
        .expect("Bad register ID")
    }

    pub fn dest_reg_low(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[1] as u32),
        )
        .expect("Bad register ID")
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, SetRegSplit>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetRegSplit")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_reg_high", &self.dest_reg_high())
            .field("dest_reg_low", &self.dest_reg_low())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_SET_FLAG
pub struct SetFlag;

impl<'func, M, F> Operation<'func, M, F, SetFlag>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_flag(&self) -> CoreFlag {
        self.function
            .arch()
            .flag_from_id(FlagId(self.op.operands[0] as u32))
            .expect("Bad flag ID")
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, SetFlag>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetFlag")
            .field("address", &self.address())
            .field("dest_flag", &self.dest_flag())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_SET_REG_STACK_REL
pub struct SetRegStackRel;

impl<'func, M, F> Operation<'func, M, F, SetRegStackRel>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg_stack(&self) -> CoreRegisterStack {
        self.function
            .arch()
            .register_stack_from_id(RegisterStackId(self.op.operands[0] as u32))
            .expect("Bad register stack ID")
    }

    pub fn dest_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, SetRegStackRel>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetRegStackRel")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_reg_stack", &self.dest_reg_stack())
            .field("dest_expr", &self.dest_expr())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_REG_STACK_PUSH
pub struct RegStackPush;

impl<'func, M, F> Operation<'func, M, F, RegStackPush>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg_stack(&self) -> CoreRegisterStack {
        self.function
            .arch()
            .register_stack_from_id(RegisterStackId(self.op.operands[0] as u32))
            .expect("Bad register stack ID")
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegStackPush>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStackPush")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_reg_stack", &self.dest_reg_stack())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_ASSERT
pub struct Assert;

impl<'func, M, F> Operation<'func, M, F, Assert>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[0] as u32),
        )
        .expect("Bad register ID")
    }

    pub fn constraint(&self) -> PossibleValueSet {
        PossibleValueSet::from_owned_core_raw(unsafe {
            BNGetCachedLowLevelILPossibleValueSet(
                self.function.handle,
                self.op.operands[1] as usize,
            )
        })
    }
}

impl<M, F> Debug for Operation<'_, M, F, Assert>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Assert")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_reg", &self.source_reg())
            .field("constraint", &self.constraint())
            .finish()
    }
}

// LLIL_FORCE_VER
pub struct ForceVersion;

impl<'func, M, F> Operation<'func, M, F, ForceVersion>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[0] as u32),
        )
        .expect("Bad register ID")
    }
}

impl<M, F> Debug for Operation<'_, M, F, ForceVersion>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForceVersion")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_reg", &self.dest_reg())
            .finish()
    }
}

// LLIL_LOAD
pub struct Load;

impl<'func, M, F> Operation<'func, M, F, Load>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, Load>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Load")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_STORE
pub struct Store;

impl<'func, M, F> Operation<'func, M, F, Store>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, Store>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_expr", &self.dest_expr())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_PUSH, LLIL_NEG, LLIL_NOT, LLIL_SX, LLIL_ZX, LLIL_LOW_PART, LLIL_BOOL_TO_INT, LLIL_FSQRT,
// LLIL_FNEG, LLIL_FABS, LLIL_FLOAT_TO_INT, LLIL_INT_TO_FLOAT, LLIL_FLOAT_CONV, LLIL_ROUND_TO_INT,
// LLIL_FLOOR, LLIL_CEIL, LLIL_FTRUNC, LLIL_BSWAP, LLIL_POPCNT, LLIL_CLZ, LLIL_CTZ, LLIL_RBIT,
// LLIL_CLS, LLIL_ABS
pub struct UnaryOp;

impl<'func, M, F> Operation<'func, M, F, UnaryOp>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn operand(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, UnaryOp>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnaryOp")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("operand", &self.operand())
            .finish()
    }
}

// LLIL_POP
pub struct Pop;

impl<'func, M, F> Operation<'func, M, F, Pop>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }
}

impl<M, F> Debug for Operation<'_, M, F, Pop>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pop")
            .field("address", &self.address())
            .field("size", &self.size())
            .finish()
    }
}

// LLIL_REG
pub struct Reg;

impl<'func, M, F> Operation<'func, M, F, Reg>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[0] as u32),
        )
        .expect("Bad register ID")
    }
}

impl<M, F> Debug for Operation<'_, M, F, Reg>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reg")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_reg", &self.source_reg())
            .finish()
    }
}

// LLIL_REG_SPLIT
pub struct RegSplit;

impl<'func, M, F> Operation<'func, M, F, RegSplit>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn high_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[0] as u32),
        )
        .expect("Bad register ID")
    }

    pub fn low_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[1] as u32),
        )
        .expect("Bad register ID")
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegSplit>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegSplit")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("high_reg", &self.high_reg())
            .field("low_reg", &self.low_reg())
            .finish()
    }
}

// LLIL_REG_STACK_REL
pub struct RegStackRel;

impl<'func, M, F> Operation<'func, M, F, RegStackRel>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg_stack(&self) -> CoreRegisterStack {
        self.function
            .arch()
            .register_stack_from_id(RegisterStackId(self.op.operands[0] as u32))
            .expect("Bad register stack ID")
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegStackRel>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStackRel")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_reg_stack", &self.source_reg_stack())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_REG_STACK_POP
pub struct RegStackPop;

impl<'func, M, F> Operation<'func, M, F, RegStackPop>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg_stack(&self) -> CoreRegisterStack {
        self.function
            .arch()
            .register_stack_from_id(RegisterStackId(self.op.operands[0] as u32))
            .expect("Bad register stack ID")
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegStackPop>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStackPop")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_reg_stack", &self.source_reg_stack())
            .finish()
    }
}

// LLIL_REG_STACK_FREE_REG
pub struct RegStackFreeReg;

impl<'func, M, F> Operation<'func, M, F, RegStackFreeReg>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[0] as u32),
        )
        .expect("Bad register ID")
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegStackFreeReg>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStackFreeReg")
            .field("address", &self.address())
            .field("dest_reg", &self.dest_reg())
            .finish()
    }
}

// LLIL_REG_STACK_FREE_REL
pub struct RegStackFreeRel;

impl<'func, M, F> Operation<'func, M, F, RegStackFreeRel>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_reg_stack(&self) -> CoreRegisterStack {
        self.function
            .arch()
            .register_stack_from_id(RegisterStackId(self.op.operands[0] as u32))
            .expect("Bad register stack ID")
    }

    pub fn dest_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegStackFreeRel>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStackFreeRel")
            .field("address", &self.address())
            .field("dest_reg_stack", &self.dest_reg_stack())
            .field("dest_expr", &self.dest_expr())
            .finish()
    }
}

// LLIL_CONST, LLIL_CONST_PTR
pub struct Const;

impl<'func, M, F> Operation<'func, M, F, Const>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }
}

impl<M, F> Debug for Operation<'_, M, F, Const>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Const")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("value", &self.value())
            .finish()
    }
}

// LLIL_EXTERN_PTR
pub struct Extern;

impl<'func, M, F> Operation<'func, M, F, Extern>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn offset(&self) -> u64 {
        self.op.operands[1]
    }
}

impl<M, F> Debug for Operation<'_, M, F, Extern>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extern")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("value", &self.value())
            .field("offset", &self.offset())
            .finish()
    }
}

// LLIL_FLOAT_CONST
pub struct FloatConst;

impl<'func, M, F> Operation<'func, M, F, FloatConst>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn raw_value(&self) -> u64 {
        self.op.operands[0]
    }
}

impl<M, F> Debug for Operation<'_, M, F, FloatConst>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FloatConst")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("raw_value", &self.raw_value())
            .field("float_value", &self.float_value())
            .finish()
    }
}

// LLIL_ADD, LLIL_SUB, LLIL_AND, LLIL_OR, LLIL_XOR, LLIL_LSL, LLIL_LSR, LLIL_ASR, LLIL_ROL,
// LLIL_ROR, LLIL_MUL, LLIL_MULU_DP, LLIL_MULS_DP, LLIL_DIVU, LLIL_DIVU_DP, LLIL_DIVS, LLIL_DIVS_DP,
// LLIL_MODU, LLIL_MODU_DP, LLIL_MODS, LLIL_MODS_DP, LLIL_TEST_BIT, LLIL_ADD_OVERFLOW, LLIL_FADD,
// LLIL_FSUB, LLIL_FMUL, LLIL_FDIV, LLIL_MINS, LLIL_MAXS, LLIL_MINU, LLIL_MAXU
pub struct BinaryOp;

impl<'func, M, F> Operation<'func, M, F, BinaryOp>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn left(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn right(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, BinaryOp>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinaryOp")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("left", &self.left())
            .field("right", &self.right())
            .finish()
    }
}

// LLIL_ADC, LLIL_SBB, LLIL_RLC, LLIL_RRC
pub struct BinaryOpCarry;

impl<'func, M, F> Operation<'func, M, F, BinaryOpCarry>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn left(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn right(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }

    pub fn carry(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, BinaryOpCarry>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinaryOpCarry")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("left", &self.left())
            .field("right", &self.right())
            .field("carry", &self.carry())
            .finish()
    }
}

// LLIL_JUMP
pub struct Jump;

impl<'func, M, F> Operation<'func, M, F, Jump>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, Jump>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jump")
            .field("address", &self.address())
            .field("target", &self.target())
            .finish()
    }
}

// LLIL_JUMP_TO
pub struct JumpTo;

impl<'func, M, F> Operation<'func, M, F, JumpTo>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn target_list(&self) -> BTreeMap<u64, LowLevelInstructionIndex> {
        self.get_operand_list(1)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| (pair[0], LowLevelInstructionIndex(pair[1] as usize)))
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, JumpTo>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("JumpTo")
            .field("address", &self.address())
            .field("target", &self.target())
            .field("target_list", &self.target_list())
            .finish()
    }
}

// LLIL_RET
pub struct Ret;

impl<'func, M, F> Operation<'func, M, F, Ret>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, Ret>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ret")
            .field("address", &self.address())
            .field("target", &self.target())
            .finish()
    }
}

// LLIL_IF
pub struct If;

impl<'func, M, F> Operation<'func, M, F, If>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn condition(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn true_target(&self) -> LowLevelILInstruction<'func, M, F> {
        LowLevelILInstruction::new(
            self.function,
            LowLevelInstructionIndex(self.op.operands[1] as usize),
        )
    }

    pub fn false_target(&self) -> LowLevelILInstruction<'func, M, F> {
        LowLevelILInstruction::new(
            self.function,
            LowLevelInstructionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, If>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("If")
            .field("address", &self.address())
            .field("condition", &self.condition())
            .field("true_target", &self.true_target())
            .field("false_target", &self.false_target())
            .finish()
    }
}

// LLIL_GOTO
pub struct Goto;

impl<'func, M, F> Operation<'func, M, F, Goto>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> LowLevelILInstruction<'func, M, F> {
        LowLevelILInstruction::new(
            self.function,
            LowLevelInstructionIndex(self.op.operands[0] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, Goto>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Goto")
            .field("address", &self.address())
            .field("target", &self.target())
            .finish()
    }
}

// LLIL_FLAG_COND
pub struct FlagCond;

impl<'func, M, F> Operation<'func, M, F, FlagCond>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn flag_condition(&self) -> FlagCondition {
        unsafe { mem::transmute::<u8, FlagCondition>(self.op.operands[0] as u8) }
    }

    pub fn semantic_flag_class(&self) -> Option<CoreFlagClass> {
        self.function
            .arch()
            .flag_class_from_id(FlagClassId(self.op.operands[1] as u32))
    }
}

impl<M, F> Debug for Operation<'_, M, F, FlagCond>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagCond")
            .field("address", &self.address())
            .field("flag_condition", &self.flag_condition())
            .field("semantic_flag_class", &self.semantic_flag_class())
            .finish()
    }
}

// LLIL_FLAG_GROUP
pub struct FlagGroup;

impl<'func, M, F> Operation<'func, M, F, FlagGroup>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn flag_group(&self) -> CoreFlagGroup {
        self.function
            .arch()
            .flag_group_from_id(FlagGroupId(self.op.operands[0] as u32))
            .expect("Bad flag group ID")
    }
}

impl<M, F> Debug for Operation<'_, M, F, FlagGroup>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagGroup")
            .field("address", &self.address())
            .field("flag_group", &self.flag_group())
            .finish()
    }
}

// LLIL_CMP_E, LLIL_CMP_NE, LLIL_CMP_SLT, LLIL_CMP_ULT, LLIL_CMP_SLE, LLIL_CMP_ULE, LLIL_CMP_SGE,
// LLIL_CMP_UGE, LLIL_CMP_SGT, LLIL_CMP_UGT, LLIL_FCMP_E, LLIL_FCMP_NE, LLIL_FCMP_LT, LLIL_FCMP_LE,
// LLIL_FCMP_GE, LLIL_FCMP_GT, LLIL_FCMP_O, LLIL_FCMP_UO
pub struct Condition;

impl<'func, M, F> Operation<'func, M, F, Condition>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn left(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn right(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, Condition>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Condition")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("left", &self.left())
            .field("right", &self.right())
            .finish()
    }
}

// LLIL_SYSCALL
pub struct Syscall;

impl<M, F> Debug for Operation<'_, M, F, Syscall>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Syscall")
            .field("address", &self.address())
            .finish()
    }
}

// LLIL_TRAP
pub struct Trap;

impl<'func, M, F> Operation<'func, M, F, Trap>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn vector(&self) -> u64 {
        self.op.operands[0]
    }
}

impl<M, F> Debug for Operation<'_, M, F, Trap>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trap")
            .field("address", &self.address())
            .field("vector", &self.vector())
            .finish()
    }
}

// LLIL_UNIMPL_MEM
pub struct UnimplMem;

impl<'func, M, F> Operation<'func, M, F, UnimplMem>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn mem_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn unknown(&self) -> bool {
        self.op.operands[1] != 0
    }
}

impl<M, F> Debug for Operation<'_, M, F, UnimplMem>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnimplMem")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("mem_expr", &self.mem_expr())
            .field("unknown", &self.unknown())
            .finish()
    }
}

// LLIL_SET_REG_SSA
pub struct SetRegSsa;

impl<'func, M, F> Operation<'func, M, F, SetRegSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.op.operands[0] as u32),
            )
            .expect("Bad register ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, SetRegSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetRegSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_reg", &self.dest_reg())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_SET_REG_SSA_PARTIAL
pub struct SetRegPartialSsa;

impl<'func, M, F> Operation<'func, M, F, SetRegPartialSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn partial_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[2] as u32),
        )
        .expect("Bad register ID")
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[3] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, SetRegPartialSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetRegPartialSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_reg", &self.dest_reg())
            .field("partial_reg", &self.partial_reg())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_SET_REG_SPLIT_SSA
pub struct SetRegSplitSsa;

impl<'func, M, F> Operation<'func, M, F, SetRegSplitSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_expr_high(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn high_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.get_sub_operand(0, 0) as u32),
            )
            .expect("Bad register ID"),
            self.get_sub_operand(0, 1) as u32,
        )
    }

    pub fn dest_expr_low(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }

    pub fn low_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.get_sub_operand(1, 0) as u32),
            )
            .expect("Bad register ID"),
            self.get_sub_operand(1, 1) as u32,
        )
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, SetRegSplitSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetRegSplitSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_expr_high", &self.dest_expr_high())
            .field("high_reg", &self.high_reg())
            .field("dest_expr_low", &self.dest_expr_low())
            .field("low_reg", &self.low_reg())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_SET_REG_STACK_REL_SSA
pub struct SetRegStackRelSsa;

impl<'func, M, F> Operation<'func, M, F, SetRegStackRelSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn stack_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn dest_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.get_sub_operand(0, 0) as u32))
                .expect("Bad register stack ID"),
            self.get_sub_operand(0, 1) as u32,
        )
    }

    pub fn source_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.get_sub_operand(0, 0) as u32))
                .expect("Bad register stack ID"),
            self.get_sub_operand(0, 2) as u32,
        )
    }

    pub fn dest_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }

    pub fn top_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }

    pub fn top_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.get_sub_operand(2, 0) as u32),
            )
            .expect("Bad register ID"),
            self.get_sub_operand(2, 1) as u32,
        )
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[3] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, SetRegStackRelSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetRegStackRelSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("stack_expr", &self.stack_expr())
            .field("dest_reg_stack", &self.dest_reg_stack())
            .field("source_reg_stack", &self.source_reg_stack())
            .field("dest_expr", &self.dest_expr())
            .field("top_expr", &self.top_expr())
            .field("top_reg", &self.top_reg())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_SET_REG_STACK_ABS_SSA
pub struct SetRegStackAbsSsa;

impl<'func, M, F> Operation<'func, M, F, SetRegStackAbsSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn stack_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn dest_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.get_sub_operand(0, 0) as u32))
                .expect("Bad register stack ID"),
            self.get_sub_operand(0, 1) as u32,
        )
    }

    pub fn source_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.get_sub_operand(0, 0) as u32))
                .expect("Bad register stack ID"),
            self.get_sub_operand(0, 2) as u32,
        )
    }

    pub fn dest_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[1] as u32),
        )
        .expect("Bad register ID")
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, SetRegStackAbsSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetRegStackAbsSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("stack_expr", &self.stack_expr())
            .field("dest_reg_stack", &self.dest_reg_stack())
            .field("source_reg_stack", &self.source_reg_stack())
            .field("dest_reg", &self.dest_reg())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_REG_SPLIT_DEST_SSA
pub struct RegSplitDestSsa;

impl<'func, M, F> Operation<'func, M, F, RegSplitDestSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.op.operands[0] as u32),
            )
            .expect("Bad register ID"),
            self.op.operands[1] as u32,
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegSplitDestSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegSplitDestSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_reg", &self.dest_reg())
            .finish()
    }
}

// LLIL_REG_STACK_DEST_SSA
pub struct RegStackDestSsa;

impl<'func, M, F> Operation<'func, M, F, RegStackDestSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.op.operands[0] as u32))
                .expect("Bad register stack ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn source_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.op.operands[0] as u32))
                .expect("Bad register stack ID"),
            self.op.operands[2] as u32,
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegStackDestSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStackDestSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_reg_stack", &self.dest_reg_stack())
            .field("source_reg_stack", &self.source_reg_stack())
            .finish()
    }
}

// LLIL_REG_SSA
pub struct RegSsa;

impl<'func, M, F> Operation<'func, M, F, RegSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.op.operands[0] as u32),
            )
            .expect("Bad register ID"),
            self.op.operands[1] as u32,
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_reg", &self.source_reg())
            .finish()
    }
}

// LLIL_REG_SSA_PARTIAL
pub struct RegPartialSsa;

impl<'func, M, F> Operation<'func, M, F, RegPartialSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn partial_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[2] as u32),
        )
        .expect("Bad register ID")
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegPartialSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegPartialSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_reg", &self.source_reg())
            .field("partial_reg", &self.partial_reg())
            .finish()
    }
}

// LLIL_REG_SPLIT_SSA
pub struct RegSplitSsa;

impl<'func, M, F> Operation<'func, M, F, RegSplitSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn high_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.op.operands[0] as u32),
            )
            .expect("Bad register ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn low_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.op.operands[2] as u32),
            )
            .expect("Bad register ID"),
            self.op.operands[3] as u32,
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegSplitSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegSplitSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("high_reg", &self.high_reg())
            .field("low_reg", &self.low_reg())
            .finish()
    }
}

// LLIL_REG_STACK_REL_SSA
pub struct RegStackRelSsa;

impl<'func, M, F> Operation<'func, M, F, RegStackRelSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.op.operands[0] as u32))
                .expect("Bad register stack ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }

    pub fn top_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[3] as usize),
        )
    }

    pub fn top_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.get_sub_operand(3, 0) as u32),
            )
            .expect("Bad register ID"),
            self.get_sub_operand(3, 1) as u32,
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegStackRelSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStackRelSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_reg_stack", &self.source_reg_stack())
            .field("source_expr", &self.source_expr())
            .field("top_expr", &self.top_expr())
            .field("top_reg", &self.top_reg())
            .finish()
    }
}

// LLIL_REG_STACK_ABS_SSA
pub struct RegStackAbsSsa;

impl<'func, M, F> Operation<'func, M, F, RegStackAbsSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.op.operands[0] as u32))
                .expect("Bad register stack ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn source_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[2] as u32),
        )
        .expect("Bad register ID")
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegStackAbsSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStackAbsSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_reg_stack", &self.source_reg_stack())
            .field("source_reg", &self.source_reg())
            .finish()
    }
}

// LLIL_REG_STACK_FREE_REL_SSA
pub struct RegStackFreeRelSsa;

impl<'func, M, F> Operation<'func, M, F, RegStackFreeRelSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn stack_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn dest_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.get_sub_operand(0, 0) as u32))
                .expect("Bad register stack ID"),
            self.get_sub_operand(0, 1) as u32,
        )
    }

    pub fn source_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.get_sub_operand(0, 0) as u32))
                .expect("Bad register stack ID"),
            self.get_sub_operand(0, 2) as u32,
        )
    }

    pub fn dest_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }

    pub fn top_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }

    pub fn top_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.get_sub_operand(2, 0) as u32),
            )
            .expect("Bad register ID"),
            self.get_sub_operand(2, 1) as u32,
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegStackFreeRelSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStackFreeRelSsa")
            .field("address", &self.address())
            .field("stack_expr", &self.stack_expr())
            .field("dest_reg_stack", &self.dest_reg_stack())
            .field("source_reg_stack", &self.source_reg_stack())
            .field("dest_expr", &self.dest_expr())
            .field("top_expr", &self.top_expr())
            .field("top_reg", &self.top_reg())
            .finish()
    }
}

// LLIL_REG_STACK_FREE_ABS_SSA
pub struct RegStackFreeAbsSsa;

impl<'func, M, F> Operation<'func, M, F, RegStackFreeAbsSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn stack_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn dest_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.get_sub_operand(0, 0) as u32))
                .expect("Bad register stack ID"),
            self.get_sub_operand(0, 1) as u32,
        )
    }

    pub fn source_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.get_sub_operand(0, 0) as u32))
                .expect("Bad register stack ID"),
            self.get_sub_operand(0, 2) as u32,
        )
    }

    pub fn dest_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        LowLevelILRegisterKind::from_raw(
            &self.function.arch(),
            RegisterId(self.op.operands[1] as u32),
        )
        .expect("Bad register ID")
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegStackFreeAbsSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStackFreeAbsSsa")
            .field("address", &self.address())
            .field("stack_expr", &self.stack_expr())
            .field("dest_reg_stack", &self.dest_reg_stack())
            .field("source_reg_stack", &self.source_reg_stack())
            .field("dest_reg", &self.dest_reg())
            .finish()
    }
}

// LLIL_SET_FLAG_SSA
pub struct SetFlagSsa;

impl<'func, M, F> Operation<'func, M, F, SetFlagSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_flag(&self) -> LowLevelILSSAFlag<CoreFlag> {
        LowLevelILSSAFlag::new(
            self.function
                .arch()
                .flag_from_id(FlagId(self.op.operands[0] as u32))
                .expect("Bad flag ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, SetFlagSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetFlagSsa")
            .field("address", &self.address())
            .field("dest_flag", &self.dest_flag())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_ASSERT_SSA
pub struct AssertSsa;

impl<'func, M, F> Operation<'func, M, F, AssertSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.op.operands[0] as u32),
            )
            .expect("Bad register ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn constraint(&self) -> PossibleValueSet {
        PossibleValueSet::from_owned_core_raw(unsafe {
            BNGetCachedLowLevelILPossibleValueSet(
                self.function.handle,
                self.op.operands[2] as usize,
            )
        })
    }
}

impl<M, F> Debug for Operation<'_, M, F, AssertSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssertSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_reg", &self.source_reg())
            .field("constraint", &self.constraint())
            .finish()
    }
}

// LLIL_FORCE_VER_SSA
pub struct ForceVersionSsa;

impl<'func, M, F> Operation<'func, M, F, ForceVersionSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.op.operands[0] as u32),
            )
            .expect("Bad register ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn source_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.op.operands[2] as u32),
            )
            .expect("Bad register ID"),
            self.op.operands[3] as u32,
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, ForceVersionSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForceVersionSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_reg", &self.dest_reg())
            .field("source_reg", &self.source_reg())
            .finish()
    }
}

// LLIL_CALL_SSA, LLIL_TAILCALL_SSA
pub struct CallSsa;

impl<'func, M, F> Operation<'func, M, F, CallSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn output_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn output_regs(&self) -> Vec<LowLevelILSSARegisterKind<CoreRegister>> {
        self.get_sub_operand_list(0, 1)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                LowLevelILSSARegisterKind::new_full(
                    LowLevelILRegisterKind::from_raw(
                        &self.function.arch(),
                        RegisterId(pair[0] as u32),
                    )
                    .expect("Bad register ID"),
                    pair[1] as u32,
                )
            })
            .collect()
    }

    pub fn dest_memory_version(&self) -> u64 {
        self.get_sub_operand(0, 0)
    }

    pub fn target(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }

    pub fn stack_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }

    pub fn stack_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.get_sub_operand(2, 0) as u32),
            )
            .expect("Bad register ID"),
            self.get_sub_operand(2, 1) as u32,
        )
    }

    pub fn source_memory_version(&self) -> u64 {
        self.get_sub_operand(2, 2)
    }

    pub fn param_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[3] as usize),
        )
    }

    pub fn param_exprs(&self) -> Vec<LowLevelILExpression<'func, M, F, ValueExpr>> {
        self.get_sub_operand_list(3, 0)
            .into_iter()
            .map(|index| {
                LowLevelILExpression::new(self.function, LowLevelExpressionIndex(index as usize))
            })
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, CallSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallSsa")
            .field("address", &self.address())
            .field("output_expr", &self.output_expr())
            .field("output_regs", &self.output_regs())
            .field("dest_memory_version", &self.dest_memory_version())
            .field("target", &self.target())
            .field("stack_expr", &self.stack_expr())
            .field("stack_reg", &self.stack_reg())
            .field("source_memory_version", &self.source_memory_version())
            .field("param_expr", &self.param_expr())
            .field("param_exprs", &self.param_exprs())
            .finish()
    }
}

// LLIL_SYSCALL_SSA
pub struct SyscallSsa;

impl<'func, M, F> Operation<'func, M, F, SyscallSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn output_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn output_regs(&self) -> Vec<LowLevelILSSARegisterKind<CoreRegister>> {
        self.get_sub_operand_list(0, 1)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                LowLevelILSSARegisterKind::new_full(
                    LowLevelILRegisterKind::from_raw(
                        &self.function.arch(),
                        RegisterId(pair[0] as u32),
                    )
                    .expect("Bad register ID"),
                    pair[1] as u32,
                )
            })
            .collect()
    }

    pub fn dest_memory_version(&self) -> u64 {
        self.get_sub_operand(0, 0)
    }

    pub fn stack_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }

    pub fn stack_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.get_sub_operand(1, 0) as u32),
            )
            .expect("Bad register ID"),
            self.get_sub_operand(1, 1) as u32,
        )
    }

    pub fn source_memory_version(&self) -> u64 {
        self.get_sub_operand(1, 2)
    }

    pub fn param_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }

    pub fn param_exprs(&self) -> Vec<LowLevelILExpression<'func, M, F, ValueExpr>> {
        self.get_sub_operand_list(2, 0)
            .into_iter()
            .map(|index| {
                LowLevelILExpression::new(self.function, LowLevelExpressionIndex(index as usize))
            })
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, SyscallSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyscallSsa")
            .field("address", &self.address())
            .field("output_expr", &self.output_expr())
            .field("output_regs", &self.output_regs())
            .field("dest_memory_version", &self.dest_memory_version())
            .field("stack_expr", &self.stack_expr())
            .field("stack_reg", &self.stack_reg())
            .field("source_memory_version", &self.source_memory_version())
            .field("param_expr", &self.param_expr())
            .field("param_exprs", &self.param_exprs())
            .finish()
    }
}

// LLIL_CALL_PARAM
pub struct CallParamSsa;

impl<'func, M, F> Operation<'func, M, F, CallParamSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn param_exprs(&self) -> Vec<LowLevelILExpression<'func, M, F, ValueExpr>> {
        self.get_operand_list(0)
            .into_iter()
            .map(|index| {
                LowLevelILExpression::new(self.function, LowLevelExpressionIndex(index as usize))
            })
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, CallParamSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallParamSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("param_exprs", &self.param_exprs())
            .finish()
    }
}

// LLIL_CALL_STACK_SSA
pub struct CallStackSsa;

impl<'func, M, F> Operation<'func, M, F, CallStackSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.op.operands[0] as u32),
            )
            .expect("Bad register ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn source_memory_version(&self) -> u64 {
        self.op.operands[2]
    }
}

impl<M, F> Debug for Operation<'_, M, F, CallStackSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallStackSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_reg", &self.source_reg())
            .field("source_memory_version", &self.source_memory_version())
            .finish()
    }
}

// LLIL_CALL_OUTPUT_SSA
pub struct CallOutputSsa;

impl<'func, M, F> Operation<'func, M, F, CallOutputSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_memory_version(&self) -> u64 {
        self.op.operands[0]
    }

    pub fn dest_regs(&self) -> Vec<LowLevelILSSARegisterKind<CoreRegister>> {
        self.get_operand_list(1)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                LowLevelILSSARegisterKind::new_full(
                    LowLevelILRegisterKind::from_raw(
                        &self.function.arch(),
                        RegisterId(pair[0] as u32),
                    )
                    .expect("Bad register ID"),
                    pair[1] as u32,
                )
            })
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, CallOutputSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallOutputSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_memory_version", &self.dest_memory_version())
            .field("dest_regs", &self.dest_regs())
            .finish()
    }
}

// LLIL_SEPARATE_PARAM_LIST_SSA
pub struct SeparateParamListSsa;

impl<'func, M, F> Operation<'func, M, F, SeparateParamListSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn param_exprs(&self) -> Vec<LowLevelILExpression<'func, M, F, ValueExpr>> {
        self.get_operand_list(0)
            .into_iter()
            .map(|index| {
                LowLevelILExpression::new(self.function, LowLevelExpressionIndex(index as usize))
            })
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, SeparateParamListSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeparateParamListSsa")
            .field("address", &self.address())
            .field("param_exprs", &self.param_exprs())
            .finish()
    }
}

// LLIL_SHARED_PARAM_SLOT_SSA
pub struct SharedParamSlotSsa;

impl<'func, M, F> Operation<'func, M, F, SharedParamSlotSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn param_exprs(&self) -> Vec<LowLevelILExpression<'func, M, F, ValueExpr>> {
        self.get_operand_list(0)
            .into_iter()
            .map(|index| {
                LowLevelILExpression::new(self.function, LowLevelExpressionIndex(index as usize))
            })
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, SharedParamSlotSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedParamSlotSsa")
            .field("address", &self.address())
            .field("param_exprs", &self.param_exprs())
            .finish()
    }
}

// LLIL_MEMORY_INTRINSIC_OUTPUT_SSA
pub struct MemoryIntrinsicOutputSsa;

impl<'func, M, F> Operation<'func, M, F, MemoryIntrinsicOutputSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_memory_version(&self) -> u64 {
        self.op.operands[0]
    }

    pub fn output(&self) -> Vec<SSAIntrinsicOutput> {
        let arch = self.function.arch();
        self.get_operand_list(1)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| SSAIntrinsicOutput {
                output: IntrinsicOutput::from_raw(&arch, pair[0]),
                version: pair[1] as u32,
            })
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, MemoryIntrinsicOutputSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryIntrinsicOutputSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_memory_version", &self.dest_memory_version())
            .field("output", &self.output())
            .finish()
    }
}

// LLIL_LOAD_SSA
pub struct LoadSsa;

impl<'func, M, F> Operation<'func, M, F, LoadSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn source_memory_version(&self) -> u64 {
        self.op.operands[1]
    }
}

impl<M, F> Debug for Operation<'_, M, F, LoadSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_expr", &self.source_expr())
            .field("source_memory_version", &self.source_memory_version())
            .finish()
    }
}

// LLIL_STORE_SSA
pub struct StoreSsa;

impl<'func, M, F> Operation<'func, M, F, StoreSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn dest_memory_version(&self) -> u64 {
        self.op.operands[1]
    }

    pub fn source_memory_version(&self) -> u64 {
        self.op.operands[2]
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[3] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, StoreSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreSsa")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_expr", &self.dest_expr())
            .field("dest_memory_version", &self.dest_memory_version())
            .field("source_memory_version", &self.source_memory_version())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_MEMORY_INTRINSIC_SSA
pub struct MemoryIntrinsicSsa;

impl<'func, M, F> Operation<'func, M, F, MemoryIntrinsicSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn output_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn output(&self) -> Vec<SSAIntrinsicOutput> {
        let arch = self.function.arch();
        self.get_sub_operand_list(0, 1)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| SSAIntrinsicOutput {
                output: IntrinsicOutput::from_raw(&arch, pair[0]),
                version: pair[1] as u32,
            })
            .collect()
    }

    pub fn dest_memory_version(&self) -> u64 {
        self.get_sub_operand(0, 0)
    }

    pub fn intrinsic(&self) -> Option<CoreIntrinsic> {
        self.function
            .arch()
            .intrinsic_from_id(IntrinsicId(self.op.operands[1] as u32))
    }

    pub fn param_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }

    pub fn param_exprs(&self) -> Vec<LowLevelILExpression<'func, M, F, ValueExpr>> {
        self.get_sub_operand_list(2, 0)
            .into_iter()
            .map(|index| {
                LowLevelILExpression::new(self.function, LowLevelExpressionIndex(index as usize))
            })
            .collect()
    }

    pub fn source_memory_version(&self) -> u64 {
        self.op.operands[3]
    }
}

impl<M, F> Debug for Operation<'_, M, F, MemoryIntrinsicSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryIntrinsicSsa")
            .field("address", &self.address())
            .field("output_expr", &self.output_expr())
            .field("output", &self.output())
            .field("dest_memory_version", &self.dest_memory_version())
            .field("intrinsic", &self.intrinsic())
            .field("param_expr", &self.param_expr())
            .field("param_exprs", &self.param_exprs())
            .field("source_memory_version", &self.source_memory_version())
            .finish()
    }
}

// LLIL_REG_PHI
pub struct RegPhi;

impl<'func, M, F> Operation<'func, M, F, RegPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        LowLevelILSSARegisterKind::new_full(
            LowLevelILRegisterKind::from_raw(
                &self.function.arch(),
                RegisterId(self.op.operands[0] as u32),
            )
            .expect("Bad register ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn source_regs(&self) -> Vec<LowLevelILSSARegisterKind<CoreRegister>> {
        self.get_operand_list(2)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                LowLevelILSSARegisterKind::new_full(
                    LowLevelILRegisterKind::from_raw(
                        &self.function.arch(),
                        RegisterId(pair[0] as u32),
                    )
                    .expect("Bad register ID"),
                    pair[1] as u32,
                )
            })
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegPhi")
            .field("address", &self.address())
            .field("dest_reg", &self.dest_reg())
            .field("source_regs", &self.source_regs())
            .finish()
    }
}

// LLIL_REG_STACK_PHI
pub struct RegStackPhi;

impl<'func, M, F> Operation<'func, M, F, RegStackPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_reg_stack(&self) -> LowLevelILSSARegisterStack<CoreRegisterStack> {
        LowLevelILSSARegisterStack::new(
            self.function
                .arch()
                .register_stack_from_id(RegisterStackId(self.op.operands[0] as u32))
                .expect("Bad register stack ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn source_reg_stacks(&self) -> Vec<LowLevelILSSARegisterStack<CoreRegisterStack>> {
        self.get_operand_list(2)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                LowLevelILSSARegisterStack::new(
                    self.function
                        .arch()
                        .register_stack_from_id(RegisterStackId(pair[0] as u32))
                        .expect("Bad register stack ID"),
                    pair[1] as u32,
                )
            })
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, RegStackPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStackPhi")
            .field("address", &self.address())
            .field("dest_reg_stack", &self.dest_reg_stack())
            .field("source_reg_stacks", &self.source_reg_stacks())
            .finish()
    }
}

// LLIL_FLAG_PHI
pub struct FlagPhi;

impl<'func, M, F> Operation<'func, M, F, FlagPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_flag(&self) -> LowLevelILSSAFlag<CoreFlag> {
        LowLevelILSSAFlag::new(
            self.function
                .arch()
                .flag_from_id(FlagId(self.op.operands[0] as u32))
                .expect("Bad flag ID"),
            self.op.operands[1] as u32,
        )
    }

    pub fn source_flags(&self) -> Vec<LowLevelILSSAFlag<CoreFlag>> {
        self.get_operand_list(2)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                LowLevelILSSAFlag::new(
                    self.function
                        .arch()
                        .flag_from_id(FlagId(pair[0] as u32))
                        .expect("Bad flag ID"),
                    pair[1] as u32,
                )
            })
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, FlagPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagPhi")
            .field("address", &self.address())
            .field("dest_flag", &self.dest_flag())
            .field("source_flags", &self.source_flags())
            .finish()
    }
}

// LLIL_MEM_PHI
pub struct MemPhi;

impl<'func, M, F> Operation<'func, M, F, MemPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_memory_version(&self) -> usize {
        self.op.operands[0] as usize
    }

    pub fn source_memory_versions(&self) -> Vec<usize> {
        self.get_operand_list(1)
            .into_iter()
            .map(|version| version as usize)
            .collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, MemPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemPhi")
            .field("address", &self.address())
            .field("dest_memory_version", &self.dest_memory_version())
            .field("source_memory_versions", &self.source_memory_versions())
            .finish()
    }
}

pub trait OperationArguments: 'static {}

impl OperationArguments for NoArgs {}
impl OperationArguments for SetReg {}
impl OperationArguments for SetRegSplit {}
impl OperationArguments for SetFlag {}
impl OperationArguments for SetRegStackRel {}
impl OperationArguments for RegStackPush {}
impl OperationArguments for Assert {}
impl OperationArguments for ForceVersion {}
impl OperationArguments for Load {}
impl OperationArguments for Store {}
impl OperationArguments for UnaryOp {}
impl OperationArguments for Pop {}
impl OperationArguments for Reg {}
impl OperationArguments for RegSplit {}
impl OperationArguments for RegStackRel {}
impl OperationArguments for RegStackPop {}
impl OperationArguments for RegStackFreeReg {}
impl OperationArguments for RegStackFreeRel {}
impl OperationArguments for Const {}
impl OperationArguments for Extern {}
impl OperationArguments for FloatConst {}
impl OperationArguments for Flag {}
impl OperationArguments for FlagBit {}
impl OperationArguments for BinaryOp {}
impl OperationArguments for BinaryOpCarry {}
impl OperationArguments for Jump {}
impl OperationArguments for JumpTo {}
impl OperationArguments for Call {}
impl OperationArguments for Ret {}
impl OperationArguments for If {}
impl OperationArguments for Goto {}
impl OperationArguments for FlagCond {}
impl OperationArguments for FlagGroup {}
impl OperationArguments for Condition {}
impl OperationArguments for Syscall {}
impl OperationArguments for Trap {}
impl OperationArguments for Intrinsic {}
impl OperationArguments for UnimplMem {}
impl OperationArguments for SetRegSsa {}
impl OperationArguments for SetRegPartialSsa {}
impl OperationArguments for SetRegSplitSsa {}
impl OperationArguments for SetRegStackRelSsa {}
impl OperationArguments for SetRegStackAbsSsa {}
impl OperationArguments for RegSplitDestSsa {}
impl OperationArguments for RegStackDestSsa {}
impl OperationArguments for RegSsa {}
impl OperationArguments for RegPartialSsa {}
impl OperationArguments for RegSplitSsa {}
impl OperationArguments for RegStackRelSsa {}
impl OperationArguments for RegStackAbsSsa {}
impl OperationArguments for RegStackFreeRelSsa {}
impl OperationArguments for RegStackFreeAbsSsa {}
impl OperationArguments for SetFlagSsa {}
impl OperationArguments for AssertSsa {}
impl OperationArguments for ForceVersionSsa {}
impl OperationArguments for CallSsa {}
impl OperationArguments for SyscallSsa {}
impl OperationArguments for CallParamSsa {}
impl OperationArguments for CallStackSsa {}
impl OperationArguments for CallOutputSsa {}
impl OperationArguments for SeparateParamListSsa {}
impl OperationArguments for SharedParamSlotSsa {}
impl OperationArguments for MemoryIntrinsicOutputSsa {}
impl OperationArguments for LoadSsa {}
impl OperationArguments for StoreSsa {}
impl OperationArguments for MemoryIntrinsicSsa {}
impl OperationArguments for RegPhi {}
impl OperationArguments for RegStackPhi {}
impl OperationArguments for FlagPhi {}
impl OperationArguments for MemPhi {}
// END GENERATED llil-operations
