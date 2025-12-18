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
    BNGetCachedLowLevelILPossibleValueSet, BNGetLowLevelILByIndex, BNLowLevelILFreeOperandList,
    BNLowLevelILGetOperandList, BNLowLevelILInstruction,
};

use super::*;
use crate::architecture::{
    CoreFlag, CoreFlagGroup, CoreFlagWrite, CoreIntrinsic, CoreRegister, CoreRegisterStack,
    FlagGroupId, FlagId, FlagWriteId, IntrinsicId, RegisterStackId,
};
use crate::variable::PossibleValueSet;
use std::collections::BTreeMap;
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

    fn get_constraint(&self, operand_idx: usize) -> PossibleValueSet {
        let raw_pvs = unsafe {
            BNGetCachedLowLevelILPossibleValueSet(
                self.function.handle,
                self.op.operands[operand_idx] as usize,
            )
        };
        PossibleValueSet::from_owned_core_raw(raw_pvs)
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

// LLIL_NOP, LLIL_NORET, LLIL_BP, LLIL_UNDEF, LLIL_UNIMPL
pub struct NoArgs;

impl<M, F> Debug for Operation<'_, M, F, NoArgs>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoArgs").finish()
    }
}

// LLIL_POP
pub struct Pop;

impl<M, F> Operation<'_, M, F, Pop>
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

// LLIL_SYSCALL
pub struct Syscall;

impl<M, F> Debug for Operation<'_, M, F, Syscall>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Syscall").finish()
    }
}

// LLIL_SYSCALL_SSA
pub struct SyscallSsa;

impl<'func, M, F> Operation<'func, M, F, SyscallSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    /// Get the output expression of the call.
    ///
    /// NOTE: This is currently always [`CallOutputSsa`].
    pub fn output_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    /// Get the parameter expression of the call.
    ///
    /// NOTE: This is currently always [`CallParamSsa`].
    pub fn param_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }

    /// Get the stack expression of the call.
    ///
    /// NOTE: This is currently always [`CallStackSsa`].
    pub fn stack_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, SyscallSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyscallSsa")
            .field("output_expr", &self.output_expr())
            .field("param_expr", &self.param_expr())
            .field("stack_expr", &self.stack_expr())
            .finish()
    }
}

// LLIL_INTRINSIC, LLIL_INTRINSIC_SSA
pub struct Intrinsic;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IntrinsicOutput {
    Reg(CoreRegister),
    Flag(CoreFlag),
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

impl<M, F> Operation<'_, M, F, Intrinsic>
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
        // Convert the operand to either a register or flag id.
        let operand_to_output = |o: u64| {
            if o & (1 << 32) != 0 {
                self.function
                    .arch()
                    .flag_from_id(FlagId((o & 0xffffffff) as u32))
                    .expect("Invalid core flag ID")
                    .into()
            } else {
                self.function
                    .arch()
                    .register_from_id(RegisterId((o & 0xffffffff) as u32))
                    .expect("Invalid register ID")
                    .into()
            }
        };

        self.get_operand_list(0)
            .into_iter()
            .map(operand_to_output)
            .collect::<Vec<_>>()
    }

    /// Get the input list for the intrinsic.
    ///
    /// This will just be a CallParamSsa expression.
    #[inline]
    pub fn inputs(&self) -> LowLevelILExpression<'_, M, F, ValueExpr> {
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
        let raw_id = RegisterId(self.op.operands[0] as u32);
        LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id).expect("Bad register ID")
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
        let raw_id = RegisterId(self.op.operands[0] as u32);
        let reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id)
            .expect("Bad register ID");
        let version = self.op.operands[1] as u32;
        LowLevelILSSARegisterKind::new_full(reg_kind, version)
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

// LLIL_SET_REG_PARTIAL_SSA
pub struct SetRegPartialSsa;

impl<'func, M, F> Operation<'func, M, F, SetRegPartialSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

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
        let raw_id = RegisterId(self.op.operands[0] as u32);
        LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id).expect("Bad register ID")
    }

    pub fn dest_reg_low(&self) -> LowLevelILRegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[1] as u32);
        LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id).expect("Bad register ID")
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

    /// Because of the fixed operand list size we use another expression for the dest high register.
    ///
    /// NOTE: This should always be an expression of [`RegSsa`].
    pub fn dest_expr_high(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    /// Because of the fixed operand list size we use another expression for the dest low register.
    ///
    /// NOTE: This should always be an expression of [`RegSsa`].
    pub fn dest_expr_low(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
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
            .field("dest_expr_low", &self.dest_expr_low())
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

// LLIL_SET_FLAG_SSA
pub struct SetFlagSsa;

impl<'func, M, F> Operation<'func, M, F, SetFlagSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_flag(&self) -> LowLevelILSSAFlag<CoreFlag> {
        let flag = self
            .function
            .arch()
            .flag_from_id(FlagId(self.op.operands[0] as u32))
            .expect("Bad flag ID");
        let version = self.op.operands[1] as u32;
        LowLevelILSSAFlag::new(flag, version)
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

    pub fn source_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[3] as usize),
        )
    }

    pub fn source_memory_version(&self) -> u64 {
        self.op.operands[2]
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
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_REG
pub struct Reg;

impl<M, F> Operation<'_, M, F, Reg>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[0] as u32);
        LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id).expect("Bad register ID")
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

// LLIL_REG_SSA
pub struct RegSsa;

impl<M, F> Operation<'_, M, F, RegSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[0] as u32);
        let reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id)
            .expect("Bad register ID");
        let version = self.op.operands[1] as u32;
        LowLevelILSSARegisterKind::new_full(reg_kind, version)
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

impl<M, F> Operation<'_, M, F, RegPartialSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

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
            .finish()
    }
}

// LLIL_REG_SPLIT
pub struct RegSplit;

impl<M, F> Operation<'_, M, F, RegSplit>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn low_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[0] as u32);
        LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id).expect("Bad register ID")
    }

    pub fn high_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[1] as u32);
        LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id).expect("Bad register ID")
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
            .field("low_reg", &self.low_reg())
            .field("high_reg", &self.high_reg())
            .finish()
    }
}

// LLIL_REG_SPLIT_SSA
pub struct RegSplitSsa;

impl<M, F> Operation<'_, M, F, RegSplitSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn low_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[0] as u32);
        let reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id)
            .expect("Bad register ID");
        let version = self.op.operands[1] as u32;
        LowLevelILSSARegisterKind::new_full(reg_kind, version)
    }

    pub fn high_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[2] as u32);
        let reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id)
            .expect("Bad register ID");
        let version = self.op.operands[3] as u32;
        LowLevelILSSARegisterKind::new_full(reg_kind, version)
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
            .field("low_reg", &self.low_reg())
            .field("high_reg", &self.high_reg())
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
        let raw_id = self.op.operands[0] as u32;
        self.function
            .arch()
            .register_stack_from_id(RegisterStackId(raw_id))
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

// LLIL_REG_STACK_POP
pub struct RegStackPop;

impl<M, F> Operation<'_, M, F, RegStackPop>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg_stack(&self) -> CoreRegisterStack {
        let raw_id = self.op.operands[0] as u32;
        self.function
            .arch()
            .register_stack_from_id(RegisterStackId(raw_id))
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

impl<M, F> Operation<'_, M, F, RegStackFreeReg>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg(&self) -> CoreRegister {
        let raw_id = self.op.operands[0] as u32;
        self.function
            .arch()
            .register_from_id(RegisterId(raw_id))
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
            .field("size", &self.size())
            .field("dest_reg", &self.dest_reg())
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
}

impl<M, F> Debug for Operation<'_, M, F, Flag>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flag")
            .field("source_flag", &self.source_flag())
            .finish()
    }
}

// LLIL_FLAG_BIT, LLIL_FLAG_BIT_SSA
pub struct FlagBit;

impl<M, F> Debug for Operation<'_, M, F, FlagBit>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagBit").finish()
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
            .field("target", &self.target())
            .finish()
    }
}

// LLIL_JUMP_TO
pub struct JumpTo;

struct TargetListIter<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    function: &'func LowLevelILFunction<M, F>,
    cursor: BNLowLevelILInstruction,
    cursor_operand: usize,
}

impl<M, F> TargetListIter<'_, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn next(&mut self) -> u64 {
        if self.cursor_operand >= 3 {
            self.cursor = unsafe {
                BNGetLowLevelILByIndex(self.function.handle, self.cursor.operands[3] as usize)
            };
            self.cursor_operand = 0;
        }
        let result = self.cursor.operands[self.cursor_operand];
        self.cursor_operand += 1;
        result
    }
}

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
        let mut result = BTreeMap::new();
        let count = self.op.operands[1] as usize / 2;
        let mut list = TargetListIter {
            function: self.function,
            cursor: unsafe {
                BNGetLowLevelILByIndex(self.function.handle, self.op.operands[2] as usize)
            },
            cursor_operand: 0,
        };

        for _ in 0..count {
            let value = list.next();
            let target = LowLevelInstructionIndex(list.next() as usize);
            result.insert(value, target);
        }

        result
    }
}

impl<M, F> Debug for Operation<'_, M, F, JumpTo>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("JumpTo")
            .field("target", &self.target())
            .field("target_list", &self.target_list())
            .finish()
    }
}

// LLIL_CALL, LLIL_CALL_STACK_ADJUST
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
            .finish()
    }
}

// LLIL_CALL_SSA
pub struct CallSsa;

impl<'func, M, F> Operation<'func, M, F, CallSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }

    /// Get the output expression of the call.
    ///
    /// NOTE: This is currently always [`CallOutputSsa`].
    pub fn output_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    /// Get the parameter expression of the call.
    ///
    /// NOTE: This is currently always [`CallParamSsa`].
    pub fn param_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[3] as usize),
        )
    }

    /// Get the stack expression of the call.
    ///
    /// NOTE: This is currently always [`CallStackSsa`].
    pub fn stack_expr(&self) -> LowLevelILExpression<'func, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<M, F> Debug for Operation<'_, M, F, CallSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallSsa")
            .field("target", &self.target())
            .field("output_expr", &self.output_expr())
            .field("param_expr", &self.param_expr())
            .field("stack_expr", &self.stack_expr())
            .finish()
    }
}

// LLIL_CALL_OUTPUT_SSA
pub struct CallOutputSsa;

impl<M, F> Operation<'_, M, F, CallOutputSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_regs(&self) -> Vec<LowLevelILSSARegisterKind<CoreRegister>> {
        let operand_list = self.get_operand_list(1);

        // The operand list contains a list of ([0: reg, 1: version], ...).
        let paired_ssa_reg = |paired: &[u64]| {
            let raw_id = RegisterId(paired[0] as u32);
            let version = paired[1] as u32;
            let reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id)
                .expect("Bad register ID");
            LowLevelILSSARegisterKind::new_full(reg_kind, version)
        };

        operand_list.chunks_exact(2).map(paired_ssa_reg).collect()
    }

    pub fn dest_memory_version(&self) -> u64 {
        self.op.operands[0]
    }
}

impl<M, F> Debug for Operation<'_, M, F, CallOutputSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallOutputSsa")
            .field("dest_regs", &self.dest_regs())
            .finish()
    }
}

// LLIL_CALL_PARAM_SSA
pub struct CallParamSsa;

impl<'func, M, F> Operation<'func, M, F, CallParamSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn param_exprs(&self) -> Vec<LowLevelILExpression<'func, M, F, ValueExpr>> {
        self.get_operand_list(0)
            .into_iter()
            .map(|val| LowLevelExpressionIndex(val as usize))
            .map(|expr_idx| LowLevelILExpression::new(self.function, expr_idx))
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
            .field("param_exprs", &self.param_exprs())
            .finish()
    }
}

// LLIL_CALL_STACK_SSA
pub struct CallStackSsa;

impl<M, F> Operation<'_, M, F, CallStackSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn source_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[0] as u32);
        let reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id)
            .expect("Bad register ID");
        let version = self.op.operands[1] as u32;
        LowLevelILSSARegisterKind::new_full(reg_kind, version)
    }
}

impl<M, F> Debug for Operation<'_, M, F, CallStackSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallStackSsa")
            .field("source_reg", &self.source_reg())
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
            .field("target", &self.target())
            .finish()
    }
}

// LLIL_FLAG_COND
// Valid only in Lifted IL
pub struct FlagCond;

impl<M, F> Debug for Operation<'_, M, F, FlagCond>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagCond").finish()
    }
}

// LLIL_FLAG_GROUP
// Valid only in Lifted IL
pub struct FlagGroup;

impl<M, F> Operation<'_, M, F, FlagGroup>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn flag_group(&self) -> CoreFlagGroup {
        let id = self.op.operands[0] as u32;
        self.function
            .arch()
            .flag_group_from_id(FlagGroupId(id))
            .unwrap()
    }
}

impl<M, F> Debug for Operation<'_, M, F, FlagGroup>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagGroup")
            .field("flag_group", &self.flag_group())
            .finish()
    }
}

// LLIL_TRAP
pub struct Trap;

impl<M, F> Operation<'_, M, F, Trap>
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
            .field("vector", &self.vector())
            .finish()
    }
}

// LLIL_REG_PHI
pub struct RegPhi;
impl<M, F> Operation<'_, M, F, RegPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[0] as u32);
        let reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id)
            .expect("Bad register ID");
        let version = self.op.operands[1] as u32;
        LowLevelILSSARegisterKind::new_full(reg_kind, version)
    }

    pub fn source_regs(&self) -> Vec<LowLevelILSSARegisterKind<CoreRegister>> {
        let operand_list = self.get_operand_list(2);
        let arch = self.function.arch();
        operand_list
            .chunks_exact(2)
            .map(|chunk| {
                let (register, version) = (chunk[0], chunk[1]);
                LowLevelILSSARegisterKind::new_full(
                    LowLevelILRegisterKind::from_raw(&arch, RegisterId(register as u32))
                        .expect("Bad register ID"),
                    version as u32,
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
            .field("dest_reg", &self.dest_reg())
            .field("source_regs", &self.source_regs())
            .finish()
    }
}

// LLIL_FLAG_PHI
pub struct FlagPhi;

impl<M, F> Operation<'_, M, F, FlagPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_flag(&self) -> LowLevelILSSAFlag<CoreFlag> {
        let flag = self
            .function
            .arch()
            .flag_from_id(FlagId(self.op.operands[0] as u32))
            .expect("Bad flag ID");
        let version = self.op.operands[1] as u32;
        LowLevelILSSAFlag::new(flag, version)
    }

    pub fn source_flags(&self) -> Vec<LowLevelILSSAFlag<CoreFlag>> {
        let operand_list = self.get_operand_list(2);
        operand_list
            .chunks_exact(2)
            .map(|chunk| {
                let (flag, version) = (chunk[0], chunk[1]);
                let flag = self
                    .function
                    .arch()
                    .flag_from_id(FlagId(flag as u32))
                    .expect("Bad flag ID");
                LowLevelILSSAFlag::new(flag, version as u32)
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
            .field("dest_flag", &self.dest_flag())
            .field("source_flags", &self.source_flags())
            .finish()
    }
}

// LLIL_MEM_PHI
pub struct MemPhi;

impl<M, F> Operation<'_, M, F, MemPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_memory_version(&self) -> usize {
        self.op.operands[0] as usize
    }

    pub fn source_memory_versions(&self) -> Vec<usize> {
        let operand_list = self.get_operand_list(1);
        operand_list.into_iter().map(|op| op as usize).collect()
    }
}

impl<M, F> Debug for Operation<'_, M, F, MemPhi>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemPhi")
            .field("dest_memory_version", &self.dest_memory_version())
            .field("source_memory_versions", &self.source_memory_versions())
            .finish()
    }
}

// LLIL_CONST, LLIL_CONST_PTR
pub struct Const;

impl<M, F> Operation<'_, M, F, Const>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

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

impl<M, F> Debug for Operation<'_, M, F, Const>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Const")
            .field("size", &self.size())
            .field("value", &self.value())
            .finish()
    }
}

// LLIL_FLOAT_CONST
pub struct FloatConst;

impl<M, F> Operation<'_, M, F, FloatConst>
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

impl<M, F> Debug for Operation<'_, M, F, FloatConst>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FloatConst")
            .field("size", &self.size())
            .field("float_value", &self.float_value())
            .field("raw_value", &self.raw_value())
            .finish()
    }
}

// LLIL_EXTERN_PTR
pub struct Extern;

impl<M, F> Operation<'_, M, F, Extern>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

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

impl<M, F> Debug for Operation<'_, M, F, Extern>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extern")
            .field("size", &self.size())
            .field("value", &self.value())
            .finish()
    }
}

// LLIL_ADD, LLIL_SUB, LLIL_AND, LLIL_OR
// LLIL_XOR, LLIL_LSL, LLIL_LSR, LLIL_ASR
// LLIL_ROL, LLIL_ROR, LLIL_MUL, LLIL_MULU_DP,
// LLIL_MULS_DP, LLIL_DIVU, LLIL_DIVS, LLIL_MODU,
// LLIL_MODS
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
            .field("size", &self.size())
            .field("left", &self.left())
            .field("right", &self.right())
            .field("carry", &self.carry())
            .finish()
    }
}

// LLIL_PUSH, LLIL_NEG, LLIL_NOT, LLIL_SX,
// LLIL_ZX, LLIL_LOW_PART, LLIL_BOOL_TO_INT, LLIL_UNIMPL_MEM
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
            .field("size", &self.size())
            .field("operand", &self.operand())
            .finish()
    }
}

// LLIL_CMP_X
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
            .field("size", &self.size())
            .field("left", &self.left())
            .field("right", &self.right())
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
}

impl<M, F> Debug for Operation<'_, M, F, UnimplMem>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnimplMem")
            .field("size", &self.size())
            .field("mem_expr", &self.mem_expr())
            .finish()
    }
}

// LLIL_ASSERT
pub struct Assert;

impl<M, F> Operation<'_, M, F, Assert>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[0] as u32);
        LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id).expect("Bad register ID")
    }

    pub fn constraint(&self) -> PossibleValueSet {
        self.get_constraint(1)
    }
}

impl<M, F> Debug for Operation<'_, M, F, Assert>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Assert")
            .field("size", &self.size())
            .field("source_reg", &self.source_reg())
            .field("constraint", &self.constraint())
            .finish()
    }
}

// LLIL_ASSERT_SSA
pub struct AssertSsa;

impl<M, F> Operation<'_, M, F, AssertSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[0] as u32);
        let reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id)
            .expect("Bad register ID");
        let version = self.op.operands[1] as u32;
        LowLevelILSSARegisterKind::new_full(reg_kind, version)
    }

    pub fn constraint(&self) -> PossibleValueSet {
        self.get_constraint(2)
    }
}

impl<M, F> Debug for Operation<'_, M, F, AssertSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssertSsa")
            .field("size", &self.size())
            .field("source_reg", &self.source_reg())
            .field("constraint", &self.constraint())
            .finish()
    }
}

// LLIL_FORCE_VER
pub struct ForceVersion;

impl<M, F> Operation<'_, M, F, ForceVersion>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg(&self) -> LowLevelILRegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[0] as u32);
        LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id).expect("Bad register ID")
    }
}

impl<M, F> Debug for Operation<'_, M, F, ForceVersion>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForceVersion")
            .field("size", &self.size())
            .field("dest_reg", &self.dest_reg())
            .finish()
    }
}

// LLIL_FORCE_VER_SSA
pub struct ForceVersionSsa;

impl<M, F> Operation<'_, M, F, ForceVersionSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[0] as u32);
        let reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id)
            .expect("Bad register ID");
        let version = self.op.operands[1] as u32;
        LowLevelILSSARegisterKind::new_full(reg_kind, version)
    }

    pub fn source_reg(&self) -> LowLevelILSSARegisterKind<CoreRegister> {
        let raw_id = RegisterId(self.op.operands[2] as u32);
        let reg_kind = LowLevelILRegisterKind::from_raw(&self.function.arch(), raw_id)
            .expect("Bad register ID");
        let version = self.op.operands[3] as u32;
        LowLevelILSSARegisterKind::new_full(reg_kind, version)
    }
}

impl<M, F> Debug for Operation<'_, M, F, ForceVersionSsa>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForceVersionSsa")
            .field("size", &self.size())
            .field("dest_reg", &self.dest_reg())
            .field("source_reg", &self.source_reg())
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
            .map(|val| LowLevelExpressionIndex(val as usize))
            .map(|expr_idx| LowLevelILExpression::new(self.function, expr_idx))
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
            .field("param_exprs", &self.param_exprs())
            .finish()
    }
}

// TODO TEST_BIT

pub trait OperationArguments: 'static {}

impl OperationArguments for NoArgs {}
impl OperationArguments for Pop {}
impl OperationArguments for Syscall {}
impl OperationArguments for SyscallSsa {}
impl OperationArguments for Intrinsic {}
impl OperationArguments for SetReg {}
impl OperationArguments for SetRegSsa {}
impl OperationArguments for SetRegPartialSsa {}
impl OperationArguments for SetRegSplit {}
impl OperationArguments for SetRegSplitSsa {}
impl OperationArguments for SetFlag {}
impl OperationArguments for SetFlagSsa {}
impl OperationArguments for Load {}
impl OperationArguments for LoadSsa {}
impl OperationArguments for Store {}
impl OperationArguments for StoreSsa {}
impl OperationArguments for Reg {}
impl OperationArguments for RegSsa {}
impl OperationArguments for RegPartialSsa {}
impl OperationArguments for RegSplit {}
impl OperationArguments for RegSplitSsa {}
impl OperationArguments for RegStackPush {}
impl OperationArguments for RegStackPop {}
impl OperationArguments for RegStackFreeReg {}
impl OperationArguments for Flag {}
impl OperationArguments for FlagBit {}
impl OperationArguments for Jump {}
impl OperationArguments for JumpTo {}
impl OperationArguments for Call {}
impl OperationArguments for CallSsa {}
impl OperationArguments for CallOutputSsa {}
impl OperationArguments for CallParamSsa {}
impl OperationArguments for CallStackSsa {}
impl OperationArguments for Ret {}
impl OperationArguments for If {}
impl OperationArguments for Goto {}
impl OperationArguments for FlagCond {}
impl OperationArguments for FlagGroup {}
impl OperationArguments for Trap {}
impl OperationArguments for RegPhi {}
impl OperationArguments for FlagPhi {}
impl OperationArguments for MemPhi {}
impl OperationArguments for Const {}
impl OperationArguments for FloatConst {}
impl OperationArguments for Extern {}
impl OperationArguments for BinaryOp {}
impl OperationArguments for BinaryOpCarry {}
impl OperationArguments for UnaryOp {}
impl OperationArguments for Condition {}
impl OperationArguments for UnimplMem {}
impl OperationArguments for Assert {}
impl OperationArguments for AssertSsa {}
impl OperationArguments for ForceVersion {}
impl OperationArguments for ForceVersionSsa {}
impl OperationArguments for SeparateParamListSsa {}
