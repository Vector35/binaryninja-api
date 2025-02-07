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

use binaryninjacore_sys::{BNGetLowLevelILByIndex, BNLowLevelILInstruction};

use super::*;
use crate::architecture::{FlagGroupId, FlagId, FlagWriteId, IntrinsicId, RegisterStackId};
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::mem;

pub struct Operation<'func, A, M, F, O>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    pub(crate) function: &'func LowLevelILFunction<A, M, F>,
    pub(crate) op: BNLowLevelILInstruction,
    _args: PhantomData<O>,
}

impl<'func, A, M, F, O> Operation<'func, A, M, F, O>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    pub(crate) fn new(
        function: &'func LowLevelILFunction<A, M, F>,
        op: BNLowLevelILInstruction,
    ) -> Self {
        Self {
            function,
            op,
            _args: PhantomData,
        }
    }

    pub fn address(&self) -> u64 {
        self.op.address
    }
}

impl<A, M, O> Operation<'_, A, M, NonSSA<LiftedNonSSA>, O>
where
    A: Architecture,
    M: FunctionMutability,
    O: OperationArguments,
{
    pub fn flag_write(&self) -> Option<A::FlagWrite> {
        match self.op.flags {
            0 => None,
            id => self.function.arch().flag_write_from_id(FlagWriteId(id)),
        }
    }
}

// LLIL_NOP, LLIL_NORET, LLIL_BP, LLIL_UNDEF, LLIL_UNIMPL
pub struct NoArgs;

impl<A, M, F> Debug for Operation<'_, A, M, F, NoArgs>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoArgs").finish()
    }
}

// LLIL_POP
pub struct Pop;

impl<A, M, F> Operation<'_, A, M, F, Pop>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, Pop>
where
    A: Architecture,
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

// LLIL_SYSCALL, LLIL_SYSCALL_SSA
pub struct Syscall;

impl<A, M, F> Debug for Operation<'_, A, M, F, Syscall>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Syscall").finish()
    }
}

// LLIL_INTRINSIC, LLIL_INTRINSIC_SSA
pub struct Intrinsic;

impl<A, M, F> Operation<'_, A, M, F, Intrinsic>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    // TODO: Support register and expression lists
    pub fn intrinsic(&self) -> Option<A::Intrinsic> {
        let raw_id = self.op.operands[2] as u32;
        self.function.arch().intrinsic_from_id(IntrinsicId(raw_id))
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, Intrinsic>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Intrinsic")
            .field("address", &self.address())
            .field("size", &self.intrinsic())
            .finish()
    }
}

// LLIL_SET_REG, LLIL_SET_REG_SSA, LLIL_SET_REG_PARTIAL_SSA
pub struct SetReg;

impl<'func, A, M, F> Operation<'func, A, M, F, SetReg>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg(&self) -> LowLevelILRegister<A::Register> {
        let raw_id = self.op.operands[0] as u32;

        if raw_id >= 0x8000_0000 {
            LowLevelILRegister::Temp(raw_id & 0x7fff_ffff)
        } else {
            self.function
                .arch()
                .register_from_id(RegisterId(raw_id))
                .map(LowLevelILRegister::ArchReg)
                .unwrap_or_else(|| {
                    log::error!(
                        "got garbage register from LLIL_SET_REG @ 0x{:x}",
                        self.op.address
                    );

                    LowLevelILRegister::Temp(0)
                })
        }
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, SetReg>
where
    A: Architecture,
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

// LLIL_SET_REG_SPLIT, LLIL_SET_REG_SPLIT_SSA
pub struct SetRegSplit;

impl<'func, A, M, F> Operation<'func, A, M, F, SetRegSplit>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg_high(&self) -> LowLevelILRegister<A::Register> {
        let raw_id = self.op.operands[0] as u32;

        if raw_id >= 0x8000_0000 {
            LowLevelILRegister::Temp(raw_id & 0x7fff_ffff)
        } else {
            self.function
                .arch()
                .register_from_id(RegisterId(raw_id))
                .map(LowLevelILRegister::ArchReg)
                .unwrap_or_else(|| {
                    log::error!(
                        "got garbage register from LLIL_SET_REG_SPLIT @ 0x{:x}",
                        self.op.address
                    );

                    LowLevelILRegister::Temp(0)
                })
        }
    }

    pub fn dest_reg_low(&self) -> LowLevelILRegister<A::Register> {
        let raw_id = self.op.operands[1] as u32;

        if raw_id >= 0x8000_0000 {
            LowLevelILRegister::Temp(raw_id & 0x7fff_ffff)
        } else {
            self.function
                .arch()
                .register_from_id(RegisterId(raw_id))
                .map(LowLevelILRegister::ArchReg)
                .unwrap_or_else(|| {
                    log::error!(
                        "got garbage register from LLIL_SET_REG_SPLIT @ 0x{:x}",
                        self.op.address
                    );

                    LowLevelILRegister::Temp(0)
                })
        }
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, SetRegSplit>
where
    A: Architecture,
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

// LLIL_SET_FLAG, LLIL_SET_FLAG_SSA
pub struct SetFlag;

impl<'func, A, M, F> Operation<'func, A, M, F, SetFlag>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest_flag(&self) -> A::Flag {
        // TODO: Error handling?
        // TODO: Test this.
        self.function
            .arch()
            .flag_from_id(FlagId(self.op.operands[0] as u32))
            .unwrap()
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, SetFlag>
where
    A: Architecture,
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

// LLIL_LOAD, LLIL_LOAD_SSA
pub struct Load;

impl<'func, A, M, F> Operation<'func, A, M, F, Load>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_mem_expr(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, Load>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Load")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("source_mem_expr", &self.source_mem_expr())
            .finish()
    }
}

// LLIL_STORE, LLIL_STORE_SSA
pub struct Store;

impl<'func, A, M, F> Operation<'func, A, M, F, Store>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_mem_expr(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, Store>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("address", &self.address())
            .field("size", &self.size())
            .field("dest_mem_expr", &self.dest_mem_expr())
            .field("source_expr", &self.source_expr())
            .finish()
    }
}

// LLIL_REG, LLIL_REG_SSA, LLIL_REG_SSA_PARTIAL
pub struct Reg;

impl<A, M, F> Operation<'_, A, M, F, Reg>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg(&self) -> LowLevelILRegister<A::Register> {
        let raw_id = self.op.operands[0] as u32;

        if raw_id >= 0x8000_0000 {
            LowLevelILRegister::Temp(raw_id & 0x7fff_ffff)
        } else {
            self.function
                .arch()
                .register_from_id(RegisterId(raw_id))
                .map(LowLevelILRegister::ArchReg)
                .unwrap_or_else(|| {
                    log::error!(
                        "got garbage register from LLIL_REG @ 0x{:x}",
                        self.op.address
                    );

                    LowLevelILRegister::Temp(0)
                })
        }
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, Reg>
where
    A: Architecture,
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

// LLIL_REG_SPLIT, LLIL_REG_SPLIT_SSA
pub struct RegSplit;

impl<A, M, F> Operation<'_, A, M, F, RegSplit>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn low_reg(&self) -> LowLevelILRegister<A::Register> {
        let raw_id = self.op.operands[0] as u32;

        if raw_id >= 0x8000_0000 {
            LowLevelILRegister::Temp(raw_id & 0x7fff_ffff)
        } else {
            self.function
                .arch()
                .register_from_id(RegisterId(raw_id))
                .map(LowLevelILRegister::ArchReg)
                .unwrap_or_else(|| {
                    log::error!(
                        "got garbage register from LLIL_REG @ 0x{:x}",
                        self.op.address
                    );

                    LowLevelILRegister::Temp(0)
                })
        }
    }

    pub fn high_reg(&self) -> LowLevelILRegister<A::Register> {
        let raw_id = self.op.operands[1] as u32;

        if raw_id >= 0x8000_0000 {
            LowLevelILRegister::Temp(raw_id & 0x7fff_ffff)
        } else {
            self.function
                .arch()
                .register_from_id(RegisterId(raw_id))
                .map(LowLevelILRegister::ArchReg)
                .unwrap_or_else(|| {
                    log::error!(
                        "got garbage register from LLIL_REG @ 0x{:x}",
                        self.op.address
                    );

                    LowLevelILRegister::Temp(0)
                })
        }
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, RegSplit>
where
    A: Architecture,
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

// LLIL_REG_STACK_PUSH
pub struct RegStackPush;

impl<'func, A, M, F> Operation<'func, A, M, F, RegStackPush>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg_stack(&self) -> A::RegisterStack {
        let raw_id = self.op.operands[0] as u32;
        self.function
            .arch()
            .register_stack_from_id(RegisterStackId(raw_id))
            .expect("Bad register stack ID")
    }

    pub fn source_expr(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, RegStackPush>
where
    A: Architecture,
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

impl<A, M, F> Operation<'_, A, M, F, RegStackPop>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg_stack(&self) -> A::RegisterStack {
        let raw_id = self.op.operands[0] as u32;
        self.function
            .arch()
            .register_stack_from_id(RegisterStackId(raw_id))
            .expect("Bad register stack ID")
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, RegStackPop>
where
    A: Architecture,
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

// LLIL_FLAG, LLIL_FLAG_SSA
pub struct Flag;

impl<A, M, F> Debug for Operation<'_, A, M, F, Flag>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flag").finish()
    }
}

// LLIL_FLAG_BIT, LLIL_FLAG_BIT_SSA
pub struct FlagBit;

impl<A, M, F> Debug for Operation<'_, A, M, F, FlagBit>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagBit").finish()
    }
}

// LLIL_JUMP
pub struct Jump;

impl<'func, A, M, F> Operation<'func, A, M, F, Jump>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, Jump>
where
    A: Architecture,
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

struct TargetListIter<'func, A, M, F>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    function: &'func LowLevelILFunction<A, M, F>,
    cursor: BNLowLevelILInstruction,
    cursor_operand: usize,
}

impl<A, M, F> TargetListIter<'_, A, M, F>
where
    A: Architecture,
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

impl<'func, A, M, F> Operation<'func, A, M, F, JumpTo>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
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

impl<A, M, F> Debug for Operation<'_, A, M, F, JumpTo>
where
    A: Architecture,
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

// LLIL_CALL, LLIL_CALL_SSA
pub struct Call;

impl<'func, A, M, F> Operation<'func, A, M, F, Call>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
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

impl<A, M, F> Debug for Operation<'_, A, M, F, Call>
where
    A: Architecture,
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

// LLIL_RET
pub struct Ret;

impl<'func, A, M, F> Operation<'func, A, M, F, Ret>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, Ret>
where
    A: Architecture,
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

impl<'func, A, M, F> Operation<'func, A, M, F, If>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn condition(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn true_target(&self) -> LowLevelILInstruction<'func, A, M, F> {
        LowLevelILInstruction::new(
            self.function,
            LowLevelInstructionIndex(self.op.operands[1] as usize),
        )
    }

    pub fn false_target(&self) -> LowLevelILInstruction<'func, A, M, F> {
        LowLevelILInstruction::new(
            self.function,
            LowLevelInstructionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, If>
where
    A: Architecture,
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

impl<'func, A, M, F> Operation<'func, A, M, F, Goto>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> LowLevelILInstruction<'func, A, M, F> {
        LowLevelILInstruction::new(
            self.function,
            LowLevelInstructionIndex(self.op.operands[0] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, Goto>
where
    A: Architecture,
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

impl<A, M, F> Debug for Operation<'_, A, M, F, FlagCond>
where
    A: Architecture,
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

impl<A, M> Operation<'_, A, M, NonSSA<LiftedNonSSA>, FlagGroup>
where
    A: Architecture,
    M: FunctionMutability,
{
    pub fn flag_group(&self) -> A::FlagGroup {
        let id = self.op.operands[0] as u32;
        self.function
            .arch()
            .flag_group_from_id(FlagGroupId(id))
            .unwrap()
    }
}

impl<A, M> Debug for Operation<'_, A, M, NonSSA<LiftedNonSSA>, FlagGroup>
where
    A: Architecture,
    M: FunctionMutability,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagGroup")
            .field("flag_group", &self.flag_group())
            .finish()
    }
}

impl<A, M> Debug for Operation<'_, A, M, SSA, FlagGroup>
where
    A: Architecture,
    M: FunctionMutability,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagGroup").finish()
    }
}

// LLIL_TRAP
pub struct Trap;

impl<A, M, F> Operation<'_, A, M, F, Trap>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn vector(&self) -> u64 {
        self.op.operands[0]
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, Trap>
where
    A: Architecture,
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

impl<A, M, F> Debug for Operation<'_, A, M, F, RegPhi>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegPhi").finish()
    }
}

// LLIL_FLAG_PHI
pub struct FlagPhi;

impl<A, M, F> Debug for Operation<'_, A, M, F, FlagPhi>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagPhi").finish()
    }
}

// LLIL_MEM_PHI
pub struct MemPhi;

impl<A, M, F> Debug for Operation<'_, A, M, F, MemPhi>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemPhi").finish()
    }
}

// LLIL_CONST, LLIL_CONST_PTR
pub struct Const;

impl<A, M, F> Operation<'_, A, M, F, Const>
where
    A: Architecture,
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
                log::error!(
                    "il expr @ {:x} contains constant 0x{:x} as {} byte value (doesn't fit!)",
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

impl<A, M, F> Debug for Operation<'_, A, M, F, Const>
where
    A: Architecture,
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

// LLIL_EXTERN_PTR
pub struct Extern;

impl<A, M, F> Operation<'_, A, M, F, Extern>
where
    A: Architecture,
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
                log::error!(
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

impl<A, M, F> Debug for Operation<'_, A, M, F, Extern>
where
    A: Architecture,
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

impl<'func, A, M, F> Operation<'func, A, M, F, BinaryOp>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn left(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn right(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, BinaryOp>
where
    A: Architecture,
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

impl<'func, A, M, F> Operation<'func, A, M, F, BinaryOpCarry>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn left(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn right(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }

    pub fn carry(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, BinaryOpCarry>
where
    A: Architecture,
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

// LLIL_DIVS_DP, LLIL_DIVU_DP, LLIL_MODU_DP, LLIL_MODS_DP
pub struct DoublePrecDivOp;

impl<'func, A, M, F> Operation<'func, A, M, F, DoublePrecDivOp>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn high(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn low(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }

    // TODO: I don't think this actually exists?
    pub fn right(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[2] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, DoublePrecDivOp>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DoublePrecDivOp")
            .field("size", &self.size())
            .field("high", &self.high())
            .field("low", &self.low())
            // TODO: I don't think this actually is used...
            .field("right", &self.right())
            .finish()
    }
}

// LLIL_PUSH, LLIL_NEG, LLIL_NOT, LLIL_SX,
// LLIL_ZX, LLIL_LOW_PART, LLIL_BOOL_TO_INT, LLIL_UNIMPL_MEM
pub struct UnaryOp;

impl<'func, A, M, F> Operation<'func, A, M, F, UnaryOp>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn operand(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, UnaryOp>
where
    A: Architecture,
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

impl<'func, A, M, F> Operation<'func, A, M, F, Condition>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn left(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }

    pub fn right(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[1] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, Condition>
where
    A: Architecture,
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

impl<'func, A, M, F> Operation<'func, A, M, F, UnimplMem>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn mem_expr(&self) -> LowLevelILExpression<'func, A, M, F, ValueExpr> {
        LowLevelILExpression::new(
            self.function,
            LowLevelExpressionIndex(self.op.operands[0] as usize),
        )
    }
}

impl<A, M, F> Debug for Operation<'_, A, M, F, UnimplMem>
where
    A: Architecture,
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

// TODO TEST_BIT

pub trait OperationArguments: 'static {}

impl OperationArguments for NoArgs {}
impl OperationArguments for Pop {}
impl OperationArguments for Syscall {}
impl OperationArguments for Intrinsic {}
impl OperationArguments for SetReg {}
impl OperationArguments for SetRegSplit {}
impl OperationArguments for SetFlag {}
impl OperationArguments for Load {}
impl OperationArguments for Store {}
impl OperationArguments for Reg {}
impl OperationArguments for RegSplit {}
impl OperationArguments for RegStackPush {}
impl OperationArguments for RegStackPop {}
impl OperationArguments for Flag {}
impl OperationArguments for FlagBit {}
impl OperationArguments for Jump {}
impl OperationArguments for JumpTo {}
impl OperationArguments for Call {}
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
impl OperationArguments for Extern {}
impl OperationArguments for BinaryOp {}
impl OperationArguments for BinaryOpCarry {}
impl OperationArguments for DoublePrecDivOp {}
impl OperationArguments for UnaryOp {}
impl OperationArguments for Condition {}
impl OperationArguments for UnimplMem {}
