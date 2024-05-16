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

use binaryninjacore_sys::BNLowLevelILInstruction;

use std::marker::PhantomData;
use std::mem;

use crate::architecture::{FlagGroupId, FlagWriteId, IntrinsicId};

use super::*;

pub struct Operation<'func, A, M, F, O>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    pub(crate) function: &'func Function<A, M, F>,
    pub(crate) op: BNLowLevelILInstruction,
    _args: PhantomData<O>,
}

impl<'func, A, M, F, O> Operation<'func, A, M, F, O>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    pub(crate) fn new(function: &'func Function<A, M, F>, op: BNLowLevelILInstruction) -> Self {
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

impl<'func, A, M, O> Operation<'func, A, M, NonSSA<LiftedNonSSA>, O>
where
    A: 'func + Architecture,
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

// LLIL_POP
pub struct Pop;

impl<'func, A, M, F> Operation<'func, A, M, F, Pop>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }
}

// LLIL_SYSCALL, LLIL_SYSCALL_SSA
pub struct Syscall;

// LLIL_INTRINSIC, LLIL_INTRINSIC_SSA
pub struct Intrinsic;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, Intrinsic>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    // TODO: Support register and expression lists
    pub fn intrinsic(&self) -> Option<A::Intrinsic> {
        let raw_id = self.op.operands[2] as u32;
        self.function.arch().intrinsic_from_id(IntrinsicId(raw_id))
    }
}

// LLIL_SET_REG, LLIL_SET_REG_SSA, LLIL_SET_REG_PARTIAL_SSA
pub struct SetReg;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, SetReg>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg(&self) -> Register<A::Register> {
        let raw_id = self.op.operands[0] as u32;

        if raw_id >= 0x8000_0000 {
            Register::Temp(raw_id & 0x7fff_ffff)
        } else {
            self.function
                .arch()
                .register_from_id(RegisterId(raw_id))
                .map(Register::ArchReg)
                .unwrap_or_else(|| {
                    error!(
                        "got garbage register from LLIL_SET_REG @ 0x{:x}",
                        self.op.address
                    );

                    Register::Temp(0)
                })
        }
    }

    pub fn source_expr(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        Expression::new(self.function, self.op.operands[1] as usize)
    }
}

// LLIL_SET_REG_SPLIT, LLIL_SET_REG_SPLIT_SSA
pub struct SetRegSplit;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, SetRegSplit>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_reg_high(&self) -> Register<A::Register> {
        let raw_id = self.op.operands[0] as u32;

        if raw_id >= 0x8000_0000 {
            Register::Temp(raw_id & 0x7fff_ffff)
        } else {
            self.function
                .arch()
                .register_from_id(RegisterId(raw_id))
                .map(Register::ArchReg)
                .unwrap_or_else(|| {
                    error!(
                        "got garbage register from LLIL_SET_REG_SPLIT @ 0x{:x}",
                        self.op.address
                    );

                    Register::Temp(0)
                })
        }
    }

    pub fn dest_reg_low(&self) -> Register<A::Register> {
        let raw_id = self.op.operands[1] as u32;

        if raw_id >= 0x8000_0000 {
            Register::Temp(raw_id & 0x7fff_ffff)
        } else {
            self.function
                .arch()
                .register_from_id(RegisterId(raw_id))
                .map(Register::ArchReg)
                .unwrap_or_else(|| {
                    error!(
                        "got garbage register from LLIL_SET_REG_SPLIT @ 0x{:x}",
                        self.op.address
                    );

                    Register::Temp(0)
                })
        }
    }

    pub fn source_expr(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        Expression::new(self.function, self.op.operands[2] as usize)
    }
}

// LLIL_SET_FLAG, LLIL_SET_FLAG_SSA
pub struct SetFlag;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, SetFlag>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn source_expr(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        Expression::new(self.function, self.op.operands[1] as usize)
    }
}

// LLIL_LOAD, LLIL_LOAD_SSA
pub struct Load;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, Load>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_mem_expr(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
    }
}

// LLIL_STORE, LLIL_STORE_SSA
pub struct Store;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, Store>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn dest_mem_expr(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
    }

    pub fn source_expr(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        Expression::new(self.function, self.op.operands[1] as usize)
    }
}

// LLIL_REG, LLIL_REG_SSA, LLIL_REG_SSA_PARTIAL
pub struct Reg;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, Reg>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn source_reg(&self) -> Register<A::Register> {
        let raw_id = self.op.operands[0] as u32;

        if raw_id >= 0x8000_0000 {
            Register::Temp(raw_id & 0x7fff_ffff)
        } else {
            self.function
                .arch()
                .register_from_id(RegisterId(raw_id))
                .map(Register::ArchReg)
                .unwrap_or_else(|| {
                    error!(
                        "got garbage register from LLIL_REG @ 0x{:x}",
                        self.op.address
                    );

                    Register::Temp(0)
                })
        }
    }
}

// LLIL_FLAG, LLIL_FLAG_SSA
pub struct Flag;

// LLIL_FLAG_BIT, LLIL_FLAG_BIT_SSA
pub struct FlagBit;

// LLIL_JUMP
pub struct Jump;

impl<'func, A, M, F> Operation<'func, A, M, F, Jump>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
    }
}

// LLIL_JUMP_TO
pub struct JumpTo;

impl<'func, A, M, F> Operation<'func, A, M, F, JumpTo>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
    }
    // TODO target list
}

// LLIL_CALL, LLIL_CALL_SSA
pub struct Call;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, Call>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn target(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
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

// LLIL_RET
pub struct Ret;

impl<'func, A, M, F> Operation<'func, A, M, F, Ret>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
    }
}

// LLIL_IF
pub struct If;

impl<'func, A, M, F> Operation<'func, A, M, F, If>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn condition(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
    }

    pub fn true_target(&self) -> Instruction<'func, A, M, F> {
        Instruction {
            function: self.function,
            instr_idx: self.op.operands[1] as usize,
        }
    }

    pub fn true_target_idx(&self) -> usize {
        self.op.operands[1] as usize
    }

    pub fn false_target(&self) -> Instruction<'func, A, M, F> {
        Instruction {
            function: self.function,
            instr_idx: self.op.operands[2] as usize,
        }
    }

    pub fn false_target_idx(&self) -> usize {
        self.op.operands[2] as usize
    }
}

// LLIL_GOTO
pub struct Goto;

impl<'func, A, M, F> Operation<'func, A, M, F, Goto>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> Instruction<'func, A, M, F> {
        Instruction {
            function: self.function,
            instr_idx: self.op.operands[0] as usize,
        }
    }

    pub fn target_idx(&self) -> usize {
        self.op.operands[0] as usize
    }
}

// LLIL_FLAG_COND
pub struct FlagCond;

// LLIL_FLAG_GROUP
pub struct FlagGroup;

impl<'func, A, M> Operation<'func, A, M, NonSSA<LiftedNonSSA>, FlagGroup>
where
    A: 'func + Architecture,
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

// LLIL_TRAP
pub struct Trap;

impl<'func, A, M, F> Operation<'func, A, M, F, Trap>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn vector(&self) -> u64 {
        self.op.operands[0]
    }
}

// LLIL_REG_PHI
pub struct RegPhi;

// LLIL_FLAG_PHI
pub struct FlagPhi;

// LLIL_MEM_PHI
pub struct MemPhi;

// LLIL_CONST, LLIL_CONST_PTR
pub struct Const;

impl<'func, A, M, F> Operation<'func, A, M, F, Const>
where
    A: 'func + Architecture,
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
                error!(
                    "il expr @ {:x} contains constant 0x{:x} as {} byte value (doesn't fit!)",
                    self.op.address, self.op.operands[0], self.op.size
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

// LLIL_ADD, LLIL_SUB, LLIL_AND, LLIL_OR
// LLIL_XOR, LLIL_LSL, LLIL_LSR, LLIL_ASR
// LLIL_ROL, LLIL_ROR, LLIL_MUL, LLIL_MULU_DP,
// LLIL_MULS_DP, LLIL_DIVU, LLIL_DIVS, LLIL_MODU,
// LLIL_MODS
pub struct BinaryOp;

impl<'func, A, M, F> Operation<'func, A, M, F, BinaryOp>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn left(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
    }

    pub fn right(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[1] as usize)
    }
}

// LLIL_ADC, LLIL_SBB, LLIL_RLC, LLIL_RRC
pub struct BinaryOpCarry;

impl<'func, A, M, F> Operation<'func, A, M, F, BinaryOpCarry>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn left(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
    }

    pub fn right(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[1] as usize)
    }

    pub fn carry(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[2] as usize)
    }
}

// LLIL_DIVS_DP, LLIL_DIVU_DP, LLIL_MODU_DP, LLIL_MODS_DP
pub struct DoublePrecDivOp;

impl<'func, A, M, F> Operation<'func, A, M, F, DoublePrecDivOp>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn high(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
    }

    pub fn low(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[1] as usize)
    }

    pub fn right(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[2] as usize)
    }
}

// LLIL_PUSH, LLIL_NEG, LLIL_NOT, LLIL_SX,
// LLIL_ZX, LLIL_LOW_PART, LLIL_BOOL_TO_INT, LLIL_UNIMPL_MEM
pub struct UnaryOp;

impl<'func, A, M, F> Operation<'func, A, M, F, UnaryOp>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn operand(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
    }
}

// LLIL_CMP_X
pub struct Condition;

impl<'func, A, M, F> Operation<'func, A, M, F, Condition>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn left(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
    }

    pub fn right(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[1] as usize)
    }
}

// LLIL_UNIMPL_MEM
pub struct UnimplMem;

impl<'func, A, M, F> Operation<'func, A, M, F, UnimplMem>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn size(&self) -> usize {
        self.op.size
    }

    pub fn mem_expr(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[0] as usize)
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
impl OperationArguments for BinaryOp {}
impl OperationArguments for BinaryOpCarry {}
impl OperationArguments for DoublePrecDivOp {}
impl OperationArguments for UnaryOp {}
impl OperationArguments for Condition {}
impl OperationArguments for UnimplMem {}
