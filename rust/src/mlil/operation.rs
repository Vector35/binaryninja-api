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

use binaryninjacore_sys::BNMediumLevelILInstruction;

use std::marker::PhantomData;
use std::mem;

use super::*;

pub struct Operation<'func, A, M, F, O>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    pub(crate) function: &'func Function<A, M, F>,
    pub(crate) op: BNMediumLevelILInstruction,
    _args: PhantomData<O>,
}

impl<'func, A, M, F, O> Operation<'func, A, M, F, O>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    pub(crate) fn new(function: &'func Function<A, M, F>, op: BNMediumLevelILInstruction) -> Self {
        Self {
            function: function,
            op: op,
            _args: PhantomData,
        }
    }

    pub fn address(&self) -> u64 {
        self.op.address
    }
}

// MLIL_ADD, MLIL_SUB, MLIL_AND, MLIL_OR,
// MLIL_XOR, MLIL_LSL, MLIL_LSR, MLIL_ASR,
// MLIL_ROL, MLIL_ROR, MLIL_MUL, MLIL_DIVU,
// MLIL_MODU, MLIL_ADD_OVERFLOW
pub struct ArithmeticBinaryOp;

// MLIL_DIVS, MLIL_MODS
pub struct SignedArithmeticBinaryOp;

// MLIL_MULS_DP, MLIL_DIVS_DP, MLIL_MODS_DP
pub struct SignedDoublePrecisionBinaryOp;

// MLIL_MULU_DP, MLIL_DIVU_DP, MLIL_MODU_DP
pub struct DoublePrecisionBinaryOp;

// MLIL_NEG, MLIL_NOT, MLIL_SX, MLIL_ZX
// MLIL_LOW_PART
pub struct ArithmeticUnaryOp;

// MLIL_FSQRT, MLIL_FNEG, MLIL_FABS, MLIL_FLOAT_TO_INT
// MLIL_INT_TO_FLOAT, MLIL_FLOAT_CONV, MLIL_ROUND_TO_INT, MLIL_FLOOR
// MLIL_CEIL, MLIL_FTRUNC
pub struct ArithmeticFloatingPointUnaryOp;

// MLIL_CMP_SLT, MLIL_CMP_SLE, MLIL_CMP_SGE, MLIL_CMP_SGT
pub struct SignedComparisonOp;

// MLIL_SET_VAR, MLIL_SET_VAR_FIELD, MLIL_SET_VAR_SPLIT
pub struct SetVarOp;

// MLIL_RET
pub struct ReturnOp;

// MLIL_NORET, MLIL_BP, MLIL_JUMP, MLIL_GOTO
// MLIL_TRAP, MLIL_IF, MLIL_JUMP_TO
pub struct TerminalOp;

// MLIL_FCMP_E, MLIL_FCMP_NE, MLIL_FCMP_LT, MLIL_FCMP_LE
// MLIL_FCMP_GE, MLIL_FCMP_GT, MLIL_FCMP_O, MLIL_FCMP_UO
pub struct FloatingPointComparisonOp;

// MLIL_FADD, MLIL_FSUB, MLIL_FMUL, MLIL_FDIV
pub struct ArithmeticFloatingPointBinaryOp;

// MLIL_LOAD, MLIL_LOAD_STRUCT
pub struct LoadOp;

// MLIL_STORE, MLIL_STORE_STRUCT
pub struct StoreOp;

// MLIL_CONST, MLIL_CONST_PTR, MLIL_IMPORT, MLIL_EXTERN_PTR
pub struct ConstOp;

// MLIL_FLOAT_CONST
pub struct FloatingPointConstOp;

// MLIL_ADC, MLIL_SBB, MLIL_RLC, MLIL_RRC
pub struct CarryOp;

// MLIL_TAILCALL, MLIL_TAILCALL_UNTYPED
pub struct TailcallOp;

// MLIL_SYSCALL, MLIL_SYSCALL_UNTYPED
pub struct SyscallOp;

// MLIL_CMP_E, MLIL_CMP_NE, MLIL_CMP_ULT, MLIL_CMP_ULE
// MLIL_CMP_UGE, MLIL_CMP_UGT, MLIL_TEST_BIT
pub struct ComparisonOp;

// MLIL_CALL, MLIL_CALL_UNTYPED
pub struct LocalcallOp;

// MLIL_UNIMPL_MEM
pub struct MemoryOp;

// MLIL_RET_HINT
pub struct ControlFlowOp;

// MLIL_INTRINSIC
pub struct IntrinsicOp;

// MLIL_FREE_VAR_SLOT
pub struct RegisterStackOp;

// MLIL_NOP, MLIL_VAR, MLIL_VAR_FIELD, MLIL_VAR_SPLIT
// MLIL_ADDRESS_OF, MLIL_ADDRESS_OF_FIELD, MLIL_CALL_OUTPUT, MLIL_CALL_PARAM
// MLIL_BOOL_TO_INT, MLIL_UNDEF, MLIL_UNIMPL
pub struct MediumLevelInstructionOp;

pub struct NoArgs;

pub struct Syscall;

pub struct Load;

pub struct Store;

pub struct Jump;

pub struct JumpTo;

pub struct Call;

pub struct Ret;

pub struct If;

pub struct Goto;

pub struct Trap;

pub struct Const;

// MLIL_ADD
pub struct BinaryOp;

pub struct BinaryOpCarry;

pub struct DoublePrecDivOp;

pub struct UnaryOp;

pub struct Condition;

pub struct UnimplMem;

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
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }
}

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
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }

    pub fn source_expr(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[1] as usize,
            _ty: PhantomData,
        }
    }
}

impl<'func, A, M, F> Operation<'func, A, M, F, Jump>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }
}

impl<'func, A, M, F> Operation<'func, A, M, F, JumpTo>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }
    // TODO target list
}

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, Call>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn target(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }
}

impl<'func, A, M, F> Operation<'func, A, M, F, Ret>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn target(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }
}

impl<'func, A, M, F> Operation<'func, A, M, F, If>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn condition(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }

    pub fn true_target(&self) -> Instruction<'func, A, M, F> {
        Instruction {
            function: self.function,
            instr_idx: self.op.operands[1] as usize,
        }
    }

    pub fn false_target(&self) -> Instruction<'func, A, M, F> {
        Instruction {
            function: self.function,
            instr_idx: self.op.operands[2] as usize,
        }
    }
}

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
}

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
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }

    pub fn right(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[1] as usize,
            _ty: PhantomData,
        }
    }
}

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
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }

    pub fn right(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[1] as usize,
            _ty: PhantomData,
        }
    }

    pub fn carry(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[2] as usize,
            _ty: PhantomData,
        }
    }
}

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
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }

    pub fn low(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[1] as usize,
            _ty: PhantomData,
        }
    }

    pub fn right(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[2] as usize,
            _ty: PhantomData,
        }
    }
}

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
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }
}

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
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }

    pub fn right(&self) -> Expression<'func, A, M, F, ValueExpr> {
        Expression {
            function: self.function,
            expr_idx: self.op.operands[1] as usize,
            _ty: PhantomData,
        }
    }
}

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
        Expression {
            function: self.function,
            expr_idx: self.op.operands[0] as usize,
            _ty: PhantomData,
        }
    }
}

pub trait OperationArguments: 'static {}

impl OperationArguments for NoArgs {}

impl OperationArguments for Syscall {}

impl OperationArguments for Load {}

impl OperationArguments for Store {}

impl OperationArguments for Jump {}

impl OperationArguments for JumpTo {}

impl OperationArguments for Call {}

impl OperationArguments for Ret {}

impl OperationArguments for If {}

impl OperationArguments for Goto {}

impl OperationArguments for Trap {}

impl OperationArguments for Const {}

impl OperationArguments for BinaryOp {}

impl OperationArguments for BinaryOpCarry {}

impl OperationArguments for DoublePrecDivOp {}

impl OperationArguments for UnaryOp {}

impl OperationArguments for Condition {}

impl OperationArguments for UnimplMem {}
