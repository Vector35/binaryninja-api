use super::lift::*;
use super::operation::*;
use super::{MediumLevelILBlock, MediumLevelILFunction};
use crate::architecture::{CoreIntrinsic, FlagId, IntrinsicId, RegisterId};
use crate::basic_block::BasicBlock;
use crate::confidence::Conf;
use crate::disassembly::InstructionTextToken;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::types::Type;
use crate::variable::{ConstantData, PossibleValueSet, RegisterValue, SSAVariable, Variable};
use crate::{DataFlowQueryOption, ILBranchDependence};
use binaryninjacore_sys::*;
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MediumLevelInstructionIndex(pub usize);

impl MediumLevelInstructionIndex {
    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<usize> for MediumLevelInstructionIndex {
    fn from(index: usize) -> Self {
        Self(index)
    }
}

impl From<u64> for MediumLevelInstructionIndex {
    fn from(index: u64) -> Self {
        Self(index as usize)
    }
}

impl Display for MediumLevelInstructionIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MediumLevelExpressionIndex(pub usize);

impl MediumLevelExpressionIndex {
    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<usize> for MediumLevelExpressionIndex {
    fn from(index: usize) -> Self {
        Self(index)
    }
}

impl From<u64> for MediumLevelExpressionIndex {
    fn from(index: u64) -> Self {
        Self(index as usize)
    }
}

impl Display for MediumLevelExpressionIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

#[derive(Clone)]
pub struct MediumLevelILInstruction {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub instr_index: MediumLevelInstructionIndex,
    pub expr_index: MediumLevelExpressionIndex,
    pub size: usize,
    pub kind: MediumLevelILInstructionKind,
}

impl MediumLevelILInstruction {
    pub(crate) fn from_instr_index(
        function: Ref<MediumLevelILFunction>,
        instr_index: MediumLevelInstructionIndex,
    ) -> Self {
        // Get the associated expression index for the top-level instruction.
        let expr_index_raw =
            unsafe { BNGetMediumLevelILIndexForInstruction(function.handle, instr_index.0) };
        Self::new(
            function,
            instr_index,
            MediumLevelExpressionIndex(expr_index_raw),
        )
    }

    pub(crate) fn from_expr_index(
        function: Ref<MediumLevelILFunction>,
        expr_index: MediumLevelExpressionIndex,
    ) -> Self {
        // Get the associated top-level instruction index for the expression.
        let instr_index_raw =
            unsafe { BNGetMediumLevelILInstructionForExpr(function.handle, expr_index.0) };
        Self::new(
            function,
            MediumLevelInstructionIndex(instr_index_raw),
            expr_index,
        )
    }

    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        instr_index: MediumLevelInstructionIndex,
        expr_index: MediumLevelExpressionIndex,
    ) -> Self {
        // TODO: If op.sourceOperation == BN_INVALID_OPERAND && op.operation == MLIL_NOP return None
        let op = unsafe { BNGetMediumLevelILByIndex(function.handle, expr_index.0) };
        use BNMediumLevelILOperation::*;
        use MediumLevelILInstructionKind as Op;
        let kind = match op.operation {
            // BEGIN GENERATED mlil-decode: from api/il, do not edit
            MLIL_NOP => Op::Nop,
            MLIL_SET_VAR => Op::SetVar(SetVar {
                dest: get_var(op.operands[0]),
                src: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_SET_VAR_FIELD => Op::SetVarField(SetVarField {
                dest: get_var(op.operands[0]),
                offset: op.operands[1],
                src: MediumLevelExpressionIndex::from(op.operands[2]),
            }),
            MLIL_SET_VAR_SPLIT => Op::SetVarSplit(SetVarSplit {
                high: get_var(op.operands[0]),
                low: get_var(op.operands[1]),
                src: MediumLevelExpressionIndex::from(op.operands[2]),
            }),
            MLIL_ASSERT => Op::Assert(Assert {
                src: get_var(op.operands[0]),
                constraint_index: op.operands[1] as usize,
            }),
            MLIL_FORCE_VER => Op::ForceVer(ForceVer {
                dest: get_var(op.operands[0]),
                src: get_var(op.operands[1]),
                reason: unsafe {
                    std::mem::transmute::<u8, ForceVersionReason>(op.operands[2] as u8)
                },
            }),
            MLIL_LOAD => Op::Load(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_LOAD_STRUCT => Op::LoadStruct(LoadStruct {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
                offset: op.operands[1],
            }),
            MLIL_STORE => Op::Store(Store {
                dest: MediumLevelExpressionIndex::from(op.operands[0]),
                src: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_STORE_STRUCT => Op::StoreStruct(StoreStruct {
                dest: MediumLevelExpressionIndex::from(op.operands[0]),
                offset: op.operands[1],
                src: MediumLevelExpressionIndex::from(op.operands[2]),
            }),
            MLIL_VAR => Op::Var(Var {
                src: get_var(op.operands[0]),
            }),
            MLIL_VAR_FIELD => Op::VarField(Field {
                src: get_var(op.operands[0]),
                offset: op.operands[1],
            }),
            MLIL_VAR_SPLIT => Op::VarSplit(VarSplit {
                high: get_var(op.operands[0]),
                low: get_var(op.operands[1]),
            }),
            MLIL_ADDRESS_OF => Op::AddressOf(Var {
                src: get_var(op.operands[0]),
            }),
            MLIL_ADDRESS_OF_FIELD => Op::AddressOfField(Field {
                src: get_var(op.operands[0]),
                offset: op.operands[1],
            }),
            MLIL_PASS_BY_REF => Op::PassByRef(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_RETURN_BY_REF => Op::ReturnByRef(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_CONST => Op::Const(Constant {
                constant: op.operands[0],
            }),
            MLIL_CONST_DATA => Op::ConstData(ConstData {
                constant_data_kind: op.operands[0] as u32,
                constant_data_value: op.operands[1] as i64,
                size: op.size,
            }),
            MLIL_CONST_PTR => Op::ConstPtr(Constant {
                constant: op.operands[0],
            }),
            MLIL_EXTERN_PTR => Op::ExternPtr(ExternPtr {
                constant: op.operands[0],
                offset: op.operands[1],
            }),
            MLIL_FLOAT_CONST => Op::FloatConst(FloatConst {
                constant: get_float(op.operands[0], op.size),
            }),
            MLIL_IMPORT => Op::Import(Constant {
                constant: op.operands[0],
            }),
            MLIL_ADD => Op::Add(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_ADC => Op::Adc(BinaryOpCarry {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
                carry: MediumLevelExpressionIndex::from(op.operands[2]),
            }),
            MLIL_SUB => Op::Sub(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_SBB => Op::Sbb(BinaryOpCarry {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
                carry: MediumLevelExpressionIndex::from(op.operands[2]),
            }),
            MLIL_AND => Op::And(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_OR => Op::Or(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_XOR => Op::Xor(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_LSL => Op::Lsl(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_LSR => Op::Lsr(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_ASR => Op::Asr(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_ROL => Op::Rol(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_RLC => Op::Rlc(BinaryOpCarry {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
                carry: MediumLevelExpressionIndex::from(op.operands[2]),
            }),
            MLIL_ROR => Op::Ror(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_RRC => Op::Rrc(BinaryOpCarry {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
                carry: MediumLevelExpressionIndex::from(op.operands[2]),
            }),
            MLIL_MUL => Op::Mul(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_MULU_DP => Op::MuluDp(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_MULS_DP => Op::MulsDp(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_DIVU => Op::Divu(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_DIVU_DP => Op::DivuDp(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_DIVS => Op::Divs(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_DIVS_DP => Op::DivsDp(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_MODU => Op::Modu(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_MODU_DP => Op::ModuDp(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_MODS => Op::Mods(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_MODS_DP => Op::ModsDp(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_NEG => Op::Neg(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_NOT => Op::Not(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_SX => Op::Sx(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_ZX => Op::Zx(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_LOW_PART => Op::LowPart(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_JUMP => Op::Jump(Jump {
                dest: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_JUMP_TO => Op::JumpTo(JumpTo {
                dest: MediumLevelExpressionIndex::from(op.operands[0]),
                first_operand: op.operands[2] as usize,
                num_operands: op.operands[1] as usize,
            }),
            MLIL_RET_HINT => Op::RetHint(Jump {
                dest: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_CALL => Op::Call(Call {
                first_output: op.operands[1] as usize,
                num_outputs: op.operands[0] as usize,
                dest: MediumLevelExpressionIndex::from(op.operands[2]),
                first_param: op.operands[4] as usize,
                num_params: op.operands[3] as usize,
            }),
            MLIL_CALL_UNTYPED => Op::CallUntyped(CallUntyped {
                first_output: op.operands[1] as usize,
                num_outputs: op.operands[0] as usize,
                dest: MediumLevelExpressionIndex::from(op.operands[2]),
                params: MediumLevelExpressionIndex::from(op.operands[3]),
                stack: MediumLevelExpressionIndex::from(op.operands[4]),
            }),
            MLIL_CALL_PARAM => Op::CallParam(CallParam {
                first_param: op.operands[1] as usize,
                num_params: op.operands[0] as usize,
            }),
            MLIL_SEPARATE_PARAM_LIST => Op::SeparateParamList(SeparateParamList {
                first_param: op.operands[1] as usize,
                num_params: op.operands[0] as usize,
            }),
            MLIL_SHARED_PARAM_SLOT => Op::SharedParamSlot(SharedParamSlot {
                first_param: op.operands[1] as usize,
                num_params: op.operands[0] as usize,
            }),
            MLIL_VAR_OUTPUT => Op::VarOutput(VarOutput {
                dest: get_var(op.operands[0]),
            }),
            MLIL_VAR_OUTPUT_FIELD => Op::VarOutputField(VarOutputField {
                dest: get_var(op.operands[0]),
                offset: op.operands[1],
            }),
            MLIL_STORE_OUTPUT => Op::StoreOutput(StoreOutput {
                dest: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_RET => Op::Ret(Ret {
                first_operand: op.operands[1] as usize,
                num_operands: op.operands[0] as usize,
            }),
            MLIL_NORET => Op::Noret,
            MLIL_IF => Op::If(MediumLevelILOperationIf {
                condition: MediumLevelExpressionIndex::from(op.operands[0]),
                dest_true: MediumLevelInstructionIndex(op.operands[1] as usize),
                dest_false: MediumLevelInstructionIndex(op.operands[2] as usize),
            }),
            MLIL_GOTO => Op::Goto(Goto {
                dest: MediumLevelInstructionIndex(op.operands[0] as usize),
            }),
            MLIL_CMP_E => Op::CmpE(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_CMP_NE => Op::CmpNe(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_CMP_SLT => Op::CmpSlt(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_CMP_ULT => Op::CmpUlt(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_CMP_SLE => Op::CmpSle(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_CMP_ULE => Op::CmpUle(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_CMP_SGE => Op::CmpSge(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_CMP_UGE => Op::CmpUge(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_CMP_SGT => Op::CmpSgt(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_CMP_UGT => Op::CmpUgt(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_TEST_BIT => Op::TestBit(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_BOOL_TO_INT => Op::BoolToInt(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_ADD_OVERFLOW => Op::AddOverflow(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_SYSCALL => Op::Syscall(Syscall {
                first_output: op.operands[1] as usize,
                num_outputs: op.operands[0] as usize,
                first_param: op.operands[3] as usize,
                num_params: op.operands[2] as usize,
            }),
            MLIL_SYSCALL_UNTYPED => Op::SyscallUntyped(SyscallUntyped {
                first_output: op.operands[1] as usize,
                num_outputs: op.operands[0] as usize,
                params: MediumLevelExpressionIndex::from(op.operands[2]),
                stack: MediumLevelExpressionIndex::from(op.operands[3]),
            }),
            MLIL_TAILCALL => Op::Tailcall(Call {
                first_output: op.operands[1] as usize,
                num_outputs: op.operands[0] as usize,
                dest: MediumLevelExpressionIndex::from(op.operands[2]),
                first_param: op.operands[4] as usize,
                num_params: op.operands[3] as usize,
            }),
            MLIL_TAILCALL_UNTYPED => Op::TailcallUntyped(CallUntyped {
                first_output: op.operands[1] as usize,
                num_outputs: op.operands[0] as usize,
                dest: MediumLevelExpressionIndex::from(op.operands[2]),
                params: MediumLevelExpressionIndex::from(op.operands[3]),
                stack: MediumLevelExpressionIndex::from(op.operands[4]),
            }),
            MLIL_INTRINSIC => Op::Intrinsic(Intrinsic {
                first_output: op.operands[1] as usize,
                num_outputs: op.operands[0] as usize,
                intrinsic: op.operands[2] as u32,
                first_param: op.operands[4] as usize,
                num_params: op.operands[3] as usize,
            }),
            MLIL_FREE_VAR_SLOT => Op::FreeVarSlot(FreeVarSlot {
                dest: get_var(op.operands[0]),
            }),
            MLIL_BP => Op::Bp,
            MLIL_TRAP => Op::Trap(Trap {
                vector: op.operands[0],
            }),
            MLIL_UNDEF => Op::Undef,
            MLIL_UNIMPL => Op::Unimpl,
            MLIL_UNIMPL_MEM => Op::UnimplMem(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_FADD => Op::Fadd(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_FSUB => Op::Fsub(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_FMUL => Op::Fmul(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_FDIV => Op::Fdiv(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_FSQRT => Op::Fsqrt(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_FNEG => Op::Fneg(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_FABS => Op::Fabs(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_FLOAT_TO_INT => Op::FloatToInt(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_INT_TO_FLOAT => Op::IntToFloat(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_FLOAT_CONV => Op::FloatConv(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_ROUND_TO_INT => Op::RoundToInt(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_FLOOR => Op::Floor(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_CEIL => Op::Ceil(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_FTRUNC => Op::Ftrunc(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_FCMP_E => Op::FcmpE(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_FCMP_NE => Op::FcmpNe(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_FCMP_LT => Op::FcmpLt(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_FCMP_LE => Op::FcmpLe(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_FCMP_GE => Op::FcmpGe(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_FCMP_GT => Op::FcmpGt(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_FCMP_O => Op::FcmpO(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_FCMP_UO => Op::FcmpUo(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_SET_VAR_SSA => Op::SetVarSsa(SetVarSsa {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                src: MediumLevelExpressionIndex::from(op.operands[2]),
            }),
            MLIL_SET_VAR_SSA_FIELD => Op::SetVarSsaField(SetVarSsaField {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
                offset: op.operands[3],
                src: MediumLevelExpressionIndex::from(op.operands[4]),
            }),
            MLIL_SET_VAR_SPLIT_SSA => Op::SetVarSplitSsa(SetVarSplitSsa {
                high: get_var_ssa(op.operands[0], op.operands[1] as usize),
                low: get_var_ssa(op.operands[2], op.operands[3] as usize),
                src: MediumLevelExpressionIndex::from(op.operands[4]),
            }),
            MLIL_SET_VAR_ALIASED => Op::SetVarAliased(SetVarAliased {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
                src: MediumLevelExpressionIndex::from(op.operands[3]),
            }),
            MLIL_SET_VAR_ALIASED_FIELD => Op::SetVarAliasedField(SetVarSsaField {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
                offset: op.operands[3],
                src: MediumLevelExpressionIndex::from(op.operands[4]),
            }),
            MLIL_VAR_SSA => Op::VarSsa(VarSsa {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
            }),
            MLIL_VAR_SSA_FIELD => Op::VarSsaField(VarSsaField {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
                offset: op.operands[2],
            }),
            MLIL_VAR_ALIASED => Op::VarAliased(VarSsa {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
            }),
            MLIL_VAR_ALIASED_FIELD => Op::VarAliasedField(VarSsaField {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
                offset: op.operands[2],
            }),
            MLIL_VAR_SPLIT_SSA => Op::VarSplitSsa(VarSplitSsa {
                high: get_var_ssa(op.operands[0], op.operands[1] as usize),
                low: get_var_ssa(op.operands[2], op.operands[3] as usize),
            }),
            MLIL_ASSERT_SSA => Op::AssertSsa(AssertSsa {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
                constraint_index: op.operands[2] as usize,
            }),
            MLIL_FORCE_VER_SSA => Op::ForceVerSsa(ForceVerSsa {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                src: get_var_ssa(op.operands[2], op.operands[3] as usize),
                reason: unsafe {
                    std::mem::transmute::<u8, ForceVersionReason>(op.operands[4] as u8)
                },
            }),
            MLIL_CALL_SSA => Op::CallSsa(CallSsa {
                output: MediumLevelExpressionIndex::from(op.operands[0]),
                dest: MediumLevelExpressionIndex::from(op.operands[1]),
                first_param: op.operands[3] as usize,
                num_params: op.operands[2] as usize,
                src_memory: op.operands[4],
            }),
            MLIL_CALL_UNTYPED_SSA => Op::CallUntypedSsa(CallUntypedSsa {
                output: MediumLevelExpressionIndex::from(op.operands[0]),
                dest: MediumLevelExpressionIndex::from(op.operands[1]),
                params: MediumLevelExpressionIndex::from(op.operands[2]),
                stack: MediumLevelExpressionIndex::from(op.operands[3]),
            }),
            MLIL_SYSCALL_SSA => Op::SyscallSsa(SyscallSsa {
                output: MediumLevelExpressionIndex::from(op.operands[0]),
                first_param: op.operands[2] as usize,
                num_params: op.operands[1] as usize,
                src_memory: op.operands[3],
            }),
            MLIL_SYSCALL_UNTYPED_SSA => Op::SyscallUntypedSsa(SyscallUntypedSsa {
                output: MediumLevelExpressionIndex::from(op.operands[0]),
                params: MediumLevelExpressionIndex::from(op.operands[1]),
                stack: MediumLevelExpressionIndex::from(op.operands[2]),
            }),
            MLIL_TAILCALL_SSA => Op::TailcallSsa(CallSsa {
                output: MediumLevelExpressionIndex::from(op.operands[0]),
                dest: MediumLevelExpressionIndex::from(op.operands[1]),
                first_param: op.operands[3] as usize,
                num_params: op.operands[2] as usize,
                src_memory: op.operands[4],
            }),
            MLIL_TAILCALL_UNTYPED_SSA => Op::TailcallUntypedSsa(CallUntypedSsa {
                output: MediumLevelExpressionIndex::from(op.operands[0]),
                dest: MediumLevelExpressionIndex::from(op.operands[1]),
                params: MediumLevelExpressionIndex::from(op.operands[2]),
                stack: MediumLevelExpressionIndex::from(op.operands[3]),
            }),
            MLIL_CALL_PARAM_SSA => Op::CallParamSsa(CallParamSsa {
                src_memory: op.operands[0],
                first_param: op.operands[2] as usize,
                num_params: op.operands[1] as usize,
            }),
            MLIL_CALL_OUTPUT_SSA => Op::CallOutputSsa(CallOutputSsa {
                dest_memory: op.operands[0],
                first_output: op.operands[2] as usize,
                num_outputs: op.operands[1] as usize,
            }),
            MLIL_VAR_OUTPUT_SSA => Op::VarOutputSsa(VarOutputSsa {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
            }),
            MLIL_VAR_OUTPUT_SSA_FIELD => Op::VarOutputSsaField(VarOutputSsaField {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
                offset: op.operands[3],
            }),
            MLIL_VAR_OUTPUT_ALIASED => Op::VarOutputAliased(VarOutputAliased {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
            }),
            MLIL_VAR_OUTPUT_ALIASED_FIELD => Op::VarOutputAliasedField(VarOutputAliasedField {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
                offset: op.operands[3],
            }),
            MLIL_MEMORY_INTRINSIC_OUTPUT_SSA => {
                Op::MemoryIntrinsicOutputSsa(MemoryIntrinsicOutputSsa {
                    dest_memory: op.operands[0],
                    first_output: op.operands[2] as usize,
                    num_outputs: op.operands[1] as usize,
                })
            }
            MLIL_LOAD_SSA => Op::LoadSsa(LoadSsa {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
                src_memory: op.operands[1],
            }),
            MLIL_LOAD_STRUCT_SSA => Op::LoadStructSsa(LoadStructSsa {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
                offset: op.operands[1],
                src_memory: op.operands[2],
            }),
            MLIL_STORE_SSA => Op::StoreSsa(StoreSsa {
                dest: MediumLevelExpressionIndex::from(op.operands[0]),
                dest_memory: op.operands[1],
                src_memory: op.operands[2],
                src: MediumLevelExpressionIndex::from(op.operands[3]),
            }),
            MLIL_STORE_STRUCT_SSA => Op::StoreStructSsa(StoreStructSsa {
                dest: MediumLevelExpressionIndex::from(op.operands[0]),
                offset: op.operands[1],
                dest_memory: op.operands[2],
                src_memory: op.operands[3],
                src: MediumLevelExpressionIndex::from(op.operands[4]),
            }),
            MLIL_INTRINSIC_SSA => Op::IntrinsicSsa(IntrinsicSsa {
                first_output: op.operands[1] as usize,
                num_outputs: op.operands[0] as usize,
                intrinsic: op.operands[2] as u32,
                first_param: op.operands[4] as usize,
                num_params: op.operands[3] as usize,
            }),
            MLIL_MEMORY_INTRINSIC_SSA => Op::MemoryIntrinsicSsa(MemoryIntrinsicSsa {
                output: MediumLevelExpressionIndex::from(op.operands[0]),
                intrinsic: op.operands[1] as u32,
                first_param: op.operands[3] as usize,
                num_params: op.operands[2] as usize,
                src_memory: op.operands[4],
            }),
            MLIL_FREE_VAR_SLOT_SSA => Op::FreeVarSlotSsa(FreeVarSlotSsa {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
            }),
            MLIL_VAR_PHI => Op::VarPhi(VarPhi {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                first_operand: op.operands[3] as usize,
                num_operands: op.operands[2] as usize,
            }),
            MLIL_MEM_PHI => Op::MemPhi(MemPhi {
                dest_memory: op.operands[0],
                first_operand: op.operands[2] as usize,
                num_operands: op.operands[1] as usize,
            }),
            MLIL_BLOCK_TO_EXPAND => Op::BlockToExpand(BlockToExpand {
                first_operand: op.operands[1] as usize,
                num_operands: op.operands[0] as usize,
            }),
            MLIL_BSWAP => Op::Bswap(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_POPCNT => Op::Popcnt(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_CLZ => Op::Clz(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_CTZ => Op::Ctz(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_RBIT => Op::Rbit(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_CLS => Op::Cls(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            MLIL_MINS => Op::MinSigned(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_MAXS => Op::MaxSigned(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_MINU => Op::MinUnsigned(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_MAXU => Op::MaxUnsigned(BinaryOp {
                left: MediumLevelExpressionIndex::from(op.operands[0]),
                right: MediumLevelExpressionIndex::from(op.operands[1]),
            }),
            MLIL_ABS => Op::Abs(UnaryOp {
                src: MediumLevelExpressionIndex::from(op.operands[0]),
            }),
            // END GENERATED mlil-decode
        };

        Self {
            function,
            address: op.address,
            instr_index,
            expr_index,
            size: op.size,
            kind,
        }
    }

    fn get_operand_list(&self, operand_idx: usize) -> Vec<u64> {
        let mut count = 0;
        let raw_list_ptr = unsafe {
            BNMediumLevelILGetOperandList(
                self.function.handle,
                self.expr_index.0,
                operand_idx,
                &mut count,
            )
        };
        assert!(!raw_list_ptr.is_null());
        let list = unsafe { std::slice::from_raw_parts(raw_list_ptr, count).to_vec() };
        unsafe { BNMediumLevelILFreeOperandList(raw_list_ptr) };
        list
    }

    fn get_var_list(&self, operand_idx: usize) -> Vec<Variable> {
        self.get_operand_list(operand_idx)
            .into_iter()
            .map(Variable::from_identifier)
            .collect()
    }

    fn get_ssa_var_list(&self, operand_idx: usize) -> Vec<SSAVariable> {
        self.get_operand_list(operand_idx)
            .chunks(2)
            .map(|chunk| (Variable::from_identifier(chunk[0]), chunk[1] as usize))
            .map(|(var, version)| SSAVariable::new(var, version))
            .collect()
    }

    fn get_expr_list(&self, operand_idx: usize) -> Vec<MediumLevelILInstruction> {
        self.get_operand_list(operand_idx)
            .into_iter()
            .map(|val| MediumLevelExpressionIndex(val as usize))
            .filter_map(|idx| self.function.instruction_from_expr_index(idx))
            .collect()
    }

    fn get_target_map(&self, operand_idx: usize) -> BTreeMap<u64, MediumLevelInstructionIndex> {
        self.get_operand_list(operand_idx)
            .chunks(2)
            // TODO: This filter is kinda redundant.
            .filter_map(|chunk| chunk.get(0..2))
            .map(|chunk| (chunk[0], MediumLevelInstructionIndex(chunk[1] as usize)))
            .collect()
    }

    pub fn lift(&self) -> MediumLevelILLiftedInstruction {
        use BNMediumLevelILOperation::*;
        use MediumLevelILInstructionKind::*;
        use MediumLevelILLiftedInstructionKind as Lifted;

        let kind = match self.kind {
            // BEGIN GENERATED mlil-lift: from api/il, do not edit
            Nop => Lifted::Nop,
            SetVar(op) => Lifted::SetVar(LiftedSetVar {
                dest: op.dest,
                src: self.lift_operand(op.src),
            }),
            SetVarField(op) => Lifted::SetVarField(LiftedSetVarField {
                dest: op.dest,
                offset: op.offset,
                src: self.lift_operand(op.src),
            }),
            SetVarSplit(op) => Lifted::SetVarSplit(LiftedSetVarSplit {
                high: op.high,
                low: op.low,
                src: self.lift_operand(op.src),
            }),
            Assert(op) => Lifted::Assert(LiftedAssert {
                src: op.src,
                constraint: PossibleValueSet::from_owned_core_raw(unsafe {
                    BNGetCachedMediumLevelILPossibleValueSet(
                        self.function.handle,
                        op.constraint_index,
                    )
                }),
            }),
            ForceVer(op) => Lifted::ForceVer(op),
            Load(op) => Lifted::Load(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            LoadStruct(op) => Lifted::LoadStruct(LiftedLoadStruct {
                src: self.lift_operand(op.src),
                offset: op.offset,
            }),
            Store(op) => Lifted::Store(LiftedStore {
                dest: self.lift_operand(op.dest),
                src: self.lift_operand(op.src),
            }),
            StoreStruct(op) => Lifted::StoreStruct(LiftedStoreStruct {
                dest: self.lift_operand(op.dest),
                offset: op.offset,
                src: self.lift_operand(op.src),
            }),
            Var(op) => Lifted::Var(op),
            VarField(op) => Lifted::VarField(op),
            VarSplit(op) => Lifted::VarSplit(op),
            AddressOf(op) => Lifted::AddressOf(op),
            AddressOfField(op) => Lifted::AddressOfField(op),
            PassByRef(op) => Lifted::PassByRef(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            ReturnByRef(op) => Lifted::ReturnByRef(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Const(op) => Lifted::Const(op),
            ConstData(op) => Lifted::ConstData(LiftedConstData {
                constant_data: ConstantData::new(
                    self.function.function(),
                    RegisterValue {
                        state: unsafe {
                            std::mem::transmute::<u32, BNRegisterValueType>(op.constant_data_kind)
                        },
                        value: op.constant_data_value,
                        offset: 0,
                        size: op.size,
                    },
                ),
            }),
            ConstPtr(op) => Lifted::ConstPtr(op),
            ExternPtr(op) => Lifted::ExternPtr(op),
            FloatConst(op) => Lifted::FloatConst(op),
            Import(op) => Lifted::Import(op),
            Add(op) => Lifted::Add(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Adc(op) => Lifted::Adc(LiftedBinaryOpCarry {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
                carry: self.lift_operand(op.carry),
            }),
            Sub(op) => Lifted::Sub(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Sbb(op) => Lifted::Sbb(LiftedBinaryOpCarry {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
                carry: self.lift_operand(op.carry),
            }),
            And(op) => Lifted::And(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Or(op) => Lifted::Or(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Xor(op) => Lifted::Xor(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Lsl(op) => Lifted::Lsl(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Lsr(op) => Lifted::Lsr(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Asr(op) => Lifted::Asr(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Rol(op) => Lifted::Rol(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Rlc(op) => Lifted::Rlc(LiftedBinaryOpCarry {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
                carry: self.lift_operand(op.carry),
            }),
            Ror(op) => Lifted::Ror(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Rrc(op) => Lifted::Rrc(LiftedBinaryOpCarry {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
                carry: self.lift_operand(op.carry),
            }),
            Mul(op) => Lifted::Mul(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            MuluDp(op) => Lifted::MuluDp(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            MulsDp(op) => Lifted::MulsDp(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Divu(op) => Lifted::Divu(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            DivuDp(op) => Lifted::DivuDp(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Divs(op) => Lifted::Divs(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            DivsDp(op) => Lifted::DivsDp(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Modu(op) => Lifted::Modu(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            ModuDp(op) => Lifted::ModuDp(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Mods(op) => Lifted::Mods(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            ModsDp(op) => Lifted::ModsDp(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Neg(op) => Lifted::Neg(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Not(op) => Lifted::Not(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Sx(op) => Lifted::Sx(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Zx(op) => Lifted::Zx(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            LowPart(op) => Lifted::LowPart(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Jump(op) => Lifted::Jump(LiftedJump {
                dest: self.lift_operand(op.dest),
            }),
            JumpTo(op) => Lifted::JumpTo(LiftedJumpTo {
                dest: self.lift_operand(op.dest),
                targets: self.get_target_map(1),
            }),
            RetHint(op) => Lifted::RetHint(LiftedJump {
                dest: self.lift_operand(op.dest),
            }),
            Call(op) => Lifted::Call(LiftedCall {
                output: self.lift_expr_list(0),
                dest: self.lift_operand(op.dest),
                params: self.lift_expr_list(3),
            }),
            CallUntyped(op) => Lifted::CallUntyped(LiftedCallUntyped {
                output: self.lift_expr_list(0),
                dest: self.lift_operand(op.dest),
                params: self.lift_part_expr_list(op.params, MLIL_CALL_PARAM, 0),
                stack: self.lift_operand(op.stack),
            }),
            CallParam(_op) => Lifted::CallParam(LiftedCallParam {
                params: self.lift_expr_list(0),
            }),
            SeparateParamList(_op) => Lifted::SeparateParamList(LiftedSeparateParamList {
                params: self.lift_expr_list(0),
            }),
            SharedParamSlot(_op) => Lifted::SharedParamSlot(LiftedSharedParamSlot {
                params: self.lift_expr_list(0),
            }),
            VarOutput(op) => Lifted::VarOutput(op),
            VarOutputField(op) => Lifted::VarOutputField(op),
            StoreOutput(op) => Lifted::StoreOutput(LiftedStoreOutput {
                dest: self.lift_operand(op.dest),
            }),
            Ret(_op) => Lifted::Ret(LiftedRet {
                src: self.lift_expr_list(0),
            }),
            Noret => Lifted::Noret,
            If(op) => Lifted::If(LiftedIf {
                condition: self.lift_operand(op.condition),
                dest_true: op.dest_true,
                dest_false: op.dest_false,
            }),
            Goto(op) => Lifted::Goto(op),
            CmpE(op) => Lifted::CmpE(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            CmpNe(op) => Lifted::CmpNe(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            CmpSlt(op) => Lifted::CmpSlt(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            CmpUlt(op) => Lifted::CmpUlt(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            CmpSle(op) => Lifted::CmpSle(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            CmpUle(op) => Lifted::CmpUle(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            CmpSge(op) => Lifted::CmpSge(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            CmpUge(op) => Lifted::CmpUge(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            CmpSgt(op) => Lifted::CmpSgt(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            CmpUgt(op) => Lifted::CmpUgt(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            TestBit(op) => Lifted::TestBit(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            BoolToInt(op) => Lifted::BoolToInt(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            AddOverflow(op) => Lifted::AddOverflow(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Syscall(_op) => Lifted::Syscall(LiftedSyscallCall {
                output: self.lift_expr_list(0),
                params: self.lift_expr_list(2),
            }),
            SyscallUntyped(op) => Lifted::SyscallUntyped(LiftedSyscallUntyped {
                output: self.lift_expr_list(0),
                params: self.lift_part_expr_list(op.params, MLIL_CALL_PARAM, 0),
                stack: self.lift_operand(op.stack),
            }),
            Tailcall(op) => Lifted::Tailcall(LiftedCall {
                output: self.lift_expr_list(0),
                dest: self.lift_operand(op.dest),
                params: self.lift_expr_list(3),
            }),
            TailcallUntyped(op) => Lifted::TailcallUntyped(LiftedCallUntyped {
                output: self.lift_expr_list(0),
                dest: self.lift_operand(op.dest),
                params: self.lift_part_expr_list(op.params, MLIL_CALL_PARAM, 0),
                stack: self.lift_operand(op.stack),
            }),
            Intrinsic(op) => Lifted::Intrinsic(LiftedIntrinsic {
                output: self.get_var_list(0),
                intrinsic: CoreIntrinsic::new(
                    self.function.function().arch(),
                    IntrinsicId(op.intrinsic),
                )
                .expect("Valid intrinsic"),
                params: self.lift_expr_list(3),
            }),
            FreeVarSlot(op) => Lifted::FreeVarSlot(op),
            Bp => Lifted::Bp,
            Trap(op) => Lifted::Trap(op),
            Undef => Lifted::Undef,
            Unimpl => Lifted::Unimpl,
            UnimplMem(op) => Lifted::UnimplMem(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Fadd(op) => Lifted::Fadd(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Fsub(op) => Lifted::Fsub(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Fmul(op) => Lifted::Fmul(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Fdiv(op) => Lifted::Fdiv(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Fsqrt(op) => Lifted::Fsqrt(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Fneg(op) => Lifted::Fneg(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Fabs(op) => Lifted::Fabs(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            FloatToInt(op) => Lifted::FloatToInt(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            IntToFloat(op) => Lifted::IntToFloat(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            FloatConv(op) => Lifted::FloatConv(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            RoundToInt(op) => Lifted::RoundToInt(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Floor(op) => Lifted::Floor(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Ceil(op) => Lifted::Ceil(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Ftrunc(op) => Lifted::Ftrunc(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            FcmpE(op) => Lifted::FcmpE(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            FcmpNe(op) => Lifted::FcmpNe(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            FcmpLt(op) => Lifted::FcmpLt(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            FcmpLe(op) => Lifted::FcmpLe(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            FcmpGe(op) => Lifted::FcmpGe(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            FcmpGt(op) => Lifted::FcmpGt(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            FcmpO(op) => Lifted::FcmpO(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            FcmpUo(op) => Lifted::FcmpUo(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            SetVarSsa(op) => Lifted::SetVarSsa(LiftedSetVarSsa {
                dest: op.dest,
                src: self.lift_operand(op.src),
            }),
            SetVarSsaField(op) => Lifted::SetVarSsaField(LiftedSetVarSsaField {
                dest: op.dest,
                prev: op.prev,
                offset: op.offset,
                src: self.lift_operand(op.src),
            }),
            SetVarSplitSsa(op) => Lifted::SetVarSplitSsa(LiftedSetVarSplitSsa {
                high: op.high,
                low: op.low,
                src: self.lift_operand(op.src),
            }),
            SetVarAliased(op) => Lifted::SetVarAliased(LiftedSetVarAliased {
                dest: op.dest,
                prev: op.prev,
                src: self.lift_operand(op.src),
            }),
            SetVarAliasedField(op) => Lifted::SetVarAliasedField(LiftedSetVarSsaField {
                dest: op.dest,
                prev: op.prev,
                offset: op.offset,
                src: self.lift_operand(op.src),
            }),
            VarSsa(op) => Lifted::VarSsa(op),
            VarSsaField(op) => Lifted::VarSsaField(op),
            VarAliased(op) => Lifted::VarAliased(op),
            VarAliasedField(op) => Lifted::VarAliasedField(op),
            VarSplitSsa(op) => Lifted::VarSplitSsa(op),
            AssertSsa(op) => Lifted::AssertSsa(LiftedAssertSsa {
                src: op.src,
                constraint: PossibleValueSet::from_owned_core_raw(unsafe {
                    BNGetCachedMediumLevelILPossibleValueSet(
                        self.function.handle,
                        op.constraint_index,
                    )
                }),
            }),
            ForceVerSsa(op) => Lifted::ForceVerSsa(op),
            CallSsa(op) => Lifted::CallSsa(LiftedCallSsa {
                output: self.lift_part_expr_list(op.output, MLIL_CALL_OUTPUT_SSA, 1),
                dest: self.lift_operand(op.dest),
                params: self.lift_expr_list(2),
                src_memory: op.src_memory,
            }),
            CallUntypedSsa(op) => Lifted::CallUntypedSsa(LiftedCallUntypedSsa {
                output: self.lift_part_expr_list(op.output, MLIL_CALL_OUTPUT_SSA, 1),
                dest: self.lift_operand(op.dest),
                params: self.lift_part_expr_list(op.params, MLIL_CALL_PARAM_SSA, 1),
                stack: self.lift_operand(op.stack),
            }),
            SyscallSsa(op) => Lifted::SyscallSsa(LiftedSyscallSsa {
                output: self.lift_part_expr_list(op.output, MLIL_CALL_OUTPUT_SSA, 1),
                params: self.lift_expr_list(1),
                src_memory: op.src_memory,
            }),
            SyscallUntypedSsa(op) => Lifted::SyscallUntypedSsa(LiftedSyscallUntypedSsa {
                output: self.lift_part_expr_list(op.output, MLIL_CALL_OUTPUT_SSA, 1),
                params: self.lift_part_expr_list(op.params, MLIL_CALL_PARAM_SSA, 1),
                stack: self.lift_operand(op.stack),
            }),
            TailcallSsa(op) => Lifted::TailcallSsa(LiftedCallSsa {
                output: self.lift_part_expr_list(op.output, MLIL_CALL_OUTPUT_SSA, 1),
                dest: self.lift_operand(op.dest),
                params: self.lift_expr_list(2),
                src_memory: op.src_memory,
            }),
            TailcallUntypedSsa(op) => Lifted::TailcallUntypedSsa(LiftedCallUntypedSsa {
                output: self.lift_part_expr_list(op.output, MLIL_CALL_OUTPUT_SSA, 1),
                dest: self.lift_operand(op.dest),
                params: self.lift_part_expr_list(op.params, MLIL_CALL_PARAM_SSA, 1),
                stack: self.lift_operand(op.stack),
            }),
            CallParamSsa(op) => Lifted::CallParamSsa(LiftedCallParamSsa {
                src_memory: op.src_memory,
                params: self.lift_expr_list(1),
            }),
            CallOutputSsa(op) => Lifted::CallOutputSsa(LiftedCallOutputSsa {
                dest_memory: op.dest_memory,
                output: self.lift_expr_list(1),
            }),
            VarOutputSsa(op) => Lifted::VarOutputSsa(op),
            VarOutputSsaField(op) => Lifted::VarOutputSsaField(op),
            VarOutputAliased(op) => Lifted::VarOutputAliased(op),
            VarOutputAliasedField(op) => Lifted::VarOutputAliasedField(op),
            MemoryIntrinsicOutputSsa(op) => {
                Lifted::MemoryIntrinsicOutputSsa(LiftedMemoryIntrinsicOutputSsa {
                    dest_memory: op.dest_memory,
                    output: self.get_ssa_var_list(1),
                })
            }
            LoadSsa(op) => Lifted::LoadSsa(LiftedLoadSsa {
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
            }),
            LoadStructSsa(op) => Lifted::LoadStructSsa(LiftedLoadStructSsa {
                src: self.lift_operand(op.src),
                offset: op.offset,
                src_memory: op.src_memory,
            }),
            StoreSsa(op) => Lifted::StoreSsa(LiftedStoreSsa {
                dest: self.lift_operand(op.dest),
                dest_memory: op.dest_memory,
                src_memory: op.src_memory,
                src: self.lift_operand(op.src),
            }),
            StoreStructSsa(op) => Lifted::StoreStructSsa(LiftedStoreStructSsa {
                dest: self.lift_operand(op.dest),
                offset: op.offset,
                dest_memory: op.dest_memory,
                src_memory: op.src_memory,
                src: self.lift_operand(op.src),
            }),
            IntrinsicSsa(op) => Lifted::IntrinsicSsa(LiftedIntrinsicSsa {
                output: self.get_ssa_var_list(0),
                intrinsic: CoreIntrinsic::new(
                    self.function.function().arch(),
                    IntrinsicId(op.intrinsic),
                )
                .expect("Valid intrinsic"),
                params: self.lift_expr_list(3),
            }),
            MemoryIntrinsicSsa(op) => Lifted::MemoryIntrinsicSsa(LiftedMemoryIntrinsicSsa {
                output: self.lift_operand(op.output),
                intrinsic: CoreIntrinsic::new(
                    self.function.function().arch(),
                    IntrinsicId(op.intrinsic),
                )
                .expect("Valid intrinsic"),
                params: self.lift_expr_list(2),
                src_memory: op.src_memory,
            }),
            FreeVarSlotSsa(op) => Lifted::FreeVarSlotSsa(op),
            VarPhi(op) => Lifted::VarPhi(LiftedVarPhi {
                dest: op.dest,
                src: self.get_ssa_var_list(2),
            }),
            MemPhi(op) => Lifted::MemPhi(LiftedMemPhi {
                dest_memory: op.dest_memory,
                src_memory: self.get_operand_list(1),
            }),
            BlockToExpand(_op) => Lifted::BlockToExpand(LiftedBlockToExpand {
                exprs: self.lift_expr_list(0),
            }),
            Bswap(op) => Lifted::Bswap(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Popcnt(op) => Lifted::Popcnt(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Clz(op) => Lifted::Clz(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Ctz(op) => Lifted::Ctz(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Rbit(op) => Lifted::Rbit(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            Cls(op) => Lifted::Cls(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            MinSigned(op) => Lifted::MinSigned(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            MaxSigned(op) => Lifted::MaxSigned(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            MinUnsigned(op) => Lifted::MinUnsigned(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            MaxUnsigned(op) => Lifted::MaxUnsigned(LiftedBinaryOp {
                left: self.lift_operand(op.left),
                right: self.lift_operand(op.right),
            }),
            Abs(op) => Lifted::Abs(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            // END GENERATED mlil-lift
        };

        MediumLevelILLiftedInstruction {
            function: self.function.clone(),
            address: self.address,
            instr_index: self.instr_index,
            expr_index: self.expr_index,
            size: self.size,
            kind,
        }
    }

    pub fn tokens(&self) -> Array<InstructionTextToken> {
        let mut count = 0;
        let mut tokens = core::ptr::null_mut();
        assert!(unsafe {
            BNGetMediumLevelILExprText(
                self.function.handle,
                self.function.function().arch().handle,
                self.expr_index.0,
                &mut tokens,
                &mut count,
                core::ptr::null_mut(),
            )
        });
        unsafe { Array::new(tokens, count, ()) }
    }

    /// Value of expression if constant or a known value
    pub fn value(&self) -> RegisterValue {
        unsafe { BNGetMediumLevelILExprValue(self.function.handle, self.expr_index.0) }.into()
    }

    /// Returns the [`BasicBlock`] containing the given [`MediumLevelILInstruction`].
    pub fn basic_block(&self) -> Option<Ref<BasicBlock<MediumLevelILBlock>>> {
        // TODO: We might be able to .expect this if we guarantee that self.index is valid.
        self.function.basic_block_containing_index(self.instr_index)
    }

    /// Possible values of expression using path-sensitive static data flow analysis
    pub fn possible_values(&self) -> PossibleValueSet {
        self.possible_values_with_opts(&[])
    }

    /// Possible values of expression using path-sensitive static data flow analysis
    pub fn possible_values_with_opts(&self, options: &[DataFlowQueryOption]) -> PossibleValueSet {
        let value = unsafe {
            BNGetMediumLevelILPossibleExprValues(
                self.function.handle,
                self.instr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_core_raw(value)
    }

    pub fn possible_ssa_variable_values(&self, ssa_var: &SSAVariable) -> PossibleValueSet {
        self.possible_ssa_variable_values_with_opts(ssa_var, &[])
    }

    pub fn possible_ssa_variable_values_with_opts(
        &self,
        ssa_var: &SSAVariable,
        options: &[DataFlowQueryOption],
    ) -> PossibleValueSet {
        let raw_var = BNVariable::from(ssa_var.variable);
        let value = unsafe {
            BNGetMediumLevelILPossibleSSAVarValues(
                self.function.handle,
                &raw_var,
                ssa_var.version,
                self.instr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_core_raw(value)
    }

    /// Return the ssa version of a [`Variable`] at the given instruction.
    pub fn ssa_variable_version(&self, var: Variable) -> SSAVariable {
        let raw_var = BNVariable::from(var);
        let version = unsafe {
            BNGetMediumLevelILSSAVarVersionAtILInstruction(
                self.function.handle,
                &raw_var,
                self.instr_index.0,
            )
        };
        SSAVariable::new(var, version)
    }

    /// Return the ssa version of a [`Variable`] after the given instruction.
    pub fn ssa_variable_version_after(&self, var: Variable) -> SSAVariable {
        let raw_var = BNVariable::from(var);
        let version = unsafe {
            BNGetMediumLevelILSSAVarVersionAfterILInstruction(
                self.function.handle,
                &raw_var,
                self.instr_index.0,
            )
        };
        SSAVariable::new(var, version)
    }

    /// Set of branching instructions that must take the true or false path to reach this instruction
    pub fn branch_dependencies(&self) -> Array<BranchDependence> {
        let mut count = 0;
        let deps = unsafe {
            BNGetAllMediumLevelILBranchDependence(
                self.function.handle,
                self.instr_index.0,
                &mut count,
            )
        };
        assert!(!deps.is_null());
        unsafe { Array::new(deps, count, self.function.clone()) }
    }

    pub fn branch_dependence_at(
        &self,
        branch_instruction: MediumLevelILInstruction,
    ) -> BranchDependence {
        let deps = unsafe {
            BNGetMediumLevelILBranchDependence(
                self.function.handle,
                self.instr_index.0,
                branch_instruction.instr_index.0,
            )
        };
        BranchDependence {
            instruction: branch_instruction,
            dependence: deps,
        }
    }

    /// Version of active memory contents in SSA form for this instruction
    pub fn ssa_memory_version(&self) -> usize {
        unsafe {
            BNGetMediumLevelILSSAMemoryVersionAtILInstruction(
                self.function.handle,
                self.instr_index.0,
            )
        }
    }

    /// Version of active memory contents in SSA form for this instruction
    pub fn ssa_memory_version_after(&self) -> usize {
        unsafe {
            BNGetMediumLevelILSSAMemoryVersionAfterILInstruction(
                self.function.handle,
                self.instr_index.0,
            )
        }
    }

    /// Type of expression
    pub fn expr_type(&self) -> Option<Conf<Ref<Type>>> {
        let result = unsafe { BNGetMediumLevelILExprType(self.function.handle, self.expr_index.0) };
        (!result.type_.is_null()).then(|| Conf::<Ref<Type>>::from_owned_raw(result))
    }

    /// Set type of expression
    ///
    /// This API is only meant for workflows or for debugging purposes, since the changes they make are not persistent
    /// and get lost after a database save and reload. To make persistent changes to the analysis, one should use other
    /// APIs to, for example, change the type of variables. The analysis will then propagate the type of the variable
    /// and update the type of related expressions.
    pub fn set_expr_type<'a, T: Into<Conf<&'a Type>>>(&self, ty: T) {
        let mut ty: BNTypeWithConfidence = Conf::<&Type>::into_raw(ty.into());
        unsafe { BNSetMediumLevelILExprType(self.function.handle, self.expr_index.0, &mut ty) }
    }

    pub fn variable_for_register(&self, reg_id: RegisterId) -> Variable {
        let result = unsafe {
            BNGetMediumLevelILVariableForRegisterAtInstruction(
                self.function.handle,
                reg_id.0,
                self.instr_index.0,
            )
        };
        Variable::from(result)
    }

    pub fn variable_for_register_after(&self, reg_id: RegisterId) -> Variable {
        let result = unsafe {
            BNGetMediumLevelILVariableForRegisterAfterInstruction(
                self.function.handle,
                reg_id.0,
                self.instr_index.0,
            )
        };
        Variable::from(result)
    }

    pub fn variable_for_flag(&self, flag_id: FlagId) -> Variable {
        let result = unsafe {
            BNGetMediumLevelILVariableForFlagAtInstruction(
                self.function.handle,
                flag_id.0,
                self.instr_index.0,
            )
        };
        Variable::from(result)
    }

    pub fn variable_for_flag_after(&self, flag_id: FlagId) -> Variable {
        let result = unsafe {
            BNGetMediumLevelILVariableForFlagAfterInstruction(
                self.function.handle,
                flag_id.0,
                self.instr_index.0,
            )
        };
        Variable::from(result)
    }

    pub fn variable_for_stack_location(&self, offset: i64) -> Variable {
        let result = unsafe {
            BNGetMediumLevelILVariableForStackLocationAtInstruction(
                self.function.handle,
                offset,
                self.instr_index.0,
            )
        };
        Variable::from(result)
    }

    pub fn variable_for_stack_location_after(&self, offset: i64) -> Variable {
        let result = unsafe {
            BNGetMediumLevelILVariableForStackLocationAfterInstruction(
                self.function.handle,
                offset,
                self.instr_index.0,
            )
        };
        Variable::from(result)
    }

    pub fn register_value(&self, reg_id: RegisterId) -> RegisterValue {
        unsafe {
            BNGetMediumLevelILRegisterValueAtInstruction(
                self.function.handle,
                reg_id.0,
                self.instr_index.0,
            )
        }
        .into()
    }

    pub fn register_value_after(&self, reg_id: RegisterId) -> RegisterValue {
        unsafe {
            BNGetMediumLevelILRegisterValueAfterInstruction(
                self.function.handle,
                reg_id.0,
                self.instr_index.0,
            )
        }
        .into()
    }

    pub fn possible_register_values(&self, reg_id: RegisterId) -> PossibleValueSet {
        self.possible_register_values_with_opts(reg_id, &[])
    }

    pub fn possible_register_values_with_opts(
        &self,
        reg_id: RegisterId,
        options: &[DataFlowQueryOption],
    ) -> PossibleValueSet {
        let value = unsafe {
            BNGetMediumLevelILPossibleRegisterValuesAtInstruction(
                self.function.handle,
                reg_id.0,
                self.instr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_core_raw(value)
    }

    pub fn possible_register_values_after(&self, reg_id: RegisterId) -> PossibleValueSet {
        self.possible_register_values_after_with_opts(reg_id, &[])
    }

    pub fn possible_register_values_after_with_opts(
        &self,
        reg_id: RegisterId,
        options: &[DataFlowQueryOption],
    ) -> PossibleValueSet {
        let value = unsafe {
            BNGetMediumLevelILPossibleRegisterValuesAfterInstruction(
                self.function.handle,
                reg_id.0,
                self.instr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_core_raw(value)
    }

    pub fn flag_value(&self, flag_id: FlagId) -> RegisterValue {
        unsafe {
            BNGetMediumLevelILFlagValueAtInstruction(
                self.function.handle,
                flag_id.0,
                self.instr_index.0,
            )
        }
        .into()
    }

    pub fn flag_value_after(&self, flag_id: FlagId) -> RegisterValue {
        unsafe {
            BNGetMediumLevelILFlagValueAfterInstruction(
                self.function.handle,
                flag_id.0,
                self.instr_index.0,
            )
        }
        .into()
    }

    pub fn possible_flag_values(&self, flag_id: FlagId) -> PossibleValueSet {
        self.possible_flag_values_with_opts(flag_id, &[])
    }

    pub fn possible_flag_values_with_opts(
        &self,
        flag_id: FlagId,
        options: &[DataFlowQueryOption],
    ) -> PossibleValueSet {
        let value = unsafe {
            BNGetMediumLevelILPossibleFlagValuesAtInstruction(
                self.function.handle,
                flag_id.0,
                self.instr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_core_raw(value)
    }

    pub fn possible_flag_values_after_with_opts(
        &self,
        flag_id: FlagId,
        options: &[DataFlowQueryOption],
    ) -> PossibleValueSet {
        let value = unsafe {
            BNGetMediumLevelILPossibleFlagValuesAfterInstruction(
                self.function.handle,
                flag_id.0,
                self.instr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_core_raw(value)
    }

    pub fn stack_contents(&self, offset: i64, size: usize) -> RegisterValue {
        unsafe {
            BNGetMediumLevelILStackContentsAtInstruction(
                self.function.handle,
                offset,
                size,
                self.instr_index.0,
            )
        }
        .into()
    }

    pub fn stack_contents_after(&self, offset: i64, size: usize) -> RegisterValue {
        unsafe {
            BNGetMediumLevelILStackContentsAfterInstruction(
                self.function.handle,
                offset,
                size,
                self.instr_index.0,
            )
        }
        .into()
    }

    pub fn possible_stack_contents_with_opts(
        &self,
        offset: i64,
        size: usize,
        options: &[DataFlowQueryOption],
    ) -> PossibleValueSet {
        let value = unsafe {
            BNGetMediumLevelILPossibleStackContentsAtInstruction(
                self.function.handle,
                offset,
                size,
                self.instr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_core_raw(value)
    }

    pub fn possible_stack_contents_after_with_opts(
        &self,
        offset: i64,
        size: usize,
        options: &[DataFlowQueryOption],
    ) -> PossibleValueSet {
        let value = unsafe {
            BNGetMediumLevelILPossibleStackContentsAfterInstruction(
                self.function.handle,
                offset,
                size,
                self.instr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_core_raw(value)
    }

    /// Gets the unique variable for a definition instruction. This unique variable can be passed
    /// to [crate::function::Function::split_variable] to split a variable at a definition. The given `var` is the
    /// assigned variable to query.
    ///
    /// * `var` - variable to query
    pub fn split_var_for_definition(&self, var: &Variable) -> Variable {
        let raw_var = BNVariable::from(var);
        let index = unsafe {
            BNGetDefaultIndexForMediumLevelILVariableDefinition(
                self.function.handle,
                &raw_var,
                self.instr_index.0,
            )
        };
        Variable::new(var.ty, index, var.storage)
    }

    fn lift_operand(
        &self,
        expr_idx: MediumLevelExpressionIndex,
    ) -> Box<MediumLevelILLiftedInstruction> {
        let operand_instr = self
            .function
            .instruction_from_expr_index(expr_idx)
            .expect("Invalid operand expression index");
        Box::new(operand_instr.lift())
    }

    fn lift_expr_list(&self, operand_idx: usize) -> Vec<MediumLevelILLiftedInstruction> {
        self.get_expr_list(operand_idx)
            .iter()
            .map(|expr| expr.lift())
            .collect()
    }

    /// Lifts the expression list at `operand_idx` of `part`, or returns an empty list if `part` isn't a
    /// `part_operation`.
    fn lift_part_expr_list(
        &self,
        part: MediumLevelExpressionIndex,
        part_operation: BNMediumLevelILOperation,
        operand_idx: usize,
    ) -> Vec<MediumLevelILLiftedInstruction> {
        let part_instr = self
            .function
            .instruction_from_expr_index(part)
            .expect("Valid part expression index");
        let raw = unsafe { BNGetMediumLevelILByIndex(self.function.handle, part.0) };
        if raw.operation != part_operation {
            return vec![];
        }

        part_instr.lift_expr_list(operand_idx)
    }
}

impl Debug for MediumLevelILInstruction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediumLevelILInstruction")
            .field("address", &self.address)
            .field("instr_index", &self.instr_index)
            .field("expr_index", &self.expr_index)
            .field("size", &self.size)
            .field("kind", &self.kind)
            .finish()
    }
}

impl CoreArrayProvider for MediumLevelILInstruction {
    type Raw = usize;
    type Context = Ref<MediumLevelILFunction>;
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for MediumLevelILInstruction {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeILInstructionList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        context
            .instruction_from_index(MediumLevelInstructionIndex(*raw))
            .unwrap()
    }
}

// BEGIN GENERATED mlil-instruction-kind: from api/il, do not edit
#[derive(Debug, Copy, Clone)]
pub enum MediumLevelILInstructionKind {
    Nop,
    SetVar(SetVar),
    SetVarField(SetVarField),
    SetVarSplit(SetVarSplit),
    Assert(Assert),
    ForceVer(ForceVer),
    Load(UnaryOp),
    LoadStruct(LoadStruct),
    Store(Store),
    StoreStruct(StoreStruct),
    Var(Var),
    VarField(Field),
    VarSplit(VarSplit),
    AddressOf(Var),
    AddressOfField(Field),
    PassByRef(UnaryOp),
    ReturnByRef(UnaryOp),
    Const(Constant),
    ConstData(ConstData),
    ConstPtr(Constant),
    ExternPtr(ExternPtr),
    FloatConst(FloatConst),
    Import(Constant),
    Add(BinaryOp),
    Adc(BinaryOpCarry),
    Sub(BinaryOp),
    Sbb(BinaryOpCarry),
    And(BinaryOp),
    Or(BinaryOp),
    Xor(BinaryOp),
    Lsl(BinaryOp),
    Lsr(BinaryOp),
    Asr(BinaryOp),
    Rol(BinaryOp),
    Rlc(BinaryOpCarry),
    Ror(BinaryOp),
    Rrc(BinaryOpCarry),
    Mul(BinaryOp),
    MuluDp(BinaryOp),
    MulsDp(BinaryOp),
    Divu(BinaryOp),
    DivuDp(BinaryOp),
    Divs(BinaryOp),
    DivsDp(BinaryOp),
    Modu(BinaryOp),
    ModuDp(BinaryOp),
    Mods(BinaryOp),
    ModsDp(BinaryOp),
    Neg(UnaryOp),
    Not(UnaryOp),
    Sx(UnaryOp),
    Zx(UnaryOp),
    LowPart(UnaryOp),
    Jump(Jump),
    JumpTo(JumpTo),
    RetHint(Jump),
    Call(Call),
    CallUntyped(CallUntyped),
    CallParam(CallParam),
    SeparateParamList(SeparateParamList),
    SharedParamSlot(SharedParamSlot),
    VarOutput(VarOutput),
    VarOutputField(VarOutputField),
    StoreOutput(StoreOutput),
    Ret(Ret),
    Noret,
    If(MediumLevelILOperationIf),
    Goto(Goto),
    CmpE(BinaryOp),
    CmpNe(BinaryOp),
    CmpSlt(BinaryOp),
    CmpUlt(BinaryOp),
    CmpSle(BinaryOp),
    CmpUle(BinaryOp),
    CmpSge(BinaryOp),
    CmpUge(BinaryOp),
    CmpSgt(BinaryOp),
    CmpUgt(BinaryOp),
    TestBit(BinaryOp),
    BoolToInt(UnaryOp),
    AddOverflow(BinaryOp),
    Syscall(Syscall),
    SyscallUntyped(SyscallUntyped),
    Tailcall(Call),
    TailcallUntyped(CallUntyped),
    Intrinsic(Intrinsic),
    FreeVarSlot(FreeVarSlot),
    Bp,
    Trap(Trap),
    Undef,
    Unimpl,
    UnimplMem(UnaryOp),
    Fadd(BinaryOp),
    Fsub(BinaryOp),
    Fmul(BinaryOp),
    Fdiv(BinaryOp),
    Fsqrt(UnaryOp),
    Fneg(UnaryOp),
    Fabs(UnaryOp),
    FloatToInt(UnaryOp),
    IntToFloat(UnaryOp),
    FloatConv(UnaryOp),
    RoundToInt(UnaryOp),
    Floor(UnaryOp),
    Ceil(UnaryOp),
    Ftrunc(UnaryOp),
    FcmpE(BinaryOp),
    FcmpNe(BinaryOp),
    FcmpLt(BinaryOp),
    FcmpLe(BinaryOp),
    FcmpGe(BinaryOp),
    FcmpGt(BinaryOp),
    FcmpO(BinaryOp),
    FcmpUo(BinaryOp),
    SetVarSsa(SetVarSsa),
    SetVarSsaField(SetVarSsaField),
    SetVarSplitSsa(SetVarSplitSsa),
    SetVarAliased(SetVarAliased),
    SetVarAliasedField(SetVarSsaField),
    VarSsa(VarSsa),
    VarSsaField(VarSsaField),
    VarAliased(VarSsa),
    VarAliasedField(VarSsaField),
    VarSplitSsa(VarSplitSsa),
    AssertSsa(AssertSsa),
    ForceVerSsa(ForceVerSsa),
    CallSsa(CallSsa),
    CallUntypedSsa(CallUntypedSsa),
    SyscallSsa(SyscallSsa),
    SyscallUntypedSsa(SyscallUntypedSsa),
    TailcallSsa(CallSsa),
    TailcallUntypedSsa(CallUntypedSsa),
    CallParamSsa(CallParamSsa),
    CallOutputSsa(CallOutputSsa),
    VarOutputSsa(VarOutputSsa),
    VarOutputSsaField(VarOutputSsaField),
    VarOutputAliased(VarOutputAliased),
    VarOutputAliasedField(VarOutputAliasedField),
    MemoryIntrinsicOutputSsa(MemoryIntrinsicOutputSsa),
    LoadSsa(LoadSsa),
    LoadStructSsa(LoadStructSsa),
    StoreSsa(StoreSsa),
    StoreStructSsa(StoreStructSsa),
    IntrinsicSsa(IntrinsicSsa),
    MemoryIntrinsicSsa(MemoryIntrinsicSsa),
    FreeVarSlotSsa(FreeVarSlotSsa),
    VarPhi(VarPhi),
    MemPhi(MemPhi),
    BlockToExpand(BlockToExpand),
    Bswap(UnaryOp),
    Popcnt(UnaryOp),
    Clz(UnaryOp),
    Ctz(UnaryOp),
    Rbit(UnaryOp),
    Cls(UnaryOp),
    MinSigned(BinaryOp),
    MaxSigned(BinaryOp),
    MinUnsigned(BinaryOp),
    MaxUnsigned(BinaryOp),
    Abs(UnaryOp),
}
// END GENERATED mlil-instruction-kind

fn get_float(value: u64, size: usize) -> f64 {
    match size {
        4 => f32::from_bits(value as u32) as f64,
        8 => f64::from_bits(value),
        // TODO how to handle this value?
        size => todo!("float size {}", size),
    }
}

fn get_var(id: u64) -> Variable {
    Variable::from_identifier(id)
}

fn get_var_ssa(id: u64, version: usize) -> SSAVariable {
    SSAVariable::new(get_var(id), version)
}

/// Conditional branching instruction and an expected conditional result
pub struct BranchDependence {
    pub instruction: MediumLevelILInstruction,
    pub dependence: ILBranchDependence,
}

impl CoreArrayProvider for BranchDependence {
    type Raw = BNILBranchInstructionAndDependence;
    type Context = Ref<MediumLevelILFunction>;
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for BranchDependence {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        unsafe { BNFreeILBranchDependenceList(raw) };
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self {
            instruction: MediumLevelILInstruction::from_expr_index(
                context.clone(),
                MediumLevelExpressionIndex(raw.branch),
            ),
            dependence: raw.dependence,
        }
    }
}
