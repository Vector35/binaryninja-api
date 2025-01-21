use super::lift::*;
use super::operation::*;
use super::{MediumLevelILBlock, MediumLevelILFunction};
use crate::architecture::{CoreIntrinsic, FlagId, IntrinsicId, RegisterId};
use crate::basic_block::BasicBlock;
use crate::confidence::Conf;
use crate::disassembly::InstructionTextToken;
use crate::operand_iter::OperandIter;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::types::Type;
use crate::variable::{ConstantData, PossibleValueSet, RegisterValue, SSAVariable, Variable};
use crate::{DataFlowQueryOption, ILBranchDependence};
use binaryninjacore_sys::*;
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

#[derive(Clone)]
pub struct MediumLevelILInstruction {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    // TODO; Because this structure is incorrectly named instruction, we want to make it clear that we actually have the expression index.
    pub expr_index: MediumLevelInstructionIndex,
    pub size: usize,
    pub kind: MediumLevelILInstructionKind,
}

impl MediumLevelILInstruction {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        index: MediumLevelInstructionIndex,
    ) -> Self {
        // TODO: If op.sourceOperation == BN_INVALID_OPERAND && op.operation == MLIL_NOP return None
        let expr_index = unsafe { BNGetMediumLevelILIndexForInstruction(function.handle, index.0) };
        Self::new_expr(function, MediumLevelInstructionIndex(expr_index))
    }

    // TODO: I need MediumLevelILExpression YESTERDAY!!!!
    pub(crate) fn new_expr(
        function: Ref<MediumLevelILFunction>,
        expr_index: MediumLevelInstructionIndex,
    ) -> Self {
        // TODO: If op.sourceOperation == BN_INVALID_OPERAND && op.operation == MLIL_NOP return None
        let op = unsafe { BNGetMediumLevelILByIndex(function.handle, expr_index.0) };
        use BNMediumLevelILOperation::*;
        use MediumLevelILInstructionKind as Op;
        let kind = match op.operation {
            MLIL_NOP => Op::Nop,
            MLIL_NORET => Op::Noret,
            MLIL_BP => Op::Bp,
            MLIL_UNDEF => Op::Undef,
            MLIL_UNIMPL => Op::Unimpl,
            MLIL_IF => Op::If(MediumLevelILOperationIf {
                condition: op.operands[0] as usize,
                dest_true: MediumLevelInstructionIndex(op.operands[1] as usize),
                dest_false: MediumLevelInstructionIndex(op.operands[2] as usize),
            }),
            MLIL_FLOAT_CONST => Op::FloatConst(FloatConst {
                constant: get_float(op.operands[0], op.size),
            }),
            MLIL_CONST => Op::Const(Constant {
                constant: op.operands[0],
            }),
            MLIL_CONST_PTR => Op::ConstPtr(Constant {
                constant: op.operands[0],
            }),
            MLIL_IMPORT => Op::Import(Constant {
                constant: op.operands[0],
            }),
            MLIL_EXTERN_PTR => Op::ExternPtr(ExternPtr {
                constant: op.operands[0],
                offset: op.operands[1],
            }),
            MLIL_CONST_DATA => Op::ConstData(ConstData {
                constant_data_kind: op.operands[0] as u32,
                constant_data_value: op.operands[1] as i64,
                size: op.size,
            }),
            MLIL_JUMP => Op::Jump(Jump {
                dest: op.operands[0] as usize,
            }),
            MLIL_RET_HINT => Op::RetHint(Jump {
                dest: op.operands[0] as usize,
            }),
            MLIL_STORE_SSA => Op::StoreSsa(StoreSsa {
                dest: op.operands[0] as usize,
                dest_memory: op.operands[1],
                src_memory: op.operands[2],
                src: op.operands[3] as usize,
            }),
            MLIL_STORE_STRUCT_SSA => Op::StoreStructSsa(StoreStructSsa {
                dest: op.operands[0] as usize,
                offset: op.operands[1],
                dest_memory: op.operands[2],
                src_memory: op.operands[3],
                src: op.operands[4] as usize,
            }),
            MLIL_STORE_STRUCT => Op::StoreStruct(StoreStruct {
                dest: op.operands[0] as usize,
                offset: op.operands[1],
                src: op.operands[2] as usize,
            }),
            MLIL_STORE => Op::Store(Store {
                dest: op.operands[0] as usize,
                src: op.operands[1] as usize,
            }),
            MLIL_JUMP_TO => Op::JumpTo(JumpTo {
                dest: op.operands[0] as usize,
                num_operands: op.operands[1] as usize,
                first_operand: op.operands[2] as usize,
            }),
            MLIL_GOTO => Op::Goto(Goto {
                dest: MediumLevelInstructionIndex(op.operands[0] as usize),
            }),
            MLIL_FREE_VAR_SLOT => Op::FreeVarSlot(FreeVarSlot {
                dest: get_var(op.operands[0]),
            }),
            MLIL_SET_VAR_FIELD => Op::SetVarField(SetVarField {
                dest: get_var(op.operands[0]),
                offset: op.operands[1],
                src: op.operands[2] as usize,
            }),
            MLIL_SET_VAR => Op::SetVar(SetVar {
                dest: get_var(op.operands[0]),
                src: op.operands[1] as usize,
            }),
            MLIL_FREE_VAR_SLOT_SSA => Op::FreeVarSlotSsa(FreeVarSlotSsa {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
            }),
            MLIL_SET_VAR_SSA_FIELD => Op::SetVarSsaField(SetVarSsaField {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
                offset: op.operands[3],
                src: op.operands[4] as usize,
            }),
            MLIL_SET_VAR_ALIASED_FIELD => Op::SetVarAliasedField(SetVarSsaField {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
                offset: op.operands[3],
                src: op.operands[4] as usize,
            }),
            MLIL_SET_VAR_ALIASED => Op::SetVarAliased(SetVarAliased {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
                src: op.operands[3] as usize,
            }),
            MLIL_SET_VAR_SSA => Op::SetVarSsa(SetVarSsa {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                src: op.operands[2] as usize,
            }),
            MLIL_VAR_PHI => Op::VarPhi(VarPhi {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                num_operands: op.operands[2] as usize,
                first_operand: op.operands[3] as usize,
            }),
            MLIL_MEM_PHI => Op::MemPhi(MemPhi {
                dest_memory: op.operands[0],
                num_operands: op.operands[1] as usize,
                first_operand: op.operands[2] as usize,
            }),
            MLIL_VAR_SPLIT => Op::VarSplit(VarSplit {
                high: get_var(op.operands[0]),
                low: get_var(op.operands[1]),
            }),
            MLIL_SET_VAR_SPLIT => Op::SetVarSplit(SetVarSplit {
                high: get_var(op.operands[0]),
                low: get_var(op.operands[1]),
                src: op.operands[2] as usize,
            }),
            MLIL_VAR_SPLIT_SSA => Op::VarSplitSsa(VarSplitSsa {
                high: get_var_ssa(op.operands[0], op.operands[1] as usize),
                low: get_var_ssa(op.operands[2], op.operands[3] as usize),
            }),
            MLIL_SET_VAR_SPLIT_SSA => Op::SetVarSplitSsa(SetVarSplitSsa {
                high: get_var_ssa(op.operands[0], op.operands[1] as usize),
                low: get_var_ssa(op.operands[2], op.operands[3] as usize),
                src: op.operands[4] as usize,
            }),
            MLIL_ADD => Op::Add(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_SUB => Op::Sub(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_AND => Op::And(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_OR => Op::Or(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_XOR => Op::Xor(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_LSL => Op::Lsl(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_LSR => Op::Lsr(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_ASR => Op::Asr(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_ROL => Op::Rol(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_ROR => Op::Ror(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_MUL => Op::Mul(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_MULU_DP => Op::MuluDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_MULS_DP => Op::MulsDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_DIVU => Op::Divu(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_DIVU_DP => Op::DivuDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_DIVS => Op::Divs(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_DIVS_DP => Op::DivsDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_MODU => Op::Modu(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_MODU_DP => Op::ModuDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_MODS => Op::Mods(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_MODS_DP => Op::ModsDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_CMP_E => Op::CmpE(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_CMP_NE => Op::CmpNe(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_CMP_SLT => Op::CmpSlt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_CMP_ULT => Op::CmpUlt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_CMP_SLE => Op::CmpSle(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_CMP_ULE => Op::CmpUle(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_CMP_SGE => Op::CmpSge(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_CMP_UGE => Op::CmpUge(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_CMP_SGT => Op::CmpSgt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_CMP_UGT => Op::CmpUgt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_TEST_BIT => Op::TestBit(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_ADD_OVERFLOW => Op::AddOverflow(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FCMP_E => Op::FcmpE(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FCMP_NE => Op::FcmpNe(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FCMP_LT => Op::FcmpLt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FCMP_LE => Op::FcmpLe(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FCMP_GE => Op::FcmpGe(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FCMP_GT => Op::FcmpGt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FCMP_O => Op::FcmpO(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FCMP_UO => Op::FcmpUo(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FADD => Op::Fadd(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FSUB => Op::Fsub(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FMUL => Op::Fmul(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_FDIV => Op::Fdiv(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            MLIL_ADC => Op::Adc(BinaryOpCarry {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
                carry: op.operands[2] as usize,
            }),
            MLIL_SBB => Op::Sbb(BinaryOpCarry {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
                carry: op.operands[2] as usize,
            }),
            MLIL_RLC => Op::Rlc(BinaryOpCarry {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
                carry: op.operands[2] as usize,
            }),
            MLIL_RRC => Op::Rrc(BinaryOpCarry {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
                carry: op.operands[2] as usize,
            }),
            MLIL_CALL => Op::Call(Call {
                num_outputs: op.operands[0] as usize,
                first_output: op.operands[1] as usize,
                dest: op.operands[2] as usize,
                num_params: op.operands[3] as usize,
                first_param: op.operands[4] as usize,
            }),
            MLIL_TAILCALL => Op::Tailcall(Call {
                num_outputs: op.operands[0] as usize,
                first_output: op.operands[1] as usize,
                dest: op.operands[2] as usize,
                num_params: op.operands[3] as usize,
                first_param: op.operands[4] as usize,
            }),
            MLIL_SYSCALL => Op::Syscall(Syscall {
                num_outputs: op.operands[0] as usize,
                first_output: op.operands[1] as usize,
                num_params: op.operands[2] as usize,
                first_param: op.operands[3] as usize,
            }),
            MLIL_INTRINSIC => Op::Intrinsic(Intrinsic {
                num_outputs: op.operands[0] as usize,
                first_output: op.operands[1] as usize,
                intrinsic: op.operands[2] as u32,
                num_params: op.operands[3] as usize,
                first_param: op.operands[4] as usize,
            }),
            MLIL_INTRINSIC_SSA => Op::IntrinsicSsa(IntrinsicSsa {
                num_outputs: op.operands[0] as usize,
                first_output: op.operands[1] as usize,
                intrinsic: op.operands[2] as u32,
                num_params: op.operands[3] as usize,
                first_param: op.operands[4] as usize,
            }),
            MLIL_CALL_SSA => Op::CallSsa(CallSsa {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                num_params: op.operands[2] as usize,
                first_param: op.operands[3] as usize,
                src_memory: op.operands[4],
            }),
            MLIL_TAILCALL_SSA => Op::TailcallSsa(CallSsa {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                num_params: op.operands[2] as usize,
                first_param: op.operands[3] as usize,
                src_memory: op.operands[4],
            }),
            MLIL_CALL_UNTYPED_SSA => Op::CallUntypedSsa(CallUntypedSsa {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                params: op.operands[2] as usize,
                stack: op.operands[3] as usize,
            }),
            MLIL_TAILCALL_UNTYPED_SSA => Op::TailcallUntypedSsa(CallUntypedSsa {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                params: op.operands[2] as usize,
                stack: op.operands[3] as usize,
            }),
            MLIL_SYSCALL_SSA => Op::SyscallSsa(SyscallSsa {
                output: op.operands[0] as usize,
                num_params: op.operands[1] as usize,
                first_param: op.operands[2] as usize,
                src_memory: op.operands[3],
            }),
            MLIL_SYSCALL_UNTYPED_SSA => Op::SyscallUntypedSsa(SyscallUntypedSsa {
                output: op.operands[0] as usize,
                params: op.operands[1] as usize,
                stack: op.operands[2] as usize,
            }),
            MLIL_CALL_UNTYPED => Op::CallUntyped(CallUntyped {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                params: op.operands[2] as usize,
                stack: op.operands[3] as usize,
            }),
            MLIL_TAILCALL_UNTYPED => Op::TailcallUntyped(CallUntyped {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                params: op.operands[2] as usize,
                stack: op.operands[3] as usize,
            }),
            MLIL_SYSCALL_UNTYPED => Op::SyscallUntyped(SyscallUntyped {
                output: op.operands[0] as usize,
                params: op.operands[1] as usize,
                stack: op.operands[2] as usize,
            }),
            MLIL_NEG => Op::Neg(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_NOT => Op::Not(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_SX => Op::Sx(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_ZX => Op::Zx(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_LOW_PART => Op::LowPart(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_BOOL_TO_INT => Op::BoolToInt(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_UNIMPL_MEM => Op::UnimplMem(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_FSQRT => Op::Fsqrt(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_FNEG => Op::Fneg(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_FABS => Op::Fabs(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_FLOAT_TO_INT => Op::FloatToInt(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_INT_TO_FLOAT => Op::IntToFloat(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_FLOAT_CONV => Op::FloatConv(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_ROUND_TO_INT => Op::RoundToInt(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_FLOOR => Op::Floor(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_CEIL => Op::Ceil(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_FTRUNC => Op::Ftrunc(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_LOAD => Op::Load(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_LOAD_STRUCT => Op::LoadStruct(LoadStruct {
                src: op.operands[0] as usize,
                offset: op.operands[1],
            }),
            MLIL_LOAD_STRUCT_SSA => Op::LoadStructSsa(LoadStructSsa {
                src: op.operands[0] as usize,
                offset: op.operands[1],
                src_memory: op.operands[2],
            }),
            MLIL_LOAD_SSA => Op::LoadSsa(LoadSsa {
                src: op.operands[0] as usize,
                src_memory: op.operands[1],
            }),
            MLIL_RET => Op::Ret(Ret {
                num_operands: op.operands[0] as usize,
                first_operand: op.operands[1] as usize,
            }),
            MLIL_SEPARATE_PARAM_LIST => Op::SeparateParamList(SeparateParamList {
                num_params: op.operands[0] as usize,
                first_param: op.operands[1] as usize,
            }),
            MLIL_SHARED_PARAM_SLOT => Op::SharedParamSlot(SharedParamSlot {
                num_params: op.operands[0] as usize,
                first_param: op.operands[1] as usize,
            }),
            MLIL_VAR => Op::Var(Var {
                src: get_var(op.operands[0]),
            }),
            MLIL_ADDRESS_OF => Op::AddressOf(Var {
                src: get_var(op.operands[0]),
            }),
            MLIL_VAR_FIELD => Op::VarField(Field {
                src: get_var(op.operands[0]),
                offset: op.operands[1],
            }),
            MLIL_ADDRESS_OF_FIELD => Op::AddressOfField(Field {
                src: get_var(op.operands[0]),
                offset: op.operands[1],
            }),
            MLIL_VAR_SSA => Op::VarSsa(VarSsa {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
            }),
            MLIL_VAR_ALIASED => Op::VarAliased(VarSsa {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
            }),
            MLIL_VAR_SSA_FIELD => Op::VarSsaField(VarSsaField {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
                offset: op.operands[2],
            }),
            MLIL_VAR_ALIASED_FIELD => Op::VarAliasedField(VarSsaField {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
                offset: op.operands[2],
            }),
            MLIL_TRAP => Op::Trap(Trap {
                vector: op.operands[0],
            }),
            // translated directly into a list for Expression or Variables
            // TODO MLIL_MEMORY_INTRINSIC_SSA needs to be handled properly
            MLIL_CALL_OUTPUT
            | MLIL_CALL_PARAM
            | MLIL_CALL_PARAM_SSA
            | MLIL_CALL_OUTPUT_SSA
            | MLIL_MEMORY_INTRINSIC_OUTPUT_SSA
            | MLIL_MEMORY_INTRINSIC_SSA => {
                unimplemented!()
            }
        };

        Self {
            function,
            address: op.address,
            expr_index,
            size: op.size,
            kind,
        }
    }

    pub fn lift(&self) -> MediumLevelILLiftedInstruction {
        use MediumLevelILInstructionKind::*;
        use MediumLevelILLiftedInstructionKind as Lifted;

        let kind = match self.kind {
            Nop => Lifted::Nop,
            Noret => Lifted::Noret,
            Bp => Lifted::Bp,
            Undef => Lifted::Undef,
            Unimpl => Lifted::Unimpl,
            If(op) => Lifted::If(LiftedIf {
                condition: self.lift_operand(op.condition),
                dest_true: op.dest_true,
                dest_false: op.dest_false,
            }),

            FloatConst(op) => Lifted::FloatConst(op),
            Const(op) => Lifted::Const(op),
            ConstPtr(op) => Lifted::ConstPtr(op),
            Import(op) => Lifted::Import(op),
            ExternPtr(op) => Lifted::ExternPtr(op),

            ConstData(op) => Lifted::ConstData(LiftedConstData {
                constant_data: ConstantData::new(
                    self.function.function(),
                    RegisterValue {
                        // TODO: Replace with a From<u32> for RegisterValueType.
                        // TODO: We might also want to change the type of `op.constant_data_kind`
                        // TODO: To RegisterValueType and do the conversion when creating instruction.
                        state: unsafe {
                            std::mem::transmute::<u32, BNRegisterValueType>(op.constant_data_kind)
                        },
                        value: op.constant_data_value,
                        offset: 0,
                        size: op.size,
                    },
                ),
            }),
            Jump(op) => Lifted::Jump(LiftedJump {
                dest: self.lift_operand(op.dest),
            }),
            RetHint(op) => Lifted::RetHint(LiftedJump {
                dest: self.lift_operand(op.dest),
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
            StoreStruct(op) => Lifted::StoreStruct(LiftedStoreStruct {
                dest: self.lift_operand(op.dest),
                offset: op.offset,
                src: self.lift_operand(op.src),
            }),
            Store(op) => Lifted::Store(LiftedStore {
                dest: self.lift_operand(op.dest),
                src: self.lift_operand(op.src),
            }),
            JumpTo(op) => Lifted::JumpTo(LiftedJumpTo {
                dest: self.lift_operand(op.dest),
                targets: OperandIter::new(&*self.function, op.first_operand, op.num_operands)
                    .pairs()
                    .map(|(addr, instr_idx)| {
                        (addr, MediumLevelInstructionIndex(instr_idx as usize))
                    })
                    .collect(),
            }),
            Goto(op) => Lifted::Goto(op),
            FreeVarSlot(op) => Lifted::FreeVarSlot(op),
            SetVarField(op) => Lifted::SetVarField(LiftedSetVarField {
                dest: op.dest,
                offset: op.offset,
                src: self.lift_operand(op.src),
            }),
            SetVar(op) => Lifted::SetVar(LiftedSetVar {
                dest: op.dest,
                src: self.lift_operand(op.src),
            }),
            FreeVarSlotSsa(op) => Lifted::FreeVarSlotSsa(op),
            SetVarSsaField(op) => Lifted::SetVarSsaField(LiftedSetVarSsaField {
                dest: op.dest,
                prev: op.prev,
                offset: op.offset,
                src: self.lift_operand(op.src),
            }),
            SetVarAliasedField(op) => Lifted::SetVarAliasedField(LiftedSetVarSsaField {
                dest: op.dest,
                prev: op.prev,
                offset: op.offset,
                src: self.lift_operand(op.src),
            }),
            SetVarAliased(op) => Lifted::SetVarAliased(LiftedSetVarAliased {
                dest: op.dest,
                prev: op.prev,
                src: self.lift_operand(op.src),
            }),
            SetVarSsa(op) => Lifted::SetVarSsa(LiftedSetVarSsa {
                dest: op.dest,
                src: self.lift_operand(op.src),
            }),
            VarPhi(op) => Lifted::VarPhi(LiftedVarPhi {
                dest: op.dest,
                src: OperandIter::new(&*self.function, op.first_operand, op.num_operands)
                    .ssa_vars()
                    .collect(),
            }),
            MemPhi(op) => Lifted::MemPhi(LiftedMemPhi {
                dest_memory: op.dest_memory,
                src_memory: OperandIter::new(&*self.function, op.first_operand, op.num_operands)
                    .collect(),
            }),
            VarSplit(op) => Lifted::VarSplit(op),
            SetVarSplit(op) => Lifted::SetVarSplit(LiftedSetVarSplit {
                high: op.high,
                low: op.low,
                src: self.lift_operand(op.src),
            }),
            VarSplitSsa(op) => Lifted::VarSplitSsa(op),
            SetVarSplitSsa(op) => Lifted::SetVarSplitSsa(LiftedSetVarSplitSsa {
                high: op.high,
                low: op.low,
                src: self.lift_operand(op.src),
            }),

            Add(op) => Lifted::Add(self.lift_binary_op(op)),
            Sub(op) => Lifted::Sub(self.lift_binary_op(op)),
            And(op) => Lifted::And(self.lift_binary_op(op)),
            Or(op) => Lifted::Or(self.lift_binary_op(op)),
            Xor(op) => Lifted::Xor(self.lift_binary_op(op)),
            Lsl(op) => Lifted::Lsl(self.lift_binary_op(op)),
            Lsr(op) => Lifted::Lsr(self.lift_binary_op(op)),
            Asr(op) => Lifted::Asr(self.lift_binary_op(op)),
            Rol(op) => Lifted::Rol(self.lift_binary_op(op)),
            Ror(op) => Lifted::Ror(self.lift_binary_op(op)),
            Mul(op) => Lifted::Mul(self.lift_binary_op(op)),
            MuluDp(op) => Lifted::MuluDp(self.lift_binary_op(op)),
            MulsDp(op) => Lifted::MulsDp(self.lift_binary_op(op)),
            Divu(op) => Lifted::Divu(self.lift_binary_op(op)),
            DivuDp(op) => Lifted::DivuDp(self.lift_binary_op(op)),
            Divs(op) => Lifted::Divs(self.lift_binary_op(op)),
            DivsDp(op) => Lifted::DivsDp(self.lift_binary_op(op)),
            Modu(op) => Lifted::Modu(self.lift_binary_op(op)),
            ModuDp(op) => Lifted::ModuDp(self.lift_binary_op(op)),
            Mods(op) => Lifted::Mods(self.lift_binary_op(op)),
            ModsDp(op) => Lifted::ModsDp(self.lift_binary_op(op)),
            CmpE(op) => Lifted::CmpE(self.lift_binary_op(op)),
            CmpNe(op) => Lifted::CmpNe(self.lift_binary_op(op)),
            CmpSlt(op) => Lifted::CmpSlt(self.lift_binary_op(op)),
            CmpUlt(op) => Lifted::CmpUlt(self.lift_binary_op(op)),
            CmpSle(op) => Lifted::CmpSle(self.lift_binary_op(op)),
            CmpUle(op) => Lifted::CmpUle(self.lift_binary_op(op)),
            CmpSge(op) => Lifted::CmpSge(self.lift_binary_op(op)),
            CmpUge(op) => Lifted::CmpUge(self.lift_binary_op(op)),
            CmpSgt(op) => Lifted::CmpSgt(self.lift_binary_op(op)),
            CmpUgt(op) => Lifted::CmpUgt(self.lift_binary_op(op)),
            TestBit(op) => Lifted::TestBit(self.lift_binary_op(op)),
            AddOverflow(op) => Lifted::AddOverflow(self.lift_binary_op(op)),
            FcmpE(op) => Lifted::FcmpE(self.lift_binary_op(op)),
            FcmpNe(op) => Lifted::FcmpNe(self.lift_binary_op(op)),
            FcmpLt(op) => Lifted::FcmpLt(self.lift_binary_op(op)),
            FcmpLe(op) => Lifted::FcmpLe(self.lift_binary_op(op)),
            FcmpGe(op) => Lifted::FcmpGe(self.lift_binary_op(op)),
            FcmpGt(op) => Lifted::FcmpGt(self.lift_binary_op(op)),
            FcmpO(op) => Lifted::FcmpO(self.lift_binary_op(op)),
            FcmpUo(op) => Lifted::FcmpUo(self.lift_binary_op(op)),
            Fadd(op) => Lifted::Fadd(self.lift_binary_op(op)),
            Fsub(op) => Lifted::Fsub(self.lift_binary_op(op)),
            Fmul(op) => Lifted::Fmul(self.lift_binary_op(op)),
            Fdiv(op) => Lifted::Fdiv(self.lift_binary_op(op)),

            Adc(op) => Lifted::Adc(self.lift_binary_op_carry(op)),
            Sbb(op) => Lifted::Sbb(self.lift_binary_op_carry(op)),
            Rlc(op) => Lifted::Rlc(self.lift_binary_op_carry(op)),
            Rrc(op) => Lifted::Rrc(self.lift_binary_op_carry(op)),

            Call(op) => Lifted::Call(self.lift_call(op)),
            Tailcall(op) => Lifted::Tailcall(self.lift_call(op)),

            Intrinsic(op) => Lifted::Intrinsic(LiftedIntrinsic {
                output: OperandIter::new(&*self.function, op.first_output, op.num_outputs)
                    .vars()
                    .collect(),
                intrinsic: CoreIntrinsic::new(
                    self.function.function().arch(),
                    IntrinsicId(op.intrinsic),
                )
                .expect("Valid intrinsic"),
                params: OperandIter::new(&*self.function, op.first_param, op.num_params)
                    .exprs()
                    .map(|expr| expr.lift())
                    .collect(),
            }),
            Syscall(op) => Lifted::Syscall(LiftedSyscallCall {
                output: OperandIter::new(&*self.function, op.first_output, op.num_outputs)
                    .vars()
                    .collect(),
                params: OperandIter::new(&*self.function, op.first_param, op.num_params)
                    .exprs()
                    .map(|expr| expr.lift())
                    .collect(),
            }),
            IntrinsicSsa(op) => Lifted::IntrinsicSsa(LiftedIntrinsicSsa {
                output: OperandIter::new(&*self.function, op.first_output, op.num_outputs)
                    .ssa_vars()
                    .collect(),
                intrinsic: CoreIntrinsic::new(
                    self.function.function().arch(),
                    IntrinsicId(op.intrinsic),
                )
                .expect("Valid intrinsic"),
                params: OperandIter::new(&*self.function, op.first_param, op.num_params)
                    .exprs()
                    .map(|expr| expr.lift())
                    .collect(),
            }),

            CallSsa(op) => Lifted::CallSsa(self.lift_call_ssa(op)),
            TailcallSsa(op) => Lifted::TailcallSsa(self.lift_call_ssa(op)),

            CallUntypedSsa(op) => Lifted::CallUntypedSsa(self.lift_call_untyped_ssa(op)),
            TailcallUntypedSsa(op) => Lifted::TailcallUntypedSsa(self.lift_call_untyped_ssa(op)),

            SyscallSsa(op) => Lifted::SyscallSsa(LiftedSyscallSsa {
                output: get_call_output_ssa(&self.function, op.output).collect(),
                params: OperandIter::new(&*self.function, op.first_param, op.num_params)
                    .exprs()
                    .map(|expr| expr.lift())
                    .collect(),
                src_memory: op.src_memory,
            }),
            SyscallUntypedSsa(op) => Lifted::SyscallUntypedSsa(LiftedSyscallUntypedSsa {
                output: get_call_output_ssa(&self.function, op.output).collect(),
                params: get_call_params_ssa(&self.function, op.params)
                    .map(|param| param.lift())
                    .collect(),
                stack: self.lift_operand(op.stack),
            }),

            CallUntyped(op) => Lifted::CallUntyped(self.lift_call_untyped(op)),
            TailcallUntyped(op) => Lifted::TailcallUntyped(self.lift_call_untyped(op)),
            SyscallUntyped(op) => Lifted::SyscallUntyped(LiftedSyscallUntyped {
                output: get_call_output(&self.function, op.output).collect(),
                params: get_call_params(&self.function, op.params)
                    .map(|param| param.lift())
                    .collect(),
                stack: self.lift_operand(op.stack),
            }),

            Neg(op) => Lifted::Neg(self.lift_unary_op(op)),
            Not(op) => Lifted::Not(self.lift_unary_op(op)),
            Sx(op) => Lifted::Sx(self.lift_unary_op(op)),
            Zx(op) => Lifted::Zx(self.lift_unary_op(op)),
            LowPart(op) => Lifted::LowPart(self.lift_unary_op(op)),
            BoolToInt(op) => Lifted::BoolToInt(self.lift_unary_op(op)),
            UnimplMem(op) => Lifted::UnimplMem(self.lift_unary_op(op)),
            Fsqrt(op) => Lifted::Fsqrt(self.lift_unary_op(op)),
            Fneg(op) => Lifted::Fneg(self.lift_unary_op(op)),
            Fabs(op) => Lifted::Fabs(self.lift_unary_op(op)),
            FloatToInt(op) => Lifted::FloatToInt(self.lift_unary_op(op)),
            IntToFloat(op) => Lifted::IntToFloat(self.lift_unary_op(op)),
            FloatConv(op) => Lifted::FloatConv(self.lift_unary_op(op)),
            RoundToInt(op) => Lifted::RoundToInt(self.lift_unary_op(op)),
            Floor(op) => Lifted::Floor(self.lift_unary_op(op)),
            Ceil(op) => Lifted::Ceil(self.lift_unary_op(op)),
            Ftrunc(op) => Lifted::Ftrunc(self.lift_unary_op(op)),
            Load(op) => Lifted::Load(self.lift_unary_op(op)),

            LoadStruct(op) => Lifted::LoadStruct(LiftedLoadStruct {
                src: self.lift_operand(op.src),
                offset: op.offset,
            }),
            LoadStructSsa(op) => Lifted::LoadStructSsa(LiftedLoadStructSsa {
                src: self.lift_operand(op.src),
                offset: op.offset,
                src_memory: op.src_memory,
            }),
            LoadSsa(op) => Lifted::LoadSsa(LiftedLoadSsa {
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
            }),
            Ret(op) => Lifted::Ret(LiftedRet {
                src: OperandIter::new(&*self.function, op.first_operand, op.num_operands)
                    .exprs()
                    .map(|expr| expr.lift())
                    .collect(),
            }),
            SeparateParamList(op) => Lifted::SeparateParamList(LiftedSeparateParamList {
                params: OperandIter::new(&*self.function, op.first_param, op.num_params)
                    .exprs()
                    .map(|expr| expr.lift())
                    .collect(),
            }),
            SharedParamSlot(op) => Lifted::SharedParamSlot(LiftedSharedParamSlot {
                params: OperandIter::new(&*self.function, op.first_param, op.num_params)
                    .exprs()
                    .map(|expr| expr.lift())
                    .collect(),
            }),
            Var(op) => Lifted::Var(op),
            AddressOf(op) => Lifted::AddressOf(op),
            VarField(op) => Lifted::VarField(op),
            AddressOfField(op) => Lifted::AddressOfField(op),
            VarSsa(op) => Lifted::VarSsa(op),
            VarAliased(op) => Lifted::VarAliased(op),
            VarSsaField(op) => Lifted::VarSsaField(op),
            VarAliasedField(op) => Lifted::VarAliasedField(op),
            Trap(op) => Lifted::Trap(op),
        };

        MediumLevelILLiftedInstruction {
            function: self.function.clone(),
            address: self.address,
            index: self.expr_index,
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
        self.function.basic_block_containing_index(self.expr_index)
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
                self.expr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_raw(value)
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
                self.expr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_raw(value)
    }

    /// Return the ssa version of a [`Variable`] at the given instruction.
    pub fn ssa_variable_version(&self, var: Variable) -> SSAVariable {
        let raw_var = BNVariable::from(var);
        let version = unsafe {
            BNGetMediumLevelILSSAVarVersionAtILInstruction(
                self.function.handle,
                &raw_var,
                self.expr_index.0,
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
                self.expr_index.0,
                &mut count,
            )
        };
        assert!(!deps.is_null());
        unsafe { Array::new(deps, count, self.function.clone()) }
    }

    pub fn branch_dependence_at(&self, instruction: MediumLevelILInstruction) -> BranchDependence {
        let deps = unsafe {
            BNGetMediumLevelILBranchDependence(
                self.function.handle,
                self.expr_index.0,
                instruction.expr_index.0,
            )
        };
        BranchDependence {
            instruction,
            dependence: deps,
        }
    }

    /// Version of active memory contents in SSA form for this instruction
    pub fn ssa_memory_version(&self) -> usize {
        unsafe {
            BNGetMediumLevelILSSAMemoryVersionAtILInstruction(
                self.function.handle,
                self.expr_index.0,
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
                self.expr_index.0,
            )
        };
        Variable::from(result)
    }

    pub fn variable_for_flag(&self, flag_id: FlagId) -> Variable {
        let result = unsafe {
            BNGetMediumLevelILVariableForFlagAtInstruction(
                self.function.handle,
                flag_id.0,
                self.expr_index.0,
            )
        };
        Variable::from(result)
    }

    pub fn variable_for_stack_location(&self, offset: i64) -> Variable {
        let result = unsafe {
            BNGetMediumLevelILVariableForStackLocationAtInstruction(
                self.function.handle,
                offset,
                self.expr_index.0,
            )
        };
        Variable::from(result)
    }

    pub fn register_value(&self, reg_id: RegisterId) -> RegisterValue {
        unsafe {
            BNGetMediumLevelILRegisterValueAtInstruction(
                self.function.handle,
                reg_id.0,
                self.expr_index.0,
            )
        }
        .into()
    }

    pub fn register_value_after(&self, reg_id: RegisterId) -> RegisterValue {
        unsafe {
            BNGetMediumLevelILRegisterValueAfterInstruction(
                self.function.handle,
                reg_id.0,
                self.expr_index.0,
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
                self.expr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_raw(value)
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
                self.expr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_raw(value)
    }

    pub fn flag_value(&self, flag_id: FlagId) -> RegisterValue {
        unsafe {
            BNGetMediumLevelILFlagValueAtInstruction(
                self.function.handle,
                flag_id.0,
                self.expr_index.0,
            )
        }
        .into()
    }

    pub fn flag_value_after(&self, flag_id: FlagId) -> RegisterValue {
        unsafe {
            BNGetMediumLevelILFlagValueAfterInstruction(
                self.function.handle,
                flag_id.0,
                self.expr_index.0,
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
                self.expr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_raw(value)
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
                self.expr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_raw(value)
    }

    pub fn stack_contents(&self, offset: i64, size: usize) -> RegisterValue {
        unsafe {
            BNGetMediumLevelILStackContentsAtInstruction(
                self.function.handle,
                offset,
                size,
                self.expr_index.0,
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
                self.expr_index.0,
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
                self.expr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_raw(value)
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
                self.expr_index.0,
                options.as_ptr() as *mut _,
                options.len(),
            )
        };
        PossibleValueSet::from_owned_raw(value)
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
                self.expr_index.0,
            )
        };
        Variable::new(var.ty, index, var.storage)
    }

    /// alias for [MediumLevelILInstruction::split_var_for_definition]
    #[inline]
    pub fn get_split_var_for_definition(&self, var: &Variable) -> Variable {
        self.split_var_for_definition(var)
    }

    fn lift_operand(&self, expr_idx: usize) -> Box<MediumLevelILLiftedInstruction> {
        // TODO: UGH, if your gonna call it expr_idx, call the instruction and expression!!!!!
        // TODO: We dont even need to say instruction in the type!
        // TODO: IF you want to have an instruction type, there needs to be a separate expression type
        // TODO: See the lowlevelil module.
        let expr_idx_is_really_instr_idx = MediumLevelInstructionIndex(expr_idx);
        // TODO: See the comment in the unchecked function, ugh, i hate this..
        let operand_instr = self
            .function
            .instruction_from_expr_index(expr_idx_is_really_instr_idx)
            .unwrap();
        Box::new(operand_instr.lift())
    }

    fn lift_binary_op(&self, op: BinaryOp) -> LiftedBinaryOp {
        LiftedBinaryOp {
            left: self.lift_operand(op.left),
            right: self.lift_operand(op.right),
        }
    }

    fn lift_binary_op_carry(&self, op: BinaryOpCarry) -> LiftedBinaryOpCarry {
        LiftedBinaryOpCarry {
            left: self.lift_operand(op.left),
            right: self.lift_operand(op.right),
            carry: self.lift_operand(op.carry),
        }
    }

    fn lift_unary_op(&self, op: UnaryOp) -> LiftedUnaryOp {
        LiftedUnaryOp {
            src: self.lift_operand(op.src),
        }
    }

    fn lift_call(&self, op: Call) -> LiftedCall {
        LiftedCall {
            output: OperandIter::new(&*self.function, op.first_output, op.num_outputs)
                .vars()
                .collect(),
            dest: self.lift_operand(op.dest),
            params: OperandIter::new(&*self.function, op.first_param, op.num_params)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
        }
    }

    fn lift_call_untyped(&self, op: CallUntyped) -> LiftedCallUntyped {
        LiftedCallUntyped {
            output: get_call_output(&self.function, op.output).collect(),
            dest: self.lift_operand(op.dest),
            params: get_call_params(&self.function, op.params)
                .map(|expr| expr.lift())
                .collect(),
            stack: self.lift_operand(op.stack),
        }
    }

    fn lift_call_ssa(&self, op: CallSsa) -> LiftedCallSsa {
        LiftedCallSsa {
            output: get_call_output_ssa(&self.function, op.output).collect(),
            dest: self.lift_operand(op.dest),
            params: OperandIter::new(&*self.function, op.first_param, op.num_params)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
            src_memory: op.src_memory,
        }
    }

    fn lift_call_untyped_ssa(&self, op: CallUntypedSsa) -> LiftedCallUntypedSsa {
        LiftedCallUntypedSsa {
            output: get_call_output_ssa(&self.function, op.output).collect(),
            dest: self.lift_operand(op.dest),
            params: get_call_params_ssa(&self.function, op.params)
                .map(|param| param.lift())
                .collect(),
            stack: self.lift_operand(op.stack),
        }
    }
}

impl Debug for MediumLevelILInstruction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediumLevelILInstruction")
            .field("address", &self.address)
            .field("index", &self.expr_index)
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
        // TODO: This needs to be tested!!!!
        // TODO: What if this does not need to be mapped!!!!
        context
            .instruction_from_index(MediumLevelInstructionIndex(*raw))
            .unwrap()
    }
}

#[derive(Debug, Copy, Clone)]
pub enum MediumLevelILInstructionKind {
    Nop,
    Noret,
    Bp,
    Undef,
    Unimpl,
    If(MediumLevelILOperationIf),
    FloatConst(FloatConst),
    Const(Constant),
    ConstPtr(Constant),
    Import(Constant),
    ExternPtr(ExternPtr),
    ConstData(ConstData),
    Jump(Jump),
    RetHint(Jump),
    StoreSsa(StoreSsa),
    StoreStructSsa(StoreStructSsa),
    StoreStruct(StoreStruct),
    Store(Store),
    JumpTo(JumpTo),
    Goto(Goto),
    FreeVarSlot(FreeVarSlot),
    SetVarField(SetVarField),
    SetVar(SetVar),
    FreeVarSlotSsa(FreeVarSlotSsa),
    SetVarSsaField(SetVarSsaField),
    SetVarAliasedField(SetVarSsaField),
    SetVarAliased(SetVarAliased),
    SetVarSsa(SetVarSsa),
    VarPhi(VarPhi),
    MemPhi(MemPhi),
    VarSplit(VarSplit),
    SetVarSplit(SetVarSplit),
    VarSplitSsa(VarSplitSsa),
    SetVarSplitSsa(SetVarSplitSsa),
    Add(BinaryOp),
    Sub(BinaryOp),
    And(BinaryOp),
    Or(BinaryOp),
    Xor(BinaryOp),
    Lsl(BinaryOp),
    Lsr(BinaryOp),
    Asr(BinaryOp),
    Rol(BinaryOp),
    Ror(BinaryOp),
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
    AddOverflow(BinaryOp),
    FcmpE(BinaryOp),
    FcmpNe(BinaryOp),
    FcmpLt(BinaryOp),
    FcmpLe(BinaryOp),
    FcmpGe(BinaryOp),
    FcmpGt(BinaryOp),
    FcmpO(BinaryOp),
    FcmpUo(BinaryOp),
    Fadd(BinaryOp),
    Fsub(BinaryOp),
    Fmul(BinaryOp),
    Fdiv(BinaryOp),
    Adc(BinaryOpCarry),
    Sbb(BinaryOpCarry),
    Rlc(BinaryOpCarry),
    Rrc(BinaryOpCarry),
    Call(Call),
    Tailcall(Call),
    Syscall(Syscall),
    Intrinsic(Intrinsic),
    IntrinsicSsa(IntrinsicSsa),
    CallSsa(CallSsa),
    TailcallSsa(CallSsa),
    CallUntypedSsa(CallUntypedSsa),
    TailcallUntypedSsa(CallUntypedSsa),
    SyscallSsa(SyscallSsa),
    SyscallUntypedSsa(SyscallUntypedSsa),
    CallUntyped(CallUntyped),
    TailcallUntyped(CallUntyped),
    SyscallUntyped(SyscallUntyped),
    SeparateParamList(SeparateParamList),
    SharedParamSlot(SharedParamSlot),
    Neg(UnaryOp),
    Not(UnaryOp),
    Sx(UnaryOp),
    Zx(UnaryOp),
    LowPart(UnaryOp),
    BoolToInt(UnaryOp),
    UnimplMem(UnaryOp),
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
    Load(UnaryOp),
    LoadStruct(LoadStruct),
    LoadStructSsa(LoadStructSsa),
    LoadSsa(LoadSsa),
    Ret(Ret),
    Var(Var),
    AddressOf(Var),
    VarField(Field),
    AddressOfField(Field),
    VarSsa(VarSsa),
    VarAliased(VarSsa),
    VarSsaField(VarSsaField),
    VarAliasedField(VarSsaField),
    Trap(Trap),
}

fn get_float(value: u64, size: usize) -> f64 {
    match size {
        4 => f32::from_bits(value as u32) as f64,
        8 => f64::from_bits(value),
        // TODO how to handle this value?
        size => todo!("float size {}", size),
    }
}

fn get_raw_operation(function: &MediumLevelILFunction, idx: usize) -> BNMediumLevelILInstruction {
    unsafe { BNGetMediumLevelILByIndex(function.handle, idx) }
}

fn get_var(id: u64) -> Variable {
    Variable::from_identifier(id)
}

fn get_var_ssa(id: u64, version: usize) -> SSAVariable {
    SSAVariable::new(get_var(id), version)
}

fn get_call_output(function: &MediumLevelILFunction, idx: usize) -> impl Iterator<Item = Variable> {
    let op = get_raw_operation(function, idx);
    assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_OUTPUT);
    OperandIter::new(function, op.operands[1] as usize, op.operands[0] as usize).vars()
}

fn get_call_params(
    function: &MediumLevelILFunction,
    idx: usize,
) -> impl Iterator<Item = MediumLevelILInstruction> {
    let op = get_raw_operation(function, idx);
    assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_PARAM);
    OperandIter::new(function, op.operands[1] as usize, op.operands[0] as usize).exprs()
}

fn get_call_output_ssa(
    function: &MediumLevelILFunction,
    idx: usize,
) -> impl Iterator<Item = SSAVariable> {
    let op = get_raw_operation(function, idx);
    assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_OUTPUT_SSA);
    OperandIter::new(function, op.operands[2] as usize, op.operands[1] as usize).ssa_vars()
}

fn get_call_params_ssa(
    function: &MediumLevelILFunction,
    idx: usize,
) -> impl Iterator<Item = MediumLevelILInstruction> {
    let op = get_raw_operation(function, idx);
    assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_PARAM_SSA);
    OperandIter::new(function, op.operands[2] as usize, op.operands[1] as usize).exprs()
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
            instruction: MediumLevelILInstruction::new(
                context.clone(),
                MediumLevelInstructionIndex(raw.branch),
            ),
            dependence: raw.dependence,
        }
    }
}
