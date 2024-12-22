use binaryninjacore_sys::*;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

use super::operation::*;
use super::{HighLevelILFunction, HighLevelILLiftedInstruction, HighLevelILLiftedInstructionKind};
use crate::architecture::{CoreIntrinsic, IntrinsicId};
use crate::confidence::Conf;
use crate::disassembly::DisassemblyTextLine;
use crate::operand_iter::OperandIter;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::types::Type;
use crate::variable::{ConstantData, RegisterValue, SSAVariable, Variable};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HighLevelInstructionIndex(pub usize);

impl HighLevelInstructionIndex {
    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<usize> for HighLevelInstructionIndex {
    fn from(index: usize) -> Self {
        Self(index)
    }
}

impl From<u64> for HighLevelInstructionIndex {
    fn from(index: u64) -> Self {
        Self(index as usize)
    }
}

impl Display for HighLevelInstructionIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

#[derive(Clone)]
pub struct HighLevelILInstruction {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub expr_index: HighLevelInstructionIndex,
    pub size: usize,
    pub kind: HighLevelILInstructionKind,
}

impl HighLevelILInstruction {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        index: HighLevelInstructionIndex,
    ) -> Self {
        let expr_index = unsafe { BNGetHighLevelILIndexForInstruction(function.handle, index.0) };
        Self::new_expr(function, HighLevelInstructionIndex(expr_index))
    }

    // TODO: I need HighLevelILExpression YESTERDAY!!!!
    pub(crate) fn new_expr(
        function: Ref<HighLevelILFunction>,
        expr_index: HighLevelInstructionIndex,
    ) -> Self {
        let op =
            unsafe { BNGetHighLevelILByIndex(function.handle, expr_index.0, function.full_ast) };
        use BNHighLevelILOperation::*;
        use HighLevelILInstructionKind as Op;
        let kind = match op.operation {
            HLIL_NOP => Op::Nop,
            HLIL_BREAK => Op::Break,
            HLIL_CONTINUE => Op::Continue,
            HLIL_NORET => Op::Noret,
            HLIL_UNREACHABLE => Op::Unreachable,
            HLIL_BP => Op::Bp,
            HLIL_UNDEF => Op::Undef,
            HLIL_UNIMPL => Op::Unimpl,
            HLIL_ADC => Op::Adc(BinaryOpCarry {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
                carry: op.operands[2] as usize,
            }),
            HLIL_SBB => Op::Sbb(BinaryOpCarry {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
                carry: op.operands[2] as usize,
            }),
            HLIL_RLC => Op::Rlc(BinaryOpCarry {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
                carry: op.operands[2] as usize,
            }),
            HLIL_RRC => Op::Rrc(BinaryOpCarry {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
                carry: op.operands[2] as usize,
            }),
            HLIL_ADD => Op::Add(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_SUB => Op::Sub(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_AND => Op::And(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_OR => Op::Or(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_XOR => Op::Xor(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_LSL => Op::Lsl(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_LSR => Op::Lsr(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_ASR => Op::Asr(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_ROL => Op::Rol(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_ROR => Op::Ror(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_MUL => Op::Mul(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_MULU_DP => Op::MuluDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_MULS_DP => Op::MulsDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_DIVU => Op::Divu(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_DIVU_DP => Op::DivuDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_DIVS => Op::Divs(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_DIVS_DP => Op::DivsDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_MODU => Op::Modu(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_MODU_DP => Op::ModuDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_MODS => Op::Mods(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_MODS_DP => Op::ModsDp(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_CMP_E => Op::CmpE(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_CMP_NE => Op::CmpNe(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_CMP_SLT => Op::CmpSlt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_CMP_ULT => Op::CmpUlt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_CMP_SLE => Op::CmpSle(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_CMP_ULE => Op::CmpUle(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_CMP_SGE => Op::CmpSge(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_CMP_UGE => Op::CmpUge(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_CMP_SGT => Op::CmpSgt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_CMP_UGT => Op::CmpUgt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_TEST_BIT => Op::TestBit(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_ADD_OVERFLOW => Op::AddOverflow(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FADD => Op::Fadd(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FSUB => Op::Fsub(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FMUL => Op::Fmul(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FDIV => Op::Fdiv(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FCMP_E => Op::FcmpE(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FCMP_NE => Op::FcmpNe(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FCMP_LT => Op::FcmpLt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FCMP_LE => Op::FcmpLe(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FCMP_GE => Op::FcmpGe(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FCMP_GT => Op::FcmpGt(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FCMP_O => Op::FcmpO(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_FCMP_UO => Op::FcmpUo(BinaryOp {
                left: op.operands[0] as usize,
                right: op.operands[1] as usize,
            }),
            HLIL_ARRAY_INDEX => Op::ArrayIndex(ArrayIndex {
                src: op.operands[0] as usize,
                index: op.operands[1] as usize,
            }),
            HLIL_ARRAY_INDEX_SSA => Op::ArrayIndexSsa(ArrayIndexSsa {
                src: op.operands[0] as usize,
                src_memory: op.operands[1],
                index: op.operands[2] as usize,
            }),
            HLIL_ASSIGN => Op::Assign(Assign {
                dest: op.operands[0] as usize,
                src: op.operands[1] as usize,
            }),
            HLIL_ASSIGN_MEM_SSA => Op::AssignMemSsa(AssignMemSsa {
                dest: op.operands[0] as usize,
                dest_memory: op.operands[1],
                src: op.operands[2] as usize,
                src_memory: op.operands[3],
            }),
            HLIL_ASSIGN_UNPACK => Op::AssignUnpack(AssignUnpack {
                num_dests: op.operands[0] as usize,
                first_dest: op.operands[1] as usize,
                src: op.operands[2] as usize,
            }),
            HLIL_ASSIGN_UNPACK_MEM_SSA => Op::AssignUnpackMemSsa(AssignUnpackMemSsa {
                num_dests: op.operands[0] as usize,
                first_dest: op.operands[1] as usize,
                dest_memory: op.operands[2],
                src: op.operands[3] as usize,
                src_memory: op.operands[4],
            }),
            HLIL_BLOCK => Op::Block(Block {
                num_params: op.operands[0] as usize,
                first_param: op.operands[1] as usize,
            }),
            HLIL_CALL => Op::Call(Call {
                dest: op.operands[0] as usize,
                num_params: op.operands[1] as usize,
                first_param: op.operands[2] as usize,
            }),
            HLIL_TAILCALL => Op::Tailcall(Call {
                dest: op.operands[0] as usize,
                num_params: op.operands[1] as usize,
                first_param: op.operands[2] as usize,
            }),
            HLIL_CALL_SSA => Op::CallSsa(CallSsa {
                dest: op.operands[0] as usize,
                num_params: op.operands[1] as usize,
                first_param: op.operands[2] as usize,
                dest_memory: op.operands[3],
                src_memory: op.operands[4],
            }),
            HLIL_CASE => Op::Case(Case {
                num_values: op.operands[0] as usize,
                first_value: op.operands[1] as usize,
                body: op.operands[2] as usize,
            }),
            HLIL_CONST => Op::Const(Const {
                constant: op.operands[0],
            }),
            HLIL_CONST_PTR => Op::ConstPtr(Const {
                constant: op.operands[0],
            }),
            HLIL_IMPORT => Op::Import(Const {
                constant: op.operands[0],
            }),
            HLIL_CONST_DATA => Op::ConstData(ConstData {
                constant_data_kind: op.operands[0] as u32,
                constant_data_value: op.operands[1] as i64,
                size: op.size,
            }),
            HLIL_DEREF => Op::Deref(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_ADDRESS_OF => Op::AddressOf(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_NEG => Op::Neg(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_NOT => Op::Not(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_SX => Op::Sx(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_ZX => Op::Zx(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_LOW_PART => Op::LowPart(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_BOOL_TO_INT => Op::BoolToInt(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_UNIMPL_MEM => Op::UnimplMem(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_FSQRT => Op::Fsqrt(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_FNEG => Op::Fneg(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_FABS => Op::Fabs(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_FLOAT_TO_INT => Op::FloatToInt(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_INT_TO_FLOAT => Op::IntToFloat(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_FLOAT_CONV => Op::FloatConv(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_ROUND_TO_INT => Op::RoundToInt(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_FLOOR => Op::Floor(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_CEIL => Op::Ceil(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_FTRUNC => Op::Ftrunc(UnaryOp {
                src: op.operands[0] as usize,
            }),
            HLIL_DEREF_FIELD_SSA => Op::DerefFieldSsa(DerefFieldSsa {
                src: op.operands[0] as usize,
                src_memory: op.operands[1],
                offset: op.operands[2],
                member_index: get_member_index(op.operands[3]),
            }),
            HLIL_DEREF_SSA => Op::DerefSsa(DerefSsa {
                src: op.operands[0] as usize,
                src_memory: op.operands[1],
            }),
            HLIL_EXTERN_PTR => Op::ExternPtr(ExternPtr {
                constant: op.operands[0],
                offset: op.operands[1],
            }),
            HLIL_FLOAT_CONST => Op::FloatConst(FloatConst {
                constant: get_float(op.operands[0], op.size),
            }),
            HLIL_FOR => Op::For(ForLoop {
                init: op.operands[0] as usize,
                condition: op.operands[1] as usize,
                update: op.operands[2] as usize,
                body: op.operands[3] as usize,
            }),
            HLIL_FOR_SSA => Op::ForSsa(ForLoopSsa {
                init: op.operands[0] as usize,
                condition_phi: op.operands[1] as usize,
                condition: op.operands[2] as usize,
                update: op.operands[3] as usize,
                body: op.operands[4] as usize,
            }),
            HLIL_GOTO => Op::Goto(Label {
                target: op.operands[0],
            }),
            HLIL_LABEL => Op::Label(Label {
                target: op.operands[0],
            }),
            HLIL_IF => Op::If(If {
                condition: op.operands[0] as usize,
                cond_true: op.operands[1] as usize,
                cond_false: op.operands[2] as usize,
            }),
            HLIL_INTRINSIC => Op::Intrinsic(Intrinsic {
                intrinsic: op.operands[0] as u32,
                num_params: op.operands[1] as usize,
                first_param: op.operands[2] as usize,
            }),
            HLIL_INTRINSIC_SSA => Op::IntrinsicSsa(IntrinsicSsa {
                intrinsic: op.operands[0] as u32,
                num_params: op.operands[1] as usize,
                first_param: op.operands[2] as usize,
                dest_memory: op.operands[3],
                src_memory: op.operands[4],
            }),
            HLIL_JUMP => Op::Jump(Jump {
                dest: op.operands[0] as usize,
            }),
            HLIL_MEM_PHI => Op::MemPhi(MemPhi {
                dest: op.operands[0],
                num_srcs: op.operands[1] as usize,
                first_src: op.operands[2] as usize,
            }),
            HLIL_RET => Op::Ret(Ret {
                num_srcs: op.operands[0] as usize,
                first_src: op.operands[1] as usize,
            }),
            HLIL_SPLIT => Op::Split(Split {
                high: op.operands[0] as usize,
                low: op.operands[1] as usize,
            }),
            HLIL_STRUCT_FIELD => Op::StructField(StructField {
                src: op.operands[0] as usize,
                offset: op.operands[1],
                member_index: get_member_index(op.operands[2]),
            }),
            HLIL_DEREF_FIELD => Op::DerefField(StructField {
                src: op.operands[0] as usize,
                offset: op.operands[1],
                member_index: get_member_index(op.operands[2]),
            }),
            HLIL_SWITCH => Op::Switch(Switch {
                condition: op.operands[0] as usize,
                default: op.operands[1] as usize,
                num_cases: op.operands[2] as usize,
                first_case: op.operands[3] as usize,
            }),
            HLIL_SYSCALL => Op::Syscall(Syscall {
                num_params: op.operands[0] as usize,
                first_param: op.operands[1] as usize,
            }),
            HLIL_SYSCALL_SSA => Op::SyscallSsa(SyscallSsa {
                num_params: op.operands[0] as usize,
                first_param: op.operands[1] as usize,
                dest_memory: op.operands[2],
                src_memory: op.operands[3],
            }),
            HLIL_TRAP => Op::Trap(Trap {
                vector: op.operands[0],
            }),
            HLIL_VAR_DECLARE => Op::VarDeclare(Var {
                var: get_var(op.operands[0]),
            }),
            HLIL_VAR => Op::Var(Var {
                var: get_var(op.operands[0]),
            }),
            HLIL_VAR_INIT => Op::VarInit(VarInit {
                dest: get_var(op.operands[0]),
                src: op.operands[1] as usize,
            }),
            HLIL_VAR_INIT_SSA => Op::VarInitSsa(VarInitSsa {
                dest: get_var_ssa((op.operands[0], op.operands[1] as usize)),
                src: op.operands[2] as usize,
            }),
            HLIL_VAR_PHI => Op::VarPhi(VarPhi {
                dest: get_var_ssa((op.operands[0], op.operands[1] as usize)),
                num_srcs: op.operands[2] as usize,
                first_src: op.operands[3] as usize,
            }),
            HLIL_VAR_SSA => Op::VarSsa(VarSsa {
                var: get_var_ssa((op.operands[0], op.operands[1] as usize)),
            }),
            HLIL_WHILE => Op::While(While {
                condition: op.operands[0] as usize,
                body: op.operands[1] as usize,
            }),
            HLIL_DO_WHILE => Op::DoWhile(While {
                body: op.operands[0] as usize,
                condition: op.operands[1] as usize,
            }),
            HLIL_WHILE_SSA => Op::WhileSsa(WhileSsa {
                condition_phi: op.operands[0] as usize,
                condition: op.operands[1] as usize,
                body: op.operands[2] as usize,
            }),
            HLIL_DO_WHILE_SSA => Op::DoWhileSsa(WhileSsa {
                condition_phi: op.operands[0] as usize,
                condition: op.operands[1] as usize,
                body: op.operands[2] as usize,
            }),
        };
        Self {
            function,
            address: op.address,
            expr_index,
            size: op.size,
            kind,
        }
    }

    pub fn lift(&self) -> HighLevelILLiftedInstruction {
        use HighLevelILInstructionKind::*;
        use HighLevelILLiftedInstructionKind as Lifted;
        let kind = match self.kind {
            Nop => Lifted::Nop,
            Break => Lifted::Break,
            Continue => Lifted::Continue,
            Noret => Lifted::Noret,
            Unreachable => Lifted::Unreachable,
            Bp => Lifted::Bp,
            Undef => Lifted::Undef,
            Unimpl => Lifted::Unimpl,

            Adc(op) => Lifted::Adc(self.lift_binary_op_carry(op)),
            Sbb(op) => Lifted::Sbb(self.lift_binary_op_carry(op)),
            Rlc(op) => Lifted::Rlc(self.lift_binary_op_carry(op)),
            Rrc(op) => Lifted::Rrc(self.lift_binary_op_carry(op)),

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
            Fadd(op) => Lifted::Fadd(self.lift_binary_op(op)),
            Fsub(op) => Lifted::Fsub(self.lift_binary_op(op)),
            Fmul(op) => Lifted::Fmul(self.lift_binary_op(op)),
            Fdiv(op) => Lifted::Fdiv(self.lift_binary_op(op)),
            FcmpE(op) => Lifted::FcmpE(self.lift_binary_op(op)),
            FcmpNe(op) => Lifted::FcmpNe(self.lift_binary_op(op)),
            FcmpLt(op) => Lifted::FcmpLt(self.lift_binary_op(op)),
            FcmpLe(op) => Lifted::FcmpLe(self.lift_binary_op(op)),
            FcmpGe(op) => Lifted::FcmpGe(self.lift_binary_op(op)),
            FcmpGt(op) => Lifted::FcmpGt(self.lift_binary_op(op)),
            FcmpO(op) => Lifted::FcmpO(self.lift_binary_op(op)),
            FcmpUo(op) => Lifted::FcmpUo(self.lift_binary_op(op)),

            ArrayIndex(op) => Lifted::ArrayIndex(LiftedArrayIndex {
                src: self.lift_operand(op.src),
                index: self.lift_operand(op.index),
            }),
            ArrayIndexSsa(op) => Lifted::ArrayIndexSsa(LiftedArrayIndexSsa {
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
                index: self.lift_operand(op.index),
            }),
            Assign(op) => Lifted::Assign(LiftedAssign {
                dest: self.lift_operand(op.dest),
                src: self.lift_operand(op.src),
            }),
            AssignUnpack(op) => Lifted::AssignUnpack(LiftedAssignUnpack {
                dest: self.lift_instruction_list(op.first_dest, op.num_dests),
                src: self.lift_operand(op.src),
            }),
            AssignMemSsa(op) => Lifted::AssignMemSsa(LiftedAssignMemSsa {
                dest: self.lift_operand(op.dest),
                dest_memory: op.dest_memory,
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
            }),
            AssignUnpackMemSsa(op) => Lifted::AssignUnpackMemSsa(LiftedAssignUnpackMemSsa {
                dest: self.lift_instruction_list(op.first_dest, op.num_dests),
                dest_memory: op.dest_memory,
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
            }),
            Block(op) => Lifted::Block(LiftedBlock {
                body: self.lift_instruction_list(op.first_param, op.num_params),
            }),

            Call(op) => Lifted::Call(self.lift_call(op)),
            Tailcall(op) => Lifted::Tailcall(self.lift_call(op)),
            CallSsa(op) => Lifted::CallSsa(LiftedCallSsa {
                dest: self.lift_operand(op.dest),
                params: self.lift_instruction_list(op.first_param, op.num_params),
                dest_memory: op.dest_memory,
                src_memory: op.src_memory,
            }),

            Case(op) => Lifted::Case(LiftedCase {
                values: self.lift_instruction_list(op.first_value, op.num_values),
                body: self.lift_operand(op.body),
            }),
            Const(op) => Lifted::Const(op),
            ConstPtr(op) => Lifted::ConstPtr(op),
            Import(op) => Lifted::Import(op),
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

            Deref(op) => Lifted::Deref(self.lift_unary_op(op)),
            AddressOf(op) => Lifted::AddressOf(self.lift_unary_op(op)),
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

            DerefFieldSsa(op) => Lifted::DerefFieldSsa(LiftedDerefFieldSsa {
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
                offset: op.offset,
                member_index: op.member_index,
            }),
            DerefSsa(op) => Lifted::DerefSsa(LiftedDerefSsa {
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
            }),
            ExternPtr(op) => Lifted::ExternPtr(op),
            FloatConst(op) => Lifted::FloatConst(op),
            For(op) => Lifted::For(LiftedForLoop {
                init: self.lift_operand(op.init),
                condition: self.lift_operand(op.condition),
                update: self.lift_operand(op.update),
                body: self.lift_operand(op.body),
            }),
            Goto(op) => Lifted::Goto(self.lift_label(op)),
            Label(op) => Lifted::Label(self.lift_label(op)),
            ForSsa(op) => Lifted::ForSsa(LiftedForLoopSsa {
                init: self.lift_operand(op.init),
                condition_phi: self.lift_operand(op.condition_phi),
                condition: self.lift_operand(op.condition),
                update: self.lift_operand(op.update),
                body: self.lift_operand(op.body),
            }),
            If(op) => Lifted::If(LiftedIf {
                condition: self.lift_operand(op.condition),
                cond_true: self.lift_operand(op.cond_true),
                cond_false: self.lift_operand(op.cond_false),
            }),
            Intrinsic(op) => Lifted::Intrinsic(LiftedIntrinsic {
                intrinsic: CoreIntrinsic::new(
                    self.function.function().arch(),
                    IntrinsicId(op.intrinsic),
                )
                .expect("Invalid intrinsic"),
                params: self.lift_instruction_list(op.first_param, op.num_params),
            }),
            IntrinsicSsa(op) => Lifted::IntrinsicSsa(LiftedIntrinsicSsa {
                intrinsic: CoreIntrinsic::new(
                    self.function.function().arch(),
                    IntrinsicId(op.intrinsic),
                )
                .expect("Invalid intrinsic"),
                params: self.lift_instruction_list(op.first_param, op.num_params),
                dest_memory: op.dest_memory,
                src_memory: op.src_memory,
            }),
            Jump(op) => Lifted::Jump(LiftedJump {
                dest: self.lift_operand(op.dest),
            }),
            MemPhi(op) => Lifted::MemPhi(LiftedMemPhi {
                dest: op.dest,
                src: OperandIter::new(&*self.function, op.first_src, op.num_srcs).collect(),
            }),
            Ret(op) => Lifted::Ret(LiftedRet {
                src: self.lift_instruction_list(op.first_src, op.num_srcs),
            }),
            Split(op) => Lifted::Split(LiftedSplit {
                high: self.lift_operand(op.high),
                low: self.lift_operand(op.low),
            }),
            StructField(op) => Lifted::StructField(self.lift_struct_field(op)),
            DerefField(op) => Lifted::DerefField(self.lift_struct_field(op)),
            Switch(op) => Lifted::Switch(LiftedSwitch {
                condition: self.lift_operand(op.condition),
                default: self.lift_operand(op.default),
                cases: self.lift_instruction_list(op.first_case, op.num_cases),
            }),
            Syscall(op) => Lifted::Syscall(LiftedSyscall {
                params: self.lift_instruction_list(op.first_param, op.num_params),
            }),
            SyscallSsa(op) => Lifted::SyscallSsa(LiftedSyscallSsa {
                params: self.lift_instruction_list(op.first_param, op.num_params),
                dest_memory: op.dest_memory,
                src_memory: op.src_memory,
            }),
            Trap(op) => Lifted::Trap(op),
            VarDeclare(op) => Lifted::VarDeclare(op),
            Var(op) => Lifted::Var(op),
            VarInit(op) => Lifted::VarInit(LiftedVarInit {
                dest: op.dest,
                src: self.lift_operand(op.src),
            }),
            VarInitSsa(op) => Lifted::VarInitSsa(LiftedVarInitSsa {
                dest: op.dest,
                src: self.lift_operand(op.src),
            }),
            VarPhi(op) => Lifted::VarPhi(LiftedVarPhi {
                dest: op.dest,
                src: OperandIter::new(&*self.function, op.first_src, op.num_srcs)
                    .ssa_vars()
                    .collect(),
            }),
            VarSsa(op) => Lifted::VarSsa(op),

            While(op) => Lifted::While(self.lift_while(op)),
            DoWhile(op) => Lifted::DoWhile(self.lift_while(op)),

            WhileSsa(op) => Lifted::WhileSsa(self.lift_while_ssa(op)),
            DoWhileSsa(op) => Lifted::DoWhileSsa(self.lift_while_ssa(op)),
        };
        HighLevelILLiftedInstruction {
            function: self.function.clone(),
            address: self.address,
            expr_index: self.expr_index,
            size: self.size,
            kind,
        }
    }

    /// HLIL text lines
    pub fn lines(&self) -> Array<DisassemblyTextLine> {
        let mut count = 0;
        let lines = unsafe {
            BNGetHighLevelILExprText(
                self.function.handle,
                self.expr_index.0,
                self.function.full_ast,
                &mut count,
                core::ptr::null_mut(),
            )
        };
        unsafe { Array::new(lines, count, ()) }
    }

    /// Type of expression
    pub fn expr_type(&self) -> Option<Conf<Ref<Type>>> {
        let result = unsafe { BNGetHighLevelILExprType(self.function.handle, self.expr_index.0) };
        (!result.type_.is_null()).then(|| {
            Conf::new(
                unsafe { Type::ref_from_raw(result.type_) },
                result.confidence,
            )
        })
    }

    /// Version of active memory contents in SSA form for this instruction
    pub fn ssa_memory_version(&self) -> usize {
        unsafe {
            BNGetHighLevelILSSAMemoryVersionAtILInstruction(self.function.handle, self.expr_index.0)
        }
    }

    pub fn ssa_variable_version(&self, variable: Variable) -> SSAVariable {
        let version = unsafe {
            BNGetHighLevelILSSAVarVersionAtILInstruction(
                self.function.handle,
                &variable.into(),
                self.expr_index.0,
            )
        };
        SSAVariable::new(variable, version)
    }

    fn lift_operand(&self, expr_idx: usize) -> Box<HighLevelILLiftedInstruction> {
        // TODO: UGH, if your gonna call it expr_idx, call the instruction and expression!!!!!
        // TODO: We dont even need to say instruction in the type!
        // TODO: IF you want to have an instruction type, there needs to be a separate expression type
        // TODO: See the lowlevelil module.
        let expr_idx_is_really_instr_idx = HighLevelInstructionIndex(expr_idx);
        // TODO: Ugh, this is so dumb..... i want HighLevelILLiftedExpression yesterday!!!
        let operand_instr = self
            .function
            .instruction_from_expr_index(expr_idx_is_really_instr_idx)
            .unwrap();
        // TODO: Why box it here??!?!?! insane.
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

    fn lift_label(&self, op: Label) -> LiftedLabel {
        LiftedLabel {
            target: GotoLabel {
                function: self.function.function(),
                target: op.target,
            },
        }
    }

    fn lift_call(&self, op: Call) -> LiftedCall {
        LiftedCall {
            dest: self.lift_operand(op.dest),
            params: OperandIter::new(&*self.function, op.first_param, op.num_params)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
        }
    }

    fn lift_while(&self, op: While) -> LiftedWhile {
        LiftedWhile {
            condition: self.lift_operand(op.condition),
            body: self.lift_operand(op.body),
        }
    }

    fn lift_while_ssa(&self, op: WhileSsa) -> LiftedWhileSsa {
        LiftedWhileSsa {
            condition_phi: self.lift_operand(op.condition_phi),
            condition: self.lift_operand(op.condition),
            body: self.lift_operand(op.body),
        }
    }

    fn lift_struct_field(&self, op: StructField) -> LiftedStructField {
        LiftedStructField {
            src: self.lift_operand(op.src),
            offset: op.offset,
            member_index: op.member_index,
        }
    }

    fn lift_instruction_list(
        &self,
        first_instruction: usize,
        num_instructions: usize,
    ) -> Vec<HighLevelILLiftedInstruction> {
        OperandIter::new(&*self.function, first_instruction, num_instructions)
            .exprs()
            .map(|expr| expr.lift())
            .collect()
    }
}

impl CoreArrayProvider for HighLevelILInstruction {
    type Raw = usize;
    type Context = Ref<HighLevelILFunction>;
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for HighLevelILInstruction {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        unsafe { BNFreeILInstructionList(raw) }
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::new(context.clone(), HighLevelInstructionIndex(*raw))
    }
}

impl Debug for HighLevelILInstruction {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // TODO: Actual debug impl please!
        write!(
            f,
            "<{} at 0x{:08}>",
            core::any::type_name::<Self>(),
            self.address,
        )
    }
}

#[derive(Debug, Copy, Clone)]
pub enum HighLevelILInstructionKind {
    Nop,
    Break,
    Continue,
    Noret,
    Unreachable,
    Bp,
    Undef,
    Unimpl,
    Adc(BinaryOpCarry),
    Sbb(BinaryOpCarry),
    Rlc(BinaryOpCarry),
    Rrc(BinaryOpCarry),
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
    Fadd(BinaryOp),
    Fsub(BinaryOp),
    Fmul(BinaryOp),
    Fdiv(BinaryOp),
    FcmpE(BinaryOp),
    FcmpNe(BinaryOp),
    FcmpLt(BinaryOp),
    FcmpLe(BinaryOp),
    FcmpGe(BinaryOp),
    FcmpGt(BinaryOp),
    FcmpO(BinaryOp),
    FcmpUo(BinaryOp),
    ArrayIndex(ArrayIndex),
    ArrayIndexSsa(ArrayIndexSsa),
    Assign(Assign),
    AssignMemSsa(AssignMemSsa),
    AssignUnpack(AssignUnpack),
    AssignUnpackMemSsa(AssignUnpackMemSsa),
    Block(Block),
    Call(Call),
    Tailcall(Call),
    CallSsa(CallSsa),
    Case(Case),
    Const(Const),
    ConstPtr(Const),
    Import(Const),
    ConstData(ConstData),
    Deref(UnaryOp),
    AddressOf(UnaryOp),
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
    DerefFieldSsa(DerefFieldSsa),
    DerefSsa(DerefSsa),
    ExternPtr(ExternPtr),
    FloatConst(FloatConst),
    For(ForLoop),
    ForSsa(ForLoopSsa),
    Goto(Label),
    Label(Label),
    If(If),
    Intrinsic(Intrinsic),
    IntrinsicSsa(IntrinsicSsa),
    Jump(Jump),
    MemPhi(MemPhi),
    Ret(Ret),
    Split(Split),
    StructField(StructField),
    DerefField(StructField),
    Switch(Switch),
    Syscall(Syscall),
    SyscallSsa(SyscallSsa),
    Trap(Trap),
    VarDeclare(Var),
    Var(Var),
    VarInit(VarInit),
    VarInitSsa(VarInitSsa),
    VarPhi(VarPhi),
    VarSsa(VarSsa),
    While(While),
    DoWhile(While),
    WhileSsa(WhileSsa),
    DoWhileSsa(WhileSsa),
}

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

fn get_member_index(idx: u64) -> Option<usize> {
    (idx as i64 > 0).then_some(idx as usize)
}

fn get_var_ssa(input: (u64, usize)) -> SSAVariable {
    SSAVariable::new(get_var(input.0), input.1)
}
