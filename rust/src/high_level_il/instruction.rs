use binaryninjacore_sys::*;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

use super::operation::*;
use super::{HighLevelILFunction, HighLevelILLiftedInstruction, HighLevelILLiftedInstructionKind};
use crate::architecture::{CoreIntrinsic, IntrinsicId};
use crate::confidence::Conf;
use crate::disassembly::DisassemblyTextLine;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::types::Type;
use crate::variable::{ConstantData, PossibleValueSet, RegisterValue, SSAVariable, Variable};

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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HighLevelExpressionIndex(pub usize);

impl HighLevelExpressionIndex {
    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<usize> for HighLevelExpressionIndex {
    fn from(index: usize) -> Self {
        Self(index)
    }
}

impl From<u64> for HighLevelExpressionIndex {
    fn from(index: u64) -> Self {
        Self(index as usize)
    }
}

impl Display for HighLevelExpressionIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

#[derive(Clone)]
pub struct HighLevelILInstruction {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub instr_index: HighLevelInstructionIndex,
    pub expr_index: HighLevelExpressionIndex,
    pub size: usize,
    pub kind: HighLevelILInstructionKind,
}

impl HighLevelILInstruction {
    pub(crate) fn from_instr_index(
        function: Ref<HighLevelILFunction>,
        instr_index: HighLevelInstructionIndex,
    ) -> Self {
        // Get the associated expression index for the top-level instruction.
        let expr_index_raw =
            unsafe { BNGetHighLevelILIndexForInstruction(function.handle, instr_index.0) };
        Self::new(
            function,
            instr_index,
            HighLevelExpressionIndex(expr_index_raw),
        )
    }

    pub(crate) fn from_expr_index(
        function: Ref<HighLevelILFunction>,
        expr_index: HighLevelExpressionIndex,
    ) -> Self {
        // Get the associated top-level instruction index for the expression.
        let instr_index_raw =
            unsafe { BNGetHighLevelILInstructionForExpr(function.handle, expr_index.0) };
        Self::new(
            function,
            HighLevelInstructionIndex(instr_index_raw),
            expr_index,
        )
    }

    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        instr_index: HighLevelInstructionIndex,
        expr_index: HighLevelExpressionIndex,
    ) -> Self {
        let op =
            unsafe { BNGetHighLevelILByIndex(function.handle, expr_index.0, function.full_ast) };
        use BNHighLevelILOperation::*;
        use HighLevelILInstructionKind as Op;
        let kind = match op.operation {
            // BEGIN GENERATED hlil-decode: from api/il, do not edit
            HLIL_NOP => Op::Nop,
            HLIL_BLOCK => Op::Block(Block {
                first_param: op.operands[1] as usize,
                num_params: op.operands[0] as usize,
            }),
            HLIL_IF => Op::If(If {
                condition: HighLevelExpressionIndex::from(op.operands[0]),
                cond_true: HighLevelExpressionIndex::from(op.operands[1]),
                cond_false: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_WHILE => Op::While(While {
                condition: HighLevelExpressionIndex::from(op.operands[0]),
                body: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_DO_WHILE => Op::DoWhile(While {
                body: HighLevelExpressionIndex::from(op.operands[0]),
                condition: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FOR => Op::For(ForLoop {
                init: HighLevelExpressionIndex::from(op.operands[0]),
                condition: HighLevelExpressionIndex::from(op.operands[1]),
                update: HighLevelExpressionIndex::from(op.operands[2]),
                body: HighLevelExpressionIndex::from(op.operands[3]),
            }),
            HLIL_SWITCH => Op::Switch(Switch {
                condition: HighLevelExpressionIndex::from(op.operands[0]),
                default: HighLevelExpressionIndex::from(op.operands[1]),
                first_case: op.operands[3] as usize,
                num_cases: op.operands[2] as usize,
            }),
            HLIL_CASE => Op::Case(Case {
                first_value: op.operands[1] as usize,
                num_values: op.operands[0] as usize,
                body: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_BREAK => Op::Break,
            HLIL_CONTINUE => Op::Continue,
            HLIL_JUMP => Op::Jump(Jump {
                dest: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_RET => Op::Ret(Ret {
                first_src: op.operands[1] as usize,
                num_srcs: op.operands[0] as usize,
            }),
            HLIL_NORET => Op::Noret,
            HLIL_GOTO => Op::Goto(Label {
                target: op.operands[0],
            }),
            HLIL_LABEL => Op::Label(Label {
                target: op.operands[0],
            }),
            HLIL_VAR_DECLARE => Op::VarDeclare(Var {
                var: get_var(op.operands[0]),
            }),
            HLIL_VAR_INIT => Op::VarInit(VarInit {
                dest: get_var(op.operands[0]),
                src: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_ASSIGN => Op::Assign(Assign {
                dest: HighLevelExpressionIndex::from(op.operands[0]),
                src: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_ASSIGN_UNPACK => Op::AssignUnpack(AssignUnpack {
                first_dest: op.operands[1] as usize,
                num_dests: op.operands[0] as usize,
                src: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_FORCE_VER => Op::ForceVer(ForceVer {
                dest: get_var(op.operands[0]),
                src: get_var(op.operands[1]),
            }),
            HLIL_ASSERT => Op::Assert(Assert {
                src: get_var(op.operands[0]),
                constraint_index: op.operands[1] as usize,
            }),
            HLIL_VAR => Op::Var(Var {
                var: get_var(op.operands[0]),
            }),
            HLIL_STRUCT_FIELD => Op::StructField(StructField {
                src: HighLevelExpressionIndex::from(op.operands[0]),
                offset: op.operands[1],
                member_index: get_member_index(op.operands[2]),
            }),
            HLIL_ARRAY_INDEX => Op::ArrayIndex(ArrayIndex {
                src: HighLevelExpressionIndex::from(op.operands[0]),
                index: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_SPLIT => Op::Split(Split {
                high: HighLevelExpressionIndex::from(op.operands[0]),
                low: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_DEREF => Op::Deref(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_DEREF_FIELD => Op::DerefField(StructField {
                src: HighLevelExpressionIndex::from(op.operands[0]),
                offset: op.operands[1],
                member_index: get_member_index(op.operands[2]),
            }),
            HLIL_ADDRESS_OF => Op::AddressOf(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_PASS_BY_REF => Op::PassByRef(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_RETURN_BY_REF => Op::ReturnByRef(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_CONST => Op::Const(Const {
                constant: op.operands[0],
            }),
            HLIL_CONST_DATA => Op::ConstData(ConstData {
                constant_data_kind: op.operands[0] as u32,
                constant_data_value: op.operands[1] as i64,
                size: op.size,
            }),
            HLIL_CONST_PTR => Op::ConstPtr(Const {
                constant: op.operands[0],
            }),
            HLIL_EXTERN_PTR => Op::ExternPtr(ExternPtr {
                constant: op.operands[0],
                offset: op.operands[1],
            }),
            HLIL_FLOAT_CONST => Op::FloatConst(FloatConst {
                constant: get_float(op.operands[0], op.size),
            }),
            HLIL_IMPORT => Op::Import(Const {
                constant: op.operands[0],
            }),
            HLIL_ADD => Op::Add(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_ADC => Op::Adc(BinaryOpCarry {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
                carry: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_SUB => Op::Sub(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_SBB => Op::Sbb(BinaryOpCarry {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
                carry: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_AND => Op::And(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_OR => Op::Or(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_XOR => Op::Xor(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_LSL => Op::Lsl(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_LSR => Op::Lsr(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_ASR => Op::Asr(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_ROL => Op::Rol(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_RLC => Op::Rlc(BinaryOpCarry {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
                carry: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_ROR => Op::Ror(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_RRC => Op::Rrc(BinaryOpCarry {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
                carry: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_MUL => Op::Mul(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_MULU_DP => Op::MuluDp(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_MULS_DP => Op::MulsDp(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_DIVU => Op::Divu(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_DIVU_DP => Op::DivuDp(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_DIVS => Op::Divs(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_DIVS_DP => Op::DivsDp(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_MODU => Op::Modu(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_MODU_DP => Op::ModuDp(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_MODS => Op::Mods(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_MODS_DP => Op::ModsDp(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_NEG => Op::Neg(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_NOT => Op::Not(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_SX => Op::Sx(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_ZX => Op::Zx(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_LOW_PART => Op::LowPart(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_CALL => Op::Call(Call {
                dest: HighLevelExpressionIndex::from(op.operands[0]),
                first_param: op.operands[2] as usize,
                num_params: op.operands[1] as usize,
            }),
            HLIL_CMP_E => Op::CmpE(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_CMP_NE => Op::CmpNe(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_CMP_SLT => Op::CmpSlt(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_CMP_ULT => Op::CmpUlt(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_CMP_SLE => Op::CmpSle(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_CMP_ULE => Op::CmpUle(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_CMP_SGE => Op::CmpSge(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_CMP_UGE => Op::CmpUge(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_CMP_SGT => Op::CmpSgt(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_CMP_UGT => Op::CmpUgt(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_TEST_BIT => Op::TestBit(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_BOOL_TO_INT => Op::BoolToInt(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_ADD_OVERFLOW => Op::AddOverflow(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_SYSCALL => Op::Syscall(Syscall {
                first_param: op.operands[1] as usize,
                num_params: op.operands[0] as usize,
            }),
            HLIL_TAILCALL => Op::Tailcall(Call {
                dest: HighLevelExpressionIndex::from(op.operands[0]),
                first_param: op.operands[2] as usize,
                num_params: op.operands[1] as usize,
            }),
            HLIL_INTRINSIC => Op::Intrinsic(Intrinsic {
                intrinsic: op.operands[0] as u32,
                first_param: op.operands[2] as usize,
                num_params: op.operands[1] as usize,
            }),
            HLIL_BP => Op::Bp,
            HLIL_TRAP => Op::Trap(Trap {
                vector: op.operands[0],
            }),
            HLIL_UNDEF => Op::Undef,
            HLIL_UNIMPL => Op::Unimpl,
            HLIL_UNIMPL_MEM => Op::UnimplMem(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_STRUCT_INIT => Op::StructInit(StructInit {
                first_field: op.operands[1] as usize,
                num_fields: op.operands[0] as usize,
            }),
            HLIL_STRUCT_INIT_FIELD => Op::StructInitField(StructField {
                offset: op.operands[0],
                member_index: get_member_index(op.operands[1]),
                src: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_FADD => Op::Fadd(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FSUB => Op::Fsub(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FMUL => Op::Fmul(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FDIV => Op::Fdiv(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FSQRT => Op::Fsqrt(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_FNEG => Op::Fneg(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_FABS => Op::Fabs(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_FLOAT_TO_INT => Op::FloatToInt(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_INT_TO_FLOAT => Op::IntToFloat(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_FLOAT_CONV => Op::FloatConv(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_ROUND_TO_INT => Op::RoundToInt(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_FLOOR => Op::Floor(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_CEIL => Op::Ceil(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_FTRUNC => Op::Ftrunc(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_FCMP_E => Op::FcmpE(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FCMP_NE => Op::FcmpNe(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FCMP_LT => Op::FcmpLt(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FCMP_LE => Op::FcmpLe(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FCMP_GE => Op::FcmpGe(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FCMP_GT => Op::FcmpGt(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FCMP_O => Op::FcmpO(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_FCMP_UO => Op::FcmpUo(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_UNREACHABLE => Op::Unreachable,
            HLIL_WHILE_SSA => Op::WhileSsa(WhileSsa {
                condition_phi: HighLevelExpressionIndex::from(op.operands[0]),
                condition: HighLevelExpressionIndex::from(op.operands[1]),
                body: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_DO_WHILE_SSA => Op::DoWhileSsa(WhileSsa {
                body: HighLevelExpressionIndex::from(op.operands[0]),
                condition_phi: HighLevelExpressionIndex::from(op.operands[1]),
                condition: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_FOR_SSA => Op::ForSsa(ForLoopSsa {
                init: HighLevelExpressionIndex::from(op.operands[0]),
                condition_phi: HighLevelExpressionIndex::from(op.operands[1]),
                condition: HighLevelExpressionIndex::from(op.operands[2]),
                update: HighLevelExpressionIndex::from(op.operands[3]),
                body: HighLevelExpressionIndex::from(op.operands[4]),
            }),
            HLIL_VAR_INIT_SSA => Op::VarInitSsa(VarInitSsa {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                src: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_ASSIGN_MEM_SSA => Op::AssignMemSsa(AssignMemSsa {
                dest: HighLevelExpressionIndex::from(op.operands[0]),
                dest_memory: op.operands[1],
                src: HighLevelExpressionIndex::from(op.operands[2]),
                src_memory: op.operands[3],
            }),
            HLIL_ASSIGN_UNPACK_MEM_SSA => Op::AssignUnpackMemSsa(AssignUnpackMemSsa {
                first_dest: op.operands[1] as usize,
                num_dests: op.operands[0] as usize,
                dest_memory: op.operands[2],
                src: HighLevelExpressionIndex::from(op.operands[3]),
                src_memory: op.operands[4],
            }),
            HLIL_FORCE_VER_SSA => Op::ForceVerSsa(ForceVerSsa {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                src: get_var_ssa(op.operands[2], op.operands[3] as usize),
            }),
            HLIL_ASSERT_SSA => Op::AssertSsa(AssertSsa {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
                constraint_index: op.operands[2] as usize,
            }),
            HLIL_VAR_SSA => Op::VarSsa(VarSsa {
                var: get_var_ssa(op.operands[0], op.operands[1] as usize),
            }),
            HLIL_VAR_SSA_PARTIAL => Op::VarSsaPartial(VarSsaPartial {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
            }),
            HLIL_ARRAY_INDEX_SSA => Op::ArrayIndexSsa(ArrayIndexSsa {
                src: HighLevelExpressionIndex::from(op.operands[0]),
                src_memory: op.operands[1],
                index: HighLevelExpressionIndex::from(op.operands[2]),
            }),
            HLIL_DEREF_SSA => Op::DerefSsa(DerefSsa {
                src: HighLevelExpressionIndex::from(op.operands[0]),
                src_memory: op.operands[1],
            }),
            HLIL_DEREF_FIELD_SSA => Op::DerefFieldSsa(DerefFieldSsa {
                src: HighLevelExpressionIndex::from(op.operands[0]),
                src_memory: op.operands[1],
                offset: op.operands[2],
                member_index: get_member_index(op.operands[3]),
            }),
            HLIL_CALL_SSA => Op::CallSsa(CallSsa {
                dest: HighLevelExpressionIndex::from(op.operands[0]),
                first_param: op.operands[2] as usize,
                num_params: op.operands[1] as usize,
                dest_memory: op.operands[3],
                src_memory: op.operands[4],
            }),
            HLIL_SYSCALL_SSA => Op::SyscallSsa(SyscallSsa {
                first_param: op.operands[1] as usize,
                num_params: op.operands[0] as usize,
                dest_memory: op.operands[2],
                src_memory: op.operands[3],
            }),
            HLIL_INTRINSIC_SSA => Op::IntrinsicSsa(IntrinsicSsa {
                intrinsic: op.operands[0] as u32,
                first_param: op.operands[2] as usize,
                num_params: op.operands[1] as usize,
                dest_memory: op.operands[3],
                src_memory: op.operands[4],
            }),
            HLIL_VAR_PHI => Op::VarPhi(VarPhi {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                first_src: op.operands[3] as usize,
                num_srcs: op.operands[2] as usize,
            }),
            HLIL_MEM_PHI => Op::MemPhi(MemPhi {
                dest: op.operands[0],
                first_src: op.operands[2] as usize,
                num_srcs: op.operands[1] as usize,
            }),
            HLIL_BSWAP => Op::Bswap(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_POPCNT => Op::Popcnt(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_CLZ => Op::Clz(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_CTZ => Op::Ctz(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_RBIT => Op::Rbit(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_CLS => Op::Cls(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            HLIL_MINS => Op::MinSigned(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_MAXS => Op::MaxSigned(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_MINU => Op::MinUnsigned(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_MAXU => Op::MaxUnsigned(BinaryOp {
                left: HighLevelExpressionIndex::from(op.operands[0]),
                right: HighLevelExpressionIndex::from(op.operands[1]),
            }),
            HLIL_ABS => Op::Abs(UnaryOp {
                src: HighLevelExpressionIndex::from(op.operands[0]),
            }),
            // END GENERATED hlil-decode
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
            BNHighLevelILGetOperandList(
                self.function.handle,
                self.expr_index.0,
                operand_idx,
                &mut count,
            )
        };
        assert!(!raw_list_ptr.is_null());
        let list = unsafe { std::slice::from_raw_parts(raw_list_ptr, count).to_vec() };
        unsafe { BNHighLevelILFreeOperandList(raw_list_ptr) };
        list
    }

    fn get_ssa_var_list(&self, operand_idx: usize) -> Vec<SSAVariable> {
        self.get_operand_list(operand_idx)
            .chunks(2)
            .map(|chunk| (Variable::from_identifier(chunk[0]), chunk[1] as usize))
            .map(|(var, version)| SSAVariable::new(var, version))
            .collect()
    }

    fn get_expr_list(&self, operand_idx: usize) -> Vec<HighLevelILInstruction> {
        self.get_operand_list(operand_idx)
            .into_iter()
            .map(|val| HighLevelExpressionIndex(val as usize))
            .filter_map(|idx| self.function.instruction_from_expr_index(idx))
            .collect()
    }

    pub fn lift(&self) -> HighLevelILLiftedInstruction {
        use HighLevelILInstructionKind::*;
        use HighLevelILLiftedInstructionKind as Lifted;
        let kind = match self.kind {
            // BEGIN GENERATED hlil-lift: from api/il, do not edit
            Nop => Lifted::Nop,
            Block(_op) => Lifted::Block(LiftedBlock {
                body: self.lift_expr_list(0),
            }),
            If(op) => Lifted::If(LiftedIf {
                condition: self.lift_operand(op.condition),
                cond_true: self.lift_operand(op.cond_true),
                cond_false: self.lift_operand(op.cond_false),
            }),
            While(op) => Lifted::While(LiftedWhile {
                condition: self.lift_operand(op.condition),
                body: self.lift_operand(op.body),
            }),
            DoWhile(op) => Lifted::DoWhile(LiftedWhile {
                body: self.lift_operand(op.body),
                condition: self.lift_operand(op.condition),
            }),
            For(op) => Lifted::For(LiftedForLoop {
                init: self.lift_operand(op.init),
                condition: self.lift_operand(op.condition),
                update: self.lift_operand(op.update),
                body: self.lift_operand(op.body),
            }),
            Switch(op) => Lifted::Switch(LiftedSwitch {
                condition: self.lift_operand(op.condition),
                default: self.lift_operand(op.default),
                cases: self.lift_expr_list(2),
            }),
            Case(op) => Lifted::Case(LiftedCase {
                values: self.lift_expr_list(0),
                body: self.lift_operand(op.body),
            }),
            Break => Lifted::Break,
            Continue => Lifted::Continue,
            Jump(op) => Lifted::Jump(LiftedJump {
                dest: self.lift_operand(op.dest),
            }),
            Ret(_op) => Lifted::Ret(LiftedRet {
                src: self.lift_expr_list(0),
            }),
            Noret => Lifted::Noret,
            Goto(op) => Lifted::Goto(LiftedLabel {
                target: GotoLabel {
                    function: self.function.function(),
                    target: op.target,
                },
            }),
            Label(op) => Lifted::Label(LiftedLabel {
                target: GotoLabel {
                    function: self.function.function(),
                    target: op.target,
                },
            }),
            VarDeclare(op) => Lifted::VarDeclare(op),
            VarInit(op) => Lifted::VarInit(LiftedVarInit {
                dest: op.dest,
                src: self.lift_operand(op.src),
            }),
            Assign(op) => Lifted::Assign(LiftedAssign {
                dest: self.lift_operand(op.dest),
                src: self.lift_operand(op.src),
            }),
            AssignUnpack(op) => Lifted::AssignUnpack(LiftedAssignUnpack {
                dest: self.lift_expr_list(0),
                src: self.lift_operand(op.src),
            }),
            ForceVer(op) => Lifted::ForceVer(op),
            Assert(op) => Lifted::Assert(LiftedAssert {
                src: op.src,
                constraint: PossibleValueSet::from_owned_core_raw(unsafe {
                    BNGetCachedHighLevelILPossibleValueSet(
                        self.function.handle,
                        op.constraint_index,
                    )
                }),
            }),
            Var(op) => Lifted::Var(op),
            StructField(op) => Lifted::StructField(LiftedStructField {
                src: self.lift_operand(op.src),
                offset: op.offset,
                member_index: op.member_index,
            }),
            ArrayIndex(op) => Lifted::ArrayIndex(LiftedArrayIndex {
                src: self.lift_operand(op.src),
                index: self.lift_operand(op.index),
            }),
            Split(op) => Lifted::Split(LiftedSplit {
                high: self.lift_operand(op.high),
                low: self.lift_operand(op.low),
            }),
            Deref(op) => Lifted::Deref(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            DerefField(op) => Lifted::DerefField(LiftedStructField {
                src: self.lift_operand(op.src),
                offset: op.offset,
                member_index: op.member_index,
            }),
            AddressOf(op) => Lifted::AddressOf(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
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
            Call(op) => Lifted::Call(LiftedCall {
                dest: self.lift_operand(op.dest),
                params: self.lift_expr_list(1),
            }),
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
            Syscall(_op) => Lifted::Syscall(LiftedSyscall {
                params: self.lift_expr_list(0),
            }),
            Tailcall(op) => Lifted::Tailcall(LiftedCall {
                dest: self.lift_operand(op.dest),
                params: self.lift_expr_list(1),
            }),
            Intrinsic(op) => Lifted::Intrinsic(LiftedIntrinsic {
                intrinsic: CoreIntrinsic::new(
                    self.function.function().arch(),
                    IntrinsicId(op.intrinsic),
                )
                .expect("Valid intrinsic"),
                params: self.lift_expr_list(1),
            }),
            Bp => Lifted::Bp,
            Trap(op) => Lifted::Trap(op),
            Undef => Lifted::Undef,
            Unimpl => Lifted::Unimpl,
            UnimplMem(op) => Lifted::UnimplMem(LiftedUnaryOp {
                src: self.lift_operand(op.src),
            }),
            StructInit(_op) => Lifted::StructInit(LiftedStructInit {
                fields: self.lift_expr_list(0),
            }),
            StructInitField(op) => Lifted::StructInitField(LiftedStructField {
                offset: op.offset,
                member_index: op.member_index,
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
            Unreachable => Lifted::Unreachable,
            WhileSsa(op) => Lifted::WhileSsa(LiftedWhileSsa {
                condition_phi: self.lift_operand(op.condition_phi),
                condition: self.lift_operand(op.condition),
                body: self.lift_operand(op.body),
            }),
            DoWhileSsa(op) => Lifted::DoWhileSsa(LiftedWhileSsa {
                body: self.lift_operand(op.body),
                condition_phi: self.lift_operand(op.condition_phi),
                condition: self.lift_operand(op.condition),
            }),
            ForSsa(op) => Lifted::ForSsa(LiftedForLoopSsa {
                init: self.lift_operand(op.init),
                condition_phi: self.lift_operand(op.condition_phi),
                condition: self.lift_operand(op.condition),
                update: self.lift_operand(op.update),
                body: self.lift_operand(op.body),
            }),
            VarInitSsa(op) => Lifted::VarInitSsa(LiftedVarInitSsa {
                dest: op.dest,
                src: self.lift_operand(op.src),
            }),
            AssignMemSsa(op) => Lifted::AssignMemSsa(LiftedAssignMemSsa {
                dest: self.lift_operand(op.dest),
                dest_memory: op.dest_memory,
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
            }),
            AssignUnpackMemSsa(op) => Lifted::AssignUnpackMemSsa(LiftedAssignUnpackMemSsa {
                dest: self.lift_expr_list(0),
                dest_memory: op.dest_memory,
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
            }),
            ForceVerSsa(op) => Lifted::ForceVerSsa(op),
            AssertSsa(op) => Lifted::AssertSsa(LiftedAssertSsa {
                src: op.src,
                constraint: PossibleValueSet::from_owned_core_raw(unsafe {
                    BNGetCachedHighLevelILPossibleValueSet(
                        self.function.handle,
                        op.constraint_index,
                    )
                }),
            }),
            VarSsa(op) => Lifted::VarSsa(op),
            VarSsaPartial(op) => Lifted::VarSsaPartial(op),
            ArrayIndexSsa(op) => Lifted::ArrayIndexSsa(LiftedArrayIndexSsa {
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
                index: self.lift_operand(op.index),
            }),
            DerefSsa(op) => Lifted::DerefSsa(LiftedDerefSsa {
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
            }),
            DerefFieldSsa(op) => Lifted::DerefFieldSsa(LiftedDerefFieldSsa {
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
                offset: op.offset,
                member_index: op.member_index,
            }),
            CallSsa(op) => Lifted::CallSsa(LiftedCallSsa {
                dest: self.lift_operand(op.dest),
                params: self.lift_expr_list(1),
                dest_memory: op.dest_memory,
                src_memory: op.src_memory,
            }),
            SyscallSsa(op) => Lifted::SyscallSsa(LiftedSyscallSsa {
                params: self.lift_expr_list(0),
                dest_memory: op.dest_memory,
                src_memory: op.src_memory,
            }),
            IntrinsicSsa(op) => Lifted::IntrinsicSsa(LiftedIntrinsicSsa {
                intrinsic: CoreIntrinsic::new(
                    self.function.function().arch(),
                    IntrinsicId(op.intrinsic),
                )
                .expect("Valid intrinsic"),
                params: self.lift_expr_list(1),
                dest_memory: op.dest_memory,
                src_memory: op.src_memory,
            }),
            VarPhi(op) => Lifted::VarPhi(LiftedVarPhi {
                dest: op.dest,
                src: self.get_ssa_var_list(2),
            }),
            MemPhi(op) => Lifted::MemPhi(LiftedMemPhi {
                dest: op.dest,
                src: self.get_operand_list(1),
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
            // END GENERATED hlil-lift
        };
        HighLevelILLiftedInstruction {
            function: self.function.clone(),
            address: self.address,
            instr_index: self.instr_index,
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

    fn lift_operand(
        &self,
        expr_idx: HighLevelExpressionIndex,
    ) -> Box<HighLevelILLiftedInstruction> {
        let operand_instr = self.function.instruction_from_expr_index(expr_idx).unwrap();
        Box::new(operand_instr.lift())
    }

    fn lift_expr_list(&self, operand_idx: usize) -> Vec<HighLevelILLiftedInstruction> {
        self.get_expr_list(operand_idx)
            .iter()
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
        context
            .instruction_from_expr_index(HighLevelExpressionIndex(*raw))
            .unwrap()
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

// BEGIN GENERATED hlil-instruction-kind: from api/il, do not edit
#[derive(Debug, Copy, Clone)]
pub enum HighLevelILInstructionKind {
    Nop,
    Block(Block),
    If(If),
    While(While),
    DoWhile(While),
    For(ForLoop),
    Switch(Switch),
    Case(Case),
    Break,
    Continue,
    Jump(Jump),
    Ret(Ret),
    Noret,
    Goto(Label),
    Label(Label),
    VarDeclare(Var),
    VarInit(VarInit),
    Assign(Assign),
    AssignUnpack(AssignUnpack),
    ForceVer(ForceVer),
    Assert(Assert),
    Var(Var),
    StructField(StructField),
    ArrayIndex(ArrayIndex),
    Split(Split),
    Deref(UnaryOp),
    DerefField(StructField),
    AddressOf(UnaryOp),
    PassByRef(UnaryOp),
    ReturnByRef(UnaryOp),
    Const(Const),
    ConstData(ConstData),
    ConstPtr(Const),
    ExternPtr(ExternPtr),
    FloatConst(FloatConst),
    Import(Const),
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
    Call(Call),
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
    Tailcall(Call),
    Intrinsic(Intrinsic),
    Bp,
    Trap(Trap),
    Undef,
    Unimpl,
    UnimplMem(UnaryOp),
    StructInit(StructInit),
    StructInitField(StructField),
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
    Unreachable,
    WhileSsa(WhileSsa),
    DoWhileSsa(WhileSsa),
    ForSsa(ForLoopSsa),
    VarInitSsa(VarInitSsa),
    AssignMemSsa(AssignMemSsa),
    AssignUnpackMemSsa(AssignUnpackMemSsa),
    ForceVerSsa(ForceVerSsa),
    AssertSsa(AssertSsa),
    VarSsa(VarSsa),
    VarSsaPartial(VarSsaPartial),
    ArrayIndexSsa(ArrayIndexSsa),
    DerefSsa(DerefSsa),
    DerefFieldSsa(DerefFieldSsa),
    CallSsa(CallSsa),
    SyscallSsa(SyscallSsa),
    IntrinsicSsa(IntrinsicSsa),
    VarPhi(VarPhi),
    MemPhi(MemPhi),
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
// END GENERATED hlil-instruction-kind

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
    (idx as i64 >= 0).then_some(idx as usize)
}

fn get_var_ssa(id: u64, version: usize) -> SSAVariable {
    SSAVariable::new(get_var(id), version)
}
