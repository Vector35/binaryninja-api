use binaryninjacore_sys::BNGetHighLevelILByIndex;
use binaryninjacore_sys::BNHighLevelILOperation;

use crate::operand_iter::OperandIter;
use crate::rc::Ref;
use crate::types::{ConstantData, ILIntrinsic, RegisterValue, RegisterValueType};

use super::operation::*;
use super::{HighLevelILFunction, HighLevelILLiftedInstruction, HighLevelILLiftedInstructionKind};

#[derive(Clone)]
pub struct HighLevelILInstruction {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub kind: HighLevelILInstructionKind,
}

#[derive(Copy, Clone)]
pub enum HighLevelILInstructionKind {
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
    Nop,
    Break,
    Continue,
    Noret,
    Unreachable,
    Bp,
    Undef,
    Unimpl,
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
impl HighLevelILInstruction {
    pub(crate) fn new(function: Ref<HighLevelILFunction>, idx: usize) -> Self {
        let op = unsafe { BNGetHighLevelILByIndex(function.handle, idx, function.full_ast) };
        use BNHighLevelILOperation::*;
        use HighLevelILInstructionKind as Op;
        let kind = match op.operation {
            HLIL_ADC => Op::Adc(BinaryOpCarry::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_SBB => Op::Sbb(BinaryOpCarry::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_RLC => Op::Rlc(BinaryOpCarry::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_RRC => Op::Rrc(BinaryOpCarry::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_ADD => Op::Add(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_SUB => Op::Sub(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_AND => Op::And(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_OR => Op::Or(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_XOR => Op::Xor(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_LSL => Op::Lsl(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_LSR => Op::Lsr(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_ASR => Op::Asr(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_ROL => Op::Rol(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_ROR => Op::Ror(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_MUL => Op::Mul(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_MULU_DP => Op::MuluDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_MULS_DP => Op::MulsDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_DIVU => Op::Divu(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_DIVU_DP => Op::DivuDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_DIVS => Op::Divs(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_DIVS_DP => Op::DivsDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_MODU => Op::Modu(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_MODU_DP => Op::ModuDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_MODS => Op::Mods(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_MODS_DP => Op::ModsDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_CMP_E => Op::CmpE(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_CMP_NE => Op::CmpNe(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_CMP_SLT => Op::CmpSlt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_CMP_ULT => Op::CmpUlt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_CMP_SLE => Op::CmpSle(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_CMP_ULE => Op::CmpUle(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_CMP_SGE => Op::CmpSge(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_CMP_UGE => Op::CmpUge(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_CMP_SGT => Op::CmpSgt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_CMP_UGT => Op::CmpUgt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_TEST_BIT => Op::TestBit(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_ADD_OVERFLOW => Op::AddOverflow(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FADD => Op::Fadd(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FSUB => Op::Fsub(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FMUL => Op::Fmul(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FDIV => Op::Fdiv(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FCMP_E => Op::FcmpE(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FCMP_NE => Op::FcmpNe(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FCMP_LT => Op::FcmpLt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FCMP_LE => Op::FcmpLe(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FCMP_GE => Op::FcmpGe(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FCMP_GT => Op::FcmpGt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FCMP_O => Op::FcmpO(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_FCMP_UO => Op::FcmpUo(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_ARRAY_INDEX => Op::ArrayIndex(ArrayIndex::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_ARRAY_INDEX_SSA => Op::ArrayIndexSsa(ArrayIndexSsa::new(
                op.operands[0] as usize,
                op.operands[1],
                op.operands[2] as usize,
            )),
            HLIL_ASSIGN => Op::Assign(Assign::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_ASSIGN_MEM_SSA => Op::AssignMemSsa(AssignMemSsa::new(
                op.operands[0] as usize,
                op.operands[1],
                op.operands[2] as usize,
                op.operands[3],
            )),
            HLIL_ASSIGN_UNPACK => Op::AssignUnpack(AssignUnpack::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_ASSIGN_UNPACK_MEM_SSA => Op::AssignUnpackMemSsa(AssignUnpackMemSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2],
                op.operands[3] as usize,
                op.operands[4],
            )),
            HLIL_BLOCK => Op::Block(Block::new(op.operands[0] as usize, op.operands[1] as usize)),
            HLIL_CALL => Op::Call(Call::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_TAILCALL => Op::Tailcall(Call::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_CALL_SSA => Op::CallSsa(CallSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3],
                op.operands[4],
            )),
            HLIL_CASE => Op::Case(Case::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_CONST => Op::Const(Const::new(op.operands[0])),
            HLIL_CONST_PTR => Op::ConstPtr(Const::new(op.operands[0])),
            HLIL_IMPORT => Op::Import(Const::new(op.operands[0])),
            HLIL_CONST_DATA => Op::ConstData(ConstData::new(
                op.operands[0] as u32,
                op.operands[1] as i64,
                op.size,
            )),
            HLIL_DEREF => Op::Deref(UnaryOp::new(op.operands[0] as usize)),
            HLIL_ADDRESS_OF => Op::AddressOf(UnaryOp::new(op.operands[0] as usize)),
            HLIL_NEG => Op::Neg(UnaryOp::new(op.operands[0] as usize)),
            HLIL_NOT => Op::Not(UnaryOp::new(op.operands[0] as usize)),
            HLIL_SX => Op::Sx(UnaryOp::new(op.operands[0] as usize)),
            HLIL_ZX => Op::Zx(UnaryOp::new(op.operands[0] as usize)),
            HLIL_LOW_PART => Op::LowPart(UnaryOp::new(op.operands[0] as usize)),
            HLIL_BOOL_TO_INT => Op::BoolToInt(UnaryOp::new(op.operands[0] as usize)),
            HLIL_UNIMPL_MEM => Op::UnimplMem(UnaryOp::new(op.operands[0] as usize)),
            HLIL_FSQRT => Op::Fsqrt(UnaryOp::new(op.operands[0] as usize)),
            HLIL_FNEG => Op::Fneg(UnaryOp::new(op.operands[0] as usize)),
            HLIL_FABS => Op::Fabs(UnaryOp::new(op.operands[0] as usize)),
            HLIL_FLOAT_TO_INT => Op::FloatToInt(UnaryOp::new(op.operands[0] as usize)),
            HLIL_INT_TO_FLOAT => Op::IntToFloat(UnaryOp::new(op.operands[0] as usize)),
            HLIL_FLOAT_CONV => Op::FloatConv(UnaryOp::new(op.operands[0] as usize)),
            HLIL_ROUND_TO_INT => Op::RoundToInt(UnaryOp::new(op.operands[0] as usize)),
            HLIL_FLOOR => Op::Floor(UnaryOp::new(op.operands[0] as usize)),
            HLIL_CEIL => Op::Ceil(UnaryOp::new(op.operands[0] as usize)),
            HLIL_FTRUNC => Op::Ftrunc(UnaryOp::new(op.operands[0] as usize)),
            HLIL_DEREF_FIELD_SSA => Op::DerefFieldSsa(DerefFieldSsa::new(
                op.operands[0] as usize,
                op.operands[1],
                op.operands[2],
                op.operands[3],
            )),
            HLIL_DEREF_SSA => Op::DerefSsa(DerefSsa::new(op.operands[0] as usize, op.operands[1])),
            HLIL_EXTERN_PTR => Op::ExternPtr(ExternPtr::new(op.operands[0], op.operands[1])),
            HLIL_FLOAT_CONST => Op::FloatConst(FloatConst::new(op.operands[0], op.size)),
            HLIL_FOR => Op::For(ForLoop::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
            )),
            HLIL_FOR_SSA => Op::ForSsa(ForLoopSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
                op.operands[4] as usize,
            )),
            HLIL_GOTO => Op::Goto(Label::new(op.operands[0])),
            HLIL_LABEL => Op::Label(Label::new(op.operands[0])),
            HLIL_IF => Op::If(If::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_INTRINSIC => Op::Intrinsic(Intrinsic::new(
                op.operands[0] as u32,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_INTRINSIC_SSA => Op::IntrinsicSsa(IntrinsicSsa::new(
                op.operands[0] as u32,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3],
                op.operands[4],
            )),
            HLIL_JUMP => Op::Jump(Jump::new(op.operands[0] as usize)),
            HLIL_MEM_PHI => Op::MemPhi(MemPhi::new(
                op.operands[0],
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_NOP => Op::Nop,
            HLIL_BREAK => Op::Break,
            HLIL_CONTINUE => Op::Continue,
            HLIL_NORET => Op::Noret,
            HLIL_UNREACHABLE => Op::Unreachable,
            HLIL_BP => Op::Bp,
            HLIL_UNDEF => Op::Undef,
            HLIL_UNIMPL => Op::Unimpl,
            HLIL_RET => Op::Ret(Ret::new(op.operands[0] as usize, op.operands[1] as usize)),
            HLIL_SPLIT => Op::Split(Split::new(op.operands[0] as usize, op.operands[1] as usize)),
            HLIL_STRUCT_FIELD => Op::StructField(StructField::new(
                op.operands[0] as usize,
                op.operands[1],
                op.operands[2],
            )),
            HLIL_DEREF_FIELD => Op::DerefField(StructField::new(
                op.operands[0] as usize,
                op.operands[1],
                op.operands[2],
            )),
            HLIL_SWITCH => Op::Switch(Switch::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
            )),
            HLIL_SYSCALL => Op::Syscall(Syscall::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            HLIL_SYSCALL_SSA => Op::SyscallSsa(SyscallSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2],
                op.operands[3],
            )),
            HLIL_TRAP => Op::Trap(Trap::new(op.operands[0])),
            HLIL_VAR_DECLARE => Op::VarDeclare(Var::new(op.operands[0])),
            HLIL_VAR => Op::Var(Var::new(op.operands[0])),
            HLIL_VAR_INIT => Op::VarInit(VarInit::new(op.operands[0], op.operands[1] as usize)),
            HLIL_VAR_INIT_SSA => Op::VarInitSsa(VarInitSsa::new(
                (op.operands[0], op.operands[1] as usize),
                op.operands[2] as usize,
            )),
            HLIL_VAR_PHI => Op::VarPhi(VarPhi::new(
                (op.operands[0], op.operands[1] as usize),
                op.operands[2] as usize,
                op.operands[3] as usize,
            )),
            HLIL_VAR_SSA => Op::VarSsa(VarSsa::new((op.operands[0], op.operands[1] as usize))),
            HLIL_WHILE => Op::While(While::new(op.operands[0] as usize, op.operands[1] as usize)),
            HLIL_DO_WHILE => {
                Op::DoWhile(While::new(op.operands[0] as usize, op.operands[1] as usize))
            }
            HLIL_WHILE_SSA => Op::WhileSsa(WhileSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            HLIL_DO_WHILE_SSA => Op::DoWhileSsa(WhileSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
        };
        Self {
            function,
            address: op.address,
            kind,
        }
    }

    pub fn lift(&self) -> HighLevelILLiftedInstruction {
        use HighLevelILInstructionKind::*;
        use HighLevelILLiftedInstructionKind as Lifted;
        let kind = match self.kind {
            Nop => Lifted::Nop,
            Block(op) => Lifted::Block(LiftedBlock {
                body: self.lift_instruction_list(op.first_param, op.num_params),
            }),
            If(op) => Lifted::If(LiftedIf {
                condition: self.lift_operand(op.condition),
                cond_true: self.lift_operand(op.cond_true),
                cond_false: self.lift_operand(op.cond_false),
            }),
            While(op) => Lifted::While(self.lift_while(op)),
            WhileSsa(op) => Lifted::WhileSsa(self.lift_while_ssa(op)),
            DoWhile(op) => Lifted::DoWhile(self.lift_while(op)),
            DoWhileSsa(op) => Lifted::DoWhileSsa(self.lift_while_ssa(op)),
            For(op) => Lifted::For(LiftedForLoop {
                init: self.lift_operand(op.init),
                condition: self.lift_operand(op.condition),
                update: self.lift_operand(op.update),
                body: self.lift_operand(op.body),
            }),
            ForSsa(op) => Lifted::ForSsa(LiftedForLoopSsa {
                init: self.lift_operand(op.init),
                condition_phi: self.lift_operand(op.condition_phi),
                condition: self.lift_operand(op.condition),
                update: self.lift_operand(op.update),
                body: self.lift_operand(op.body),
            }),
            Switch(op) => Lifted::Switch(LiftedSwitch {
                condition: self.lift_operand(op.condition),
                default: self.lift_operand(op.default),
                cases: self.lift_instruction_list(op.first_case, op.num_cases),
            }),
            Case(op) => Lifted::Case(LiftedCase {
                values: self.lift_instruction_list(op.first_value, op.num_values),
                body: self.lift_operand(op.body),
            }),
            Break => Lifted::Break,
            Continue => Lifted::Continue,
            Jump(op) => Lifted::Jump(LiftedJump {
                dest: self.lift_operand(op.dest),
            }),
            Ret(op) => Lifted::Ret(LiftedRet {
                src: self.lift_instruction_list(op.first_src, op.num_srcs),
            }),
            Noret => Lifted::Noret,
            Unreachable => Lifted::Unreachable,
            Goto(op) => Lifted::Goto(self.lift_label(op)),
            Label(op) => Lifted::Label(self.lift_label(op)),
            VarDeclare(op) => Lifted::VarDeclare(op),
            VarInit(op) => Lifted::VarInit(LiftedVarInit {
                dest: op.dest,
                src: self.lift_operand(op.src),
            }),
            VarInitSsa(op) => Lifted::VarInitSsa(LiftedVarInitSsa {
                dest: op.dest,
                src: self.lift_operand(op.src),
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
            Var(op) => Lifted::Var(op),
            VarSsa(op) => Lifted::VarSsa(op),
            VarPhi(op) => Lifted::VarPhi(LiftedVarPhi {
                dest: op.dest,
                src: OperandIter::new(&*self.function, op.first_src, op.num_srcs)
                    .ssa_vars()
                    .collect(),
            }),
            MemPhi(op) => Lifted::MemPhi(LiftedMemPhi {
                dest: op.dest,
                src: OperandIter::new(&*self.function, op.first_src, op.num_srcs).collect(),
            }),
            ArrayIndex(op) => Lifted::ArrayIndex(LiftedArrayIndex {
                src: self.lift_operand(op.src),
                index: self.lift_operand(op.index),
            }),
            ArrayIndexSsa(op) => Lifted::ArrayIndexSsa(LiftedArrayIndexSsa {
                src: self.lift_operand(op.src),
                src_memory: op.src_memory,
                index: self.lift_operand(op.index),
            }),
            Split(op) => Lifted::Split(LiftedSplit {
                high: self.lift_operand(op.high),
                low: self.lift_operand(op.low),
            }),
            Deref(op) => Lifted::Deref(self.lift_unary_op(op)),
            StructField(op) => Lifted::StructField(self.lift_struct_field(op)),
            DerefField(op) => Lifted::DerefField(self.lift_struct_field(op)),
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
            AddressOf(op) => Lifted::AddressOf(self.lift_unary_op(op)),
            Const(op) => Lifted::Const(op),
            ConstPtr(op) => Lifted::ConstPtr(op),
            ExternPtr(op) => Lifted::ExternPtr(op),
            FloatConst(op) => Lifted::FloatConst(op),
            Import(op) => Lifted::Import(op),
            ConstData(op) => Lifted::ConstData(LiftedConstantData {
                constant_data: ConstantData::new(
                    self.function.get_function(),
                    RegisterValue {
                        state: RegisterValueType::from_raw_value(op.constant_data_kind).unwrap(),
                        value: op.constant_data_value,
                        offset: 0,
                        size: op.size,
                    },
                ),
            }),
            Add(op) => Lifted::Add(self.lift_binary_op(op)),
            Adc(op) => Lifted::Adc(self.lift_binary_op_carry(op)),
            Sub(op) => Lifted::Sub(self.lift_binary_op(op)),
            Sbb(op) => Lifted::Sbb(self.lift_binary_op_carry(op)),
            And(op) => Lifted::And(self.lift_binary_op(op)),
            Or(op) => Lifted::Or(self.lift_binary_op(op)),
            Xor(op) => Lifted::Xor(self.lift_binary_op(op)),
            Lsl(op) => Lifted::Lsl(self.lift_binary_op(op)),
            Lsr(op) => Lifted::Lsr(self.lift_binary_op(op)),
            Asr(op) => Lifted::Asr(self.lift_binary_op(op)),
            Rol(op) => Lifted::Rol(self.lift_binary_op(op)),
            Rlc(op) => Lifted::Rlc(self.lift_binary_op_carry(op)),
            Ror(op) => Lifted::Ror(self.lift_binary_op(op)),
            Rrc(op) => Lifted::Rrc(self.lift_binary_op_carry(op)),
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
            Neg(op) => Lifted::Neg(self.lift_unary_op(op)),
            Not(op) => Lifted::Not(self.lift_unary_op(op)),
            Sx(op) => Lifted::Sx(self.lift_unary_op(op)),
            Zx(op) => Lifted::Zx(self.lift_unary_op(op)),
            LowPart(op) => Lifted::LowPart(self.lift_unary_op(op)),
            Call(op) => Lifted::Call(self.lift_call(op)),
            CallSsa(op) => Lifted::CallSsa(LiftedCallSsa {
                dest: self.lift_operand(op.dest),
                params: self.lift_instruction_list(op.first_param, op.num_params),
                dest_memory: op.dest_memory,
                src_memory: op.src_memory,
            }),
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
            BoolToInt(op) => Lifted::BoolToInt(self.lift_unary_op(op)),
            AddOverflow(op) => Lifted::AddOverflow(self.lift_binary_op(op)),
            Syscall(op) => Lifted::Syscall(LiftedSyscall {
                params: self.lift_instruction_list(op.first_param, op.num_params),
            }),
            SyscallSsa(op) => Lifted::SyscallSsa(LiftedSyscallSsa {
                params: self.lift_instruction_list(op.first_param, op.num_params),
                dest_memory: op.dest_memory,
                src_memory: op.src_memory,
            }),
            Tailcall(op) => Lifted::Tailcall(self.lift_call(op)),
            Bp => Lifted::Bp,
            Trap(op) => Lifted::Trap(op),
            Intrinsic(op) => Lifted::Intrinsic(LiftedIntrinsic {
                intrinsic: ILIntrinsic::new(self.function.get_function().arch(), op.intrinsic),
                params: self.lift_instruction_list(op.first_param, op.num_params),
            }),
            IntrinsicSsa(op) => Lifted::IntrinsicSsa(LiftedIntrinsicSsa {
                intrinsic: ILIntrinsic::new(self.function.get_function().arch(), op.intrinsic),
                params: self.lift_instruction_list(op.first_param, op.num_params),
                dest_memory: op.dest_memory,
                src_memory: op.src_memory,
            }),
            Undef => Lifted::Undef,
            Unimpl => Lifted::Unimpl,
            UnimplMem(op) => Lifted::UnimplMem(self.lift_unary_op(op)),
            Fadd(op) => Lifted::Fadd(self.lift_binary_op(op)),
            Fsub(op) => Lifted::Fsub(self.lift_binary_op(op)),
            Fmul(op) => Lifted::Fmul(self.lift_binary_op(op)),
            Fdiv(op) => Lifted::Fdiv(self.lift_binary_op(op)),
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
            FcmpE(op) => Lifted::FcmpE(self.lift_binary_op(op)),
            FcmpNe(op) => Lifted::FcmpNe(self.lift_binary_op(op)),
            FcmpLt(op) => Lifted::FcmpLt(self.lift_binary_op(op)),
            FcmpLe(op) => Lifted::FcmpLe(self.lift_binary_op(op)),
            FcmpGe(op) => Lifted::FcmpGe(self.lift_binary_op(op)),
            FcmpGt(op) => Lifted::FcmpGt(self.lift_binary_op(op)),
            FcmpO(op) => Lifted::FcmpO(self.lift_binary_op(op)),
            FcmpUo(op) => Lifted::FcmpUo(self.lift_binary_op(op)),
        };
        HighLevelILLiftedInstruction {
            function: self.function.clone(),
            address: self.address,
            kind,
        }
    }

    fn lift_operand(&self, expr_idx: usize) -> Box<HighLevelILLiftedInstruction> {
        Box::new(self.function.lifted_instruction_from_idx(expr_idx))
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
                function: self.function.get_function(),
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

impl core::fmt::Debug for HighLevelILInstruction {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "<{} at 0x{:08}>",
            core::any::type_name::<Self>(),
            self.address,
        )
    }
}
