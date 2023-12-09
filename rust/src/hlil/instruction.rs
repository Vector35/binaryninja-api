use binaryninjacore_sys::BNGetHighLevelILByIndex;
use binaryninjacore_sys::BNHighLevelILOperation;

use crate::rc::Ref;
use crate::types::IntrinsicId;

use super::operation::*;
use super::{HighLevelILFunction, HighLevelILLiftedInstruction, HighLevelILLiftedOperation};

#[derive(Clone)]
pub struct HighLevelILInstruction {
    pub(crate) function: Ref<HighLevelILFunction>,
    pub(crate) address: u64,
    pub(crate) operation: HighLevelILOperation,
}

#[derive(Copy, Clone)]
pub enum HighLevelILOperation {
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
    Nop(NoArgs),
    Break(NoArgs),
    Continue(NoArgs),
    Noret(NoArgs),
    Unreachable(NoArgs),
    Bp(NoArgs),
    Undef(NoArgs),
    Unimpl(NoArgs),
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
    pub(crate) fn new(function: &HighLevelILFunction, idx: usize) -> Self {
        let op = unsafe { BNGetHighLevelILByIndex(function.handle, idx, function.full_ast) };
        use BNHighLevelILOperation::*;
        use HighLevelILOperation as Op;
        let info = match op.operation {
            HLIL_ADC => Op::Adc(BinaryOpCarry::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
                op.operands[2usize] as usize,
            )),
            HLIL_SBB => Op::Sbb(BinaryOpCarry::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
                op.operands[2usize] as usize,
            )),
            HLIL_RLC => Op::Rlc(BinaryOpCarry::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
                op.operands[2usize] as usize,
            )),
            HLIL_RRC => Op::Rrc(BinaryOpCarry::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
                op.operands[2usize] as usize,
            )),
            HLIL_ADD => Op::Add(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_SUB => Op::Sub(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_AND => Op::And(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_OR => Op::Or(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_XOR => Op::Xor(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_LSL => Op::Lsl(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_LSR => Op::Lsr(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_ASR => Op::Asr(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_ROL => Op::Rol(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_ROR => Op::Ror(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_MUL => Op::Mul(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_MULU_DP => Op::MuluDp(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_MULS_DP => Op::MulsDp(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_DIVU => Op::Divu(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_DIVU_DP => Op::DivuDp(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_DIVS => Op::Divs(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_DIVS_DP => Op::DivsDp(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_MODU => Op::Modu(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_MODU_DP => Op::ModuDp(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_MODS => Op::Mods(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_MODS_DP => Op::ModsDp(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_CMP_E => Op::CmpE(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_CMP_NE => Op::CmpNe(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_CMP_SLT => Op::CmpSlt(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_CMP_ULT => Op::CmpUlt(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_CMP_SLE => Op::CmpSle(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_CMP_ULE => Op::CmpUle(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_CMP_SGE => Op::CmpSge(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_CMP_UGE => Op::CmpUge(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_CMP_SGT => Op::CmpSgt(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_CMP_UGT => Op::CmpUgt(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_TEST_BIT => Op::TestBit(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_ADD_OVERFLOW => Op::AddOverflow(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FADD => Op::Fadd(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FSUB => Op::Fsub(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FMUL => Op::Fmul(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FDIV => Op::Fdiv(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FCMP_E => Op::FcmpE(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FCMP_NE => Op::FcmpNe(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FCMP_LT => Op::FcmpLt(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FCMP_LE => Op::FcmpLe(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FCMP_GE => Op::FcmpGe(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FCMP_GT => Op::FcmpGt(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FCMP_O => Op::FcmpO(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_FCMP_UO => Op::FcmpUo(BinaryOp::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_ARRAY_INDEX => Op::ArrayIndex(ArrayIndex::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_ARRAY_INDEX_SSA => Op::ArrayIndexSsa(ArrayIndexSsa::new(
                op.operands[0usize] as usize,
                op.operands[1usize],
                op.operands[2usize] as usize,
            )),
            HLIL_ASSIGN => Op::Assign(Assign::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_ASSIGN_MEM_SSA => Op::AssignMemSsa(AssignMemSsa::new(
                op.operands[0usize] as usize,
                op.operands[1usize],
                op.operands[2usize] as usize,
                op.operands[3usize],
            )),
            HLIL_ASSIGN_UNPACK => Op::AssignUnpack(AssignUnpack::new(
                (op.operands[0usize] as usize, op.operands[1usize] as usize),
                op.operands[2usize] as usize,
            )),
            HLIL_ASSIGN_UNPACK_MEM_SSA => Op::AssignUnpackMemSsa(AssignUnpackMemSsa::new(
                (op.operands[0usize] as usize, op.operands[1usize] as usize),
                op.operands[2usize],
                op.operands[3usize] as usize,
                op.operands[4usize],
            )),
            HLIL_BLOCK => Op::Block(Block::new((
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            ))),
            HLIL_CALL => Op::Call(Call::new(
                op.operands[0usize] as usize,
                (op.operands[1usize] as usize, op.operands[2usize] as usize),
            )),
            HLIL_TAILCALL => Op::Tailcall(Call::new(
                op.operands[0usize] as usize,
                (op.operands[1usize] as usize, op.operands[2usize] as usize),
            )),
            HLIL_CALL_SSA => Op::CallSsa(CallSsa::new(
                op.operands[0usize] as usize,
                (op.operands[1usize] as usize, op.operands[2usize] as usize),
                op.operands[3usize],
                op.operands[4usize],
            )),
            HLIL_CASE => Op::Case(Case::new(
                (op.operands[0usize] as usize, op.operands[1usize] as usize),
                op.operands[2usize] as usize,
            )),
            HLIL_CONST => Op::Const(Const::new(op.operands[0usize])),
            HLIL_CONST_PTR => Op::ConstPtr(Const::new(op.operands[0usize])),
            HLIL_IMPORT => Op::Import(Const::new(op.operands[0usize])),
            HLIL_CONST_DATA => Op::ConstData(ConstData::new((
                op.operands[0usize].try_into().unwrap(),
                op.operands[1usize],
                op.size,
            ))),
            HLIL_DEREF => Op::Deref(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_ADDRESS_OF => Op::AddressOf(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_NEG => Op::Neg(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_NOT => Op::Not(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_SX => Op::Sx(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_ZX => Op::Zx(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_LOW_PART => Op::LowPart(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_BOOL_TO_INT => Op::BoolToInt(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_UNIMPL_MEM => Op::UnimplMem(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_FSQRT => Op::Fsqrt(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_FNEG => Op::Fneg(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_FABS => Op::Fabs(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_FLOAT_TO_INT => Op::FloatToInt(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_INT_TO_FLOAT => Op::IntToFloat(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_FLOAT_CONV => Op::FloatConv(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_ROUND_TO_INT => Op::RoundToInt(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_FLOOR => Op::Floor(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_CEIL => Op::Ceil(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_FTRUNC => Op::Ftrunc(UnaryOp::new(op.operands[0usize] as usize)),
            HLIL_DEREF_FIELD_SSA => Op::DerefFieldSsa(DerefFieldSsa::new(
                op.operands[0usize] as usize,
                op.operands[1usize],
                op.operands[2usize],
                op.operands[3usize],
            )),
            HLIL_DEREF_SSA => Op::DerefSsa(DerefSsa::new(
                op.operands[0usize] as usize,
                op.operands[1usize],
            )),
            HLIL_EXTERN_PTR => {
                Op::ExternPtr(ExternPtr::new(op.operands[0usize], op.operands[1usize]))
            }
            HLIL_FLOAT_CONST => Op::FloatConst(FloatConst::new(op.operands[0usize], op.size)),
            HLIL_FOR => Op::For(ForLoop::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
                op.operands[2usize] as usize,
                op.operands[3usize] as usize,
            )),
            HLIL_FOR_SSA => Op::ForSsa(ForLoopSsa::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
                op.operands[2usize] as usize,
                op.operands[3usize] as usize,
                op.operands[4usize] as usize,
            )),
            HLIL_GOTO => Op::Goto(Label::new(op.operands[0usize])),
            HLIL_LABEL => Op::Label(Label::new(op.operands[0usize])),
            HLIL_IF => Op::If(If::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
                op.operands[2usize] as usize,
            )),
            HLIL_INTRINSIC => Op::Intrinsic(Intrinsic::new(
                IntrinsicId(op.operands[0usize] as usize),
                (op.operands[1usize] as usize, op.operands[2usize] as usize),
            )),
            HLIL_INTRINSIC_SSA => Op::IntrinsicSsa(IntrinsicSsa::new(
                IntrinsicId(op.operands[0usize] as usize),
                (op.operands[1usize] as usize, op.operands[2usize] as usize),
                op.operands[3usize],
                op.operands[4usize],
            )),
            HLIL_JUMP => Op::Jump(Jump::new(op.operands[0usize] as usize)),
            HLIL_MEM_PHI => Op::MemPhi(MemPhi::new(
                op.operands[0usize],
                (op.operands[1usize] as usize, op.operands[2usize] as usize),
            )),
            HLIL_NOP => Op::Nop(NoArgs::new()),
            HLIL_BREAK => Op::Break(NoArgs::new()),
            HLIL_CONTINUE => Op::Continue(NoArgs::new()),
            HLIL_NORET => Op::Noret(NoArgs::new()),
            HLIL_UNREACHABLE => Op::Unreachable(NoArgs::new()),
            HLIL_BP => Op::Bp(NoArgs::new()),
            HLIL_UNDEF => Op::Undef(NoArgs::new()),
            HLIL_UNIMPL => Op::Unimpl(NoArgs::new()),
            HLIL_RET => Op::Ret(Ret::new((
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            ))),
            HLIL_SPLIT => Op::Split(Split::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_STRUCT_FIELD => Op::StructField(StructField::new(
                op.operands[0usize] as usize,
                op.operands[1usize],
                op.operands[2usize],
            )),
            HLIL_DEREF_FIELD => Op::DerefField(StructField::new(
                op.operands[0usize] as usize,
                op.operands[1usize],
                op.operands[2usize],
            )),
            HLIL_SWITCH => Op::Switch(Switch::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
                (op.operands[2usize] as usize, op.operands[3usize] as usize),
            )),
            HLIL_SYSCALL => Op::Syscall(Syscall::new((
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            ))),
            HLIL_SYSCALL_SSA => Op::SyscallSsa(SyscallSsa::new(
                (op.operands[0usize] as usize, op.operands[1usize] as usize),
                op.operands[2usize],
                op.operands[3usize],
            )),
            HLIL_TRAP => Op::Trap(Trap::new(op.operands[0usize])),
            HLIL_VAR_DECLARE => Op::VarDeclare(Var::new(op.operands[0usize])),
            HLIL_VAR => Op::Var(Var::new(op.operands[0usize])),
            HLIL_VAR_INIT => Op::VarInit(VarInit::new(
                op.operands[0usize],
                op.operands[1usize] as usize,
            )),
            HLIL_VAR_INIT_SSA => Op::VarInitSsa(VarInitSsa::new(
                (op.operands[0usize], op.operands[1usize] as usize),
                op.operands[2usize] as usize,
            )),
            HLIL_VAR_PHI => Op::VarPhi(VarPhi::new(
                (op.operands[0usize], op.operands[1usize] as usize),
                (op.operands[2usize] as usize, op.operands[3usize] as usize),
            )),
            HLIL_VAR_SSA => Op::VarSsa(VarSsa::new((
                op.operands[0usize],
                op.operands[1usize] as usize,
            ))),
            HLIL_WHILE => Op::While(While::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_DO_WHILE => Op::DoWhile(While::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
            )),
            HLIL_WHILE_SSA => Op::WhileSsa(WhileSsa::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
                op.operands[2usize] as usize,
            )),
            HLIL_DO_WHILE_SSA => Op::DoWhileSsa(WhileSsa::new(
                op.operands[0usize] as usize,
                op.operands[1usize] as usize,
                op.operands[2usize] as usize,
            )),
        };
        Self {
            function: function.to_owned(),
            address: op.address,
            operation: info,
        }
    }
    pub fn function(&self) -> &HighLevelILFunction {
        &self.function
    }
    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn operation(&self) -> &HighLevelILOperation {
        &self.operation
    }
    pub fn lift(&self) -> HighLevelILLiftedInstruction {
        use HighLevelILLiftedOperation as Lifted;
        use HighLevelILOperation::*;
        let operation = match self.operation {
            Nop(op) => Lifted::Nop(op),
            Block(op) => Lifted::Block(op.lift(&self.function)),
            If(op) => Lifted::If(op.lift(&self.function)),
            While(op) => Lifted::While(op.lift(&self.function)),
            WhileSsa(op) => Lifted::WhileSsa(op.lift(&self.function)),
            DoWhile(op) => Lifted::DoWhile(op.lift(&self.function)),
            DoWhileSsa(op) => Lifted::DoWhileSsa(op.lift(&self.function)),
            For(op) => Lifted::For(op.lift(&self.function)),
            ForSsa(op) => Lifted::ForSsa(op.lift(&self.function)),
            Switch(op) => Lifted::Switch(op.lift(&self.function)),
            Case(op) => Lifted::Case(op.lift(&self.function)),
            Break(op) => Lifted::Break(op),
            Continue(op) => Lifted::Continue(op),
            Jump(op) => Lifted::Jump(op),
            Ret(op) => Lifted::Ret(op.lift(&self.function)),
            Noret(op) => Lifted::Noret(op),
            Unreachable(op) => Lifted::Unreachable(op),
            Goto(op) => Lifted::Goto(op),
            Label(op) => Lifted::Label(op),
            VarDeclare(op) => Lifted::VarDeclare(op),
            VarInit(op) => Lifted::VarInit(op.lift(&self.function)),
            VarInitSsa(op) => Lifted::VarInitSsa(op.lift(&self.function)),
            Assign(op) => Lifted::Assign(op.lift(&self.function)),
            AssignUnpack(op) => Lifted::AssignUnpack(op.lift(&self.function)),
            AssignMemSsa(op) => Lifted::AssignMemSsa(op.lift(&self.function)),
            AssignUnpackMemSsa(op) => Lifted::AssignUnpackMemSsa(op.lift(&self.function)),
            Var(op) => Lifted::Var(op),
            VarSsa(op) => Lifted::VarSsa(op),
            VarPhi(op) => Lifted::VarPhi(op.lift(&self.function)),
            MemPhi(op) => Lifted::MemPhi(op.lift(&self.function)),
            ArrayIndex(op) => Lifted::ArrayIndex(op.lift(&self.function)),
            ArrayIndexSsa(op) => Lifted::ArrayIndexSsa(op.lift(&self.function)),
            Split(op) => Lifted::Split(op.lift(&self.function)),
            Deref(op) => Lifted::Deref(op.lift(&self.function)),
            StructField(op) => Lifted::StructField(op.lift(&self.function)),
            DerefField(op) => Lifted::DerefField(op.lift(&self.function)),
            DerefSsa(op) => Lifted::DerefSsa(op.lift(&self.function)),
            DerefFieldSsa(op) => Lifted::DerefFieldSsa(op.lift(&self.function)),
            AddressOf(op) => Lifted::AddressOf(op.lift(&self.function)),
            Const(op) => Lifted::Const(op),
            ConstPtr(op) => Lifted::ConstPtr(op),
            ExternPtr(op) => Lifted::ExternPtr(op),
            FloatConst(op) => Lifted::FloatConst(op),
            Import(op) => Lifted::Import(op),
            ConstData(op) => Lifted::ConstData(op.lift(&self.function)),
            Add(op) => Lifted::Add(op.lift(&self.function)),
            Adc(op) => Lifted::Adc(op.lift(&self.function)),
            Sub(op) => Lifted::Sub(op.lift(&self.function)),
            Sbb(op) => Lifted::Sbb(op.lift(&self.function)),
            And(op) => Lifted::And(op.lift(&self.function)),
            Or(op) => Lifted::Or(op.lift(&self.function)),
            Xor(op) => Lifted::Xor(op.lift(&self.function)),
            Lsl(op) => Lifted::Lsl(op.lift(&self.function)),
            Lsr(op) => Lifted::Lsr(op.lift(&self.function)),
            Asr(op) => Lifted::Asr(op.lift(&self.function)),
            Rol(op) => Lifted::Rol(op.lift(&self.function)),
            Rlc(op) => Lifted::Rlc(op.lift(&self.function)),
            Ror(op) => Lifted::Ror(op.lift(&self.function)),
            Rrc(op) => Lifted::Rrc(op.lift(&self.function)),
            Mul(op) => Lifted::Mul(op.lift(&self.function)),
            MuluDp(op) => Lifted::MuluDp(op.lift(&self.function)),
            MulsDp(op) => Lifted::MulsDp(op.lift(&self.function)),
            Divu(op) => Lifted::Divu(op.lift(&self.function)),
            DivuDp(op) => Lifted::DivuDp(op.lift(&self.function)),
            Divs(op) => Lifted::Divs(op.lift(&self.function)),
            DivsDp(op) => Lifted::DivsDp(op.lift(&self.function)),
            Modu(op) => Lifted::Modu(op.lift(&self.function)),
            ModuDp(op) => Lifted::ModuDp(op.lift(&self.function)),
            Mods(op) => Lifted::Mods(op.lift(&self.function)),
            ModsDp(op) => Lifted::ModsDp(op.lift(&self.function)),
            Neg(op) => Lifted::Neg(op.lift(&self.function)),
            Not(op) => Lifted::Not(op.lift(&self.function)),
            Sx(op) => Lifted::Sx(op.lift(&self.function)),
            Zx(op) => Lifted::Zx(op.lift(&self.function)),
            LowPart(op) => Lifted::LowPart(op.lift(&self.function)),
            Call(op) => Lifted::Call(op.lift(&self.function)),
            CallSsa(op) => Lifted::CallSsa(op.lift(&self.function)),
            CmpE(op) => Lifted::CmpE(op.lift(&self.function)),
            CmpNe(op) => Lifted::CmpNe(op.lift(&self.function)),
            CmpSlt(op) => Lifted::CmpSlt(op.lift(&self.function)),
            CmpUlt(op) => Lifted::CmpUlt(op.lift(&self.function)),
            CmpSle(op) => Lifted::CmpSle(op.lift(&self.function)),
            CmpUle(op) => Lifted::CmpUle(op.lift(&self.function)),
            CmpSge(op) => Lifted::CmpSge(op.lift(&self.function)),
            CmpUge(op) => Lifted::CmpUge(op.lift(&self.function)),
            CmpSgt(op) => Lifted::CmpSgt(op.lift(&self.function)),
            CmpUgt(op) => Lifted::CmpUgt(op.lift(&self.function)),
            TestBit(op) => Lifted::TestBit(op.lift(&self.function)),
            BoolToInt(op) => Lifted::BoolToInt(op.lift(&self.function)),
            AddOverflow(op) => Lifted::AddOverflow(op.lift(&self.function)),
            Syscall(op) => Lifted::Syscall(op.lift(&self.function)),
            SyscallSsa(op) => Lifted::SyscallSsa(op.lift(&self.function)),
            Tailcall(op) => Lifted::Tailcall(op.lift(&self.function)),
            Bp(op) => Lifted::Bp(op),
            Trap(op) => Lifted::Trap(op),
            Intrinsic(op) => Lifted::Intrinsic(op.lift(&self.function)),
            IntrinsicSsa(op) => Lifted::IntrinsicSsa(op.lift(&self.function)),
            Undef(op) => Lifted::Undef(op),
            Unimpl(op) => Lifted::Unimpl(op),
            UnimplMem(op) => Lifted::UnimplMem(op.lift(&self.function)),
            Fadd(op) => Lifted::Fadd(op.lift(&self.function)),
            Fsub(op) => Lifted::Fsub(op.lift(&self.function)),
            Fmul(op) => Lifted::Fmul(op.lift(&self.function)),
            Fdiv(op) => Lifted::Fdiv(op.lift(&self.function)),
            Fsqrt(op) => Lifted::Fsqrt(op.lift(&self.function)),
            Fneg(op) => Lifted::Fneg(op.lift(&self.function)),
            Fabs(op) => Lifted::Fabs(op.lift(&self.function)),
            FloatToInt(op) => Lifted::FloatToInt(op.lift(&self.function)),
            IntToFloat(op) => Lifted::IntToFloat(op.lift(&self.function)),
            FloatConv(op) => Lifted::FloatConv(op.lift(&self.function)),
            RoundToInt(op) => Lifted::RoundToInt(op.lift(&self.function)),
            Floor(op) => Lifted::Floor(op.lift(&self.function)),
            Ceil(op) => Lifted::Ceil(op.lift(&self.function)),
            Ftrunc(op) => Lifted::Ftrunc(op.lift(&self.function)),
            FcmpE(op) => Lifted::FcmpE(op.lift(&self.function)),
            FcmpNe(op) => Lifted::FcmpNe(op.lift(&self.function)),
            FcmpLt(op) => Lifted::FcmpLt(op.lift(&self.function)),
            FcmpLe(op) => Lifted::FcmpLe(op.lift(&self.function)),
            FcmpGe(op) => Lifted::FcmpGe(op.lift(&self.function)),
            FcmpGt(op) => Lifted::FcmpGt(op.lift(&self.function)),
            FcmpO(op) => Lifted::FcmpO(op.lift(&self.function)),
            FcmpUo(op) => Lifted::FcmpUo(op.lift(&self.function)),
        };
        HighLevelILLiftedInstruction {
            address: self.address,
            operation,
        }
    }
    pub fn operands<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = (&'static str, HighLevelILOperand)> + 'a> {
        use HighLevelILOperation::*;
        match &self.operation {
            Adc(op) | Sbb(op) | Rlc(op) | Rrc(op) => Box::new(op.operands(&self.function)),
            Add(op) | Sub(op) | And(op) | Or(op) | Xor(op) | Lsl(op) | Lsr(op) | Asr(op)
            | Rol(op) | Ror(op) | Mul(op) | MuluDp(op) | MulsDp(op) | Divu(op) | DivuDp(op)
            | Divs(op) | DivsDp(op) | Modu(op) | ModuDp(op) | Mods(op) | ModsDp(op) | CmpE(op)
            | CmpNe(op) | CmpSlt(op) | CmpUlt(op) | CmpSle(op) | CmpUle(op) | CmpSge(op)
            | CmpUge(op) | CmpSgt(op) | CmpUgt(op) | TestBit(op) | AddOverflow(op) | Fadd(op)
            | Fsub(op) | Fmul(op) | Fdiv(op) | FcmpE(op) | FcmpNe(op) | FcmpLt(op) | FcmpLe(op)
            | FcmpGe(op) | FcmpGt(op) | FcmpO(op) | FcmpUo(op) => {
                Box::new(op.operands(&self.function))
            }
            ArrayIndex(op) => Box::new(op.operands(&self.function)),
            ArrayIndexSsa(op) => Box::new(op.operands(&self.function)),
            Assign(op) => Box::new(op.operands(&self.function)),
            AssignMemSsa(op) => Box::new(op.operands(&self.function)),
            AssignUnpack(op) => Box::new(op.operands(&self.function)),
            AssignUnpackMemSsa(op) => Box::new(op.operands(&self.function)),
            Block(op) => Box::new(op.operands(&self.function)),
            Call(op) | Tailcall(op) => Box::new(op.operands(&self.function)),
            CallSsa(op) => Box::new(op.operands(&self.function)),
            Case(op) => Box::new(op.operands(&self.function)),
            Const(op) | ConstPtr(op) | Import(op) => Box::new(op.operands()),
            ConstData(op) => Box::new(op.operands(&self.function)),
            Deref(op) | AddressOf(op) | Neg(op) | Not(op) | Sx(op) | Zx(op) | LowPart(op)
            | BoolToInt(op) | UnimplMem(op) | Fsqrt(op) | Fneg(op) | Fabs(op) | FloatToInt(op)
            | IntToFloat(op) | FloatConv(op) | RoundToInt(op) | Floor(op) | Ceil(op)
            | Ftrunc(op) => Box::new(op.operands(&self.function)),
            DerefFieldSsa(op) => Box::new(op.operands(&self.function)),
            DerefSsa(op) => Box::new(op.operands(&self.function)),
            ExternPtr(op) => Box::new(op.operands()),
            FloatConst(op) => Box::new(op.operands()),
            For(op) => Box::new(op.operands(&self.function)),
            ForSsa(op) => Box::new(op.operands(&self.function)),
            Goto(op) | Label(op) => Box::new(op.operands(&self.function)),
            If(op) => Box::new(op.operands(&self.function)),
            Intrinsic(op) => Box::new(op.operands(&self.function)),
            IntrinsicSsa(op) => Box::new(op.operands(&self.function)),
            Jump(op) => Box::new(op.operands(&self.function)),
            MemPhi(op) => Box::new(op.operands(&self.function)),
            Nop(op) | Break(op) | Continue(op) | Noret(op) | Unreachable(op) | Bp(op)
            | Undef(op) | Unimpl(op) => Box::new(op.operands()),
            Ret(op) => Box::new(op.operands(&self.function)),
            Split(op) => Box::new(op.operands(&self.function)),
            StructField(op) | DerefField(op) => Box::new(op.operands(&self.function)),
            Switch(op) => Box::new(op.operands(&self.function)),
            Syscall(op) => Box::new(op.operands(&self.function)),
            SyscallSsa(op) => Box::new(op.operands(&self.function)),
            Trap(op) => Box::new(op.operands()),
            VarDeclare(op) | Var(op) => Box::new(op.operands()),
            VarInit(op) => Box::new(op.operands(&self.function)),
            VarInitSsa(op) => Box::new(op.operands(&self.function)),
            VarPhi(op) => Box::new(op.operands(&self.function)),
            VarSsa(op) => Box::new(op.operands()),
            While(op) | DoWhile(op) => Box::new(op.operands(&self.function)),
            WhileSsa(op) | DoWhileSsa(op) => Box::new(op.operands(&self.function)),
        }
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
