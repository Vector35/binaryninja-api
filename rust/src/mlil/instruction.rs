use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNMediumLevelILOperation;

use crate::rc::Ref;
use crate::types::ILIntrinsic;

use super::lift::*;
use super::operation::*;
use super::MediumLevelILFunction;

#[derive(Clone)]
pub struct MediumLevelILInstruction {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub kind: MediumLevelILInstructionKind,
}

#[derive(Copy, Clone)]
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
    ConstData(ConstantData),
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

impl core::fmt::Debug for MediumLevelILInstruction {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "<{} at 0x{:08}>",
            core::any::type_name::<Self>(),
            self.address,
        )
    }
}

impl MediumLevelILInstruction {
    pub(crate) fn new(function: Ref<MediumLevelILFunction>, idx: usize) -> Self {
        let op = unsafe { BNGetMediumLevelILByIndex(function.handle, idx) };
        use BNMediumLevelILOperation::*;
        use MediumLevelILInstructionKind as Op;
        let kind = match op.operation {
            MLIL_NOP => Op::Nop,
            MLIL_NORET => Op::Noret,
            MLIL_BP => Op::Bp,
            MLIL_UNDEF => Op::Undef,
            MLIL_UNIMPL => Op::Unimpl,
            MLIL_IF => Op::If(MediumLevelILOperationIf::new(
                op.operands[0] as usize,
                op.operands[1],
                op.operands[2],
            )),
            MLIL_FLOAT_CONST => Op::FloatConst(FloatConst::new(op.operands[0], op.size)),
            MLIL_CONST => Op::Const(Constant::new(op.operands[0])),
            MLIL_CONST_PTR => Op::ConstPtr(Constant::new(op.operands[0])),
            MLIL_IMPORT => Op::Import(Constant::new(op.operands[0])),
            MLIL_EXTERN_PTR => Op::ExternPtr(ExternPtr::new(op.operands[0], op.operands[1])),
            MLIL_CONST_DATA => Op::ConstData(ConstantData::new(
                op.operands[0] as u32,
                op.operands[1] as i64,
                op.size,
            )),
            MLIL_JUMP => Op::Jump(Jump::new(op.operands[0] as usize)),
            MLIL_RET_HINT => Op::RetHint(Jump::new(op.operands[0] as usize)),
            MLIL_STORE_SSA => Op::StoreSsa(StoreSsa::new(
                op.operands[0] as usize,
                op.operands[1],
                op.operands[2],
                op.operands[3] as usize,
            )),
            MLIL_STORE_STRUCT_SSA => Op::StoreStructSsa(StoreStructSsa::new(
                op.operands[0] as usize,
                op.operands[1],
                op.operands[2],
                op.operands[3],
                op.operands[4] as usize,
            )),
            MLIL_STORE_STRUCT => Op::StoreStruct(StoreStruct::new(
                op.operands[0] as usize,
                op.operands[1],
                op.operands[2] as usize,
            )),
            MLIL_STORE => Op::Store(Store::new(op.operands[0] as usize, op.operands[1] as usize)),
            MLIL_JUMP_TO => Op::JumpTo(JumpTo::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            MLIL_GOTO => Op::Goto(Goto::new(op.operands[0])),
            MLIL_FREE_VAR_SLOT => Op::FreeVarSlot(FreeVarSlot::new(op.operands[0])),
            MLIL_SET_VAR_FIELD => Op::SetVarField(SetVarField::new(
                op.operands[0],
                op.operands[1],
                op.operands[2] as usize,
            )),
            MLIL_SET_VAR => Op::SetVar(SetVar::new(op.operands[0], op.operands[1] as usize)),
            MLIL_FREE_VAR_SLOT_SSA => Op::FreeVarSlotSsa(FreeVarSlotSsa::new(
                (op.operands[0], op.operands[1] as usize),
                (op.operands[0], op.operands[2] as usize),
            )),
            MLIL_SET_VAR_SSA_FIELD => Op::SetVarSsaField(SetVarSsaField::new(
                (op.operands[0], op.operands[1] as usize),
                (op.operands[0], op.operands[2] as usize),
                op.operands[3],
                op.operands[4] as usize,
            )),
            MLIL_SET_VAR_ALIASED_FIELD => Op::SetVarAliasedField(SetVarSsaField::new(
                (op.operands[0], op.operands[1] as usize),
                (op.operands[0], op.operands[2] as usize),
                op.operands[3],
                op.operands[4] as usize,
            )),
            MLIL_SET_VAR_ALIASED => Op::SetVarAliased(SetVarAliased::new(
                (op.operands[0], op.operands[1] as usize),
                (op.operands[0], op.operands[2] as usize),
                op.operands[3] as usize,
            )),
            MLIL_SET_VAR_SSA => Op::SetVarSsa(SetVarSsa::new(
                (op.operands[0], op.operands[1] as usize),
                op.operands[2] as usize,
            )),
            MLIL_VAR_PHI => Op::VarPhi(VarPhi::new(
                (op.operands[0], op.operands[1] as usize),
                op.operands[2] as usize,
                op.operands[3] as usize,
            )),
            MLIL_MEM_PHI => Op::MemPhi(MemPhi::new(
                op.operands[0],
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            MLIL_VAR_SPLIT => Op::VarSplit(VarSplit::new(op.operands[0], op.operands[1])),
            MLIL_SET_VAR_SPLIT => Op::SetVarSplit(SetVarSplit::new(
                op.operands[0],
                op.operands[1],
                op.operands[2] as usize,
            )),
            MLIL_VAR_SPLIT_SSA => Op::VarSplitSsa(VarSplitSsa::new(
                (op.operands[0], op.operands[1] as usize),
                (op.operands[2], op.operands[3] as usize),
            )),
            MLIL_SET_VAR_SPLIT_SSA => Op::SetVarSplitSsa(SetVarSplitSsa::new(
                (op.operands[0], op.operands[1] as usize),
                (op.operands[2], op.operands[3] as usize),
                op.operands[4] as usize,
            )),
            MLIL_ADD => Op::Add(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_SUB => Op::Sub(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_AND => Op::And(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_OR => Op::Or(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_XOR => Op::Xor(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_LSL => Op::Lsl(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_LSR => Op::Lsr(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_ASR => Op::Asr(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_ROL => Op::Rol(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_ROR => Op::Ror(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_MUL => Op::Mul(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_MULU_DP => Op::MuluDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_MULS_DP => Op::MulsDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_DIVU => Op::Divu(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_DIVU_DP => Op::DivuDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_DIVS => Op::Divs(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_DIVS_DP => Op::DivsDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_MODU => Op::Modu(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_MODU_DP => Op::ModuDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_MODS => Op::Mods(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_MODS_DP => Op::ModsDp(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_CMP_E => Op::CmpE(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_CMP_NE => Op::CmpNe(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_CMP_SLT => Op::CmpSlt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_CMP_ULT => Op::CmpUlt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_CMP_SLE => Op::CmpSle(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_CMP_ULE => Op::CmpUle(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_CMP_SGE => Op::CmpSge(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_CMP_UGE => Op::CmpUge(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_CMP_SGT => Op::CmpSgt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_CMP_UGT => Op::CmpUgt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_TEST_BIT => Op::TestBit(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_ADD_OVERFLOW => Op::AddOverflow(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FCMP_E => Op::FcmpE(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FCMP_NE => Op::FcmpNe(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FCMP_LT => Op::FcmpLt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FCMP_LE => Op::FcmpLe(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FCMP_GE => Op::FcmpGe(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FCMP_GT => Op::FcmpGt(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FCMP_O => Op::FcmpO(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FCMP_UO => Op::FcmpUo(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FADD => Op::Fadd(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FSUB => Op::Fsub(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FMUL => Op::Fmul(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_FDIV => Op::Fdiv(BinaryOp::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_ADC => Op::Adc(BinaryOpCarry::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            MLIL_SBB => Op::Sbb(BinaryOpCarry::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            MLIL_RLC => Op::Rlc(BinaryOpCarry::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            MLIL_RRC => Op::Rrc(BinaryOpCarry::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            MLIL_CALL => Op::Call(Call::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
                op.operands[4] as usize,
            )),
            MLIL_TAILCALL => Op::Tailcall(Call::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
                op.operands[4] as usize,
            )),
            MLIL_SYSCALL => Op::Syscall(Syscall::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
            )),
            MLIL_INTRINSIC => Op::Intrinsic(Intrinsic::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as u32,
                op.operands[3] as usize,
                op.operands[4] as usize,
            )),
            MLIL_INTRINSIC_SSA => Op::IntrinsicSsa(IntrinsicSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as u32,
                op.operands[3] as usize,
                op.operands[4] as usize,
            )),
            MLIL_CALL_SSA => Op::CallSsa(CallSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
                op.operands[4],
            )),
            MLIL_TAILCALL_SSA => Op::TailcallSsa(CallSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
                op.operands[4],
            )),
            MLIL_CALL_UNTYPED_SSA => Op::CallUntypedSsa(CallUntypedSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
            )),
            MLIL_TAILCALL_UNTYPED_SSA => Op::TailcallUntypedSsa(CallUntypedSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
            )),
            MLIL_SYSCALL_SSA => Op::SyscallSsa(SyscallSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3],
            )),
            MLIL_SYSCALL_UNTYPED_SSA => Op::SyscallUntypedSsa(SyscallUntypedSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            MLIL_CALL_UNTYPED => Op::CallUntyped(CallUntyped::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
            )),
            MLIL_TAILCALL_UNTYPED => Op::TailcallUntyped(CallUntyped::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
                op.operands[3] as usize,
            )),
            MLIL_SYSCALL_UNTYPED => Op::SyscallUntyped(SyscallUntyped::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                op.operands[2] as usize,
            )),
            MLIL_NEG => Op::Neg(UnaryOp::new(op.operands[0] as usize)),
            MLIL_NOT => Op::Not(UnaryOp::new(op.operands[0] as usize)),
            MLIL_SX => Op::Sx(UnaryOp::new(op.operands[0] as usize)),
            MLIL_ZX => Op::Zx(UnaryOp::new(op.operands[0] as usize)),
            MLIL_LOW_PART => Op::LowPart(UnaryOp::new(op.operands[0] as usize)),
            MLIL_BOOL_TO_INT => Op::BoolToInt(UnaryOp::new(op.operands[0] as usize)),
            MLIL_UNIMPL_MEM => Op::UnimplMem(UnaryOp::new(op.operands[0] as usize)),
            MLIL_FSQRT => Op::Fsqrt(UnaryOp::new(op.operands[0] as usize)),
            MLIL_FNEG => Op::Fneg(UnaryOp::new(op.operands[0] as usize)),
            MLIL_FABS => Op::Fabs(UnaryOp::new(op.operands[0] as usize)),
            MLIL_FLOAT_TO_INT => Op::FloatToInt(UnaryOp::new(op.operands[0] as usize)),
            MLIL_INT_TO_FLOAT => Op::IntToFloat(UnaryOp::new(op.operands[0] as usize)),
            MLIL_FLOAT_CONV => Op::FloatConv(UnaryOp::new(op.operands[0] as usize)),
            MLIL_ROUND_TO_INT => Op::RoundToInt(UnaryOp::new(op.operands[0] as usize)),
            MLIL_FLOOR => Op::Floor(UnaryOp::new(op.operands[0] as usize)),
            MLIL_CEIL => Op::Ceil(UnaryOp::new(op.operands[0] as usize)),
            MLIL_FTRUNC => Op::Ftrunc(UnaryOp::new(op.operands[0] as usize)),
            MLIL_LOAD => Op::Load(UnaryOp::new(op.operands[0] as usize)),
            MLIL_LOAD_STRUCT => {
                Op::LoadStruct(LoadStruct::new(op.operands[0] as usize, op.operands[1]))
            }
            MLIL_LOAD_STRUCT_SSA => Op::LoadStructSsa(LoadStructSsa::new(
                op.operands[0] as usize,
                op.operands[1],
                op.operands[2],
            )),
            MLIL_LOAD_SSA => Op::LoadSsa(LoadSsa::new(op.operands[0] as usize, op.operands[1])),
            MLIL_RET => Op::Ret(Ret::new(op.operands[0] as usize, op.operands[1] as usize)),
            MLIL_SEPARATE_PARAM_LIST => Op::SeparateParamList(SeparateParamList::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_SHARED_PARAM_SLOT => Op::SharedParamSlot(SharedParamSlot::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
            )),
            MLIL_VAR => Op::Var(Var::new(op.operands[0])),
            MLIL_ADDRESS_OF => Op::AddressOf(Var::new(op.operands[0])),
            MLIL_VAR_FIELD => Op::VarField(Field::new(op.operands[0], op.operands[1])),
            MLIL_ADDRESS_OF_FIELD => Op::AddressOfField(Field::new(op.operands[0], op.operands[1])),
            MLIL_VAR_SSA => Op::VarSsa(VarSsa::new((op.operands[0], op.operands[1] as usize))),
            MLIL_VAR_ALIASED => {
                Op::VarAliased(VarSsa::new((op.operands[0], op.operands[1] as usize)))
            }
            MLIL_VAR_SSA_FIELD => Op::VarSsaField(VarSsaField::new(
                (op.operands[0], op.operands[1] as usize),
                op.operands[2],
            )),
            MLIL_VAR_ALIASED_FIELD => Op::VarAliasedField(VarSsaField::new(
                (op.operands[0], op.operands[1] as usize),
                op.operands[2],
            )),
            MLIL_TRAP => Op::Trap(Trap::new(op.operands[0])),
            // translated directly into a list for Expression or Variables
            MLIL_CALL_OUTPUT | MLIL_CALL_PARAM | MLIL_CALL_PARAM_SSA | MLIL_CALL_OUTPUT_SSA => {
                unreachable!()
            }
        };

        Self {
            function,
            address: op.address,
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

            ConstData(op) => Lifted::ConstData(LiftedConstantData {
                constant_data: get_constant_data(
                    &self.function,
                    op.constant_data_kind,
                    op.constant_data_value,
                    op.size,
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
                targets: OperandIter::new(&self.function, op.first_operand, op.num_operands)
                    .as_pairs()
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
                src: OperandIter::new(&self.function, op.first_operand, op.num_operands)
                    .as_ssa_vars()
                    .collect(),
            }),
            MemPhi(op) => Lifted::MemPhi(LiftedMemPhi {
                dest_memory: op.dest_memory,
                src_memory: OperandIter::new(&self.function, op.first_operand, op.num_operands)
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
                output: OperandIter::new(&self.function, op.first_output, op.num_outputs)
                    .as_vars()
                    .collect(),
                intrinsic: ILIntrinsic::new(self.function.get_function().arch(), op.intrinsic),
                params: OperandIter::new(&self.function, op.first_param, op.num_params)
                    .as_exprs()
                    .map(|expr| expr.lift())
                    .collect(),
            }),
            Syscall(op) => Lifted::Syscall(LiftedSyscallCall {
                output: OperandIter::new(&self.function, op.first_output, op.num_outputs)
                    .as_vars()
                    .collect(),
                params: OperandIter::new(&self.function, op.first_param, op.num_params)
                    .as_exprs()
                    .map(|expr| expr.lift())
                    .collect(),
            }),
            IntrinsicSsa(op) => Lifted::IntrinsicSsa(LiftedIntrinsicSsa {
                output: OperandIter::new(&self.function, op.first_output, op.num_outputs)
                    .as_ssa_vars()
                    .collect(),
                intrinsic: ILIntrinsic::new(self.function.get_function().arch(), op.intrinsic),
                params: OperandIter::new(&self.function, op.first_param, op.num_params)
                    .as_exprs()
                    .map(|expr| expr.lift())
                    .collect(),
            }),

            CallSsa(op) => Lifted::CallSsa(self.lift_call_ssa(op)),
            TailcallSsa(op) => Lifted::TailcallSsa(self.lift_call_ssa(op)),

            CallUntypedSsa(op) => Lifted::CallUntypedSsa(self.lift_call_untyped_ssa(op)),
            TailcallUntypedSsa(op) => Lifted::TailcallUntypedSsa(self.lift_call_untyped_ssa(op)),

            SyscallSsa(op) => Lifted::SyscallSsa(LiftedSyscallSsa {
                output: get_call_output_ssa(&self.function, op.output).collect(),
                params: OperandIter::new(&self.function, op.first_param, op.num_params)
                    .as_exprs()
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
                src: OperandIter::new(&self.function, op.first_operand, op.num_operands)
                    .as_exprs()
                    .map(|expr| expr.lift())
                    .collect(),
            }),
            SeparateParamList(op) => Lifted::SeparateParamList(LiftedSeparateParamList {
                params: OperandIter::new(&self.function, op.first_param, op.num_params)
                    .as_exprs()
                    .map(|expr| expr.lift())
                    .collect(),
            }),
            SharedParamSlot(op) => Lifted::SharedParamSlot(LiftedSharedParamSlot {
                params: OperandIter::new(&self.function, op.first_param, op.num_params)
                    .as_exprs()
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
            kind,
        }
    }

    fn lift_operand(&self, expr_idx: usize) -> Box<MediumLevelILLiftedInstruction> {
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

    fn lift_call(&self, op: Call) -> LiftedCall {
        LiftedCall {
            output: OperandIter::new(&self.function, op.first_output, op.num_outputs)
                .as_vars()
                .collect(),
            dest: self.lift_operand(op.dest),
            params: OperandIter::new(&self.function, op.first_param, op.num_params)
                .as_exprs()
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
            params: OperandIter::new(&self.function, op.first_param, op.num_params)
                .as_exprs()
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
