use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNMediumLevelILOperation;

use crate::mlil::MediumLevelILLiftedOperation;
use crate::rc::Ref;

use super::operation::*;
use super::{MediumLevelILFunction, MediumLevelILLiftedInstruction};

#[derive(Clone)]
pub struct MediumLevelILInstruction {
    pub(crate) function: Ref<MediumLevelILFunction>,
    pub(crate) address: u64,
    pub(crate) operation: MediumLevelILOperation,
}

#[derive(Copy, Clone)]
pub enum MediumLevelILOperation {
    Nop(NoArgs),
    Noret(NoArgs),
    Bp(NoArgs),
    Undef(NoArgs),
    Unimpl(NoArgs),
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
    pub(crate) fn new(function: &MediumLevelILFunction, idx: usize) -> Self {
        let op = unsafe { BNGetMediumLevelILByIndex(function.handle, idx) };
        use BNMediumLevelILOperation::*;
        use MediumLevelILOperation as Op;
        let info = match op.operation {
            MLIL_NOP => Op::Nop(NoArgs::default()),
            MLIL_NORET => Op::Noret(NoArgs::default()),
            MLIL_BP => Op::Bp(NoArgs::default()),
            MLIL_UNDEF => Op::Undef(NoArgs::default()),
            MLIL_UNIMPL => Op::Unimpl(NoArgs::default()),
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
            MLIL_CONST_DATA => Op::ConstData(ConstData::new((op.operands[0], op.operands[1]))),
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
                (op.operands[1] as usize, op.operands[2] as usize),
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
                (op.operands[2] as usize, op.operands[3] as usize),
            )),
            MLIL_MEM_PHI => Op::MemPhi(MemPhi::new(
                op.operands[0],
                (op.operands[1] as usize, op.operands[2] as usize),
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
                (op.operands[0] as usize, op.operands[1] as usize),
                op.operands[2] as usize,
                (op.operands[3] as usize, op.operands[4] as usize),
            )),
            MLIL_TAILCALL => Op::Tailcall(Call::new(
                (op.operands[0] as usize, op.operands[1] as usize),
                op.operands[2] as usize,
                (op.operands[3] as usize, op.operands[4] as usize),
            )),
            MLIL_SYSCALL => Op::Syscall(Syscall::new(
                (op.operands[0] as usize, op.operands[1] as usize),
                (op.operands[2] as usize, op.operands[3] as usize),
            )),
            MLIL_INTRINSIC => Op::Intrinsic(Intrinsic::new(
                (op.operands[0] as usize, op.operands[1] as usize),
                op.operands[2] as usize,
                (op.operands[3] as usize, op.operands[4] as usize),
            )),
            MLIL_INTRINSIC_SSA => Op::IntrinsicSsa(IntrinsicSsa::new(
                (op.operands[0] as usize, op.operands[1] as usize),
                op.operands[2] as usize,
                (op.operands[3] as usize, op.operands[4] as usize),
            )),
            MLIL_CALL_SSA => Op::CallSsa(CallSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                (op.operands[2] as usize, op.operands[3] as usize),
                op.operands[4],
            )),
            MLIL_TAILCALL_SSA => Op::TailcallSsa(CallSsa::new(
                op.operands[0] as usize,
                op.operands[1] as usize,
                (op.operands[2] as usize, op.operands[3] as usize),
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
                (op.operands[1] as usize, op.operands[2] as usize),
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
            MLIL_SEPARATE_PARAM_LIST => Op::SeparateParamList(SeparateParamList::new(
                (op.operands[0] as usize, op.operands[1] as usize)
            )),
            MLIL_SHARED_PARAM_SLOT => Op::SharedParamSlot(SharedParamSlot::new(
                (op.operands[0] as usize, op.operands[1] as usize)
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
            MLIL_RET => Op::Ret(Ret::new((op.operands[0] as usize, op.operands[1] as usize))),
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
            function: function.to_owned(),
            address: op.address,
            operation: info,
        }
    }

    pub fn function(&self) -> &MediumLevelILFunction {
        &self.function
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn operation(&self) -> &MediumLevelILOperation {
        &self.operation
    }

    pub fn lift(&self) -> MediumLevelILLiftedInstruction {
        use MediumLevelILLiftedOperation as Lifted;
        use MediumLevelILOperation::*;

        let operation = match self.operation {
            Nop(op) => Lifted::Nop(op),
            Noret(op) => Lifted::Noret(op),
            Bp(op) => Lifted::Bp(op),
            Undef(op) => Lifted::Undef(op),
            Unimpl(op) => Lifted::Unimpl(op),
            If(op) => Lifted::If(op.lift(&self.function)),
            FloatConst(op) => Lifted::FloatConst(op),
            Const(op) => Lifted::Const(op),
            ConstPtr(op) => Lifted::ConstPtr(op),
            Import(op) => Lifted::Import(op),
            ExternPtr(op) => Lifted::ExternPtr(op),
            ConstData(op) => Lifted::ConstData(op.lift(&self.function)),
            Jump(op) => Lifted::Jump(op.lift(&self.function)),
            RetHint(op) => Lifted::RetHint(op.lift(&self.function)),
            StoreSsa(op) => Lifted::StoreSsa(op.lift(&self.function)),
            StoreStructSsa(op) => Lifted::StoreStructSsa(op.lift(&self.function)),
            StoreStruct(op) => Lifted::StoreStruct(op.lift(&self.function)),
            Store(op) => Lifted::Store(op.lift(&self.function)),
            JumpTo(op) => Lifted::JumpTo(op.lift(&self.function)),
            Goto(op) => Lifted::Goto(op),
            FreeVarSlot(op) => Lifted::FreeVarSlot(op),
            SetVarField(op) => Lifted::SetVarField(op.lift(&self.function)),
            SetVar(op) => Lifted::SetVar(op.lift(&self.function)),
            FreeVarSlotSsa(op) => Lifted::FreeVarSlotSsa(op.lift()),
            SetVarSsaField(op) => Lifted::SetVarSsaField(op.lift(&self.function)),
            SetVarAliasedField(op) => Lifted::SetVarAliasedField(op.lift(&self.function)),
            SetVarAliased(op) => Lifted::SetVarAliased(op.lift(&self.function)),
            SetVarSsa(op) => Lifted::SetVarSsa(op.lift(&self.function)),
            VarPhi(op) => Lifted::VarPhi(op.lift(&self.function)),
            MemPhi(op) => Lifted::MemPhi(op.lift(&self.function)),
            VarSplit(op) => Lifted::VarSplit(op.lift()),
            SetVarSplit(op) => Lifted::SetVarSplit(op.lift(&self.function)),
            VarSplitSsa(op) => Lifted::VarSplitSsa(op.lift()),
            SetVarSplitSsa(op) => Lifted::SetVarSplitSsa(op.lift(&self.function)),
            Add(op) => Lifted::Add(op.lift(&self.function)),
            Sub(op) => Lifted::Sub(op.lift(&self.function)),
            And(op) => Lifted::And(op.lift(&self.function)),
            Or(op) => Lifted::Or(op.lift(&self.function)),
            Xor(op) => Lifted::Xor(op.lift(&self.function)),
            Lsl(op) => Lifted::Lsl(op.lift(&self.function)),
            Lsr(op) => Lifted::Lsr(op.lift(&self.function)),
            Asr(op) => Lifted::Asr(op.lift(&self.function)),
            Rol(op) => Lifted::Rol(op.lift(&self.function)),
            Ror(op) => Lifted::Ror(op.lift(&self.function)),
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
            AddOverflow(op) => Lifted::AddOverflow(op.lift(&self.function)),
            FcmpE(op) => Lifted::FcmpE(op.lift(&self.function)),
            FcmpNe(op) => Lifted::FcmpNe(op.lift(&self.function)),
            FcmpLt(op) => Lifted::FcmpLt(op.lift(&self.function)),
            FcmpLe(op) => Lifted::FcmpLe(op.lift(&self.function)),
            FcmpGe(op) => Lifted::FcmpGe(op.lift(&self.function)),
            FcmpGt(op) => Lifted::FcmpGt(op.lift(&self.function)),
            FcmpO(op) => Lifted::FcmpO(op.lift(&self.function)),
            FcmpUo(op) => Lifted::FcmpUo(op.lift(&self.function)),
            Fadd(op) => Lifted::Fadd(op.lift(&self.function)),
            Fsub(op) => Lifted::Fsub(op.lift(&self.function)),
            Fmul(op) => Lifted::Fmul(op.lift(&self.function)),
            Fdiv(op) => Lifted::Fdiv(op.lift(&self.function)),
            Adc(op) => Lifted::Adc(op.lift(&self.function)),
            Sbb(op) => Lifted::Sbb(op.lift(&self.function)),
            Rlc(op) => Lifted::Rlc(op.lift(&self.function)),
            Rrc(op) => Lifted::Rrc(op.lift(&self.function)),
            Call(op) => Lifted::Call(op.lift(&self.function)),
            Tailcall(op) => Lifted::Tailcall(op.lift(&self.function)),
            Intrinsic(op) => Lifted::Intrinsic(op.lift(&self.function)),
            Syscall(op) => Lifted::Syscall(op.lift(&self.function)),
            IntrinsicSsa(op) => Lifted::IntrinsicSsa(op.lift(&self.function)),
            CallSsa(op) => Lifted::CallSsa(op.lift(&self.function)),
            TailcallSsa(op) => Lifted::TailcallSsa(op.lift(&self.function)),
            CallUntypedSsa(op) => Lifted::CallUntypedSsa(op.lift(&self.function)),
            TailcallUntypedSsa(op) => Lifted::TailcallUntypedSsa(op.lift(&self.function)),
            SyscallSsa(op) => Lifted::SyscallSsa(op.lift(&self.function)),
            SyscallUntypedSsa(op) => Lifted::SyscallUntypedSsa(op.lift(&self.function)),
            CallUntyped(op) => Lifted::CallUntyped(op.lift(&self.function)),
            TailcallUntyped(op) => Lifted::TailcallUntyped(op.lift(&self.function)),
            SyscallUntyped(op) => Lifted::SyscallUntyped(op.lift(&self.function)),
            SeparateParamList(op) => Lifted::SeparateParamList(op.lift(&self.function)),
            SharedParamSlot(op) => Lifted::SharedParamSlot(op.lift(&self.function)),
            Neg(op) => Lifted::Neg(op.lift(&self.function)),
            Not(op) => Lifted::Not(op.lift(&self.function)),
            Sx(op) => Lifted::Sx(op.lift(&self.function)),
            Zx(op) => Lifted::Zx(op.lift(&self.function)),
            LowPart(op) => Lifted::LowPart(op.lift(&self.function)),
            BoolToInt(op) => Lifted::BoolToInt(op.lift(&self.function)),
            UnimplMem(op) => Lifted::UnimplMem(op.lift(&self.function)),
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
            Load(op) => Lifted::Load(op.lift(&self.function)),
            LoadStruct(op) => Lifted::LoadStruct(op.lift(&self.function)),
            LoadStructSsa(op) => Lifted::LoadStructSsa(op.lift(&self.function)),
            LoadSsa(op) => Lifted::LoadSsa(op.lift(&self.function)),
            Ret(op) => Lifted::Ret(op.lift(&self.function)),
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
            address: self.address,
            operation,
        }
    }

    pub fn operands(&self) -> Box<dyn Iterator<Item = (&'static str, MediumLevelILOperand)>> {
        use MediumLevelILOperation::*;
        match &self.operation {
            Nop(_op) | Noret(_op) | Bp(_op) | Undef(_op) | Unimpl(_op) => Box::new([].into_iter()),
            If(op) => Box::new(op.operands(&self.function)),
            FloatConst(op) => Box::new(op.operands()),
            Const(op) | ConstPtr(op) | Import(op) => Box::new(op.operands()),
            ExternPtr(op) => Box::new(op.operands(&self.function)),
            ConstData(op) => Box::new(op.operands(&self.function)),
            Jump(op) | RetHint(op) => Box::new(op.operands(&self.function)),
            StoreSsa(op) => Box::new(op.operands(&self.function)),
            StoreStructSsa(op) => Box::new(op.operands(&self.function)),
            StoreStruct(op) => Box::new(op.operands(&self.function)),
            Store(op) => Box::new(op.operands(&self.function)),
            JumpTo(op) => Box::new(op.operands(&self.function)),
            Goto(op) => Box::new(op.operands()),
            FreeVarSlot(op) => Box::new(op.operands()),
            SetVarField(op) => Box::new(op.operands(&self.function)),
            SetVar(op) => Box::new(op.operands(&self.function)),
            FreeVarSlotSsa(op) => Box::new(op.operands()),
            SetVarSsaField(op) | SetVarAliasedField(op) => Box::new(op.operands(&self.function)),
            SetVarAliased(op) => Box::new(op.operands(&self.function)),
            SetVarSsa(op) => Box::new(op.operands(&self.function)),
            VarPhi(op) => Box::new(op.operands(&self.function)),
            MemPhi(op) => Box::new(op.operands(&self.function)),
            VarSplit(op) => Box::new(op.operands()),
            SetVarSplit(op) => Box::new(op.operands(&self.function)),
            VarSplitSsa(op) => Box::new(op.operands()),
            SetVarSplitSsa(op) => Box::new(op.operands(&self.function)),
            Add(op) | Sub(op) | And(op) | Or(op) | Xor(op) | Lsl(op) | Lsr(op) | Asr(op)
            | Rol(op) | Ror(op) | Mul(op) | MuluDp(op) | MulsDp(op) | Divu(op) | DivuDp(op)
            | Divs(op) | DivsDp(op) | Modu(op) | ModuDp(op) | Mods(op) | ModsDp(op) | CmpE(op)
            | CmpNe(op) | CmpSlt(op) | CmpUlt(op) | CmpSle(op) | CmpUle(op) | CmpSge(op)
            | CmpUge(op) | CmpSgt(op) | CmpUgt(op) | TestBit(op) | AddOverflow(op) | FcmpE(op)
            | FcmpNe(op) | FcmpLt(op) | FcmpLe(op) | FcmpGe(op) | FcmpGt(op) | FcmpO(op)
            | FcmpUo(op) | Fadd(op) | Fsub(op) | Fmul(op) | Fdiv(op) => {
                Box::new(op.operands(&self.function))
            }
            Adc(op) | Sbb(op) | Rlc(op) | Rrc(op) => Box::new(op.operands(&self.function)),
            Call(op) | Tailcall(op) => Box::new(op.operands(&self.function)),
            Syscall(op) => Box::new(op.operands(&self.function)),
            Intrinsic(op) => Box::new(op.operands(&self.function)),
            IntrinsicSsa(op) => Box::new(op.operands(&self.function)),
            CallSsa(op) | TailcallSsa(op) => Box::new(op.operands(&self.function)),
            CallUntypedSsa(op) | TailcallUntypedSsa(op) => Box::new(op.operands(&self.function)),
            SyscallSsa(op) => Box::new(op.operands(&self.function)),
            SyscallUntypedSsa(op) => Box::new(op.operands(&self.function)),
            CallUntyped(op) | TailcallUntyped(op) => Box::new(op.operands(&self.function)),
            SyscallUntyped(op) => Box::new(op.operands(&self.function)),
            SeparateParamList(op) => Box::new(op.operands(&self.function)),
            SharedParamSlot(op) => Box::new(op.operands(&self.function)),
            Neg(op) | Not(op) | Sx(op) | Zx(op) | LowPart(op) | BoolToInt(op) | UnimplMem(op)
            | Fsqrt(op) | Fneg(op) | Fabs(op) | FloatToInt(op) | IntToFloat(op) | FloatConv(op)
            | RoundToInt(op) | Floor(op) | Ceil(op) | Ftrunc(op) | Load(op) => {
                Box::new(op.operands(&self.function))
            }
            LoadStruct(op) => Box::new(op.operands(&self.function)),
            LoadStructSsa(op) => Box::new(op.operands(&self.function)),
            LoadSsa(op) => Box::new(op.operands(&self.function)),
            Ret(op) => Box::new(op.operands(&self.function)),
            Var(op) | AddressOf(op) => Box::new(op.operands()),
            VarField(op) | AddressOfField(op) => Box::new(op.operands()),
            VarSsa(op) | VarAliased(op) => Box::new(op.operands()),
            VarSsaField(op) | VarAliasedField(op) => Box::new(op.operands()),
            Trap(op) => Box::new(op.operands()),
        }
    }
}
