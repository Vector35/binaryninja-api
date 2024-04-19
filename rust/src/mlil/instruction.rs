use binaryninjacore_sys::BNFromVariableIdentifier;
use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNMediumLevelILInstruction;
use binaryninjacore_sys::BNMediumLevelILOperation;

use crate::mlil::InstructionLiftedTrait;
use crate::operand_iter::OperandIter;
use crate::rc::Ref;
use crate::types::{SSAVariable, Variable};

use super::lift::*;
use super::operation::*;
use super::Form;
use super::InstructionTrait;
use super::InstructionTraitFromRaw;
use super::MediumLevelILFunction;
use super::Sealed;

use strum::IntoStaticStr;

#[derive(Clone)]
pub struct MediumLevelILInstruction<I: Form> {
    pub function: Ref<MediumLevelILFunction<I>>,
    pub address: u64,
    pub index: usize,
    pub kind: MediumLevelILInstructionKind<I>,
}

#[derive(Debug, Copy, Clone, IntoStaticStr)]
pub enum MediumLevelILInstructionKind<I: Form> {
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
    JumpTo(JumpTo),
    Goto(Goto),
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
    Ret(Ret),

    MemPhi(MemPhi),
    SeparateParamList(SeparateParamList),
    SharedParamSlot(SharedParamSlot),

    AddressOf(Var),
    AddressOfField(Field),
    Trap(Trap),

    Form(I::Instruction),
}

#[derive(Debug, Copy, Clone, IntoStaticStr)]
pub enum MediumLevelILInstructionKindNonSSA {
    Var(Var),
    VarField(Field),
    Store(Store),
    StoreStruct(StoreStruct),
    SetVar(SetVar),
    SetVarField(SetVarField),
    FreeVarSlot(FreeVarSlot),
    VarSplit(VarSplit),
    SetVarSplit(SetVarSplit),
    Call(Call),
    CallUntyped(CallUntyped),
    Tailcall(Call),
    Syscall(Syscall),
    SyscallUntyped(SyscallUntyped),
    Intrinsic(Intrinsic),
    TailcallUntyped(CallUntyped),
    Load(UnaryOp),
    LoadStruct(LoadStruct),
}

impl Sealed for MediumLevelILInstructionKindNonSSA {}
impl InstructionTraitFromRaw for MediumLevelILInstructionKindNonSSA {
    fn from_operation(op: BNMediumLevelILInstruction) -> Option<Self> {
        use crate::mlil::operation::*;
        use BNMediumLevelILOperation::*;
        Some(match op.operation {
            MLIL_STORE_STRUCT => Self::StoreStruct(StoreStruct {
                dest: op.operands[0] as usize,
                offset: op.operands[1],
                src: op.operands[2] as usize,
            }),
            MLIL_STORE => Self::Store(Store {
                dest: op.operands[0] as usize,
                src: op.operands[1] as usize,
            }),
            MLIL_FREE_VAR_SLOT => Self::FreeVarSlot(FreeVarSlot {
                dest: get_var(op.operands[0]),
            }),
            MLIL_SET_VAR_FIELD => Self::SetVarField(SetVarField {
                dest: get_var(op.operands[0]),
                offset: op.operands[1],
                src: op.operands[2] as usize,
            }),
            MLIL_SET_VAR => Self::SetVar(SetVar {
                dest: get_var(op.operands[0]),
                src: op.operands[1] as usize,
            }),
            MLIL_VAR_SPLIT => Self::VarSplit(VarSplit {
                high: get_var(op.operands[0]),
                low: get_var(op.operands[1]),
            }),
            MLIL_SET_VAR_SPLIT => Self::SetVarSplit(SetVarSplit {
                high: get_var(op.operands[0]),
                low: get_var(op.operands[1]),
                src: op.operands[2] as usize,
            }),
            MLIL_CALL => Self::Call(Call {
                num_outputs: op.operands[0] as usize,
                first_output: op.operands[1] as usize,
                dest: op.operands[2] as usize,
                num_params: op.operands[3] as usize,
                first_param: op.operands[4] as usize,
            }),
            MLIL_TAILCALL => Self::Tailcall(Call {
                num_outputs: op.operands[0] as usize,
                first_output: op.operands[1] as usize,
                dest: op.operands[2] as usize,
                num_params: op.operands[3] as usize,
                first_param: op.operands[4] as usize,
            }),
            MLIL_SYSCALL => Self::Syscall(Syscall {
                num_outputs: op.operands[0] as usize,
                first_output: op.operands[1] as usize,
                num_params: op.operands[2] as usize,
                first_param: op.operands[3] as usize,
            }),
            MLIL_INTRINSIC => Self::Intrinsic(Intrinsic {
                num_outputs: op.operands[0] as usize,
                first_output: op.operands[1] as usize,
                intrinsic: op.operands[2] as u32,
                num_params: op.operands[3] as usize,
                first_param: op.operands[4] as usize,
            }),
            MLIL_CALL_UNTYPED => Self::CallUntyped(CallUntyped {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                params: op.operands[2] as usize,
                stack: op.operands[3] as usize,
            }),
            MLIL_TAILCALL_UNTYPED => Self::TailcallUntyped(CallUntyped {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                params: op.operands[2] as usize,
                stack: op.operands[3] as usize,
            }),
            MLIL_SYSCALL_UNTYPED => Self::SyscallUntyped(SyscallUntyped {
                output: op.operands[0] as usize,
                params: op.operands[1] as usize,
                stack: op.operands[2] as usize,
            }),
            MLIL_LOAD => Self::Load(UnaryOp {
                src: op.operands[0] as usize,
            }),
            MLIL_LOAD_STRUCT => Self::LoadStruct(LoadStruct {
                src: op.operands[0] as usize,
                offset: op.operands[1],
            }),
            MLIL_VAR_FIELD => Self::VarField(Field {
                src: get_var(op.operands[0]),
                offset: op.operands[1],
            }),
            _ => return None,
        })
    }
}

impl InstructionTrait for MediumLevelILInstructionKindNonSSA {
    fn name(&self) -> &'static str {
        self.into()
    }
}

#[derive(Debug, Copy, Clone, IntoStaticStr)]
pub enum MediumLevelILInstructionKindSSA {
    VarSsa(VarSsa),
    VarSsaField(VarSsaField),
    StoreSsa(StoreSsa),
    StoreStructSsa(StoreStructSsa),
    SetVarSsa(SetVarSsa),
    SetVarSsaField(SetVarSsaField),
    FreeVarSlotSsa(FreeVarSlotSsa),
    VarSplitSsa(VarSplitSsa),
    SetVarSplitSsa(SetVarSplitSsa),
    CallSsa(CallSsa),
    CallUntypedSsa(CallUntypedSsa),
    TailcallSsa(CallSsa),
    SyscallSsa(SyscallSsa),
    SyscallUntypedSsa(SyscallUntypedSsa),
    IntrinsicSsa(IntrinsicSsa),
    TailcallUntypedSsa(CallUntypedSsa),
    LoadSsa(LoadSsa),
    LoadStructSsa(LoadStructSsa),

    SetVarAliased(SetVarAliased),
    SetVarAliasedField(SetVarSsaField),
    VarPhi(VarPhi),
    VarAliased(VarSsa),
    VarAliasedField(VarSsaField),
}

impl Sealed for MediumLevelILInstructionKindSSA {}
impl InstructionTraitFromRaw for MediumLevelILInstructionKindSSA {
    fn from_operation(op: BNMediumLevelILInstruction) -> Option<Self> {
        use crate::mlil::operation::*;
        use BNMediumLevelILOperation::*;
        Some(match op.operation {
            MLIL_STORE_SSA => Self::StoreSsa(StoreSsa {
                dest: op.operands[0] as usize,
                dest_memory: op.operands[1],
                src_memory: op.operands[2],
                src: op.operands[3] as usize,
            }),
            MLIL_STORE_STRUCT_SSA => Self::StoreStructSsa(StoreStructSsa {
                dest: op.operands[0] as usize,
                offset: op.operands[1],
                dest_memory: op.operands[2],
                src_memory: op.operands[3],
                src: op.operands[4] as usize,
            }),
            MLIL_FREE_VAR_SLOT_SSA => Self::FreeVarSlotSsa(FreeVarSlotSsa {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
            }),
            MLIL_SET_VAR_SSA_FIELD => Self::SetVarSsaField(SetVarSsaField {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
                offset: op.operands[3],
                src: op.operands[4] as usize,
            }),
            MLIL_SET_VAR_ALIASED_FIELD => Self::SetVarAliasedField(SetVarSsaField {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
                offset: op.operands[3],
                src: op.operands[4] as usize,
            }),
            MLIL_SET_VAR_ALIASED => Self::SetVarAliased(SetVarAliased {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                prev: get_var_ssa(op.operands[0], op.operands[2] as usize),
                src: op.operands[3] as usize,
            }),
            MLIL_SET_VAR_SSA => Self::SetVarSsa(SetVarSsa {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                src: op.operands[2] as usize,
            }),
            MLIL_VAR_PHI => Self::VarPhi(VarPhi {
                dest: get_var_ssa(op.operands[0], op.operands[1] as usize),
                num_operands: op.operands[2] as usize,
                first_operand: op.operands[3] as usize,
            }),
            MLIL_VAR_SPLIT_SSA => Self::VarSplitSsa(VarSplitSsa {
                high: get_var_ssa(op.operands[0], op.operands[1] as usize),
                low: get_var_ssa(op.operands[2], op.operands[3] as usize),
            }),
            MLIL_SET_VAR_SPLIT_SSA => Self::SetVarSplitSsa(SetVarSplitSsa {
                high: get_var_ssa(op.operands[0], op.operands[1] as usize),
                low: get_var_ssa(op.operands[2], op.operands[3] as usize),
                src: op.operands[4] as usize,
            }),
            MLIL_INTRINSIC_SSA => Self::IntrinsicSsa(IntrinsicSsa {
                num_outputs: op.operands[0] as usize,
                first_output: op.operands[1] as usize,
                intrinsic: op.operands[2] as u32,
                num_params: op.operands[3] as usize,
                first_param: op.operands[4] as usize,
            }),
            MLIL_CALL_SSA => Self::CallSsa(CallSsa {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                num_params: op.operands[2] as usize,
                first_param: op.operands[3] as usize,
                src_memory: op.operands[4],
            }),
            MLIL_TAILCALL_SSA => Self::TailcallSsa(CallSsa {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                num_params: op.operands[2] as usize,
                first_param: op.operands[3] as usize,
                src_memory: op.operands[4],
            }),
            MLIL_CALL_UNTYPED_SSA => Self::CallUntypedSsa(CallUntypedSsa {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                params: op.operands[2] as usize,
                stack: op.operands[3] as usize,
            }),
            MLIL_TAILCALL_UNTYPED_SSA => Self::TailcallUntypedSsa(CallUntypedSsa {
                output: op.operands[0] as usize,
                dest: op.operands[1] as usize,
                params: op.operands[2] as usize,
                stack: op.operands[3] as usize,
            }),
            MLIL_SYSCALL_SSA => Self::SyscallSsa(SyscallSsa {
                output: op.operands[0] as usize,
                num_params: op.operands[1] as usize,
                first_param: op.operands[2] as usize,
                src_memory: op.operands[3],
            }),
            MLIL_SYSCALL_UNTYPED_SSA => Self::SyscallUntypedSsa(SyscallUntypedSsa {
                output: op.operands[0] as usize,
                params: op.operands[1] as usize,
                stack: op.operands[2] as usize,
            }),
            MLIL_LOAD_STRUCT_SSA => Self::LoadStructSsa(LoadStructSsa {
                src: op.operands[0] as usize,
                offset: op.operands[1],
                src_memory: op.operands[2],
            }),
            MLIL_LOAD_SSA => Self::LoadSsa(LoadSsa {
                src: op.operands[0] as usize,
                src_memory: op.operands[1],
            }),
            MLIL_VAR_SSA => Self::VarSsa(VarSsa {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
            }),
            MLIL_VAR_ALIASED => Self::VarAliased(VarSsa {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
            }),
            MLIL_VAR_SSA_FIELD => Self::VarSsaField(VarSsaField {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
                offset: op.operands[2],
            }),
            MLIL_VAR_ALIASED_FIELD => Self::VarAliasedField(VarSsaField {
                src: get_var_ssa(op.operands[0], op.operands[1] as usize),
                offset: op.operands[2],
            }),
            _ => return None,
        })
    }
}

impl InstructionTrait for MediumLevelILInstructionKindSSA {
    fn name(&self) -> &'static str {
        self.into()
    }
}

impl<I: Form> core::fmt::Debug for MediumLevelILInstruction<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "<{} at 0x{:08}>",
            core::any::type_name::<Self>(),
            self.address,
        )
    }
}

impl<I: Form> MediumLevelILInstructionKind<I> {
    pub(crate) fn from_operation(op: BNMediumLevelILInstruction) -> Option<Self> {
        use crate::mlil::operation::*;
        use BNMediumLevelILOperation::*;
        use MediumLevelILInstructionKind as Op;
        Some(match op.operation {
            MLIL_NOP => Op::Nop,
            MLIL_NORET => Op::Noret,
            MLIL_BP => Op::Bp,
            MLIL_UNDEF => Op::Undef,
            MLIL_UNIMPL => Op::Unimpl,
            MLIL_IF => Op::If(MediumLevelILOperationIf {
                condition: op.operands[0] as usize,
                dest_true: op.operands[1],
                dest_false: op.operands[2],
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
            MLIL_JUMP_TO => Op::JumpTo(JumpTo {
                dest: op.operands[0] as usize,
                num_operands: op.operands[1] as usize,
                first_operand: op.operands[2] as usize,
            }),
            MLIL_GOTO => Op::Goto(Goto {
                dest: op.operands[0],
            }),
            MLIL_MEM_PHI => Op::MemPhi(MemPhi {
                dest_memory: op.operands[0],
                num_operands: op.operands[1] as usize,
                first_operand: op.operands[2] as usize,
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
            MLIL_ADDRESS_OF => Op::AddressOf(Var {
                src: get_var(op.operands[0]),
            }),
            MLIL_ADDRESS_OF_FIELD => Op::AddressOfField(Field {
                src: get_var(op.operands[0]),
                offset: op.operands[1],
            }),
            MLIL_TRAP => Op::Trap(Trap {
                vector: op.operands[0],
            }),
            _ => return I::Instruction::from_operation(op).map(Op::Form),
        })
    }

    pub fn lift(
        &self,
        inst: &MediumLevelILInstruction<I>,
    ) -> MediumLevelILLiftedInstructionKind<I> {
        use MediumLevelILInstructionKind::*;
        use MediumLevelILLiftedInstructionKind as Lifted;
        match self {
            Nop => Lifted::Nop,
            Noret => Lifted::Noret,
            Bp => Lifted::Bp,
            Undef => Lifted::Undef,
            Unimpl => Lifted::Unimpl,
            If(op) => Lifted::If(op.lift(inst)),
            FloatConst(op) => Lifted::FloatConst(*op),
            Const(op) => Lifted::Const(*op),
            ConstPtr(op) => Lifted::ConstPtr(*op),
            Import(op) => Lifted::Import(*op),
            ExternPtr(op) => Lifted::ExternPtr(*op),
            ConstData(op) => Lifted::ConstData(op.lift(inst)),
            Jump(op) => Lifted::Jump(op.lift(inst)),
            RetHint(op) => Lifted::RetHint(op.lift(inst)),
            JumpTo(op) => Lifted::JumpTo(op.lift(inst)),
            Goto(op) => Lifted::Goto(*op),
            Add(op) => Lifted::Add(op.lift(inst)),
            Sub(op) => Lifted::Sub(op.lift(inst)),
            And(op) => Lifted::And(op.lift(inst)),
            Or(op) => Lifted::Or(op.lift(inst)),
            Xor(op) => Lifted::Xor(op.lift(inst)),
            Lsl(op) => Lifted::Lsl(op.lift(inst)),
            Lsr(op) => Lifted::Lsr(op.lift(inst)),
            Asr(op) => Lifted::Asr(op.lift(inst)),
            Rol(op) => Lifted::Rol(op.lift(inst)),
            Ror(op) => Lifted::Ror(op.lift(inst)),
            Mul(op) => Lifted::Mul(op.lift(inst)),
            MuluDp(op) => Lifted::MuluDp(op.lift(inst)),
            MulsDp(op) => Lifted::MulsDp(op.lift(inst)),
            Divu(op) => Lifted::Divu(op.lift(inst)),
            DivuDp(op) => Lifted::DivuDp(op.lift(inst)),
            Divs(op) => Lifted::Divs(op.lift(inst)),
            DivsDp(op) => Lifted::DivsDp(op.lift(inst)),
            Modu(op) => Lifted::Modu(op.lift(inst)),
            ModuDp(op) => Lifted::ModuDp(op.lift(inst)),
            Mods(op) => Lifted::Mods(op.lift(inst)),
            ModsDp(op) => Lifted::ModsDp(op.lift(inst)),
            CmpE(op) => Lifted::CmpE(op.lift(inst)),
            CmpNe(op) => Lifted::CmpNe(op.lift(inst)),
            CmpSlt(op) => Lifted::CmpSlt(op.lift(inst)),
            CmpUlt(op) => Lifted::CmpUlt(op.lift(inst)),
            CmpSle(op) => Lifted::CmpSle(op.lift(inst)),
            CmpUle(op) => Lifted::CmpUle(op.lift(inst)),
            CmpSge(op) => Lifted::CmpSge(op.lift(inst)),
            CmpUge(op) => Lifted::CmpUge(op.lift(inst)),
            CmpSgt(op) => Lifted::CmpSgt(op.lift(inst)),
            CmpUgt(op) => Lifted::CmpUgt(op.lift(inst)),
            TestBit(op) => Lifted::TestBit(op.lift(inst)),
            AddOverflow(op) => Lifted::AddOverflow(op.lift(inst)),
            FcmpE(op) => Lifted::FcmpE(op.lift(inst)),
            FcmpNe(op) => Lifted::FcmpNe(op.lift(inst)),
            FcmpLt(op) => Lifted::FcmpLt(op.lift(inst)),
            FcmpLe(op) => Lifted::FcmpLe(op.lift(inst)),
            FcmpGe(op) => Lifted::FcmpGe(op.lift(inst)),
            FcmpGt(op) => Lifted::FcmpGt(op.lift(inst)),
            FcmpO(op) => Lifted::FcmpO(op.lift(inst)),
            FcmpUo(op) => Lifted::FcmpUo(op.lift(inst)),
            Fadd(op) => Lifted::Fadd(op.lift(inst)),
            Fsub(op) => Lifted::Fsub(op.lift(inst)),
            Fmul(op) => Lifted::Fmul(op.lift(inst)),
            Fdiv(op) => Lifted::Fdiv(op.lift(inst)),
            Adc(op) => Lifted::Adc(op.lift(inst)),
            Sbb(op) => Lifted::Sbb(op.lift(inst)),
            Rlc(op) => Lifted::Rlc(op.lift(inst)),
            Rrc(op) => Lifted::Rrc(op.lift(inst)),
            Neg(op) => Lifted::Neg(op.lift(inst)),
            Not(op) => Lifted::Not(op.lift(inst)),
            Sx(op) => Lifted::Sx(op.lift(inst)),
            Zx(op) => Lifted::Zx(op.lift(inst)),
            LowPart(op) => Lifted::LowPart(op.lift(inst)),
            BoolToInt(op) => Lifted::BoolToInt(op.lift(inst)),
            UnimplMem(op) => Lifted::UnimplMem(op.lift(inst)),
            Fsqrt(op) => Lifted::Fsqrt(op.lift(inst)),
            Fneg(op) => Lifted::Fneg(op.lift(inst)),
            Fabs(op) => Lifted::Fabs(op.lift(inst)),
            FloatToInt(op) => Lifted::FloatToInt(op.lift(inst)),
            IntToFloat(op) => Lifted::IntToFloat(op.lift(inst)),
            FloatConv(op) => Lifted::FloatConv(op.lift(inst)),
            RoundToInt(op) => Lifted::RoundToInt(op.lift(inst)),
            Floor(op) => Lifted::Floor(op.lift(inst)),
            Ceil(op) => Lifted::Ceil(op.lift(inst)),
            Ftrunc(op) => Lifted::Ftrunc(op.lift(inst)),
            Ret(op) => Lifted::Ret(op.lift(inst)),

            MemPhi(op) => Lifted::MemPhi(op.lift(inst)),
            SeparateParamList(op) => Lifted::SeparateParamList(op.lift(inst)),
            SharedParamSlot(op) => Lifted::SharedParamSlot(op.lift(inst)),

            AddressOf(op) => Lifted::AddressOf(*op),
            AddressOfField(op) => Lifted::AddressOfField(*op),
            Trap(op) => Lifted::Trap(*op),

            Form(op) => Lifted::Form(I::InstructionLifted::from_instruction(inst, op)),
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Form(op) => op.name(),
            _ => self.into(),
        }
    }
}

impl<I: Form> MediumLevelILInstruction<I> {
    pub(crate) fn new(function: Ref<MediumLevelILFunction<I>>, index: usize) -> Self {
        let op = unsafe { BNGetMediumLevelILByIndex(function.handle, index) };
        let kind = MediumLevelILInstructionKind::from_operation(op)
            .expect("Invalid Medium Level IL Instruction");

        Self {
            function,
            address: op.address,
            index,
            kind,
        }
    }
    pub fn lift(&self) -> MediumLevelILLiftedInstruction<I> {
        MediumLevelILLiftedInstruction {
            function: self.function.clone(),
            address: self.address,
            index: self.index,
            kind: self.kind.lift(self),
        }
    }
    pub fn name(&self) -> &'static str {
        self.kind.name()
    }
    pub(crate) fn lift_operand(&self, expr_idx: usize) -> Box<MediumLevelILLiftedInstruction<I>> {
        Box::new(self.function.lifted_instruction_from_idx(expr_idx))
    }

    pub(crate) fn get_call_output(&self, idx: usize) -> impl Iterator<Item = Variable> {
        let op = self.get_raw_operation(idx);
        assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_OUTPUT);
        OperandIter::new(
            self.function.as_ref(),
            op.operands[1] as usize,
            op.operands[0] as usize,
        )
        .vars()
    }

    pub(crate) fn get_call_params(
        &self,
        idx: usize,
    ) -> impl Iterator<Item = MediumLevelILInstruction<I>> {
        let op = self.get_raw_operation(idx);
        assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_PARAM);
        OperandIter::new(
            self.function.as_ref(),
            op.operands[1] as usize,
            op.operands[0] as usize,
        )
        .exprs()
    }

    pub(crate) fn get_call_output_ssa(&self, idx: usize) -> impl Iterator<Item = SSAVariable> {
        let op = self.get_raw_operation(idx);
        assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_OUTPUT_SSA);
        OperandIter::new(
            self.function.as_ref(),
            op.operands[2] as usize,
            op.operands[1] as usize,
        )
        .ssa_vars()
    }

    pub(crate) fn get_call_params_ssa(
        &self,
        idx: usize,
    ) -> impl Iterator<Item = MediumLevelILInstruction<I>> {
        let op = self.get_raw_operation(idx);
        assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_PARAM_SSA);
        OperandIter::new(
            self.function.as_ref(),
            op.operands[2] as usize,
            op.operands[1] as usize,
        )
        .exprs()
    }

    pub(crate) fn get_raw_operation(&self, idx: usize) -> BNMediumLevelILInstruction {
        unsafe { BNGetMediumLevelILByIndex(self.function.handle, idx) }
    }
}

pub(crate) fn get_float(value: u64, size: usize) -> f64 {
    match size {
        4 => f32::from_bits(value as u32) as f64,
        8 => f64::from_bits(value),
        // TODO how to handle this value?
        size => todo!("float size {}", size),
    }
}

pub(crate) fn get_var(id: u64) -> Variable {
    unsafe { Variable::from_raw(BNFromVariableIdentifier(id)) }
}

pub(crate) fn get_var_ssa(id: u64, version: usize) -> SSAVariable {
    SSAVariable::new(get_var(id), version)
}
