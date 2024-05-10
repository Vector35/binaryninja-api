use binaryninjacore_sys::BNFromVariableIdentifier;
use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNMediumLevelILInstruction;
use binaryninjacore_sys::BNMediumLevelILOperation;

use crate::operand_iter::OperandIter;
use crate::rc::Ref;
use crate::types::{SSAVariable, Variable};

use super::lift::*;
use super::operation::*;
use super::{
    Form, InstructionLiftedTrait, InstructionTrait, InstructionTraitFromRaw, MediumLevelILFunction,
    Sealed,
};

use strum::IntoStaticStr;

#[derive(Clone)]
pub struct MediumLevelILInstruction<I: Form> {
    pub function: Ref<MediumLevelILFunction<I>>,
    pub address: u64,
    pub index: usize,
    pub size: usize,
    pub kind: I::Instruction,
}

macro_rules! construct_common {
    ($form:ident) => {
        fn from_common_operation(op: BNMediumLevelILInstruction) -> Option<Self> {
            use crate::mlil::operation::*;
            use BNMediumLevelILOperation::*;
            Some(match op.operation {
                MLIL_NOP => Self::Nop,
                MLIL_NORET => Self::Noret,
                MLIL_BP => Self::Bp,
                MLIL_UNDEF => Self::Undef,
                MLIL_UNIMPL => Self::Unimpl,
                MLIL_IF => Self::If(MediumLevelILOperationIf {
                    condition: op.operands[0] as usize,
                    dest_true: op.operands[1],
                    dest_false: op.operands[2],
                }),
                MLIL_FLOAT_CONST => Self::FloatConst(FloatConst {
                    constant: get_float(op.operands[0], op.size),
                }),
                MLIL_CONST => Self::Const(Constant {
                    constant: op.operands[0],
                }),
                MLIL_CONST_PTR => Self::ConstPtr(Constant {
                    constant: op.operands[0],
                }),
                MLIL_IMPORT => Self::Import(Constant {
                    constant: op.operands[0],
                }),
                MLIL_EXTERN_PTR => Self::ExternPtr(ExternPtr {
                    constant: op.operands[0],
                    offset: op.operands[1],
                }),
                MLIL_CONST_DATA => Self::ConstData(ConstData {
                    constant_data_kind: op.operands[0] as u32,
                    constant_data_value: op.operands[1] as i64,
                    size: op.size,
                }),
                MLIL_JUMP => Self::Jump(Jump {
                    dest: op.operands[0] as usize,
                }),
                MLIL_RET_HINT => Self::RetHint(Jump {
                    dest: op.operands[0] as usize,
                }),
                MLIL_JUMP_TO => Self::JumpTo(JumpTo {
                    dest: op.operands[0] as usize,
                    num_operands: op.operands[1] as usize,
                    first_operand: op.operands[2] as usize,
                }),
                MLIL_GOTO => Self::Goto(Goto {
                    dest: op.operands[0],
                }),
                MLIL_MEM_PHI => Self::MemPhi(MemPhi {
                    dest_memory: op.operands[0],
                    num_operands: op.operands[1] as usize,
                    first_operand: op.operands[2] as usize,
                }),
                MLIL_ADD => Self::Add(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_SUB => Self::Sub(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_AND => Self::And(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_OR => Self::Or(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_XOR => Self::Xor(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_LSL => Self::Lsl(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_LSR => Self::Lsr(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_ASR => Self::Asr(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_ROL => Self::Rol(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_ROR => Self::Ror(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_MUL => Self::Mul(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_MULU_DP => Self::MuluDp(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_MULS_DP => Self::MulsDp(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_DIVU => Self::Divu(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_DIVU_DP => Self::DivuDp(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_DIVS => Self::Divs(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_DIVS_DP => Self::DivsDp(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_MODU => Self::Modu(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_MODU_DP => Self::ModuDp(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_MODS => Self::Mods(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_MODS_DP => Self::ModsDp(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_CMP_E => Self::CmpE(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_CMP_NE => Self::CmpNe(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_CMP_SLT => Self::CmpSlt(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_CMP_ULT => Self::CmpUlt(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_CMP_SLE => Self::CmpSle(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_CMP_ULE => Self::CmpUle(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_CMP_SGE => Self::CmpSge(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_CMP_UGE => Self::CmpUge(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_CMP_SGT => Self::CmpSgt(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_CMP_UGT => Self::CmpUgt(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_TEST_BIT => Self::TestBit(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_ADD_OVERFLOW => Self::AddOverflow(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FCMP_E => Self::FcmpE(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FCMP_NE => Self::FcmpNe(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FCMP_LT => Self::FcmpLt(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FCMP_LE => Self::FcmpLe(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FCMP_GE => Self::FcmpGe(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FCMP_GT => Self::FcmpGt(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FCMP_O => Self::FcmpO(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FCMP_UO => Self::FcmpUo(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FADD => Self::Fadd(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FSUB => Self::Fsub(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FMUL => Self::Fmul(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_FDIV => Self::Fdiv(BinaryOp {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                }),
                MLIL_ADC => Self::Adc(BinaryOpCarry {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                    carry: op.operands[2] as usize,
                }),
                MLIL_SBB => Self::Sbb(BinaryOpCarry {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                    carry: op.operands[2] as usize,
                }),
                MLIL_RLC => Self::Rlc(BinaryOpCarry {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                    carry: op.operands[2] as usize,
                }),
                MLIL_RRC => Self::Rrc(BinaryOpCarry {
                    left: op.operands[0] as usize,
                    right: op.operands[1] as usize,
                    carry: op.operands[2] as usize,
                }),
                MLIL_NEG => Self::Neg(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_NOT => Self::Not(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_SX => Self::Sx(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_ZX => Self::Zx(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_LOW_PART => Self::LowPart(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_BOOL_TO_INT => Self::BoolToInt(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_UNIMPL_MEM => Self::UnimplMem(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_FSQRT => Self::Fsqrt(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_FNEG => Self::Fneg(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_FABS => Self::Fabs(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_FLOAT_TO_INT => Self::FloatToInt(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_INT_TO_FLOAT => Self::IntToFloat(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_FLOAT_CONV => Self::FloatConv(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_ROUND_TO_INT => Self::RoundToInt(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_FLOOR => Self::Floor(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_CEIL => Self::Ceil(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_FTRUNC => Self::Ftrunc(UnaryOp {
                    src: op.operands[0] as usize,
                }),
                MLIL_RET => Self::Ret(Ret {
                    num_operands: op.operands[0] as usize,
                    first_operand: op.operands[1] as usize,
                }),
                MLIL_SEPARATE_PARAM_LIST => Self::SeparateParamList(SeparateParamList {
                    num_params: op.operands[0] as usize,
                    first_param: op.operands[1] as usize,
                }),
                MLIL_SHARED_PARAM_SLOT => Self::SharedParamSlot(SharedParamSlot {
                    num_params: op.operands[0] as usize,
                    first_param: op.operands[1] as usize,
                }),
                MLIL_ADDRESS_OF => Self::AddressOf(Var {
                    src: get_var(op.operands[0]),
                }),
                MLIL_ADDRESS_OF_FIELD => Self::AddressOfField(Field {
                    src: get_var(op.operands[0]),
                    offset: op.operands[1],
                }),
                MLIL_TRAP => Self::Trap(Trap {
                    vector: op.operands[0],
                }),
                _ => return None,
            })
        }
    };
}

#[derive(Debug, Copy, Clone, IntoStaticStr)]
pub enum MediumLevelILInstructionKindNonSSA {
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
impl MediumLevelILInstructionKindNonSSA {
    construct_common!(NonSSA);
}
impl MediumLevelILInstructionKindNonSSA {
    fn from_this_operation(op: BNMediumLevelILInstruction) -> Option<Self> {
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

impl InstructionTraitFromRaw for MediumLevelILInstructionKindNonSSA {
    fn from_operation(op: BNMediumLevelILInstruction) -> Option<Self> {
        Self::from_common_operation(op).or_else(|| Self::from_this_operation(op))
    }
}

impl InstructionTrait for MediumLevelILInstructionKindNonSSA {
    fn name(&self) -> &'static str {
        self.into()
    }
}

#[derive(Debug, Copy, Clone, IntoStaticStr)]
pub enum MediumLevelILInstructionKindSSA {
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
impl MediumLevelILInstructionKindSSA {
    construct_common!(SSA);
    fn from_this_operation(op: BNMediumLevelILInstruction) -> Option<Self> {
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
impl InstructionTraitFromRaw for MediumLevelILInstructionKindSSA {
    fn from_operation(op: BNMediumLevelILInstruction) -> Option<Self> {
        Self::from_common_operation(op).or_else(|| Self::from_this_operation(op))
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

impl<I: Form> MediumLevelILInstruction<I> {
    pub(crate) fn new(function: Ref<MediumLevelILFunction<I>>, index: usize) -> Self {
        let op = unsafe { BNGetMediumLevelILByIndex(function.handle, index) };
        let kind =
            <I::Instruction>::from_operation(op).expect("Invalid Medium Level IL Instruction");

        Self {
            function,
            address: op.address,
            index,
            size: op.size,
            kind,
        }
    }
    pub fn lift(&self) -> MediumLevelILLiftedInstruction<I> {
        MediumLevelILLiftedInstruction {
            function: self.function.clone(),
            address: self.address,
            index: self.index,
            size: self.size,
            kind: <I::InstructionLifted>::from_instruction(self),
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
