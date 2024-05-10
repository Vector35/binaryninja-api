use std::collections::BTreeMap;

use crate::types::{ConstantData, ILIntrinsic, SSAVariable, Variable};

use super::{Form, MediumLevelILLiftedInstruction, NonSSA, SSA};

// IF
#[derive(Debug, Copy, Clone)]
pub struct MediumLevelILOperationIf {
    pub condition: usize,
    pub dest_true: u64,
    pub dest_false: u64,
}
#[derive(Debug, Clone)]
pub struct LiftedIf<I: Form> {
    pub condition: Box<MediumLevelILLiftedInstruction<I>>,
    pub dest_true: u64,
    pub dest_false: u64,
}

// FLOAT_CONST
#[derive(Debug, Copy, Clone)]
pub struct FloatConst {
    pub constant: f64,
}

// CONST, CONST_PTR, IMPORT
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Constant {
    pub constant: u64,
}

// EXTERN_PTR
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct ExternPtr {
    pub constant: u64,
    pub offset: u64,
}

// CONST_DATA
#[derive(Debug, Copy, Clone)]
pub struct ConstData {
    pub constant_data_kind: u32,
    pub constant_data_value: i64,
    pub size: usize,
}
#[derive(Debug, Clone, Hash)]
pub struct LiftedConstData {
    pub constant_data: ConstantData,
}

// JUMP, RET_HINT
#[derive(Debug, Copy, Clone)]
pub struct Jump {
    pub dest: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedJump<I: Form> {
    pub dest: Box<MediumLevelILLiftedInstruction<I>>,
}

// STORE_SSA
#[derive(Debug, Copy, Clone)]
pub struct StoreSsa {
    pub dest: usize,
    pub dest_memory: u64,
    pub src_memory: u64,
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedStoreSsa {
    pub dest: Box<MediumLevelILLiftedInstruction<SSA>>,
    pub dest_memory: u64,
    pub src_memory: u64,
    pub src: Box<MediumLevelILLiftedInstruction<SSA>>,
}

// STORE_STRUCT_SSA
#[derive(Debug, Copy, Clone)]
pub struct StoreStructSsa {
    pub dest: usize,
    pub offset: u64,
    pub dest_memory: u64,
    pub src_memory: u64,
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedStoreStructSsa {
    pub dest: Box<MediumLevelILLiftedInstruction<SSA>>,
    pub offset: u64,
    pub dest_memory: u64,
    pub src_memory: u64,
    pub src: Box<MediumLevelILLiftedInstruction<SSA>>,
}

// STORE_STRUCT
#[derive(Debug, Copy, Clone)]
pub struct StoreStruct {
    pub dest: usize,
    pub offset: u64,
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedStoreStruct {
    pub dest: Box<MediumLevelILLiftedInstruction<NonSSA>>,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction<NonSSA>>,
}

// STORE
#[derive(Debug, Copy, Clone)]
pub struct Store {
    pub dest: usize,
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedStore {
    pub dest: Box<MediumLevelILLiftedInstruction<NonSSA>>,
    pub src: Box<MediumLevelILLiftedInstruction<NonSSA>>,
}

// JUMP_TO
#[derive(Debug, Copy, Clone)]
pub struct JumpTo {
    pub dest: usize,
    pub first_operand: usize,
    pub num_operands: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedJumpTo<I: Form> {
    pub dest: Box<MediumLevelILLiftedInstruction<I>>,
    pub targets: BTreeMap<u64, u64>,
}

// GOTO
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Goto {
    pub dest: u64,
}

// FREE_VAR_SLOT
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct FreeVarSlot {
    pub dest: Variable,
}

// SET_VAR_FIELD
#[derive(Debug, Copy, Clone)]
pub struct SetVarField {
    pub dest: Variable,
    pub offset: u64,
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSetVarField {
    pub dest: Variable,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction<NonSSA>>,
}

// SET_VAR
#[derive(Debug, Copy, Clone)]
pub struct SetVar {
    pub dest: Variable,
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSetVar {
    pub dest: Variable,
    pub src: Box<MediumLevelILLiftedInstruction<NonSSA>>,
}

// FREE_VAR_SLOT_SSA
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct FreeVarSlotSsa {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
}

// SET_VAR_SSA_FIELD, SET_VAR_ALIASED_FIELD
#[derive(Debug, Copy, Clone)]
pub struct SetVarSsaField {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
    pub offset: u64,
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSetVarSsaField {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction<SSA>>,
}

// SET_VAR_ALIASED
#[derive(Debug, Copy, Clone)]
pub struct SetVarAliased {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSetVarAliased {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction<SSA>>,
}

// SET_VAR_SSA
#[derive(Debug, Copy, Clone)]
pub struct SetVarSsa {
    pub dest: SSAVariable,
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSetVarSsa {
    pub dest: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction<SSA>>,
}

// VAR_PHI
#[derive(Debug, Copy, Clone)]
pub struct VarPhi {
    pub dest: SSAVariable,
    pub first_operand: usize,
    pub num_operands: usize,
}
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct LiftedVarPhi {
    pub dest: SSAVariable,
    pub src: Vec<SSAVariable>,
}

// MEM_PHI
#[derive(Debug, Copy, Clone)]
pub struct MemPhi {
    pub dest_memory: u64,
    pub first_operand: usize,
    pub num_operands: usize,
}
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct LiftedMemPhi {
    pub dest_memory: u64,
    pub src_memory: Vec<u64>,
}

// VAR_SPLIT
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct VarSplit {
    pub high: Variable,
    pub low: Variable,
}

// SET_VAR_SPLIT
#[derive(Debug, Copy, Clone)]
pub struct SetVarSplit {
    pub high: Variable,
    pub low: Variable,
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSetVarSplit {
    pub high: Variable,
    pub low: Variable,
    pub src: Box<MediumLevelILLiftedInstruction<NonSSA>>,
}

// VAR_SPLIT_SSA
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct VarSplitSsa {
    pub high: SSAVariable,
    pub low: SSAVariable,
}

// SET_VAR_SPLIT_SSA
#[derive(Debug, Copy, Clone)]
pub struct SetVarSplitSsa {
    pub high: SSAVariable,
    pub low: SSAVariable,
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSetVarSplitSsa {
    pub high: SSAVariable,
    pub low: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction<SSA>>,
}

// ADD, SUB, AND, OR, XOR, LSL, LSR, ASR, ROL, ROR, MUL, MULU_DP, MULS_DP, DIVU, DIVU_DP, DIVS, DIVS_DP, MODU, MODU_DP, MODS, MODS_DP, CMP_E, CMP_NE, CMP_SLT, CMP_ULT, CMP_SLE, CMP_ULE, CMP_SGE, CMP_UGE, CMP_SGT, CMP_UGT, TEST_BIT, ADD_OVERFLOW, FCMP_E, FCMP_NE, FCMP_LT, FCMP_LE, FCMP_GE, FCMP_GT, FCMP_O, FCMP_UO, FADD, FSUB, FMUL, FDIV
#[derive(Debug, Copy, Clone)]
pub struct BinaryOp {
    pub left: usize,
    pub right: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedBinaryOp<I: Form> {
    pub left: Box<MediumLevelILLiftedInstruction<I>>,
    pub right: Box<MediumLevelILLiftedInstruction<I>>,
}

// ADC, SBB, RLC, RRC
#[derive(Debug, Copy, Clone)]
pub struct BinaryOpCarry {
    pub left: usize,
    pub right: usize,
    pub carry: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedBinaryOpCarry<I: Form> {
    pub left: Box<MediumLevelILLiftedInstruction<I>>,
    pub right: Box<MediumLevelILLiftedInstruction<I>>,
    pub carry: Box<MediumLevelILLiftedInstruction<I>>,
}

// CALL, TAILCALL
#[derive(Debug, Copy, Clone)]
pub struct Call {
    pub first_output: usize,
    pub num_outputs: usize,
    pub dest: usize,
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedCall {
    pub output: Vec<Variable>,
    pub dest: Box<MediumLevelILLiftedInstruction<NonSSA>>,
    pub params: Vec<MediumLevelILLiftedInstruction<NonSSA>>,
}

// SYSCALL
#[derive(Debug, Copy, Clone)]
pub struct Syscall {
    pub first_output: usize,
    pub num_outputs: usize,
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSyscall {
    pub output: Vec<Variable>,
    pub params: Vec<MediumLevelILLiftedInstruction<NonSSA>>,
}

// INTRINSIC
#[derive(Debug, Copy, Clone)]
pub struct Intrinsic {
    pub first_output: usize,
    pub num_outputs: usize,
    pub intrinsic: u32,
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedIntrinsic {
    pub output: Vec<Variable>,
    pub intrinsic: ILIntrinsic,
    pub params: Vec<MediumLevelILLiftedInstruction<NonSSA>>,
}

// INTRINSIC_SSA
#[derive(Debug, Copy, Clone)]
pub struct IntrinsicSsa {
    pub first_output: usize,
    pub num_outputs: usize,
    pub intrinsic: u32,
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedIntrinsicSsa {
    pub output: Vec<SSAVariable>,
    pub intrinsic: ILIntrinsic,
    pub params: Vec<MediumLevelILLiftedInstruction<SSA>>,
}

// CALL_SSA, TAILCALL_SSA
#[derive(Debug, Copy, Clone)]
pub struct CallSsa {
    pub output: usize,
    pub dest: usize,
    pub first_param: usize,
    pub num_params: usize,
    pub src_memory: u64,
}
#[derive(Debug, Clone)]
pub struct LiftedCallSsa {
    pub output: Vec<SSAVariable>,
    pub dest: Box<MediumLevelILLiftedInstruction<SSA>>,
    pub params: Vec<MediumLevelILLiftedInstruction<SSA>>,
    pub src_memory: u64,
}

// CALL_UNTYPED_SSA, TAILCALL_UNTYPED_SSA
#[derive(Debug, Copy, Clone)]
pub struct CallUntypedSsa {
    pub output: usize,
    pub dest: usize,
    pub params: usize,
    pub stack: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedCallUntypedSsa {
    pub output: Vec<SSAVariable>,
    pub dest: Box<MediumLevelILLiftedInstruction<SSA>>,
    pub params: Vec<MediumLevelILLiftedInstruction<SSA>>,
    pub stack: Box<MediumLevelILLiftedInstruction<SSA>>,
}

// SYSCALL_SSA
#[derive(Debug, Copy, Clone)]
pub struct SyscallSsa {
    pub output: usize,
    pub first_param: usize,
    pub num_params: usize,
    pub src_memory: u64,
}
#[derive(Debug, Clone)]
pub struct LiftedSyscallSsa {
    pub output: Vec<SSAVariable>,
    pub params: Vec<MediumLevelILLiftedInstruction<SSA>>,
    pub src_memory: u64,
}

// SYSCALL_UNTYPED_SSA
#[derive(Debug, Copy, Clone)]
pub struct SyscallUntypedSsa {
    pub output: usize,
    pub params: usize,
    pub stack: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSyscallUntypedSsa {
    pub output: Vec<SSAVariable>,
    pub params: Vec<MediumLevelILLiftedInstruction<SSA>>,
    pub stack: Box<MediumLevelILLiftedInstruction<SSA>>,
}

// CALL_UNTYPED, TAILCALL_UNTYPED
#[derive(Debug, Copy, Clone)]
pub struct CallUntyped {
    pub output: usize,
    pub dest: usize,
    pub params: usize,
    pub stack: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedCallUntyped {
    pub output: Vec<Variable>,
    pub dest: Box<MediumLevelILLiftedInstruction<NonSSA>>,
    pub params: Vec<MediumLevelILLiftedInstruction<NonSSA>>,
    pub stack: Box<MediumLevelILLiftedInstruction<NonSSA>>,
}

// SYSCALL_UNTYPED
#[derive(Debug, Copy, Clone)]
pub struct SyscallUntyped {
    pub output: usize,
    pub params: usize,
    pub stack: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSyscallUntyped {
    pub output: Vec<Variable>,
    pub params: Vec<MediumLevelILLiftedInstruction<NonSSA>>,
    pub stack: Box<MediumLevelILLiftedInstruction<NonSSA>>,
}

// NEG, NOT, SX, ZX, LOW_PART, BOOL_TO_INT, UNIMPL_MEM, FSQRT, FNEG, FABS, FLOAT_TO_INT, INT_TO_FLOAT, FLOAT_CONV, ROUND_TO_INT, FLOOR, CEIL, FTRUNC, LOAD
#[derive(Debug, Copy, Clone)]
pub struct UnaryOp {
    pub src: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedUnaryOp<I: Form> {
    pub src: Box<MediumLevelILLiftedInstruction<I>>,
}

// LOAD_STRUCT
#[derive(Debug, Copy, Clone)]
pub struct LoadStruct {
    pub src: usize,
    pub offset: u64,
}
#[derive(Debug, Clone)]
pub struct LiftedLoadStruct {
    pub src: Box<MediumLevelILLiftedInstruction<NonSSA>>,
    pub offset: u64,
}

// LOAD_STRUCT_SSA
#[derive(Debug, Copy, Clone)]
pub struct LoadStructSsa {
    pub src: usize,
    pub offset: u64,
    pub src_memory: u64,
}
#[derive(Debug, Clone)]
pub struct LiftedLoadStructSsa {
    pub src: Box<MediumLevelILLiftedInstruction<SSA>>,
    pub offset: u64,
    pub src_memory: u64,
}

// LOAD_SSA
#[derive(Debug, Copy, Clone)]
pub struct LoadSsa {
    pub src: usize,
    pub src_memory: u64,
}
#[derive(Debug, Clone)]
pub struct LiftedLoadSsa {
    pub src: Box<MediumLevelILLiftedInstruction<SSA>>,
    pub src_memory: u64,
}

// RET
#[derive(Debug, Copy, Clone)]
pub struct Ret {
    pub first_operand: usize,
    pub num_operands: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedRet<I: Form> {
    pub src: Vec<MediumLevelILLiftedInstruction<I>>,
}

// SEPARATE_PARAM_LIST
#[derive(Debug, Copy, Clone)]
pub struct SeparateParamList {
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSeparateParamList<I: Form> {
    pub params: Vec<MediumLevelILLiftedInstruction<I>>,
}

// SHARED_PARAM_SLOT
#[derive(Debug, Copy, Clone)]
pub struct SharedParamSlot {
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Debug, Clone)]
pub struct LiftedSharedParamSlot<I: Form> {
    pub params: Vec<MediumLevelILLiftedInstruction<I>>,
}

// VAR, ADDRESS_OF
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Var {
    pub src: Variable,
}

// VAR_FIELD, ADDRESS_OF_FIELD
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Field {
    pub src: Variable,
    pub offset: u64,
}

// VAR_SSA, VAR_ALIASED
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct VarSsa {
    pub src: SSAVariable,
}

// VAR_SSA_FIELD, VAR_ALIASED_FIELD
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct VarSsaField {
    pub src: SSAVariable,
    pub offset: u64,
}

// TRAP
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Trap {
    pub vector: u64,
}
