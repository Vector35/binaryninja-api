use super::{MediumLevelILLiftedInstruction, MediumLevelInstructionIndex};
use crate::architecture::CoreIntrinsic;
use crate::variable::{ConstantData, SSAVariable, Variable};
use std::collections::BTreeMap;

// IF
#[derive(Debug, Copy, Clone)]
pub struct MediumLevelILOperationIf {
    pub condition: usize,
    pub dest_true: MediumLevelInstructionIndex,
    pub dest_false: MediumLevelInstructionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIf {
    pub condition: Box<MediumLevelILLiftedInstruction>,
    pub dest_true: MediumLevelInstructionIndex,
    pub dest_false: MediumLevelInstructionIndex,
}

// FLOAT_CONST
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FloatConst {
    pub constant: f64,
}

// CONST, CONST_PTR, IMPORT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Constant {
    pub constant: u64,
}

// EXTERN_PTR
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, Hash, PartialEq)]
pub struct LiftedConstData {
    pub constant_data: ConstantData,
}

// JUMP, RET_HINT
#[derive(Debug, Copy, Clone)]
pub struct Jump {
    pub dest: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedJump {
    pub dest: Box<MediumLevelILLiftedInstruction>,
}

// STORE_SSA
#[derive(Debug, Copy, Clone)]
pub struct StoreSsa {
    pub dest: usize,
    pub dest_memory: u64,
    pub src_memory: u64,
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStoreSsa {
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
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
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStoreStructSsa {
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
    pub dest_memory: u64,
    pub src_memory: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// STORE_STRUCT
#[derive(Debug, Copy, Clone)]
pub struct StoreStruct {
    pub dest: usize,
    pub offset: u64,
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStoreStruct {
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// STORE
#[derive(Debug, Copy, Clone)]
pub struct Store {
    pub dest: usize,
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStore {
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// JUMP_TO
#[derive(Debug, Copy, Clone)]
pub struct JumpTo {
    pub dest: usize,
    pub first_operand: usize,
    pub num_operands: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedJumpTo {
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub targets: BTreeMap<u64, MediumLevelInstructionIndex>,
}

// GOTO
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Goto {
    pub dest: MediumLevelInstructionIndex,
}

// FREE_VAR_SLOT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarField {
    pub dest: Variable,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// SET_VAR
#[derive(Debug, Copy, Clone)]
pub struct SetVar {
    pub dest: Variable,
    // TODO: Expression?
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVar {
    pub dest: Variable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// FREE_VAR_SLOT_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSsaField {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// SET_VAR_ALIASED
#[derive(Debug, Copy, Clone)]
pub struct SetVarAliased {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarAliased {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// SET_VAR_SSA
#[derive(Debug, Copy, Clone)]
pub struct SetVarSsa {
    pub dest: SSAVariable,
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSsa {
    pub dest: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// VAR_PHI
#[derive(Debug, Copy, Clone)]
pub struct VarPhi {
    pub dest: SSAVariable,
    pub first_operand: usize,
    pub num_operands: usize,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct LiftedMemPhi {
    pub dest_memory: u64,
    pub src_memory: Vec<u64>,
}

// VAR_SPLIT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSplit {
    pub high: Variable,
    pub low: Variable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// VAR_SPLIT_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSplitSsa {
    pub high: SSAVariable,
    pub low: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// ADD, SUB, AND, OR, XOR, LSL, LSR, ASR, ROL, ROR, MUL, MULU_DP, MULS_DP, DIVU, DIVU_DP, DIVS, DIVS_DP, MODU, MODU_DP, MODS, MODS_DP, CMP_E, CMP_NE, CMP_SLT, CMP_ULT, CMP_SLE, CMP_ULE, CMP_SGE, CMP_UGE, CMP_SGT, CMP_UGT, TEST_BIT, ADD_OVERFLOW, FCMP_E, FCMP_NE, FCMP_LT, FCMP_LE, FCMP_GE, FCMP_GT, FCMP_O, FCMP_UO, FADD, FSUB, FMUL, FDIV
#[derive(Debug, Copy, Clone)]
pub struct BinaryOp {
    pub left: usize,
    pub right: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOp {
    pub left: Box<MediumLevelILLiftedInstruction>,
    pub right: Box<MediumLevelILLiftedInstruction>,
}

// ADC, SBB, RLC, RRC
#[derive(Debug, Copy, Clone)]
pub struct BinaryOpCarry {
    pub left: usize,
    pub right: usize,
    pub carry: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOpCarry {
    pub left: Box<MediumLevelILLiftedInstruction>,
    pub right: Box<MediumLevelILLiftedInstruction>,
    pub carry: Box<MediumLevelILLiftedInstruction>,
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
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCall {
    pub output: Vec<Variable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}

// SYSCALL
#[derive(Debug, Copy, Clone)]
pub struct Syscall {
    pub first_output: usize,
    pub num_outputs: usize,
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallCall {
    pub output: Vec<Variable>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
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
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsic {
    pub output: Vec<Variable>,
    pub intrinsic: CoreIntrinsic,
    pub params: Vec<MediumLevelILLiftedInstruction>,
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
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsicSsa {
    pub output: Vec<SSAVariable>,
    pub intrinsic: CoreIntrinsic,
    pub params: Vec<MediumLevelILLiftedInstruction>,
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
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallSsa {
    pub output: Vec<SSAVariable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
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
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallUntypedSsa {
    pub output: Vec<SSAVariable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}

// SYSCALL_SSA
#[derive(Debug, Copy, Clone)]
pub struct SyscallSsa {
    pub output: usize,
    pub first_param: usize,
    pub num_params: usize,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallSsa {
    pub output: Vec<SSAVariable>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub src_memory: u64,
}

// SYSCALL_UNTYPED_SSA
#[derive(Debug, Copy, Clone)]
pub struct SyscallUntypedSsa {
    pub output: usize,
    pub params: usize,
    pub stack: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallUntypedSsa {
    pub output: Vec<SSAVariable>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}

// CALL_UNTYPED, TAILCALL_UNTYPED
#[derive(Debug, Copy, Clone)]
pub struct CallUntyped {
    pub output: usize,
    pub dest: usize,
    pub params: usize,
    pub stack: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallUntyped {
    pub output: Vec<Variable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}

// SYSCALL_UNTYPED
#[derive(Debug, Copy, Clone)]
pub struct SyscallUntyped {
    pub output: usize,
    pub params: usize,
    pub stack: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallUntyped {
    pub output: Vec<Variable>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}

// NEG, NOT, SX, ZX, LOW_PART, BOOL_TO_INT, UNIMPL_MEM, FSQRT, FNEG, FABS, FLOAT_TO_INT, INT_TO_FLOAT, FLOAT_CONV, ROUND_TO_INT, FLOOR, CEIL, FTRUNC, LOAD
#[derive(Debug, Copy, Clone)]
pub struct UnaryOp {
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedUnaryOp {
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// LOAD_STRUCT
#[derive(Debug, Copy, Clone)]
pub struct LoadStruct {
    pub src: usize,
    pub offset: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedLoadStruct {
    pub src: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
}

// LOAD_STRUCT_SSA
#[derive(Debug, Copy, Clone)]
pub struct LoadStructSsa {
    pub src: usize,
    pub offset: u64,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedLoadStructSsa {
    pub src: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
    pub src_memory: u64,
}

// LOAD_SSA
#[derive(Debug, Copy, Clone)]
pub struct LoadSsa {
    pub src: usize,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedLoadSsa {
    pub src: Box<MediumLevelILLiftedInstruction>,
    pub src_memory: u64,
}

// RET
#[derive(Debug, Copy, Clone)]
pub struct Ret {
    pub first_operand: usize,
    pub num_operands: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedRet {
    pub src: Vec<MediumLevelILLiftedInstruction>,
}

// SEPARATE_PARAM_LIST
#[derive(Debug, Copy, Clone)]
pub struct SeparateParamList {
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSeparateParamList {
    pub params: Vec<MediumLevelILLiftedInstruction>,
}

// SHARED_PARAM_SLOT
#[derive(Debug, Copy, Clone)]
pub struct SharedParamSlot {
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSharedParamSlot {
    pub params: Vec<MediumLevelILLiftedInstruction>,
}

// VAR, ADDRESS_OF
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Var {
    pub src: Variable,
}

// VAR_FIELD, ADDRESS_OF_FIELD
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Field {
    pub src: Variable,
    pub offset: u64,
}

// VAR_SSA, VAR_ALIASED
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsa {
    pub src: SSAVariable,
}

// VAR_SSA_FIELD, VAR_ALIASED_FIELD
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsaField {
    pub src: SSAVariable,
    pub offset: u64,
}

// TRAP
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Trap {
    pub vector: u64,
}
