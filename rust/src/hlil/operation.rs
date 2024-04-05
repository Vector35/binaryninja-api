use binaryninjacore_sys::BNGetGotoLabelName;

use crate::function::Function;
use crate::types::{ConstantData, ILIntrinsic, SSAVariable, Variable};

use super::HighLevelILLiftedInstruction;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GotoLabel {
    pub(crate) function: Function,
    pub(crate) target: u64,
}

impl GotoLabel {
    pub fn name(&self) -> &str {
        let raw_str = unsafe { BNGetGotoLabelName(self.function.handle, self.target) };
        let c_str = unsafe { core::ffi::CStr::from_ptr(raw_str) };
        c_str.to_str().unwrap()
    }
}

// ADC, SBB, RLC, RRC
#[derive(Copy, Clone)]
pub struct BinaryOpCarry {
    pub left: usize,
    pub right: usize,
    pub carry: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOpCarry {
    pub left: Box<HighLevelILLiftedInstruction>,
    pub right: Box<HighLevelILLiftedInstruction>,
    pub carry: Box<HighLevelILLiftedInstruction>,
}

// ADD, SUB, AND, OR, XOR, LSL, LSR, ASR, ROL, ROR, MUL, MULU_DP, MULS_DP, DIVU, DIVU_DP, DIVS, DIVS_DP, MODU, MODU_DP, MODS, MODS_DP, CMP_E, CMP_NE, CMP_SLT, CMP_ULT, CMP_SLE, CMP_ULE, CMP_SGE, CMP_UGE, CMP_SGT, CMP_UGT, TEST_BIT, ADD_OVERFLOW, FADD, FSUB, FMUL, FDIV, FCMP_E, FCMP_NE, FCMP_LT, FCMP_LE, FCMP_GE, FCMP_GT, FCMP_O, FCMP_UO
#[derive(Copy, Clone)]
pub struct BinaryOp {
    pub left: usize,
    pub right: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOp {
    pub left: Box<HighLevelILLiftedInstruction>,
    pub right: Box<HighLevelILLiftedInstruction>,
}

// ARRAY_INDEX
#[derive(Copy, Clone)]
pub struct ArrayIndex {
    pub src: usize,
    pub index: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedArrayIndex {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub index: Box<HighLevelILLiftedInstruction>,
}

// ARRAY_INDEX_SSA
#[derive(Copy, Clone)]
pub struct ArrayIndexSsa {
    pub src: usize,
    pub src_memory: u64,
    pub index: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedArrayIndexSsa {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
    pub index: Box<HighLevelILLiftedInstruction>,
}

// ASSIGN
#[derive(Copy, Clone)]
pub struct Assign {
    pub dest: usize,
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssign {
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub src: Box<HighLevelILLiftedInstruction>,
}

// ASSIGN_MEM_SSA
#[derive(Copy, Clone)]
pub struct AssignMemSsa {
    pub dest: usize,
    pub dest_memory: u64,
    pub src: usize,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignMemSsa {
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}

// ASSIGN_UNPACK
#[derive(Copy, Clone)]
pub struct AssignUnpack {
    pub first_dest: usize,
    pub num_dests: usize,
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignUnpack {
    pub dest: Vec<HighLevelILLiftedInstruction>,
    pub src: Box<HighLevelILLiftedInstruction>,
}

// ASSIGN_UNPACK_MEM_SSA
#[derive(Copy, Clone)]
pub struct AssignUnpackMemSsa {
    pub first_dest: usize,
    pub num_dests: usize,
    pub dest_memory: u64,
    pub src: usize,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignUnpackMemSsa {
    pub dest: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}

// BLOCK
#[derive(Copy, Clone)]
pub struct Block {
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBlock {
    pub body: Vec<HighLevelILLiftedInstruction>,
}

// CALL, TAILCALL
#[derive(Copy, Clone)]
pub struct Call {
    pub dest: usize,
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCall {
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub params: Vec<HighLevelILLiftedInstruction>,
}

// CALL_SSA
#[derive(Copy, Clone)]
pub struct CallSsa {
    pub dest: usize,
    pub first_param: usize,
    pub num_params: usize,
    pub dest_memory: u64,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallSsa {
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub params: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
}

// CASE
#[derive(Copy, Clone)]
pub struct Case {
    pub first_value: usize,
    pub num_values: usize,
    pub body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCase {
    pub values: Vec<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}

// CONST, CONST_PTR, IMPORT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Const {
    pub constant: u64,
}

// CONST_DATA
#[derive(Copy, Clone)]
pub struct ConstData {
    pub constant_data_kind: u32,
    pub constant_data_value: i64,
    pub size: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedConstData {
    pub constant_data: ConstantData,
}

// DEREF, ADDRESS_OF, NEG, NOT, SX, ZX, LOW_PART, BOOL_TO_INT, UNIMPL_MEM, FSQRT, FNEG, FABS, FLOAT_TO_INT, INT_TO_FLOAT, FLOAT_CONV, ROUND_TO_INT, FLOOR, CEIL, FTRUNC
#[derive(Copy, Clone)]
pub struct UnaryOp {
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedUnaryOp {
    pub src: Box<HighLevelILLiftedInstruction>,
}

// DEREF_FIELD_SSA
#[derive(Copy, Clone)]
pub struct DerefFieldSsa {
    pub src: usize,
    pub src_memory: u64,
    pub offset: u64,
    pub member_index: Option<usize>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedDerefFieldSsa {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
    pub offset: u64,
    pub member_index: Option<usize>,
}

// DEREF_SSA
#[derive(Copy, Clone)]
pub struct DerefSsa {
    pub src: usize,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedDerefSsa {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}

// EXTERN_PTR
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ExternPtr {
    pub constant: u64,
    pub offset: u64,
}

// FLOAT_CONST
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FloatConst {
    pub constant: f64,
}

// FOR
#[derive(Copy, Clone)]
pub struct ForLoop {
    pub init: usize,
    pub condition: usize,
    pub update: usize,
    pub body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedForLoop {
    pub init: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub update: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}

// FOR_SSA
#[derive(Copy, Clone)]
pub struct ForLoopSsa {
    pub init: usize,
    pub condition_phi: usize,
    pub condition: usize,
    pub update: usize,
    pub body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedForLoopSsa {
    pub init: Box<HighLevelILLiftedInstruction>,
    pub condition_phi: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub update: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}

// GOTO, LABEL
#[derive(Copy, Clone)]
pub struct Label {
    pub target: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedLabel {
    pub target: GotoLabel,
}

// IF
#[derive(Copy, Clone)]
pub struct If {
    pub condition: usize,
    pub cond_true: usize,
    pub cond_false: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIf {
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub cond_true: Box<HighLevelILLiftedInstruction>,
    pub cond_false: Box<HighLevelILLiftedInstruction>,
}

// INTRINSIC
#[derive(Copy, Clone)]
pub struct Intrinsic {
    pub intrinsic: u32,
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsic {
    pub intrinsic: ILIntrinsic,
    pub params: Vec<HighLevelILLiftedInstruction>,
}

// INTRINSIC_SSA
#[derive(Copy, Clone)]
pub struct IntrinsicSsa {
    pub intrinsic: u32,
    pub first_param: usize,
    pub num_params: usize,
    pub dest_memory: u64,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsicSsa {
    pub intrinsic: ILIntrinsic,
    pub params: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
}

// JUMP
#[derive(Copy, Clone)]
pub struct Jump {
    pub dest: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedJump {
    pub dest: Box<HighLevelILLiftedInstruction>,
}

// MEM_PHI
#[derive(Copy, Clone)]
pub struct MemPhi {
    pub dest: u64,
    pub first_src: usize,
    pub num_srcs: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedMemPhi {
    pub dest: u64,
    pub src: Vec<u64>,
}

// RET
#[derive(Copy, Clone)]
pub struct Ret {
    pub first_src: usize,
    pub num_srcs: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedRet {
    pub src: Vec<HighLevelILLiftedInstruction>,
}

// SPLIT
#[derive(Copy, Clone)]
pub struct Split {
    pub high: usize,
    pub low: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSplit {
    pub high: Box<HighLevelILLiftedInstruction>,
    pub low: Box<HighLevelILLiftedInstruction>,
}

// STRUCT_FIELD, DEREF_FIELD
#[derive(Copy, Clone)]
pub struct StructField {
    pub src: usize,
    pub offset: u64,
    pub member_index: Option<usize>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStructField {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub offset: u64,
    pub member_index: Option<usize>,
}

// SWITCH
#[derive(Copy, Clone)]
pub struct Switch {
    pub condition: usize,
    pub default: usize,
    pub first_case: usize,
    pub num_cases: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSwitch {
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub default: Box<HighLevelILLiftedInstruction>,
    pub cases: Vec<HighLevelILLiftedInstruction>,
}

// SYSCALL
#[derive(Copy, Clone)]
pub struct Syscall {
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscall {
    pub params: Vec<HighLevelILLiftedInstruction>,
}

// SYSCALL_SSA
#[derive(Copy, Clone)]
pub struct SyscallSsa {
    pub first_param: usize,
    pub num_params: usize,
    pub dest_memory: u64,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallSsa {
    pub params: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
}

// TRAP
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Trap {
    pub vector: u64,
}

// VAR_DECLARE, VAR
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Var {
    pub var: Variable,
}

// VAR_INIT
#[derive(Copy, Clone)]
pub struct VarInit {
    pub dest: Variable,
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedVarInit {
    pub dest: Variable,
    pub src: Box<HighLevelILLiftedInstruction>,
}

// VAR_INIT_SSA
#[derive(Copy, Clone)]
pub struct VarInitSsa {
    pub dest: SSAVariable,
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedVarInitSsa {
    pub dest: SSAVariable,
    pub src: Box<HighLevelILLiftedInstruction>,
}

// VAR_PHI
#[derive(Copy, Clone)]
pub struct VarPhi {
    pub dest: SSAVariable,
    pub first_src: usize,
    pub num_srcs: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedVarPhi {
    pub dest: SSAVariable,
    pub src: Vec<SSAVariable>,
}

// VAR_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsa {
    pub var: SSAVariable,
}

// WHILE, DO_WHILE
#[derive(Copy, Clone)]
pub struct While {
    pub condition: usize,
    pub body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedWhile {
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}

// WHILE_SSA, DO_WHILE_SSA
#[derive(Copy, Clone)]
pub struct WhileSsa {
    pub condition_phi: usize,
    pub condition: usize,
    pub body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedWhileSsa {
    pub condition_phi: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}
