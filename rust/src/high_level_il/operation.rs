use binaryninjacore_sys::*;
use core::ffi;
use std::fmt::{Debug, Formatter};

use super::{HighLevelExpressionIndex, HighLevelILLiftedInstruction};
use crate::architecture::CoreIntrinsic;
use crate::function::Function;
use crate::rc::Ref;
use crate::string::{BnString, IntoCStr};
use crate::variable::{ConstantData, PossibleValueSet, SSAVariable, Variable};

#[derive(Clone, PartialEq, Eq)]
pub struct GotoLabel {
    pub(crate) function: Ref<Function>,
    pub target: u64,
}

impl GotoLabel {
    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNGetGotoLabelName(self.function.handle, self.target)) }
    }

    fn set_name(&self, name: &str) {
        let raw = name.to_cstr();
        unsafe {
            BNSetUserGotoLabelName(
                self.function.handle,
                self.target,
                raw.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }
}

impl Debug for GotoLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GotoLabel")
            .field("name", &self.name())
            .field("target", &self.target)
            .finish()
    }
}

// BEGIN GENERATED hlil-operations: from api/il, do not edit
// BLOCK
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Block {
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBlock {
    pub body: Vec<HighLevelILLiftedInstruction>,
}

// IF
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct If {
    pub condition: HighLevelExpressionIndex,
    pub cond_true: HighLevelExpressionIndex,
    pub cond_false: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIf {
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub cond_true: Box<HighLevelILLiftedInstruction>,
    pub cond_false: Box<HighLevelILLiftedInstruction>,
}

// WHILE, DO_WHILE
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct While {
    pub condition: HighLevelExpressionIndex,
    pub body: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedWhile {
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}

// FOR
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ForLoop {
    pub init: HighLevelExpressionIndex,
    pub condition: HighLevelExpressionIndex,
    pub update: HighLevelExpressionIndex,
    pub body: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedForLoop {
    pub init: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub update: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}

// SWITCH
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Switch {
    pub condition: HighLevelExpressionIndex,
    pub default: HighLevelExpressionIndex,
    pub first_case: usize,
    pub num_cases: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSwitch {
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub default: Box<HighLevelILLiftedInstruction>,
    pub cases: Vec<HighLevelILLiftedInstruction>,
}

// CASE
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Case {
    pub first_value: usize,
    pub num_values: usize,
    pub body: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCase {
    pub values: Vec<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}

// JUMP
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Jump {
    pub dest: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedJump {
    pub dest: Box<HighLevelILLiftedInstruction>,
}

// RET
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Ret {
    pub first_src: usize,
    pub num_srcs: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedRet {
    pub src: Vec<HighLevelILLiftedInstruction>,
}

// GOTO, LABEL
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Label {
    pub target: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiftedLabel {
    pub target: GotoLabel,
}

// VAR_DECLARE, VAR
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Var {
    pub var: Variable,
}

// VAR_INIT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarInit {
    pub dest: Variable,
    pub src: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedVarInit {
    pub dest: Variable,
    pub src: Box<HighLevelILLiftedInstruction>,
}

// ASSIGN
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Assign {
    pub dest: HighLevelExpressionIndex,
    pub src: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssign {
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub src: Box<HighLevelILLiftedInstruction>,
}

// ASSIGN_UNPACK
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct AssignUnpack {
    pub first_dest: usize,
    pub num_dests: usize,
    pub src: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignUnpack {
    pub dest: Vec<HighLevelILLiftedInstruction>,
    pub src: Box<HighLevelILLiftedInstruction>,
}

// FORCE_VER
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ForceVer {
    pub dest: Variable,
    pub src: Variable,
}

// ASSERT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Assert {
    pub src: Variable,
    pub constraint_index: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiftedAssert {
    pub src: Variable,
    pub constraint: PossibleValueSet,
}

// STRUCT_FIELD, DEREF_FIELD, STRUCT_INIT_FIELD
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct StructField {
    pub src: HighLevelExpressionIndex,
    pub offset: u64,
    pub member_index: Option<usize>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStructField {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub offset: u64,
    pub member_index: Option<usize>,
}

// ARRAY_INDEX
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ArrayIndex {
    pub src: HighLevelExpressionIndex,
    pub index: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedArrayIndex {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub index: Box<HighLevelILLiftedInstruction>,
}

// SPLIT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Split {
    pub high: HighLevelExpressionIndex,
    pub low: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSplit {
    pub high: Box<HighLevelILLiftedInstruction>,
    pub low: Box<HighLevelILLiftedInstruction>,
}

// DEREF, ADDRESS_OF, PASS_BY_REF, RETURN_BY_REF, NEG, NOT, SX, ZX, LOW_PART, BOOL_TO_INT, UNIMPL_MEM, FSQRT, FNEG, FABS, FLOAT_TO_INT, INT_TO_FLOAT, FLOAT_CONV, ROUND_TO_INT, FLOOR, CEIL, FTRUNC, BSWAP, POPCNT, CLZ, CTZ, RBIT, CLS, ABS
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct UnaryOp {
    pub src: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedUnaryOp {
    pub src: Box<HighLevelILLiftedInstruction>,
}

// CONST, CONST_PTR, IMPORT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Const {
    pub constant: u64,
}

// CONST_DATA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ConstData {
    pub constant_data_kind: u32,
    pub constant_data_value: i64,
    pub size: usize,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct LiftedConstData {
    pub constant_data: ConstantData,
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

// ADD, SUB, AND, OR, XOR, LSL, LSR, ASR, ROL, ROR, MUL, MULU_DP, MULS_DP, DIVU, DIVU_DP, DIVS, DIVS_DP, MODU, MODU_DP, MODS, MODS_DP, CMP_E, CMP_NE, CMP_SLT, CMP_ULT, CMP_SLE, CMP_ULE, CMP_SGE, CMP_UGE, CMP_SGT, CMP_UGT, TEST_BIT, ADD_OVERFLOW, FADD, FSUB, FMUL, FDIV, FCMP_E, FCMP_NE, FCMP_LT, FCMP_LE, FCMP_GE, FCMP_GT, FCMP_O, FCMP_UO, MINS, MAXS, MINU, MAXU
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct BinaryOp {
    pub left: HighLevelExpressionIndex,
    pub right: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOp {
    pub left: Box<HighLevelILLiftedInstruction>,
    pub right: Box<HighLevelILLiftedInstruction>,
}

// ADC, SBB, RLC, RRC
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct BinaryOpCarry {
    pub left: HighLevelExpressionIndex,
    pub right: HighLevelExpressionIndex,
    pub carry: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOpCarry {
    pub left: Box<HighLevelILLiftedInstruction>,
    pub right: Box<HighLevelILLiftedInstruction>,
    pub carry: Box<HighLevelILLiftedInstruction>,
}

// CALL, TAILCALL
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Call {
    pub dest: HighLevelExpressionIndex,
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCall {
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub params: Vec<HighLevelILLiftedInstruction>,
}

// SYSCALL
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Syscall {
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscall {
    pub params: Vec<HighLevelILLiftedInstruction>,
}

// INTRINSIC
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Intrinsic {
    pub intrinsic: u32,
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsic {
    pub intrinsic: CoreIntrinsic,
    pub params: Vec<HighLevelILLiftedInstruction>,
}

// TRAP
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Trap {
    pub vector: u64,
}

// STRUCT_INIT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct StructInit {
    pub first_field: usize,
    pub num_fields: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStructInit {
    pub fields: Vec<HighLevelILLiftedInstruction>,
}

// WHILE_SSA, DO_WHILE_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct WhileSsa {
    pub condition_phi: HighLevelExpressionIndex,
    pub condition: HighLevelExpressionIndex,
    pub body: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedWhileSsa {
    pub condition_phi: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}

// FOR_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ForLoopSsa {
    pub init: HighLevelExpressionIndex,
    pub condition_phi: HighLevelExpressionIndex,
    pub condition: HighLevelExpressionIndex,
    pub update: HighLevelExpressionIndex,
    pub body: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedForLoopSsa {
    pub init: Box<HighLevelILLiftedInstruction>,
    pub condition_phi: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub update: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}

// VAR_INIT_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarInitSsa {
    pub dest: SSAVariable,
    pub src: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedVarInitSsa {
    pub dest: SSAVariable,
    pub src: Box<HighLevelILLiftedInstruction>,
}

// ASSIGN_MEM_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct AssignMemSsa {
    pub dest: HighLevelExpressionIndex,
    pub dest_memory: u64,
    pub src: HighLevelExpressionIndex,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignMemSsa {
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}

// ASSIGN_UNPACK_MEM_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct AssignUnpackMemSsa {
    pub first_dest: usize,
    pub num_dests: usize,
    pub dest_memory: u64,
    pub src: HighLevelExpressionIndex,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignUnpackMemSsa {
    pub dest: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}

// FORCE_VER_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ForceVerSsa {
    pub dest: SSAVariable,
    pub src: SSAVariable,
}

// ASSERT_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct AssertSsa {
    pub src: SSAVariable,
    pub constraint_index: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiftedAssertSsa {
    pub src: SSAVariable,
    pub constraint: PossibleValueSet,
}

// VAR_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsa {
    pub var: SSAVariable,
}

// VAR_SSA_PARTIAL
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsaPartial {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
}

// ARRAY_INDEX_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ArrayIndexSsa {
    pub src: HighLevelExpressionIndex,
    pub src_memory: u64,
    pub index: HighLevelExpressionIndex,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedArrayIndexSsa {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
    pub index: Box<HighLevelILLiftedInstruction>,
}

// DEREF_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct DerefSsa {
    pub src: HighLevelExpressionIndex,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedDerefSsa {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}

// DEREF_FIELD_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct DerefFieldSsa {
    pub src: HighLevelExpressionIndex,
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

// CALL_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct CallSsa {
    pub dest: HighLevelExpressionIndex,
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

// SYSCALL_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
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

// INTRINSIC_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct IntrinsicSsa {
    pub intrinsic: u32,
    pub first_param: usize,
    pub num_params: usize,
    pub dest_memory: u64,
    pub src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsicSsa {
    pub intrinsic: CoreIntrinsic,
    pub params: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
}

// VAR_PHI
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarPhi {
    pub dest: SSAVariable,
    pub first_src: usize,
    pub num_srcs: usize,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct LiftedVarPhi {
    pub dest: SSAVariable,
    pub src: Vec<SSAVariable>,
}

// MEM_PHI
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct MemPhi {
    pub dest: u64,
    pub first_src: usize,
    pub num_srcs: usize,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct LiftedMemPhi {
    pub dest: u64,
    pub src: Vec<u64>,
}
// END GENERATED hlil-operations

impl LiftedLabel {
    pub fn name(&self) -> String {
        self.target.name()
    }

    pub fn set_name(&self, name: &str) {
        self.target.set_name(name)
    }
}
