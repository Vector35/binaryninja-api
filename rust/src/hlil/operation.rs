use binaryninjacore_sys::BNFromVariableIdentifier;
use binaryninjacore_sys::BNGetGotoLabelName;

use crate::function::Function;
use crate::rc::Ref;
use crate::types::{ConstantData, ILIntrinsic, SSAVariable, Variable};

use super::HighLevelILLiftedInstruction;

fn get_float(value: u64, size: usize) -> f64 {
    match size {
        4 => f32::from_bits(value as u32) as f64,
        8 => f64::from_bits(value),
        // TODO how to handle this value?
        size => todo!("float size {}", size),
    }
}

fn get_var(id: u64) -> Variable {
    unsafe { Variable::from_raw(BNFromVariableIdentifier(id)) }
}

fn get_member_index(idx: u64) -> Option<usize> {
    (idx as i64 > 0).then_some(idx as usize)
}

fn get_var_ssa(input: (u64, usize)) -> SSAVariable {
    let raw = unsafe { BNFromVariableIdentifier(input.0) };
    let var = unsafe { Variable::from_raw(raw) };
    SSAVariable::new(var, input.1)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GotoLabel {
    pub(crate) function: Ref<Function>,
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
impl BinaryOpCarry {
    pub(crate) fn new(left: usize, right: usize, carry: usize) -> Self {
        Self { left, right, carry }
    }
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
impl BinaryOp {
    pub(crate) fn new(left: usize, right: usize) -> Self {
        Self { left, right }
    }
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
impl ArrayIndex {
    pub(crate) fn new(src: usize, index: usize) -> Self {
        Self { src, index }
    }
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
impl ArrayIndexSsa {
    pub(crate) fn new(src: usize, src_memory: u64, index: usize) -> Self {
        Self {
            src,
            src_memory,
            index,
        }
    }
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
impl Assign {
    pub(crate) fn new(dest: usize, src: usize) -> Self {
        Self { dest, src }
    }
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
impl AssignMemSsa {
    pub(crate) fn new(dest: usize, dest_memory: u64, src: usize, src_memory: u64) -> Self {
        Self {
            dest,
            dest_memory,
            src,
            src_memory,
        }
    }
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
impl AssignUnpack {
    pub(crate) fn new(num_dests: usize, first_dest: usize, src: usize) -> Self {
        Self {
            num_dests,
            first_dest,
            src,
        }
    }
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
impl AssignUnpackMemSsa {
    pub(crate) fn new(
        num_dests: usize,
        first_dest: usize,
        dest_memory: u64,
        src: usize,
        src_memory: u64,
    ) -> Self {
        Self {
            num_dests,
            first_dest,
            dest_memory,
            src,
            src_memory,
        }
    }
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
impl Block {
    pub(crate) fn new(num_params: usize, first_param: usize) -> Self {
        Self {
            num_params,
            first_param,
        }
    }
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
impl Call {
    pub(crate) fn new(dest: usize, num_params: usize, first_param: usize) -> Self {
        Self {
            dest,
            num_params,
            first_param,
        }
    }
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
impl CallSsa {
    pub(crate) fn new(
        dest: usize,
        num_params: usize,
        first_param: usize,
        dest_memory: u64,
        src_memory: u64,
    ) -> Self {
        Self {
            dest,
            num_params,
            first_param,
            dest_memory,
            src_memory,
        }
    }
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
impl Case {
    pub(crate) fn new(num_values: usize, first_value: usize, body: usize) -> Self {
        Self {
            num_values,
            first_value,
            body,
        }
    }
}

// CONST, CONST_PTR, IMPORT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Const {
    pub constant: u64,
}
impl Const {
    pub(crate) fn new(constant: u64) -> Self {
        Self { constant }
    }
}

// CONST_DATA
#[derive(Copy, Clone)]
pub struct ConstData {
    pub constant_data_kind: u32,
    pub constant_data_value: i64,
    pub size: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedConstantData {
    pub constant_data: ConstantData,
}
impl ConstData {
    pub(crate) fn new(constant_data_kind: u32, constant_data_value: i64, size: usize) -> Self {
        Self {
            constant_data_kind,
            constant_data_value,
            size,
        }
    }
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
impl UnaryOp {
    pub(crate) fn new(src: usize) -> Self {
        Self { src }
    }
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
impl DerefFieldSsa {
    pub(crate) fn new(src: usize, src_memory: u64, offset: u64, member_index: u64) -> Self {
        Self {
            src,
            src_memory,
            offset,
            member_index: get_member_index(member_index),
        }
    }
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
impl DerefSsa {
    pub(crate) fn new(src: usize, src_memory: u64) -> Self {
        Self { src, src_memory }
    }
}

// EXTERN_PTR
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ExternPtr {
    pub constant: u64,
    pub offset: u64,
}
impl ExternPtr {
    pub(crate) fn new(constant: u64, offset: u64) -> Self {
        Self { constant, offset }
    }
}

// FLOAT_CONST
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FloatConst {
    pub constant: f64,
}
impl FloatConst {
    pub(crate) fn new(constant: u64, size: usize) -> Self {
        Self {
            constant: get_float(constant, size),
        }
    }
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
impl ForLoop {
    pub(crate) fn new(init: usize, condition: usize, update: usize, body: usize) -> Self {
        Self {
            init,
            condition,
            update,
            body,
        }
    }
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
impl ForLoopSsa {
    pub(crate) fn new(
        init: usize,
        condition_phi: usize,
        condition: usize,
        update: usize,
        body: usize,
    ) -> Self {
        Self {
            init,
            condition_phi,
            condition,
            update,
            body,
        }
    }
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
impl Label {
    pub(crate) fn new(target: u64) -> Self {
        Self { target }
    }
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
impl If {
    pub(crate) fn new(condition: usize, cond_true: usize, cond_false: usize) -> Self {
        Self {
            condition,
            cond_true,
            cond_false,
        }
    }
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
impl Intrinsic {
    pub(crate) fn new(intrinsic: u32, num_params: usize, first_param: usize) -> Self {
        Self {
            intrinsic,
            num_params,
            first_param,
        }
    }
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
impl IntrinsicSsa {
    pub(crate) fn new(
        intrinsic: u32,
        num_params: usize,
        first_param: usize,
        dest_memory: u64,
        src_memory: u64,
    ) -> Self {
        Self {
            intrinsic,
            num_params,
            first_param,
            dest_memory,
            src_memory,
        }
    }
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
impl Jump {
    pub(crate) fn new(dest: usize) -> Self {
        Self { dest }
    }
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
impl MemPhi {
    pub(crate) fn new(dest: u64, num_srcs: usize, first_src: usize) -> Self {
        Self {
            dest,
            num_srcs,
            first_src,
        }
    }
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
impl Ret {
    pub(crate) fn new(num_srcs: usize, first_src: usize) -> Self {
        Self {
            first_src,
            num_srcs,
        }
    }
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
impl Split {
    pub(crate) fn new(high: usize, low: usize) -> Self {
        Self { high, low }
    }
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
impl StructField {
    pub(crate) fn new(src: usize, offset: u64, member_index: u64) -> Self {
        Self {
            src,
            offset,
            member_index: get_member_index(member_index),
        }
    }
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
impl Switch {
    pub(crate) fn new(
        condition: usize,
        default: usize,
        num_cases: usize,
        first_case: usize,
    ) -> Self {
        Self {
            condition,
            default,
            num_cases,
            first_case,
        }
    }
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
impl Syscall {
    pub(crate) fn new(num_params: usize, first_param: usize) -> Self {
        Self {
            num_params,
            first_param,
        }
    }
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
impl SyscallSsa {
    pub(crate) fn new(
        num_params: usize,
        first_param: usize,
        dest_memory: u64,
        src_memory: u64,
    ) -> Self {
        Self {
            num_params,
            first_param,
            dest_memory,
            src_memory,
        }
    }
}

// TRAP
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Trap {
    pub vector: u64,
}
impl Trap {
    pub(crate) fn new(vector: u64) -> Self {
        Self { vector }
    }
}

// VAR_DECLARE, VAR
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Var {
    pub var: Variable,
}
impl Var {
    pub(crate) fn new(var: u64) -> Self {
        Self { var: get_var(var) }
    }
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
impl VarInit {
    pub(crate) fn new(dest: u64, src: usize) -> Self {
        Self {
            dest: get_var(dest),
            src,
        }
    }
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
impl VarInitSsa {
    pub(crate) fn new(dest: (u64, usize), src: usize) -> Self {
        Self {
            dest: get_var_ssa(dest),
            src,
        }
    }
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
impl VarPhi {
    pub(crate) fn new(dest: (u64, usize), num_srcs: usize, first_src: usize) -> Self {
        Self {
            dest: get_var_ssa(dest),
            num_srcs,
            first_src,
        }
    }
}

// VAR_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsa {
    pub var: SSAVariable,
}
impl VarSsa {
    pub(crate) fn new(var: (u64, usize)) -> Self {
        Self {
            var: get_var_ssa(var),
        }
    }
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
impl While {
    pub(crate) fn new(condition: usize, body: usize) -> Self {
        Self { condition, body }
    }
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
impl WhileSsa {
    pub(crate) fn new(condition_phi: usize, condition: usize, body: usize) -> Self {
        Self {
            condition_phi,
            condition,
            body,
        }
    }
}
