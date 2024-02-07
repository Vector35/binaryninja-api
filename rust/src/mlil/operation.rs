use std::collections::HashMap;

use binaryninjacore_sys::BNFromVariableIdentifier;
use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNMediumLevelILInstruction;
use binaryninjacore_sys::BNMediumLevelILOperation;

use crate::rc::Ref;
use crate::types;
use crate::types::ILIntrinsic;
use crate::types::RegisterValue;
use crate::types::RegisterValueType;
use crate::types::{SSAVariable, Variable};

use super::{MediumLevelILFunction, MediumLevelILInstruction, MediumLevelILLiftedInstruction};

pub struct OperandIter {
    function: Ref<MediumLevelILFunction>,
    remaining: usize,
    next_iter_idx: Option<usize>,
    current_iter: OperandIterInner,
}

impl OperandIter {
    pub(crate) fn new(function: &MediumLevelILFunction, idx: usize, number: usize) -> Self {
        Self {
            function: function.to_owned(),
            remaining: number,
            next_iter_idx: Some(idx),
            current_iter: OperandIterInner::empty(),
        }
    }

    pub fn as_pairs(self) -> OperandPairIter {
        assert_eq!(self.len() % 2, 0);
        OperandPairIter(self)
    }

    pub fn as_exprs(self) -> OperandExprIter {
        OperandExprIter(self)
    }

    pub fn as_vars(self) -> OperandVarIter {
        OperandVarIter(self)
    }

    pub fn as_ssa_vars(self) -> OperandSSAVarIter {
        OperandSSAVarIter(self.as_pairs())
    }
}

impl Iterator for OperandIter {
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.current_iter.next() {
            self.remaining -= 1;
            Some(item)
        } else {
            // Will short-circuit and return `None` once iter is exhausted
            let iter_idx = self.next_iter_idx?;
            let node = get_raw_operation(&self.function, iter_idx);
            assert_eq!(node.operation, BNMediumLevelILOperation::MLIL_UNDEF);

            let next = if self.remaining > 4 {
                self.next_iter_idx = Some(node.operands[4] as usize);
                &node.operands[..4]
            } else {
                self.next_iter_idx = None;
                &node.operands[..self.remaining]
            };

            self.current_iter = OperandIterInner::from_slice(next);
            self.next()
        }
    }
}
impl ExactSizeIterator for OperandIter {
    fn len(&self) -> usize {
        self.remaining + self.current_iter.len()
    }
}

struct OperandIterInner {
    arr: [u64; 4],
    idx: usize,
}

impl OperandIterInner {
    fn from_slice(slice: &[u64]) -> Self {
        assert!(slice.len() <= 4);
        let idx = 4 - slice.len();
        let mut arr = [0; 4];
        arr[idx..].copy_from_slice(slice);
        Self { arr, idx }
    }

    fn empty() -> Self {
        Self {
            arr: [0; 4],
            idx: 4,
        }
    }
}

impl Iterator for OperandIterInner {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx < 4 {
            let val = self.arr[self.idx];
            self.idx += 1;
            Some(val)
        } else {
            None
        }
    }
}
impl ExactSizeIterator for OperandIterInner {
    fn len(&self) -> usize {
        4 - self.idx
    }
}

pub struct OperandPairIter(OperandIter);
impl Iterator for OperandPairIter {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let first = self.0.next()?;
        let second = self.0.next()?;
        Some((first, second))
    }
}
impl ExactSizeIterator for OperandPairIter {
    fn len(&self) -> usize {
        self.0.len() / 2
    }
}

pub struct OperandExprIter(OperandIter);
impl Iterator for OperandExprIter {
    type Item = MediumLevelILInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|idx| self.0.function.instruction_from_idx(idx as usize))
    }
}
impl ExactSizeIterator for OperandExprIter {
    fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct OperandVarIter(OperandIter);
impl Iterator for OperandVarIter {
    type Item = Variable;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(get_var)
    }
}
impl ExactSizeIterator for OperandVarIter {
    fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct OperandSSAVarIter(OperandPairIter);
impl Iterator for OperandSSAVarIter {
    type Item = SSAVariable;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|(id, version)| get_var_ssa(id, version as usize))
    }
}
impl ExactSizeIterator for OperandSSAVarIter {
    fn len(&self) -> usize {
        self.0.len()
    }
}

pub(super) fn get_float(value: u64, size: usize) -> f64 {
    match size {
        4 => f32::from_bits(value as u32) as f64,
        8 => f64::from_bits(value),
        // TODO how to handle this value?
        size => todo!("float size {}", size),
    }
}

pub(super) fn get_constant_data(
    function: &MediumLevelILFunction,
    state: u32,
    value: i64,
    size: usize,
) -> types::ConstantData {
    types::ConstantData::new(
        function.get_function(),
        RegisterValue::new(
            RegisterValueType::from_raw_value(state).unwrap(),
            value,
            0,
            size,
        ),
    )
}

fn get_raw_operation(function: &MediumLevelILFunction, idx: usize) -> BNMediumLevelILInstruction {
    unsafe { BNGetMediumLevelILByIndex(function.handle, idx) }
}

pub(super) fn get_var(id: u64) -> Variable {
    unsafe { Variable::from_raw(BNFromVariableIdentifier(id)) }
}

pub(super) fn get_var_ssa(id: u64, version: usize) -> SSAVariable {
    SSAVariable::new(get_var(id), version)
}

pub(super) fn get_call_output(function: &MediumLevelILFunction, idx: usize) -> OperandVarIter {
    let op = get_raw_operation(function, idx);
    assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_OUTPUT);
    OperandIter::new(function, op.operands[1] as usize, op.operands[0] as usize).as_vars()
}

pub(super) fn get_call_params(function: &MediumLevelILFunction, idx: usize) -> OperandExprIter {
    let op = get_raw_operation(function, idx);
    assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_PARAM);
    OperandIter::new(function, op.operands[1] as usize, op.operands[0] as usize).as_exprs()
}

pub(super) fn get_call_output_ssa(
    function: &MediumLevelILFunction,
    idx: usize,
) -> OperandSSAVarIter {
    let op = get_raw_operation(function, idx);
    assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_OUTPUT_SSA);
    OperandIter::new(function, op.operands[2] as usize, op.operands[1] as usize).as_ssa_vars()
}

pub(super) fn get_call_params_ssa(function: &MediumLevelILFunction, idx: usize) -> OperandExprIter {
    let op = get_raw_operation(function, idx);
    assert_eq!(op.operation, BNMediumLevelILOperation::MLIL_CALL_PARAM_SSA);
    OperandIter::new(function, op.operands[2] as usize, op.operands[1] as usize).as_exprs()
}

// IF
#[derive(Copy, Clone)]
pub struct MediumLevelILOperationIf {
    pub condition: usize,
    pub dest_true: u64,
    pub dest_false: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIf {
    pub condition: Box<MediumLevelILLiftedInstruction>,
    pub dest_true: u64,
    pub dest_false: u64,
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
#[derive(Copy, Clone)]
pub struct ConstantData {
    pub constant_data_kind: u32,
    pub constant_data_value: i64,
    pub size: usize,
}
#[derive(Clone, Debug, Hash, PartialEq)]
pub struct LiftedConstantData {
    pub constant_data: types::ConstantData,
}

// JUMP, RET_HINT
#[derive(Copy, Clone)]
pub struct Jump {
    pub dest: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedJump {
    pub dest: Box<MediumLevelILLiftedInstruction>,
}

// STORE_SSA
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
pub struct JumpTo {
    pub dest: usize,
    pub first_operand: usize,
    pub num_operands: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedJumpTo {
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub targets: HashMap<u64, u64>,
}

// GOTO
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Goto {
    pub dest: u64,
}

// FREE_VAR_SLOT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct FreeVarSlot {
    pub dest: Variable,
}

// SET_VAR_FIELD
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
pub struct SetVar {
    pub dest: Variable,
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
    pub intrinsic: ILIntrinsic,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}

// INTRINSIC_SSA
#[derive(Copy, Clone)]
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
    pub intrinsic: ILIntrinsic,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}

// CALL_SSA, TAILCALL_SSA
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
pub struct UnaryOp {
    pub src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedUnaryOp {
    pub src: Box<MediumLevelILLiftedInstruction>,
}

// LOAD_STRUCT
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
pub struct Ret {
    pub first_operand: usize,
    pub num_operands: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedRet {
    pub src: Vec<MediumLevelILLiftedInstruction>,
}

// SEPARATE_PARAM_LIST
#[derive(Copy, Clone)]
pub struct SeparateParamList {
    pub first_param: usize,
    pub num_params: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSeparateParamList {
    pub params: Vec<MediumLevelILLiftedInstruction>,
}

// SHARED_PARAM_SLOT
#[derive(Copy, Clone)]
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
