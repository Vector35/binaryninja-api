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

pub enum MediumLevelILOperand {
    ConstantData(types::ConstantData),
    Intrinsic(ILIntrinsic),
    Expr(MediumLevelILInstruction),
    ExprList(OperandExprList),
    Float(f64),
    Int(u64),
    IntList(OperandList),
    TargetMap(OperandDubleList),
    Var(Variable),
    VarList(OperandVariableList),
    VarSsa(SSAVariable),
    VarSsaList(OperandSSAVariableList),
}

// Iterator for the get_list, this is better then a inline iterator because
// this also implement ExactSizeIterator, what a inline iterator does not.
pub struct OperandList {
    function: Ref<MediumLevelILFunction>,
    remaining: usize,
    next_node_idx: Option<usize>,

    current_node: core::array::IntoIter<u64, 4>,
}
impl OperandList {
    fn new(function: &MediumLevelILFunction, idx: usize, number: usize) -> Self {
        // alternative to core::array::IntoIter::empty();
        let mut iter = [0; 4].into_iter();
        for _ in 0..4 {
            let _ = iter.next();
        }
        Self {
            function: function.to_owned(),
            remaining: number,
            next_node_idx: Some(idx),
            current_node: iter,
        }
    }
    fn duble(self) -> OperandDubleList {
        assert_eq!(self.len() % 2, 0);
        OperandDubleList(self)
    }
    fn map_expr(self) -> OperandExprList {
        OperandExprList(self)
    }
    fn map_var(self) -> OperandVariableList {
        OperandVariableList(self)
    }
    fn map_ssa_var(self) -> OperandSSAVariableList {
        OperandSSAVariableList(self.duble())
    }
}
impl Iterator for OperandList {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        // if there is an item in this node, return it
        if let Some(current_node) = self.current_node.next() {
            return Some(current_node);
        }

        // no more items to fetch
        if self.remaining == 0 {
            return None;
        }

        // otherwise get the next node
        let next_idx = self.next_node_idx?;
        let node = unsafe { BNGetMediumLevelILByIndex(self.function.handle, next_idx) };
        assert_eq!(node.operation, BNMediumLevelILOperation::MLIL_UNDEF);

        // each node contains at most 4, the last is reserved to next node idx
        let consume = if self.remaining > 4 {
            // there are more nodes after this one
            self.next_node_idx = Some(node.operands[4] as usize);
            self.remaining -= 4;
            &node.operands[0..4]
        } else {
            // last part of the list, there is no next node
            self.next_node_idx = None;
            let nodes = &node.operands[0..self.remaining];
            self.remaining = 0;
            nodes
        };
        // the iter need to have a space of 4, but we may have less then that,
        // solution is create a dummy elements at the start and discard it
        let mut nodes = [0; 4];
        let dummy_values = 4 - consume.len();
        nodes[dummy_values..4].copy_from_slice(consume);
        self.current_node = nodes.into_iter();
        for _ in 0..dummy_values {
            let _ = self.current_node.next();
        }

        self.current_node.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}
impl ExactSizeIterator for OperandList {
    fn len(&self) -> usize {
        self.remaining + self.current_node.len()
    }
}

// Iterator similar to OperationList, but returns two elements
pub struct OperandDubleList(OperandList);
impl Iterator for OperandDubleList {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let first = self.0.next()?;
        let second = self.0.next().unwrap();
        Some((first, second))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}
impl ExactSizeIterator for OperandDubleList {
    fn len(&self) -> usize {
        self.0.len() / 2
    }
}

pub struct OperandExprList(OperandList);
impl Iterator for OperandExprList {
    type Item = MediumLevelILInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|idx| get_operation(&self.0.function, idx as usize))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.0.len(), Some(self.0.len()))
    }
}
impl ExactSizeIterator for OperandExprList {
    fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct OperandVariableList(OperandList);
impl Iterator for OperandVariableList {
    type Item = Variable;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(get_var)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.0.len(), Some(self.0.len()))
    }
}
impl ExactSizeIterator for OperandVariableList {
    fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct OperandSSAVariableList(OperandDubleList);
impl Iterator for OperandSSAVariableList {
    type Item = SSAVariable;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(id, version)| {
            let raw = unsafe { BNFromVariableIdentifier(id) };
            let var = unsafe { Variable::from_raw(raw) };
            SSAVariable::new(var, version as usize)
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}
impl ExactSizeIterator for OperandSSAVariableList {
    fn len(&self) -> usize {
        self.0.len()
    }
}

fn get_float(value: u64, size: usize) -> f64 {
    match size {
        4 => f32::from_bits(value as u32) as f64,
        8 => f64::from_bits(value),
        // TODO how to handle this value?
        size => todo!("float size {}", size),
    }
}

fn get_constant_data(
    function: &MediumLevelILFunction,
    state: u64,
    value: u64,
    size: usize,
) -> types::ConstantData {
    types::ConstantData::new(
        function.get_function(),
        RegisterValue::new(
            RegisterValueType::from_raw_value(state as u32).unwrap(),
            value as i64,
            0,
            size,
        ),
    )
}

fn get_intrinsic(function: &MediumLevelILFunction, idx: u32) -> ILIntrinsic {
    ILIntrinsic::new(function.get_function().arch(), idx)
}

fn get_operation(function: &MediumLevelILFunction, idx: usize) -> MediumLevelILInstruction {
    function.instruction_from_idx(idx)
}

fn get_raw_operation(function: &MediumLevelILFunction, idx: usize) -> BNMediumLevelILInstruction {
    unsafe { BNGetMediumLevelILByIndex(function.handle, idx) }
}

fn get_var(id: u64) -> Variable {
    unsafe { Variable::from_raw(BNFromVariableIdentifier(id)) }
}

fn get_var_ssa(id: u64, version: usize) -> SSAVariable {
    let raw = unsafe { BNFromVariableIdentifier(id) };
    let var = unsafe { Variable::from_raw(raw) };
    SSAVariable::new(var, version)
}

fn get_call_list(
    function: &MediumLevelILFunction,
    op_type: BNMediumLevelILOperation,
    idx: usize,
) -> OperandVariableList {
    let op = unsafe { BNGetMediumLevelILByIndex(function.handle, idx) };
    assert_eq!(op.operation, op_type);
    OperandList::new(function, op.operands[1] as usize, op.operands[0] as usize).map_var()
}

fn get_call_exprs(
    function: &MediumLevelILFunction,
    op_type: BNMediumLevelILOperation,
    idx: usize,
) -> OperandExprList {
    let op = unsafe { BNGetMediumLevelILByIndex(function.handle, idx) };
    assert_eq!(op.operation, op_type);
    OperandList::new(function, op.operands[1] as usize, op.operands[0] as usize).map_expr()
}

fn get_call_output(function: &MediumLevelILFunction, idx: usize) -> OperandVariableList {
    get_call_list(function, BNMediumLevelILOperation::MLIL_CALL_OUTPUT, idx)
}

fn get_call_params(function: &MediumLevelILFunction, idx: usize) -> OperandExprList {
    get_call_exprs(function, BNMediumLevelILOperation::MLIL_CALL_PARAM, idx)
}

fn get_call_list_ssa(
    function: &MediumLevelILFunction,
    op_type: BNMediumLevelILOperation,
    idx: usize,
) -> OperandSSAVariableList {
    let op = get_raw_operation(function, idx);
    assert_eq!(op.operation, op_type);
    OperandList::new(function, op.operands[2] as usize, op.operands[1] as usize).map_ssa_var()
}

fn get_call_exprs_ssa(
    function: &MediumLevelILFunction,
    op_type: BNMediumLevelILOperation,
    idx: usize,
) -> OperandExprList {
    let op = get_raw_operation(function, idx);
    assert_eq!(op.operation, op_type);
    OperandList::new(function, op.operands[2] as usize, op.operands[1] as usize).map_expr()
}

fn get_call_output_ssa(function: &MediumLevelILFunction, idx: usize) -> OperandSSAVariableList {
    get_call_list_ssa(
        function,
        BNMediumLevelILOperation::MLIL_CALL_OUTPUT_SSA,
        idx,
    )
}

fn get_call_params_ssa(function: &MediumLevelILFunction, idx: usize) -> OperandExprList {
    get_call_exprs_ssa(function, BNMediumLevelILOperation::MLIL_CALL_PARAM_SSA, idx)
}

// NOP, NORET, BP, UNDEF, UNIMPL
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct NoArgs {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
}

impl NoArgs {
    pub(crate) fn new(function: Ref<MediumLevelILFunction>, address: u64) -> Self {
        Self { function, address }
    }
    // NOTE self is not required, it's present just in case data is added to
    // the struct in the future
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [].into_iter()
    }
}

// IF
#[derive(Clone)]
pub struct MediumLevelILOperationIf {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    condition: usize,
    dest_true: u64,
    dest_false: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIf {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub condition: Box<MediumLevelILLiftedInstruction>,
    pub dest_true: u64,
    pub dest_false: u64,
}
impl MediumLevelILOperationIf {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        condition: usize,
        dest_true: u64,
        dest_false: u64,
    ) -> Self {
        Self {
            function,
            address,
            condition,
            dest_true,
            dest_false,
        }
    }
    pub fn condition(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.condition)
    }
    pub fn dest_true(&self) -> u64 {
        self.dest_true
    }
    pub fn dest_false(&self) -> u64 {
        self.dest_false
    }
    pub fn lift(&self) -> LiftedIf {
        LiftedIf {
            function: self.function.clone(),
            address: self.address,
            condition: Box::new(self.condition().lift()),
            dest_true: self.dest_true(),
            dest_false: self.dest_false(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("condition", Expr(self.condition())),
            ("dest_true", Int(self.dest_true())),
            ("dest_false", Int(self.dest_false())),
        ]
        .into_iter()
    }
}

// FLOAT_CONST
#[derive(Clone, Debug, PartialEq)]
pub struct FloatConst {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub constant: f64,
}
impl FloatConst {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        constant: u64,
        size: usize,
    ) -> Self {
        Self {
            function,
            address,
            constant: get_float(constant, size),
        }
    }
    pub fn constant(&self) -> f64 {
        self.constant
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [("constant", MediumLevelILOperand::Float(self.constant()))].into_iter()
    }
}

// CONST, CONST_PTR, IMPORT
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Constant {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub constant: u64,
}
impl Constant {
    pub(crate) fn new(function: Ref<MediumLevelILFunction>, address: u64, constant: u64) -> Self {
        Self {
            function,
            address,
            constant,
        }
    }
    pub fn constant(&self) -> u64 {
        self.constant
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [("constant", MediumLevelILOperand::Int(self.constant()))].into_iter()
    }
}

// EXTERN_PTR
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ExternPtr {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub constant: u64,
    pub offset: u64,
}
impl ExternPtr {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        constant: u64,
        offset: u64,
    ) -> Self {
        Self {
            function,
            address,
            constant,
            offset,
        }
    }
    pub fn constant(&self) -> u64 {
        self.constant
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("constant", MediumLevelILOperand::Int(self.constant())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
        ]
        .into_iter()
    }
}

// CONST_DATA
#[derive(Clone)]
pub struct ConstantData {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    constant_data: (u64, u64),
    size: usize,
}
#[derive(Clone, Debug, Hash, PartialEq)]
pub struct LiftedConstantData {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub constant_data: types::ConstantData,
}
impl ConstantData {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        constant_data: (u64, u64),
        size: usize,
    ) -> Self {
        Self {
            function,
            address,
            constant_data,
            size,
        }
    }
    pub fn constant_data(&self) -> types::ConstantData {
        get_constant_data(
            &self.function,
            self.constant_data.0,
            self.constant_data.1,
            self.size,
        )
    }

    pub fn lift(&self) -> LiftedConstantData {
        LiftedConstantData {
            function: self.function.clone(),
            address: self.address,
            constant_data: self.constant_data(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [(
            "contant_data",
            MediumLevelILOperand::ConstantData(self.constant_data()),
        )]
        .into_iter()
    }
}

// JUMP, RET_HINT
#[derive(Clone)]
pub struct Jump {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedJump {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: Box<MediumLevelILLiftedInstruction>,
}
impl Jump {
    pub(crate) fn new(function: Ref<MediumLevelILFunction>, address: u64, dest: usize) -> Self {
        Self {
            function,
            address,
            dest,
        }
    }
    pub fn dest(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.dest)
    }
    pub fn lift(&self) -> LiftedJump {
        LiftedJump {
            function: self.function.clone(),
            address: self.address,
            dest: Box::new(self.dest().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [("dest", MediumLevelILOperand::Expr(self.dest()))].into_iter()
    }
}

// STORE_SSA
#[derive(Clone)]
pub struct StoreSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: usize,
    dest_memory: u64,
    src_memory: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStoreSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl StoreSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: usize,
        dest_memory: u64,
        src_memory: u64,
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            dest_memory,
            src_memory,
            src,
        }
    }
    pub fn dest(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.dest)
    }
    pub fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedStoreSsa {
        LiftedStoreSsa {
            function: self.function.clone(),
            address: self.address,
            dest: Box::new(self.dest().lift()),
            dest_memory: self.dest_memory(),
            src_memory: self.src_memory(),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("dest", MediumLevelILOperand::Expr(self.dest())),
            ("dest_memory", MediumLevelILOperand::Int(self.dest_memory())),
            ("src_memory", MediumLevelILOperand::Int(self.src_memory())),
            ("src", MediumLevelILOperand::Expr(self.src())),
        ]
        .into_iter()
    }
}

// STORE_STRUCT_SSA
#[derive(Clone)]
pub struct StoreStructSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: usize,
    offset: u64,
    dest_memory: u64,
    src_memory: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStoreStructSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
    pub dest_memory: u64,
    pub src_memory: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl StoreStructSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: usize,
        offset: u64,
        dest_memory: u64,
        src_memory: u64,
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            offset,
            dest_memory,
            src_memory,
            src,
        }
    }
    pub fn dest(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.dest)
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedStoreStructSsa {
        LiftedStoreStructSsa {
            function: self.function.clone(),
            address: self.address,
            dest: Box::new(self.dest().lift()),
            offset: self.offset(),
            dest_memory: self.dest_memory(),
            src_memory: self.src_memory(),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("dest", MediumLevelILOperand::Expr(self.dest())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
            ("dest_memory", MediumLevelILOperand::Int(self.dest_memory())),
            ("src_memory", MediumLevelILOperand::Int(self.src_memory())),
            ("src", MediumLevelILOperand::Expr(self.src())),
        ]
        .into_iter()
    }
}

// STORE_STRUCT
#[derive(Clone)]
pub struct StoreStruct {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: usize,
    offset: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStoreStruct {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl StoreStruct {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: usize,
        offset: u64,
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            offset,
            src,
        }
    }
    pub fn dest(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.dest)
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedStoreStruct {
        LiftedStoreStruct {
            function: self.function.clone(),
            address: self.address,
            dest: Box::new(self.dest().lift()),
            offset: self.offset(),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("dest", MediumLevelILOperand::Expr(self.dest())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
            ("src", MediumLevelILOperand::Expr(self.src())),
        ]
        .into_iter()
    }
}

// STORE
#[derive(Clone)]
pub struct Store {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: usize,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStore {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl Store {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: usize,
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            src,
        }
    }
    pub fn dest(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.dest)
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedStore {
        LiftedStore {
            function: self.function.clone(),
            address: self.address,
            dest: Box::new(self.dest().lift()),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("dest", MediumLevelILOperand::Expr(self.dest())),
            ("src", MediumLevelILOperand::Expr(self.src())),
        ]
        .into_iter()
    }
}

// JUMP_TO
#[derive(Clone)]
pub struct JumpTo {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: usize,
    targets: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedJumpTo {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub targets: HashMap<u64, u64>,
}
impl JumpTo {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: usize,
        targets: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            dest,
            targets,
        }
    }
    pub fn dest(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.dest)
    }
    pub fn targets(&self) -> OperandDubleList {
        OperandList::new(&self.function, self.targets.1, self.targets.0).duble()
    }
    pub fn lift(&self) -> LiftedJumpTo {
        LiftedJumpTo {
            function: self.function.clone(),
            address: self.address,
            dest: Box::new(self.dest().lift()),
            targets: self.targets().collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("dest", Expr(self.dest())),
            ("targets", TargetMap(self.targets())),
        ]
        .into_iter()
    }
}

// GOTO
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Goto {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: u64,
}
impl Goto {
    pub(crate) fn new(function: Ref<MediumLevelILFunction>, address: u64, dest: u64) -> Self {
        Self {
            function,
            address,
            dest,
        }
    }
    pub fn dest(&self) -> u64 {
        self.dest
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [("dest", MediumLevelILOperand::Int(self.dest()))].into_iter()
    }
}

// FREE_VAR_SLOT
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FreeVarSlot {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: Variable,
}
impl FreeVarSlot {
    pub(crate) fn new(function: Ref<MediumLevelILFunction>, address: u64, dest: u64) -> Self {
        Self {
            function,
            address,
            dest: get_var(dest),
        }
    }
    pub fn dest(&self) -> Variable {
        self.dest
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [("dest", MediumLevelILOperand::Var(self.dest()))].into_iter()
    }
}

// SET_VAR_FIELD
#[derive(Clone)]
pub struct SetVarField {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: u64,
    offset: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarField {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: Variable,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarField {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: u64,
        offset: u64,
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            offset,
            src,
        }
    }
    pub fn dest(&self) -> Variable {
        get_var(self.dest)
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedSetVarField {
        LiftedSetVarField {
            function: self.function.clone(),
            address: self.address,
            dest: self.dest(),
            offset: self.offset(),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("dest", MediumLevelILOperand::Var(self.dest())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
            ("src", MediumLevelILOperand::Expr(self.src())),
        ]
        .into_iter()
    }
}

// SET_VAR
#[derive(Clone)]
pub struct SetVar {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVar {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: Variable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVar {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: u64,
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            src,
        }
    }
    pub fn dest(&self) -> Variable {
        get_var(self.dest)
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedSetVar {
        LiftedSetVar {
            function: self.function.clone(),
            address: self.address,
            dest: self.dest(),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("dest", MediumLevelILOperand::Var(self.dest())),
            ("src", MediumLevelILOperand::Expr(self.src())),
        ]
        .into_iter()
    }
}

// FREE_VAR_SLOT_SSA
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FreeVarSlotSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: SSAVariable,
    pub prev: SSAVariable,
}
impl FreeVarSlotSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: (u64, usize),
        prev: (u64, usize),
    ) -> Self {
        Self {
            function,
            address,
            dest: get_var_ssa(dest.0, dest.1),
            prev: get_var_ssa(prev.0, prev.1),
        }
    }
    pub fn dest(&self) -> SSAVariable {
        self.dest
    }
    pub fn prev(&self) -> SSAVariable {
        self.prev
    }
    pub fn lift(&self) -> FreeVarSlotSsa {
        FreeVarSlotSsa {
            function: self.function.clone(),
            address: self.address,
            dest: self.dest(),
            prev: self.prev(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("dest", MediumLevelILOperand::VarSsa(self.dest())),
            ("prev", MediumLevelILOperand::VarSsa(self.prev())),
        ]
        .into_iter()
    }
}

// SET_VAR_SSA_FIELD, SET_VAR_ALIASED_FIELD
#[derive(Clone)]
pub struct SetVarSsaField {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: (u64, usize),
    prev: (u64, usize),
    offset: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSsaField {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: SSAVariable,
    pub prev: SSAVariable,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarSsaField {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: (u64, usize),
        prev: (u64, usize),
        offset: u64,
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            prev,
            offset,
            src,
        }
    }
    pub fn dest(&self) -> SSAVariable {
        get_var_ssa(self.dest.0, self.dest.1)
    }
    pub fn prev(&self) -> SSAVariable {
        get_var_ssa(self.prev.0, self.prev.1)
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedSetVarSsaField {
        LiftedSetVarSsaField {
            function: self.function.clone(),
            address: self.address,
            dest: self.dest(),
            prev: self.prev(),
            offset: self.offset(),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("dest", MediumLevelILOperand::VarSsa(self.dest())),
            ("prev", MediumLevelILOperand::VarSsa(self.prev())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
            ("src", MediumLevelILOperand::Expr(self.src())),
        ]
        .into_iter()
    }
}

// SET_VAR_ALIASED
#[derive(Clone)]
pub struct SetVarAliased {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: (u64, usize),
    prev: (u64, usize),
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarAliased {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: SSAVariable,
    pub prev: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarAliased {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: (u64, usize),
        prev: (u64, usize),
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            prev,
            src,
        }
    }
    pub fn dest(&self) -> SSAVariable {
        get_var_ssa(self.dest.0, self.dest.1)
    }
    pub fn prev(&self) -> SSAVariable {
        get_var_ssa(self.prev.0, self.prev.1)
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedSetVarAliased {
        LiftedSetVarAliased {
            function: self.function.clone(),
            address: self.address,
            dest: self.dest(),
            prev: self.prev(),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("dest", MediumLevelILOperand::VarSsa(self.dest())),
            ("prev", MediumLevelILOperand::VarSsa(self.prev())),
            ("src", MediumLevelILOperand::Expr(self.src())),
        ]
        .into_iter()
    }
}

// SET_VAR_SSA
#[derive(Clone)]
pub struct SetVarSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: (u64, usize),
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: (u64, usize),
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            src,
        }
    }
    pub fn dest(&self) -> SSAVariable {
        get_var_ssa(self.dest.0, self.dest.1)
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedSetVarSsa {
        LiftedSetVarSsa {
            function: self.function.clone(),
            address: self.address,
            dest: self.dest(),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("dest", MediumLevelILOperand::VarSsa(self.dest())),
            ("src", MediumLevelILOperand::Expr(self.src())),
        ]
        .into_iter()
    }
}

// VAR_PHI
#[derive(Clone)]
pub struct VarPhi {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest: (u64, usize),
    src: (usize, usize),
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct LiftedVarPhi {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest: SSAVariable,
    pub src: Vec<SSAVariable>,
}
impl VarPhi {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest: (u64, usize),
        src: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            dest,
            src,
        }
    }
    pub fn dest(&self) -> SSAVariable {
        get_var_ssa(self.dest.0, self.dest.1)
    }
    pub fn src(&self) -> OperandSSAVariableList {
        OperandList::new(&self.function, self.src.1, self.src.0).map_ssa_var()
    }
    pub fn lift(&self) -> LiftedVarPhi {
        LiftedVarPhi {
            function: self.function.clone(),
            address: self.address,
            dest: self.dest(),
            src: self.src().collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("dest", MediumLevelILOperand::VarSsa(self.dest())),
            ("src", MediumLevelILOperand::VarSsaList(self.src())),
        ]
        .into_iter()
    }
}

// MEM_PHI
#[derive(Clone)]
pub struct MemPhi {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    dest_memory: u64,
    src_memory: (usize, usize),
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct LiftedMemPhi {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub dest_memory: u64,
    pub src_memory: Vec<u64>,
}
impl MemPhi {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        dest_memory: u64,
        src_memory: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            dest_memory,
            src_memory,
        }
    }
    pub fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    pub fn src_memory(&self) -> OperandList {
        OperandList::new(&self.function, self.src_memory.1, self.src_memory.0)
    }
    pub fn lift(&self) -> LiftedMemPhi {
        LiftedMemPhi {
            function: self.function.clone(),
            address: self.address,
            dest_memory: self.dest_memory(),
            src_memory: self.src_memory().collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("dest_memory", Int(self.dest_memory())),
            ("src_memory", IntList(self.src_memory())),
        ]
        .into_iter()
    }
}

// VAR_SPLIT
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSplit {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub high: Variable,
    pub low: Variable,
}
impl VarSplit {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        high: u64,
        low: u64,
    ) -> Self {
        Self {
            function,
            address,
            high: get_var(high),
            low: get_var(low),
        }
    }
    pub fn high(&self) -> Variable {
        self.high
    }
    pub fn low(&self) -> Variable {
        self.low
    }
    pub fn lift(&self) -> VarSplit {
        VarSplit {
            function: self.function.clone(),
            address: self.address,
            high: self.high(),
            low: self.low(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("high", MediumLevelILOperand::Var(self.high())),
            ("low", MediumLevelILOperand::Var(self.low())),
        ]
        .into_iter()
    }
}

// SET_VAR_SPLIT
#[derive(Clone)]
pub struct SetVarSplit {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    high: u64,
    low: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSplit {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub high: Variable,
    pub low: Variable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarSplit {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        high: u64,
        low: u64,
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            high,
            low,
            src,
        }
    }
    pub fn high(&self) -> Variable {
        get_var(self.high)
    }
    pub fn low(&self) -> Variable {
        get_var(self.low)
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedSetVarSplit {
        LiftedSetVarSplit {
            function: self.function.clone(),
            address: self.address,
            high: self.high(),
            low: self.low(),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("high", MediumLevelILOperand::Var(self.high())),
            ("low", MediumLevelILOperand::Var(self.low())),
            ("src", MediumLevelILOperand::Expr(self.src())),
        ]
        .into_iter()
    }
}

// VAR_SPLIT_SSA
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSplitSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub high: SSAVariable,
    pub low: SSAVariable,
}
impl VarSplitSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        high: (u64, usize),
        low: (u64, usize),
    ) -> Self {
        Self {
            function,
            address,
            high: get_var_ssa(high.0, high.1),
            low: get_var_ssa(low.0, low.1),
        }
    }
    pub fn high(&self) -> SSAVariable {
        self.high
    }
    pub fn low(&self) -> SSAVariable {
        self.low
    }
    pub fn lift(&self) -> VarSplitSsa {
        VarSplitSsa {
            function: self.function.clone(),
            address: self.address,
            high: self.high(),
            low: self.low(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("high", MediumLevelILOperand::VarSsa(self.high())),
            ("low", MediumLevelILOperand::VarSsa(self.low())),
        ]
        .into_iter()
    }
}

// SET_VAR_SPLIT_SSA
#[derive(Clone)]
pub struct SetVarSplitSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    high: (u64, usize),
    low: (u64, usize),
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSplitSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub high: SSAVariable,
    pub low: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarSplitSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        high: (u64, usize),
        low: (u64, usize),
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            high,
            low,
            src,
        }
    }
    pub fn high(&self) -> SSAVariable {
        get_var_ssa(self.high.0, self.high.1)
    }
    pub fn low(&self) -> SSAVariable {
        get_var_ssa(self.low.0, self.low.1)
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedSetVarSplitSsa {
        LiftedSetVarSplitSsa {
            function: self.function.clone(),
            address: self.address,
            high: self.high(),
            low: self.low(),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("high", MediumLevelILOperand::VarSsa(self.high())),
            ("low", MediumLevelILOperand::VarSsa(self.low())),
            ("src", MediumLevelILOperand::Expr(self.src())),
        ]
        .into_iter()
    }
}

// ADD, SUB, AND, OR, XOR, LSL, LSR, ASR, ROL, ROR, MUL, MULU_DP, MULS_DP, DIVU, DIVU_DP, DIVS, DIVS_DP, MODU, MODU_DP, MODS, MODS_DP, CMP_E, CMP_NE, CMP_SLT, CMP_ULT, CMP_SLE, CMP_ULE, CMP_SGE, CMP_UGE, CMP_SGT, CMP_UGT, TEST_BIT, ADD_OVERFLOW, FCMP_E, FCMP_NE, FCMP_LT, FCMP_LE, FCMP_GE, FCMP_GT, FCMP_O, FCMP_UO, FADD, FSUB, FMUL, FDIV
#[derive(Clone)]
pub struct BinaryOp {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    left: usize,
    right: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOp {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub left: Box<MediumLevelILLiftedInstruction>,
    pub right: Box<MediumLevelILLiftedInstruction>,
}
impl BinaryOp {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        left: usize,
        right: usize,
    ) -> Self {
        Self {
            function,
            address,
            left,
            right,
        }
    }
    pub fn left(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.left)
    }
    pub fn right(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.right)
    }
    pub fn lift(&self) -> LiftedBinaryOp {
        LiftedBinaryOp {
            function: self.function.clone(),
            address: self.address,
            left: Box::new(self.left().lift()),
            right: Box::new(self.right().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("left", MediumLevelILOperand::Expr(self.left())),
            ("right", MediumLevelILOperand::Expr(self.right())),
        ]
        .into_iter()
    }
}

// ADC, SBB, RLC, RRC
#[derive(Clone)]
pub struct BinaryOpCarry {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    left: usize,
    right: usize,
    carry: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOpCarry {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub left: Box<MediumLevelILLiftedInstruction>,
    pub right: Box<MediumLevelILLiftedInstruction>,
    pub carry: Box<MediumLevelILLiftedInstruction>,
}
impl BinaryOpCarry {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        left: usize,
        right: usize,
        carry: usize,
    ) -> Self {
        Self {
            function,
            address,
            left,
            right,
            carry,
        }
    }
    pub fn left(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.left)
    }
    pub fn right(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.right)
    }
    pub fn carry(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.carry)
    }
    pub fn lift(&self) -> LiftedBinaryOpCarry {
        LiftedBinaryOpCarry {
            function: self.function.clone(),
            address: self.address,
            left: Box::new(self.left().lift()),
            right: Box::new(self.right().lift()),
            carry: Box::new(self.carry().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("left", MediumLevelILOperand::Expr(self.left())),
            ("right", MediumLevelILOperand::Expr(self.right())),
            ("carry", MediumLevelILOperand::Expr(self.carry())),
        ]
        .into_iter()
    }
}

// CALL, TAILCALL
#[derive(Clone)]
pub struct Call {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    output: (usize, usize),
    dest: usize,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCall {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub output: Vec<Variable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}
impl Call {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        output: (usize, usize),
        dest: usize,
        params: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            output,
            dest,
            params,
        }
    }
    pub fn output(&self) -> OperandVariableList {
        OperandList::new(&self.function, self.output.1, self.output.0).map_var()
    }
    pub fn dest(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.dest)
    }
    pub fn params(&self) -> OperandExprList {
        OperandList::new(&self.function, self.params.1, self.params.0).map_expr()
    }
    pub fn lift(&self) -> LiftedCall {
        LiftedCall {
            function: self.function.clone(),
            address: self.address,
            output: self.output().collect(),
            dest: Box::new(self.dest().lift()),
            params: self.params().map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("output", MediumLevelILOperand::VarList(self.output())),
            ("dest", MediumLevelILOperand::Expr(self.dest())),
            ("params", MediumLevelILOperand::ExprList(self.params())),
        ]
        .into_iter()
    }
}

// SYSCALL
#[derive(Clone)]
pub struct Syscall {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    output: (usize, usize),
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallCall {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub output: Vec<Variable>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}
impl Syscall {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        output: (usize, usize),
        params: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            output,
            params,
        }
    }
    pub fn output(&self) -> OperandVariableList {
        OperandList::new(&self.function, self.output.1, self.output.0).map_var()
    }
    pub fn params(&self) -> OperandExprList {
        OperandList::new(&self.function, self.params.1, self.params.0).map_expr()
    }
    pub fn lift(&self) -> LiftedSyscallCall {
        LiftedSyscallCall {
            function: self.function.clone(),
            address: self.address,
            output: self.output().collect(),
            params: self.params().map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("output", VarList(self.output())),
            ("params", ExprList(self.params())),
        ]
        .into_iter()
    }
}

// INTRINSIC
#[derive(Clone)]
pub struct Intrinsic {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    output: (usize, usize),
    intrinsic: u32,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsic {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub output: Vec<Variable>,
    pub intrinsic: ILIntrinsic,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}
impl Intrinsic {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        output: (usize, usize),
        intrinsic: u32,
        params: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            output,
            intrinsic,
            params,
        }
    }
    pub fn output(&self) -> OperandVariableList {
        OperandList::new(&self.function, self.output.1, self.output.0).map_var()
    }
    pub fn intrinsic(&self) -> ILIntrinsic {
        get_intrinsic(&self.function, self.intrinsic)
    }
    pub fn params(&self) -> OperandExprList {
        OperandList::new(&self.function, self.params.1, self.params.0).map_expr()
    }
    pub fn lift(&self) -> LiftedIntrinsic {
        LiftedIntrinsic {
            function: self.function.clone(),
            address: self.address,
            output: self.output().collect(),
            intrinsic: self.intrinsic(),
            params: self.params().map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("output", VarList(self.output())),
            ("intrinsic", Intrinsic(self.intrinsic())),
            ("params", ExprList(self.params())),
        ]
        .into_iter()
    }
}

// INTRINSIC_SSA
#[derive(Clone)]
pub struct IntrinsicSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    output: (usize, usize),
    intrinsic: u32,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsicSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub output: Vec<SSAVariable>,
    pub intrinsic: ILIntrinsic,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}
impl IntrinsicSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        output: (usize, usize),
        intrinsic: u32,
        params: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            output,
            intrinsic,
            params,
        }
    }
    pub fn output(&self) -> OperandSSAVariableList {
        OperandList::new(&self.function, self.output.1, self.output.0).map_ssa_var()
    }
    pub fn intrinsic(&self) -> ILIntrinsic {
        get_intrinsic(&self.function, self.intrinsic)
    }
    pub fn params(&self) -> OperandExprList {
        OperandList::new(&self.function, self.params.1, self.params.0).map_expr()
    }
    pub fn lift(&self) -> LiftedIntrinsicSsa {
        LiftedIntrinsicSsa {
            function: self.function.clone(),
            address: self.address,
            output: self.output().collect(),
            intrinsic: get_intrinsic(&self.function, self.intrinsic),
            params: self.params().map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("output", VarSsaList(self.output())),
            ("intrinsic", Intrinsic(self.intrinsic())),
            ("params", ExprList(self.params())),
        ]
        .into_iter()
    }
}

// CALL_SSA, TAILCALL_SSA
#[derive(Clone)]
pub struct CallSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    output: usize,
    dest: usize,
    params: (usize, usize),
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub output: Vec<SSAVariable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl CallSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        output: usize,
        dest: usize,
        params: (usize, usize),
        src_memory: u64,
    ) -> Self {
        Self {
            function,
            address,
            output,
            dest,
            params,
            src_memory,
        }
    }
    pub fn output(&self) -> OperandSSAVariableList {
        get_call_output_ssa(&self.function, self.output)
    }
    pub fn dest(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.dest)
    }
    pub fn params(&self) -> OperandExprList {
        OperandList::new(&self.function, self.params.1, self.params.0).map_expr()
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self) -> LiftedCallSsa {
        LiftedCallSsa {
            function: self.function.clone(),
            address: self.address,
            output: self.output().collect(),
            dest: Box::new(self.dest().lift()),
            params: self.params().map(|instr| instr.lift()).collect(),
            src_memory: self.src_memory(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("output", VarSsaList(self.output())),
            ("dest", Expr(self.dest())),
            ("params", ExprList(self.params())),
            ("src_memory", Int(self.src_memory())),
        ]
        .into_iter()
    }
}

// CALL_UNTYPED_SSA, TAILCALL_UNTYPED_SSA
#[derive(Clone)]
pub struct CallUntypedSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    output: usize,
    dest: usize,
    params: usize,
    stack: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallUntypedSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub output: Vec<SSAVariable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}
impl CallUntypedSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        output: usize,
        dest: usize,
        params: usize,
        stack: usize,
    ) -> Self {
        Self {
            function,
            address,
            output,
            dest,
            params,
            stack,
        }
    }
    pub fn output(&self) -> OperandSSAVariableList {
        get_call_output_ssa(&self.function, self.output)
    }
    pub fn dest(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.dest)
    }
    pub fn params(&self) -> OperandExprList {
        get_call_params_ssa(&self.function, self.params)
    }
    pub fn stack(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.stack)
    }
    pub fn lift(&self) -> LiftedCallUntypedSsa {
        LiftedCallUntypedSsa {
            function: self.function.clone(),
            address: self.address,
            output: self.output().collect(),
            dest: Box::new(self.dest().lift()),
            params: self.params().map(|instr| instr.lift()).collect(),
            stack: Box::new(self.stack().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("output", VarSsaList(self.output())),
            ("dest", Expr(self.dest())),
            ("params", ExprList(self.params())),
            ("stack", Expr(self.stack())),
        ]
        .into_iter()
    }
}

// SYSCALL_SSA
#[derive(Clone)]
pub struct SyscallSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    output: usize,
    params: (usize, usize),
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub output: Vec<SSAVariable>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl SyscallSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        output: usize,
        params: (usize, usize),
        src_memory: u64,
    ) -> Self {
        Self {
            function,
            address,
            output,
            params,
            src_memory,
        }
    }
    pub fn output(&self) -> OperandSSAVariableList {
        get_call_output_ssa(&self.function, self.output)
    }
    pub fn params(&self) -> OperandExprList {
        OperandList::new(&self.function, self.params.1, self.params.0).map_expr()
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self) -> LiftedSyscallSsa {
        LiftedSyscallSsa {
            function: self.function.clone(),
            address: self.address,
            output: self.output().collect(),
            params: self.params().map(|instr| instr.lift()).collect(),
            src_memory: self.src_memory(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("output", VarSsaList(self.output())),
            ("params", ExprList(self.params())),
            ("src_memory", MediumLevelILOperand::Int(self.src_memory())),
        ]
        .into_iter()
    }
}

// SYSCALL_UNTYPED_SSA
#[derive(Clone)]
pub struct SyscallUntypedSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    output: usize,
    params: usize,
    stack: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallUntypedSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub output: Vec<SSAVariable>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}
impl SyscallUntypedSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        output: usize,
        params: usize,
        stack: usize,
    ) -> Self {
        Self {
            function,
            address,
            output,
            params,
            stack,
        }
    }
    pub fn output(&self) -> OperandSSAVariableList {
        get_call_output_ssa(&self.function, self.output)
    }
    pub fn params(&self) -> OperandExprList {
        get_call_params_ssa(&self.function, self.params)
    }
    pub fn stack(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.stack)
    }
    pub fn lift(&self) -> LiftedSyscallUntypedSsa {
        LiftedSyscallUntypedSsa {
            function: self.function.clone(),
            address: self.address,
            output: self.output().collect(),
            params: self.params().map(|instr| instr.lift()).collect(),
            stack: Box::new(self.stack().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("output", VarSsaList(self.output())),
            ("params", ExprList(self.params())),
            ("stack", Expr(self.stack())),
        ]
        .into_iter()
    }
}

// CALL_UNTYPED, TAILCALL_UNTYPED
#[derive(Clone)]
pub struct CallUntyped {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    output: usize,
    dest: usize,
    params: usize,
    stack: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallUntyped {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub output: Vec<Variable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}
impl CallUntyped {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        output: usize,
        dest: usize,
        params: usize,
        stack: usize,
    ) -> Self {
        Self {
            function,
            address,
            output,
            dest,
            params,
            stack,
        }
    }
    pub fn output(&self) -> OperandVariableList {
        get_call_output(&self.function, self.output)
    }
    pub fn dest(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.dest)
    }
    pub fn params(&self) -> OperandExprList {
        get_call_params(&self.function, self.params)
    }
    pub fn stack(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.stack)
    }
    pub fn lift(&self) -> LiftedCallUntyped {
        LiftedCallUntyped {
            function: self.function.clone(),
            address: self.address,
            output: self.output().collect(),
            dest: Box::new(self.dest().lift()),
            params: self.params().map(|instr| instr.lift()).collect(),
            stack: Box::new(self.stack().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("output", VarList(self.output())),
            ("dest", Expr(self.dest())),
            ("params", ExprList(self.params())),
            ("stack", Expr(self.stack())),
        ]
        .into_iter()
    }
}

// SYSCALL_UNTYPED
#[derive(Clone)]
pub struct SyscallUntyped {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    output: usize,
    params: usize,
    stack: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallUntyped {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub output: Vec<Variable>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}
impl SyscallUntyped {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        output: usize,
        params: usize,
        stack: usize,
    ) -> Self {
        Self {
            function,
            address,
            output,
            params,
            stack,
        }
    }
    pub fn output(&self) -> OperandVariableList {
        get_call_output(&self.function, self.output)
    }
    pub fn params(&self) -> OperandExprList {
        get_call_params(&self.function, self.params)
    }
    pub fn stack(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.stack)
    }
    pub fn lift(&self) -> LiftedSyscallUntyped {
        LiftedSyscallUntyped {
            function: self.function.clone(),
            address: self.address,
            output: self.output().collect(),
            params: self.params().map(|instr| instr.lift()).collect(),
            stack: Box::new(self.stack().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        use MediumLevelILOperand::*;
        [
            ("output", VarList(self.output())),
            ("params", ExprList(self.params())),
            ("stack", Expr(self.stack())),
        ]
        .into_iter()
    }
}

// NEG, NOT, SX, ZX, LOW_PART, BOOL_TO_INT, UNIMPL_MEM, FSQRT, FNEG, FABS, FLOAT_TO_INT, INT_TO_FLOAT, FLOAT_CONV, ROUND_TO_INT, FLOOR, CEIL, FTRUNC, LOAD
#[derive(Clone)]
pub struct UnaryOp {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedUnaryOp {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl UnaryOp {
    pub(crate) fn new(function: Ref<MediumLevelILFunction>, address: u64, src: usize) -> Self {
        Self {
            function,
            address,
            src,
        }
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedUnaryOp {
        LiftedUnaryOp {
            function: self.function.clone(),
            address: self.address,
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [("src", MediumLevelILOperand::Expr(self.src()))].into_iter()
    }
}

// LOAD_STRUCT
#[derive(Clone)]
pub struct LoadStruct {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    src: usize,
    offset: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedLoadStruct {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
}
impl LoadStruct {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        src: usize,
        offset: u64,
    ) -> Self {
        Self {
            function,
            address,
            src,
            offset,
        }
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn lift(&self) -> LiftedLoadStruct {
        LiftedLoadStruct {
            function: self.function.clone(),
            address: self.address,
            src: Box::new(self.src().lift()),
            offset: self.offset(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("src", MediumLevelILOperand::Expr(self.src())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
        ]
        .into_iter()
    }
}

// LOAD_STRUCT_SSA
#[derive(Clone)]
pub struct LoadStructSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    src: usize,
    offset: u64,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedLoadStructSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
    pub src_memory: u64,
}
impl LoadStructSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        src: usize,
        offset: u64,
        src_memory: u64,
    ) -> Self {
        Self {
            function,
            address,
            src,
            offset,
            src_memory,
        }
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self) -> LiftedLoadStructSsa {
        LiftedLoadStructSsa {
            function: self.function.clone(),
            address: self.address,
            src: Box::new(self.src().lift()),
            offset: self.offset(),
            src_memory: self.src_memory(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("src", MediumLevelILOperand::Expr(self.src())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
            ("src_memory", MediumLevelILOperand::Int(self.src_memory())),
        ]
        .into_iter()
    }
}

// LOAD_SSA
#[derive(Clone)]
pub struct LoadSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    src: usize,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedLoadSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl LoadSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        src: usize,
        src_memory: u64,
    ) -> Self {
        Self {
            function,
            address,
            src,
            src_memory,
        }
    }
    pub fn src(&self) -> MediumLevelILInstruction {
        get_operation(&self.function, self.src)
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self) -> LiftedLoadSsa {
        LiftedLoadSsa {
            function: self.function.clone(),
            address: self.address,
            src: Box::new(self.src().lift()),
            src_memory: self.src_memory(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("src", MediumLevelILOperand::Expr(self.src())),
            ("src_memory", MediumLevelILOperand::Int(self.src_memory())),
        ]
        .into_iter()
    }
}

// RET
#[derive(Clone)]
pub struct Ret {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    src: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedRet {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub src: Vec<MediumLevelILLiftedInstruction>,
}
impl Ret {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        src: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            src,
        }
    }
    pub fn src(&self) -> OperandExprList {
        OperandList::new(&self.function, self.src.1, self.src.0).map_expr()
    }
    pub fn lift(&self) -> LiftedRet {
        LiftedRet {
            function: self.function.clone(),
            address: self.address,
            src: self.src().map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [("src", MediumLevelILOperand::ExprList(self.src()))].into_iter()
    }
}

// SEPARATE_PARAM_LIST
#[derive(Clone)]
pub struct SeparateParamList {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSeparateParamList {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}
impl SeparateParamList {
    pub fn new(function: Ref<MediumLevelILFunction>, address: u64, params: (usize, usize)) -> Self {
        Self {
            function,
            address,
            params,
        }
    }
    pub fn params(&self) -> OperandExprList {
        OperandList::new(&self.function, self.params.1, self.params.0).map_expr()
    }
    pub fn lift(&self) -> LiftedSeparateParamList {
        LiftedSeparateParamList {
            function: self.function.clone(),
            address: self.address,
            params: self.params().map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("params", MediumLevelILOperand::ExprList(self.params()))].into_iter()
    }
}

// SHARED_PARAM_SLOT
#[derive(Clone)]
pub struct SharedParamSlot {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSharedParamSlot {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}
impl SharedParamSlot {
    pub fn new(function: Ref<MediumLevelILFunction>, address: u64, params: (usize, usize)) -> Self {
        Self {
            function,
            address,
            params,
        }
    }
    pub fn params(&self) -> OperandExprList {
        OperandList::new(&self.function, self.params.1, self.params.0).map_expr()
    }
    pub fn lift(&self) -> LiftedSharedParamSlot {
        LiftedSharedParamSlot {
            function: self.function.clone(),
            address: self.address,
            params: self.params().map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("params", MediumLevelILOperand::ExprList(self.params()))].into_iter()
    }
}

// VAR, ADDRESS_OF
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Var {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub src: Variable,
}
impl Var {
    pub(crate) fn new(function: Ref<MediumLevelILFunction>, address: u64, src: u64) -> Self {
        Self {
            function,
            address,
            src: get_var(src),
        }
    }
    pub fn src(&self) -> Variable {
        self.src
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [("src", MediumLevelILOperand::Var(self.src()))].into_iter()
    }
}

// VAR_FIELD, ADDRESS_OF_FIELD
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Field {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub src: Variable,
    pub offset: u64,
}
impl Field {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        src: u64,
        offset: u64,
    ) -> Self {
        Self {
            function,
            address,
            src: get_var(src),
            offset,
        }
    }
    pub fn src(&self) -> Variable {
        self.src
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("src", MediumLevelILOperand::Var(self.src())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
        ]
        .into_iter()
    }
}

// VAR_SSA, VAR_ALIASED
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsa {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub src: SSAVariable,
}
impl VarSsa {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        src: (u64, usize),
    ) -> Self {
        Self {
            function,
            address,
            src: get_var_ssa(src.0, src.1),
        }
    }
    pub fn src(&self) -> SSAVariable {
        self.src
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [("src", MediumLevelILOperand::VarSsa(self.src()))].into_iter()
    }
}

// VAR_SSA_FIELD, VAR_ALIASED_FIELD
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsaField {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub src: SSAVariable,
    pub offset: u64,
}
impl VarSsaField {
    pub(crate) fn new(
        function: Ref<MediumLevelILFunction>,
        address: u64,
        src: (u64, usize),
        offset: u64,
    ) -> Self {
        Self {
            function,
            address,
            src: get_var_ssa(src.0, src.1),
            offset,
        }
    }
    pub fn src(&self) -> SSAVariable {
        self.src
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [
            ("src", MediumLevelILOperand::VarSsa(self.src())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
        ]
        .into_iter()
    }
}

// TRAP
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Trap {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub vector: u64,
}
impl Trap {
    pub(crate) fn new(function: Ref<MediumLevelILFunction>, address: u64, vector: u64) -> Self {
        Self {
            function,
            address,
            vector,
        }
    }
    pub fn vector(&self) -> u64 {
        self.vector
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> + '_ {
        [("vector", MediumLevelILOperand::Int(self.vector()))].into_iter()
    }
}
