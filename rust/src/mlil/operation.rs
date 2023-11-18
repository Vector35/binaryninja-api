use std::collections::HashMap;

use binaryninjacore_sys::BNFromVariableIdentifier;
use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNMediumLevelILInstruction;
use binaryninjacore_sys::BNMediumLevelILOperation;

use crate::rc::Ref;
use crate::types::{SSAVariable, Variable};

use super::{MediumLevelILFunction, MediumLevelILInstruction, MediumLevelILLiftedInstruction};

pub enum MediumLevelILOperand {
    //TODO
    //ConstantData(!),
    //TODO
    //Intrinsic(!),
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

// TODO implement ConstantData
fn get_constant_data(
    _function: &MediumLevelILFunction,
    _value: u64,
    _state: u64,
    _size: usize,
) -> ! {
    todo!()
}

// TODO implement Intrinsic
fn get_intrinsic(_function: &MediumLevelILFunction, _idx: usize) -> ! {
    todo!()
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
    SSAVariable::new(var, version as usize)
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

fn get_call_output(function: &MediumLevelILFunction, idx: usize) -> OperandVariableList {
    get_call_list(function, BNMediumLevelILOperation::MLIL_CALL_OUTPUT, idx)
}

fn get_call_params(function: &MediumLevelILFunction, idx: usize) -> OperandVariableList {
    get_call_list(function, BNMediumLevelILOperation::MLIL_CALL_PARAM, idx)
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

fn get_call_output_ssa(function: &MediumLevelILFunction, idx: usize) -> OperandSSAVariableList {
    get_call_list_ssa(
        function,
        BNMediumLevelILOperation::MLIL_CALL_OUTPUT_SSA,
        idx,
    )
}

fn get_call_params_ssa(function: &MediumLevelILFunction, idx: usize) -> OperandSSAVariableList {
    get_call_list_ssa(function, BNMediumLevelILOperation::MLIL_CALL_PARAM_SSA, idx)
}

// NOP, NORET, BP, UNDEF, UNIMPL
#[derive(Default, Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct NoArgs {}

// IF
#[derive(Copy, Clone)]
pub struct MediumLevelILOperationIf {
    condition: usize,
    dest_true: u64,
    dest_false: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIf {
    pub condition: Box<MediumLevelILLiftedInstruction>,
    pub dest_true: u64,
    pub dest_false: u64,
}
impl MediumLevelILOperationIf {
    pub fn new(condition: usize, dest_true: u64, dest_false: u64) -> Self {
        Self {
            condition,
            dest_true,
            dest_false,
        }
    }
    pub fn condition(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.condition)
    }
    pub fn dest_true(&self) -> u64 {
        self.dest_true
    }
    pub fn dest_false(&self) -> u64 {
        self.dest_false
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedIf {
        LiftedIf {
            condition: Box::new(self.condition(function).lift()),
            dest_true: self.dest_true(),
            dest_false: self.dest_false(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("condition", Expr(self.condition(function))),
            ("dest_true", Int(self.dest_true())),
            ("dest_false", Int(self.dest_false())),
        ]
        .into_iter()
    }
}

// FLOAT_CONST
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FloatConst {
    pub constant: f64,
}
impl FloatConst {
    pub fn new(constant: u64, size: usize) -> Self {
        Self {
            constant: get_float(constant, size),
        }
    }
    pub fn constant(&self) -> f64 {
        self.constant
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("constant", MediumLevelILOperand::Float(self.constant()))].into_iter()
    }
}

// CONST, CONST_PTR, IMPORT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Constant {
    pub constant: u64,
}
impl Constant {
    pub fn new(constant: u64) -> Self {
        Self { constant }
    }
    pub fn constant(&self) -> u64 {
        self.constant
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("constant", MediumLevelILOperand::Int(self.constant()))].into_iter()
    }
}

// EXTERN_PTR
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ExternPtr {
    pub constant: u64,
    pub offset: u64,
}
impl ExternPtr {
    pub fn new(constant: u64, offset: u64) -> Self {
        Self { constant, offset }
    }
    pub fn constant(&self) -> u64 {
        self.constant
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn operands(
        &self,
        _function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("constant", MediumLevelILOperand::Int(self.constant())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
        ]
        .into_iter()
    }
}

// CONST_DATA
#[derive(Copy, Clone)]
pub struct ConstData {
    constant_data: (u64, u64),
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ConstantData {
    //pub constant_data: !,
}
impl ConstData {
    pub fn new(constant_data: (u64, u64)) -> Self {
        Self { constant_data }
    }
    pub fn constant_data(&self, function: &MediumLevelILFunction, size: usize) -> ! {
        get_constant_data(function, self.constant_data.0, self.constant_data.1, size)
    }
    pub fn lift(&self, _function: &MediumLevelILFunction) -> ConstantData {
        ConstantData {
            // TODO
        }
    }
    pub fn operands(
        &self,
        _function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        // TODO
        [
            //("contant_data", MediumLevelILOperand::ConstData(_self.constant_data(function, self.size)))
        ]
        .into_iter()
    }
}

// JUMP, RET_HINT
#[derive(Copy, Clone)]
pub struct Jump {
    dest: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedJump {
    pub dest: Box<MediumLevelILLiftedInstruction>,
}
impl Jump {
    pub fn new(dest: usize) -> Self {
        Self { dest }
    }
    pub fn dest(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.dest)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedJump {
        LiftedJump {
            dest: Box::new(self.dest(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("dest", MediumLevelILOperand::Expr(self.dest(&function)))].into_iter()
    }
}

// STORE_SSA
#[derive(Copy, Clone)]
pub struct StoreSsa {
    dest: usize,
    dest_memory: u64,
    src_memory: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStoreSsa {
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl StoreSsa {
    pub fn new(dest: usize, dest_memory: u64, src_memory: u64, src: usize) -> Self {
        Self {
            dest,
            dest_memory,
            src_memory,
            src,
        }
    }
    pub fn dest(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.dest)
    }
    pub fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedStoreSsa {
        LiftedStoreSsa {
            dest: Box::new(self.dest(function).lift()),
            dest_memory: self.dest_memory(),
            src_memory: self.src_memory(),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("dest", MediumLevelILOperand::Expr(self.dest(&function))),
            ("dest_memory", MediumLevelILOperand::Int(self.dest_memory())),
            ("src_memory", MediumLevelILOperand::Int(self.src_memory())),
            ("src", MediumLevelILOperand::Expr(self.src(&function))),
        ]
        .into_iter()
    }
}

// STORE_STRUCT_SSA
#[derive(Copy, Clone)]
pub struct StoreStructSsa {
    dest: usize,
    offset: u64,
    dest_memory: u64,
    src_memory: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStoreStructSsa {
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
    pub dest_memory: u64,
    pub src_memory: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl StoreStructSsa {
    pub fn new(dest: usize, offset: u64, dest_memory: u64, src_memory: u64, src: usize) -> Self {
        Self {
            dest,
            offset,
            dest_memory,
            src_memory,
            src,
        }
    }
    pub fn dest(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.dest)
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
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedStoreStructSsa {
        LiftedStoreStructSsa {
            dest: Box::new(self.dest(function).lift()),
            offset: self.offset(),
            dest_memory: self.dest_memory(),
            src_memory: self.src_memory(),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("dest", MediumLevelILOperand::Expr(self.dest(function))),
            ("offset", MediumLevelILOperand::Int(self.offset())),
            ("dest_memory", MediumLevelILOperand::Int(self.dest_memory())),
            ("src_memory", MediumLevelILOperand::Int(self.src_memory())),
            ("src", MediumLevelILOperand::Expr(self.src(function))),
        ]
        .into_iter()
    }
}

// STORE_STRUCT
#[derive(Copy, Clone)]
pub struct StoreStruct {
    dest: usize,
    offset: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStoreStruct {
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl StoreStruct {
    pub fn new(dest: usize, offset: u64, src: usize) -> Self {
        Self { dest, offset, src }
    }
    pub fn dest(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.dest)
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedStoreStruct {
        LiftedStoreStruct {
            dest: Box::new(self.dest(function).lift()),
            offset: self.offset(),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("dest", MediumLevelILOperand::Expr(self.dest(function))),
            ("offset", MediumLevelILOperand::Int(self.offset())),
            ("src", MediumLevelILOperand::Expr(self.src(function))),
        ]
        .into_iter()
    }
}

// STORE
#[derive(Copy, Clone)]
pub struct Store {
    dest: usize,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStore {
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl Store {
    pub fn new(dest: usize, src: usize) -> Self {
        Self { dest, src }
    }
    pub fn dest(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.dest)
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedStore {
        LiftedStore {
            dest: Box::new(self.dest(function).lift()),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("dest", MediumLevelILOperand::Expr(self.dest(function))),
            ("src", MediumLevelILOperand::Expr(self.src(function))),
        ]
        .into_iter()
    }
}

// JUMP_TO
#[derive(Copy, Clone)]
pub struct JumpTo {
    dest: usize,
    targets: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedJumpTo {
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub targets: HashMap<u64, u64>,
}
impl JumpTo {
    pub fn new(dest: usize, targets: (usize, usize)) -> Self {
        Self { dest, targets }
    }
    pub fn dest(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.dest)
    }
    pub fn targets(&self, function: &MediumLevelILFunction) -> OperandDubleList {
        OperandList::new(function, self.targets.1, self.targets.0).duble()
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedJumpTo {
        LiftedJumpTo {
            dest: Box::new(self.dest(function).lift()),
            targets: self.targets(function).collect(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("dest", Expr(self.dest(function))),
            ("targets", TargetMap(self.targets(function))),
        ]
        .into_iter()
    }
}

// GOTO
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Goto {
    pub dest: u64,
}
impl Goto {
    pub fn new(dest: u64) -> Self {
        Self { dest }
    }
    pub fn dest(&self) -> u64 {
        self.dest
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("dest", MediumLevelILOperand::Int(self.dest()))].into_iter()
    }
}

// FREE_VAR_SLOT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct FreeVarSlot {
    pub dest: Variable,
}
impl FreeVarSlot {
    pub fn new(dest: u64) -> Self {
        Self {
            dest: get_var(dest),
        }
    }
    pub fn dest(&self) -> Variable {
        self.dest
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("dest", MediumLevelILOperand::Var(self.dest()))].into_iter()
    }
}

// SET_VAR_FIELD
#[derive(Copy, Clone)]
pub struct SetVarField {
    dest: u64,
    offset: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarField {
    pub dest: Variable,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarField {
    pub fn new(dest: u64, offset: u64, src: usize) -> Self {
        Self { dest, offset, src }
    }
    pub fn dest(&self) -> Variable {
        get_var(self.dest)
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedSetVarField {
        LiftedSetVarField {
            dest: self.dest(),
            offset: self.offset(),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("dest", MediumLevelILOperand::Var(self.dest())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
            ("src", MediumLevelILOperand::Expr(self.src(function))),
        ]
        .into_iter()
    }
}

// SET_VAR
#[derive(Copy, Clone)]
pub struct SetVar {
    dest: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVar {
    pub dest: Variable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVar {
    pub fn new(dest: u64, src: usize) -> Self {
        Self { dest, src }
    }
    pub fn dest(&self) -> Variable {
        get_var(self.dest)
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedSetVar {
        LiftedSetVar {
            dest: self.dest(),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("dest", MediumLevelILOperand::Var(self.dest())),
            ("src", MediumLevelILOperand::Expr(self.src(function))),
        ]
        .into_iter()
    }
}

// FREE_VAR_SLOT_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct FreeVarSlotSsa {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
}
impl FreeVarSlotSsa {
    pub fn new(dest: (u64, usize), prev: (u64, usize)) -> Self {
        Self {
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
    pub fn lift(self) -> FreeVarSlotSsa {
        FreeVarSlotSsa {
            dest: self.dest(),
            prev: self.prev(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("dest", MediumLevelILOperand::VarSsa(self.dest())),
            ("prev", MediumLevelILOperand::VarSsa(self.prev())),
        ]
        .into_iter()
    }
}

// SET_VAR_SSA_FIELD, SET_VAR_ALIASED_FIELD
#[derive(Copy, Clone)]
pub struct SetVarSsaField {
    dest: (u64, usize),
    prev: (u64, usize),
    offset: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSsaField {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
    pub offset: u64,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarSsaField {
    pub fn new(dest: (u64, usize), prev: (u64, usize), offset: u64, src: usize) -> Self {
        Self {
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
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedSetVarSsaField {
        LiftedSetVarSsaField {
            dest: self.dest(),
            prev: self.prev(),
            offset: self.offset(),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("dest", MediumLevelILOperand::VarSsa(self.dest())),
            ("prev", MediumLevelILOperand::VarSsa(self.prev())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
            ("src", MediumLevelILOperand::Expr(self.src(function))),
        ]
        .into_iter()
    }
}

// SET_VAR_ALIASED
#[derive(Copy, Clone)]
pub struct SetVarAliased {
    dest: (u64, usize),
    prev: (u64, usize),
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarAliased {
    pub dest: SSAVariable,
    pub prev: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarAliased {
    pub fn new(dest: (u64, usize), prev: (u64, usize), src: usize) -> Self {
        Self { dest, prev, src }
    }
    pub fn dest(&self) -> SSAVariable {
        get_var_ssa(self.dest.0, self.dest.1)
    }
    pub fn prev(&self) -> SSAVariable {
        get_var_ssa(self.prev.0, self.prev.1)
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedSetVarAliased {
        LiftedSetVarAliased {
            dest: self.dest(),
            prev: self.prev(),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("dest", MediumLevelILOperand::VarSsa(self.dest())),
            ("prev", MediumLevelILOperand::VarSsa(self.prev())),
            ("src", MediumLevelILOperand::Expr(self.src(function))),
        ]
        .into_iter()
    }
}

// SET_VAR_SSA
#[derive(Copy, Clone)]
pub struct SetVarSsa {
    dest: (u64, usize),
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSsa {
    pub dest: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarSsa {
    pub fn new(dest: (u64, usize), src: usize) -> Self {
        Self { dest, src }
    }
    pub fn dest(&self) -> SSAVariable {
        get_var_ssa(self.dest.0, self.dest.1)
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedSetVarSsa {
        LiftedSetVarSsa {
            dest: self.dest(),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("dest", MediumLevelILOperand::VarSsa(self.dest())),
            ("src", MediumLevelILOperand::Expr(self.src(function))),
        ]
        .into_iter()
    }
}

// VAR_PHI
#[derive(Copy, Clone)]
pub struct VarPhi {
    dest: (u64, usize),
    src: (usize, usize),
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct LiftedVarPhi {
    pub dest: SSAVariable,
    pub src: Vec<SSAVariable>,
}
impl VarPhi {
    pub fn new(dest: (u64, usize), src: (usize, usize)) -> Self {
        Self { dest, src }
    }
    pub fn dest(&self) -> SSAVariable {
        get_var_ssa(self.dest.0, self.dest.1)
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> OperandSSAVariableList {
        OperandList::new(function, self.src.1, self.src.0).map_ssa_var()
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedVarPhi {
        LiftedVarPhi {
            dest: self.dest(),
            src: self.src(function).collect(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("dest", MediumLevelILOperand::VarSsa(self.dest())),
            ("src", MediumLevelILOperand::VarSsaList(self.src(function))),
        ]
        .into_iter()
    }
}

// MEM_PHI
#[derive(Copy, Clone)]
pub struct MemPhi {
    dest_memory: u64,
    src_memory: (usize, usize),
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct LiftedMemPhi {
    pub dest_memory: u64,
    pub src_memory: Vec<u64>,
}
impl MemPhi {
    pub fn new(dest_memory: u64, src_memory: (usize, usize)) -> Self {
        Self {
            dest_memory,
            src_memory,
        }
    }
    pub fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    pub fn src_memory(&self, function: &MediumLevelILFunction) -> OperandList {
        OperandList::new(function, self.src_memory.1, self.src_memory.0)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedMemPhi {
        LiftedMemPhi {
            dest_memory: self.dest_memory(),
            src_memory: self.src_memory(function).collect(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("dest_memory", Int(self.dest_memory())),
            ("src_memory", IntList(self.src_memory(function))),
        ]
        .into_iter()
    }
}

// VAR_SPLIT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSplit {
    pub high: Variable,
    pub low: Variable,
}
impl VarSplit {
    pub fn new(high: u64, low: u64) -> Self {
        Self {
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
    pub fn lift(self) -> VarSplit {
        VarSplit {
            high: self.high(),
            low: self.low(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("high", MediumLevelILOperand::Var(self.high())),
            ("low", MediumLevelILOperand::Var(self.low())),
        ]
        .into_iter()
    }
}

// SET_VAR_SPLIT
#[derive(Copy, Clone)]
pub struct SetVarSplit {
    high: u64,
    low: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSplit {
    pub high: Variable,
    pub low: Variable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarSplit {
    pub fn new(high: u64, low: u64, src: usize) -> Self {
        Self { high, low, src }
    }
    pub fn high(&self) -> Variable {
        get_var(self.high)
    }
    pub fn low(&self) -> Variable {
        get_var(self.low)
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedSetVarSplit {
        LiftedSetVarSplit {
            high: self.high(),
            low: self.low(),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("high", MediumLevelILOperand::Var(self.high())),
            ("low", MediumLevelILOperand::Var(self.low())),
            ("src", MediumLevelILOperand::Expr(self.src(function))),
        ]
        .into_iter()
    }
}

// VAR_SPLIT_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSplitSsa {
    pub high: SSAVariable,
    pub low: SSAVariable,
}
impl VarSplitSsa {
    pub fn new(high: (u64, usize), low: (u64, usize)) -> Self {
        Self {
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
    pub fn lift(self) -> VarSplitSsa {
        VarSplitSsa {
            high: self.high(),
            low: self.low(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("high", MediumLevelILOperand::VarSsa(self.high())),
            ("low", MediumLevelILOperand::VarSsa(self.low())),
        ]
        .into_iter()
    }
}

// SET_VAR_SPLIT_SSA
#[derive(Copy, Clone)]
pub struct SetVarSplitSsa {
    high: (u64, usize),
    low: (u64, usize),
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSetVarSplitSsa {
    pub high: SSAVariable,
    pub low: SSAVariable,
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl SetVarSplitSsa {
    pub fn new(high: (u64, usize), low: (u64, usize), src: usize) -> Self {
        Self { high, low, src }
    }
    pub fn high(&self) -> SSAVariable {
        get_var_ssa(self.high.0, self.high.1)
    }
    pub fn low(&self) -> SSAVariable {
        get_var_ssa(self.low.0, self.low.1)
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedSetVarSplitSsa {
        LiftedSetVarSplitSsa {
            high: self.high(),
            low: self.low(),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("high", MediumLevelILOperand::VarSsa(self.high())),
            ("low", MediumLevelILOperand::VarSsa(self.low())),
            ("src", MediumLevelILOperand::Expr(self.src(function))),
        ]
        .into_iter()
    }
}

// ADD, SUB, AND, OR, XOR, LSL, LSR, ASR, ROL, ROR, MUL, MULU_DP, MULS_DP, DIVU, DIVU_DP, DIVS, DIVS_DP, MODU, MODU_DP, MODS, MODS_DP, CMP_E, CMP_NE, CMP_SLT, CMP_ULT, CMP_SLE, CMP_ULE, CMP_SGE, CMP_UGE, CMP_SGT, CMP_UGT, TEST_BIT, ADD_OVERFLOW, FCMP_E, FCMP_NE, FCMP_LT, FCMP_LE, FCMP_GE, FCMP_GT, FCMP_O, FCMP_UO, FADD, FSUB, FMUL, FDIV
#[derive(Copy, Clone)]
pub struct BinaryOp {
    left: usize,
    right: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOp {
    pub left: Box<MediumLevelILLiftedInstruction>,
    pub right: Box<MediumLevelILLiftedInstruction>,
}
impl BinaryOp {
    pub fn new(left: usize, right: usize) -> Self {
        Self { left, right }
    }
    pub fn left(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.left)
    }
    pub fn right(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.right)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedBinaryOp {
        LiftedBinaryOp {
            left: Box::new(self.left(function).lift()),
            right: Box::new(self.right(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("left", MediumLevelILOperand::Expr(self.left(function))),
            ("right", MediumLevelILOperand::Expr(self.right(function))),
        ]
        .into_iter()
    }
}

// ADC, SBB, RLC, RRC
#[derive(Copy, Clone)]
pub struct BinaryOpCarry {
    left: usize,
    right: usize,
    carry: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOpCarry {
    pub left: Box<MediumLevelILLiftedInstruction>,
    pub right: Box<MediumLevelILLiftedInstruction>,
    pub carry: Box<MediumLevelILLiftedInstruction>,
}
impl BinaryOpCarry {
    pub fn new(left: usize, right: usize, carry: usize) -> Self {
        Self { left, right, carry }
    }
    pub fn left(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.left)
    }
    pub fn right(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.right)
    }
    pub fn carry(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.carry)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedBinaryOpCarry {
        LiftedBinaryOpCarry {
            left: Box::new(self.left(function).lift()),
            right: Box::new(self.right(function).lift()),
            carry: Box::new(self.carry(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("left", MediumLevelILOperand::Expr(self.left(function))),
            ("right", MediumLevelILOperand::Expr(self.right(function))),
            ("carry", MediumLevelILOperand::Expr(self.carry(function))),
        ]
        .into_iter()
    }
}

// CALL, TAILCALL
#[derive(Copy, Clone)]
pub struct Call {
    output: (usize, usize),
    dest: usize,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCall {
    pub output: Vec<Variable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}
impl Call {
    pub fn new(output: (usize, usize), dest: usize, params: (usize, usize)) -> Self {
        Self {
            output,
            dest,
            params,
        }
    }
    pub fn output(&self, function: &MediumLevelILFunction) -> OperandVariableList {
        OperandList::new(function, self.output.1, self.output.0).map_var()
    }
    pub fn dest(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.dest)
    }
    pub fn params(&self, function: &MediumLevelILFunction) -> OperandExprList {
        OperandList::new(function, self.params.1, self.params.0).map_expr()
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedCall {
        LiftedCall {
            output: self.output(function).collect(),
            dest: Box::new(self.dest(function).lift()),
            params: self.params(function).map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            (
                "output",
                MediumLevelILOperand::VarList(self.output(function)),
            ),
            ("dest", MediumLevelILOperand::Expr(self.dest(function))),
            (
                "params",
                MediumLevelILOperand::ExprList(self.params(function)),
            ),
        ]
        .into_iter()
    }
}

// SYSCALL
#[derive(Copy, Clone)]
pub struct Syscall {
    output: (usize, usize),
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedInnerCall {
    pub output: Vec<Variable>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}
impl Syscall {
    pub fn new(output: (usize, usize), params: (usize, usize)) -> Self {
        Self { output, params }
    }
    pub fn output(&self, function: &MediumLevelILFunction) -> OperandVariableList {
        OperandList::new(function, self.output.1, self.output.0).map_var()
    }
    pub fn params(&self, function: &MediumLevelILFunction) -> OperandExprList {
        OperandList::new(function, self.params.1, self.params.0).map_expr()
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedInnerCall {
        LiftedInnerCall {
            output: self.output(function).collect(),
            params: self.params(function).map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("output", VarList(self.output(function))),
            ("params", ExprList(self.params(function))),
        ]
        .into_iter()
    }
}

// INTRINSIC
#[derive(Copy, Clone)]
pub struct Intrinsic {
    output: (usize, usize),
    intrinsic: usize,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct MediumLevelILLiftedIntrinsic {
    pub output: Vec<Variable>,
    //pub intrinsic: !,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}
impl Intrinsic {
    pub fn new(output: (usize, usize), intrinsic: usize, params: (usize, usize)) -> Self {
        Self {
            output,
            intrinsic,
            params,
        }
    }
    pub fn output(&self, function: &MediumLevelILFunction) -> OperandVariableList {
        OperandList::new(function, self.output.1, self.output.0).map_var()
    }
    pub fn intrinsic(&self, function: &MediumLevelILFunction) -> ! {
        get_intrinsic(function, self.intrinsic)
    }
    pub fn params(&self, function: &MediumLevelILFunction) -> OperandExprList {
        OperandList::new(function, self.params.1, self.params.0).map_expr()
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedInnerCall {
        LiftedInnerCall {
            output: self.output(function).collect(),
            //intrinsic: get_intrinsic(function, self.intrinsic),
            params: self.params(function).map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("output", VarList(self.output(function))),
            //("intrinsic", VarList(self.output(function))),
            ("params", ExprList(self.params(function))),
        ]
        .into_iter()
    }
}

// INTRINSIC_SSA
#[derive(Copy, Clone)]
pub struct IntrinsicSsa {
    output: (usize, usize),
    intrinsic: usize,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsicSsa {
    pub output: Vec<SSAVariable>,
    //pub intrinsic: !,
    pub params: Vec<MediumLevelILLiftedInstruction>,
}
impl IntrinsicSsa {
    pub fn new(output: (usize, usize), intrinsic: usize, params: (usize, usize)) -> Self {
        Self {
            output,
            intrinsic,
            params,
        }
    }
    pub fn output(&self, function: &MediumLevelILFunction) -> OperandSSAVariableList {
        OperandList::new(function, self.output.1, self.output.0).map_ssa_var()
    }
    pub fn intrinsic(&self, function: &MediumLevelILFunction) -> ! {
        get_intrinsic(function, self.intrinsic)
    }
    pub fn params(&self, function: &MediumLevelILFunction) -> OperandExprList {
        OperandList::new(function, self.params.1, self.params.0).map_expr()
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedIntrinsicSsa {
        LiftedIntrinsicSsa {
            output: self.output(function).collect(),
            //intrinsic: get_intrinsic(function, self.intrinsic),
            params: self.params(function).map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("output", VarSsaList(self.output(function))),
            ("params", ExprList(self.params(function))),
        ]
        .into_iter()
    }
}

// CALL_SSA, TAILCALL_SSA
#[derive(Copy, Clone)]
pub struct CallSsa {
    output: usize,
    dest: usize,
    params: (usize, usize),
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallSsa {
    pub output: Vec<SSAVariable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl CallSsa {
    pub fn new(output: usize, dest: usize, params: (usize, usize), src_memory: u64) -> Self {
        Self {
            output,
            dest,
            params,
            src_memory,
        }
    }
    pub fn output(&self, function: &MediumLevelILFunction) -> OperandSSAVariableList {
        get_call_output_ssa(function, self.output)
    }
    pub fn dest(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.dest)
    }
    pub fn params(&self, function: &MediumLevelILFunction) -> OperandExprList {
        OperandList::new(function, self.params.1, self.params.0).map_expr()
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedCallSsa {
        LiftedCallSsa {
            output: self.output(function).collect(),
            dest: Box::new(self.dest(function).lift()),
            params: self.params(function).map(|instr| instr.lift()).collect(),
            src_memory: self.src_memory(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("output", VarSsaList(self.output(function))),
            ("dest", Expr(self.dest(function))),
            ("params", ExprList(self.params(function))),
            ("src_memory", Int(self.src_memory())),
        ]
        .into_iter()
    }
}

// CALL_UNTYPED_SSA, TAILCALL_UNTYPED_SSA
#[derive(Copy, Clone)]
pub struct CallUntypedSsa {
    output: usize,
    dest: usize,
    params: usize,
    stack: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallUntypedSsa {
    pub output: Vec<SSAVariable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<SSAVariable>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}
impl CallUntypedSsa {
    pub fn new(output: usize, dest: usize, params: usize, stack: usize) -> Self {
        Self {
            output,
            dest,
            params,
            stack,
        }
    }
    pub fn output(&self, function: &MediumLevelILFunction) -> OperandSSAVariableList {
        get_call_output_ssa(function, self.output)
    }
    pub fn dest(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.dest)
    }
    pub fn params(&self, function: &MediumLevelILFunction) -> OperandSSAVariableList {
        get_call_params_ssa(function, self.params)
    }
    pub fn stack(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.stack)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedCallUntypedSsa {
        LiftedCallUntypedSsa {
            output: self.output(function).collect(),
            dest: Box::new(self.dest(function).lift()),
            params: self.params(function).collect(),
            stack: Box::new(self.stack(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("output", VarSsaList(self.output(function))),
            ("dest", Expr(self.dest(function))),
            ("params", VarSsaList(self.params(function))),
            ("stack", Expr(self.stack(function))),
        ]
        .into_iter()
    }
}

// SYSCALL_SSA
#[derive(Copy, Clone)]
pub struct SyscallSsa {
    output: usize,
    params: (usize, usize),
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallSsa {
    pub output: Vec<SSAVariable>,
    pub params: Vec<MediumLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl SyscallSsa {
    pub fn new(output: usize, params: (usize, usize), src_memory: u64) -> Self {
        Self {
            output,
            params,
            src_memory,
        }
    }
    pub fn output(&self, function: &MediumLevelILFunction) -> OperandSSAVariableList {
        get_call_output_ssa(function, self.output)
    }
    pub fn params(&self, function: &MediumLevelILFunction) -> OperandExprList {
        OperandList::new(function, self.params.1, self.params.0).map_expr()
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedSyscallSsa {
        LiftedSyscallSsa {
            output: self.output(function).collect(),
            params: self.params(function).map(|instr| instr.lift()).collect(),
            src_memory: self.src_memory(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("output", VarSsaList(self.output(function))),
            ("params", ExprList(self.params(function))),
            ("src_memory", MediumLevelILOperand::Int(self.src_memory())),
        ]
        .into_iter()
    }
}

// SYSCALL_UNTYPED_SSA
#[derive(Copy, Clone)]
pub struct SyscallUntypedSsa {
    output: usize,
    params: usize,
    stack: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallUntypedSsa {
    pub output: Vec<SSAVariable>,
    pub params: Vec<SSAVariable>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}
impl SyscallUntypedSsa {
    pub fn new(output: usize, params: usize, stack: usize) -> Self {
        Self {
            output,
            params,
            stack,
        }
    }
    pub fn output(&self, function: &MediumLevelILFunction) -> OperandSSAVariableList {
        get_call_output_ssa(function, self.output)
    }
    pub fn params(&self, function: &MediumLevelILFunction) -> OperandSSAVariableList {
        get_call_params_ssa(function, self.params)
    }
    pub fn stack(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.stack)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedSyscallUntypedSsa {
        LiftedSyscallUntypedSsa {
            output: self.output(function).collect(),
            params: self.params(function).collect(),
            stack: Box::new(self.stack(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("output", VarSsaList(self.output(function))),
            ("params", VarSsaList(self.params(function))),
            ("stack", Expr(self.stack(function))),
        ]
        .into_iter()
    }
}

// CALL_UNTYPED, TAILCALL_UNTYPED
#[derive(Copy, Clone)]
pub struct CallUntyped {
    output: usize,
    dest: usize,
    params: usize,
    stack: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallUntyped {
    pub output: Vec<Variable>,
    pub dest: Box<MediumLevelILLiftedInstruction>,
    pub params: Vec<Variable>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}
impl CallUntyped {
    pub fn new(output: usize, dest: usize, params: usize, stack: usize) -> Self {
        Self {
            output,
            dest,
            params,
            stack,
        }
    }
    pub fn output(&self, function: &MediumLevelILFunction) -> OperandVariableList {
        get_call_output(function, self.output)
    }
    pub fn dest(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.dest)
    }
    pub fn params(&self, function: &MediumLevelILFunction) -> OperandVariableList {
        get_call_params(function, self.params)
    }
    pub fn stack(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.stack)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedCallUntyped {
        LiftedCallUntyped {
            output: self.output(function).collect(),
            dest: Box::new(self.dest(function).lift()),
            params: self.params(function).collect(),
            stack: Box::new(self.stack(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("output", VarList(self.output(function))),
            ("dest", Expr(self.dest(function))),
            ("params", VarList(self.params(function))),
            ("stack", Expr(self.stack(function))),
        ]
        .into_iter()
    }
}

// SYSCALL_UNTYPED
#[derive(Copy, Clone)]
pub struct SyscallUntyped {
    output: usize,
    params: usize,
    stack: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallUntyped {
    pub output: Vec<Variable>,
    pub params: Vec<Variable>,
    pub stack: Box<MediumLevelILLiftedInstruction>,
}
impl SyscallUntyped {
    pub fn new(output: usize, params: usize, stack: usize) -> Self {
        Self {
            output,
            params,
            stack,
        }
    }
    pub fn output(&self, function: &MediumLevelILFunction) -> OperandVariableList {
        get_call_output(function, self.output)
    }
    pub fn params(&self, function: &MediumLevelILFunction) -> OperandVariableList {
        get_call_params(function, self.params)
    }
    pub fn stack(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.stack)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedSyscallUntyped {
        LiftedSyscallUntyped {
            output: self.output(function).collect(),
            params: self.params(function).collect(),
            stack: Box::new(self.stack(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        use MediumLevelILOperand::*;
        [
            ("output", VarList(self.output(function))),
            ("params", VarList(self.params(function))),
            ("stack", Expr(self.stack(function))),
        ]
        .into_iter()
    }
}

// NEG, NOT, SX, ZX, LOW_PART, BOOL_TO_INT, UNIMPL_MEM, FSQRT, FNEG, FABS, FLOAT_TO_INT, INT_TO_FLOAT, FLOAT_CONV, ROUND_TO_INT, FLOOR, CEIL, FTRUNC, LOAD
#[derive(Copy, Clone)]
pub struct UnaryOp {
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedUnaryOp {
    pub src: Box<MediumLevelILLiftedInstruction>,
}
impl UnaryOp {
    pub fn new(src: usize) -> Self {
        Self { src }
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedUnaryOp {
        LiftedUnaryOp {
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("src", MediumLevelILOperand::Expr(self.src(function)))].into_iter()
    }
}

// LOAD_STRUCT
#[derive(Copy, Clone)]
pub struct LoadStruct {
    src: usize,
    offset: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedLoadStruct {
    pub src: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
}
impl LoadStruct {
    pub fn new(src: usize, offset: u64) -> Self {
        Self { src, offset }
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedLoadStruct {
        LiftedLoadStruct {
            src: Box::new(self.src(function).lift()),
            offset: self.offset(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("src", MediumLevelILOperand::Expr(self.src(function))),
            ("offset", MediumLevelILOperand::Int(self.offset())),
        ]
        .into_iter()
    }
}

// LOAD_STRUCT_SSA
#[derive(Copy, Clone)]
pub struct LoadStructSsa {
    src: usize,
    offset: u64,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedLoadStructSsa {
    pub src: Box<MediumLevelILLiftedInstruction>,
    pub offset: u64,
    pub src_memory: u64,
}
impl LoadStructSsa {
    pub fn new(src: usize, offset: u64, src_memory: u64) -> Self {
        Self {
            src,
            offset,
            src_memory,
        }
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedLoadStructSsa {
        LiftedLoadStructSsa {
            src: Box::new(self.src(function).lift()),
            offset: self.offset(),
            src_memory: self.src_memory(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("src", MediumLevelILOperand::Expr(self.src(function))),
            ("offset", MediumLevelILOperand::Int(self.offset())),
            ("src_memory", MediumLevelILOperand::Int(self.src_memory())),
        ]
        .into_iter()
    }
}

// LOAD_SSA
#[derive(Copy, Clone)]
pub struct LoadSsa {
    src: usize,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedLoadSsa {
    pub src: Box<MediumLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl LoadSsa {
    pub fn new(src: usize, src_memory: u64) -> Self {
        Self { src, src_memory }
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> MediumLevelILInstruction {
        get_operation(function, self.src)
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedLoadSsa {
        LiftedLoadSsa {
            src: Box::new(self.src(function).lift()),
            src_memory: self.src_memory(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("src", MediumLevelILOperand::Expr(self.src(function))),
            ("src_memory", MediumLevelILOperand::Int(self.src_memory())),
        ]
        .into_iter()
    }
}

// RET
#[derive(Copy, Clone)]
pub struct Ret {
    src: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedRet {
    pub src: Vec<MediumLevelILLiftedInstruction>,
}
impl Ret {
    pub fn new(src: (usize, usize)) -> Self {
        Self { src }
    }
    pub fn src(&self, function: &MediumLevelILFunction) -> OperandExprList {
        OperandList::new(function, self.src.1, self.src.0).map_expr()
    }
    pub fn lift(&self, function: &MediumLevelILFunction) -> LiftedRet {
        LiftedRet {
            src: self.src(function).map(|instr| instr.lift()).collect(),
        }
    }
    pub fn operands(
        &self,
        function: &MediumLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("src", MediumLevelILOperand::ExprList(self.src(function)))].into_iter()
    }
}

// VAR, ADDRESS_OF
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Var {
    pub src: Variable,
}
impl Var {
    pub fn new(src: u64) -> Self {
        Self { src: get_var(src) }
    }
    pub fn src(&self) -> Variable {
        self.src
    }
    pub fn operands(
        &self,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("src", MediumLevelILOperand::Var(self.src()))].into_iter()
    }
}

// VAR_FIELD, ADDRESS_OF_FIELD
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Field {
    pub src: Variable,
    pub offset: u64,
}
impl Field {
    pub fn new(src: u64, offset: u64) -> Self {
        Self {
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
    pub fn operands(
        &self,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("src", MediumLevelILOperand::Var(self.src())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
        ]
        .into_iter()
    }
}

// VAR_SSA, VAR_ALIASED
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsa {
    pub src: SSAVariable,
}
impl VarSsa {
    pub fn new(src: (u64, usize)) -> Self {
        Self {
            src: get_var_ssa(src.0, src.1),
        }
    }
    pub fn src(&self) -> SSAVariable {
        self.src
    }
    pub fn operands(
        &self,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("src", MediumLevelILOperand::VarSsa(self.src()))].into_iter()
    }
}

// VAR_SSA_FIELD, VAR_ALIASED_FIELD
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsaField {
    pub src: SSAVariable,
    pub offset: u64,
}
impl VarSsaField {
    pub fn new(src: (u64, usize), offset: u64) -> Self {
        Self {
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
    pub fn operands(
        &self,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [
            ("src", MediumLevelILOperand::VarSsa(self.src())),
            ("offset", MediumLevelILOperand::Int(self.offset())),
        ]
        .into_iter()
    }
}

// TRAP
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Trap {
    pub vector: u64,
}
impl Trap {
    pub fn new(vector: u64) -> Self {
        Self { vector }
    }
    pub fn vector(&self) -> u64 {
        self.vector
    }
    pub fn operands(
        &self,
    ) -> impl Iterator<Item = (&'static str, MediumLevelILOperand)> {
        [("vector", MediumLevelILOperand::Int(self.vector()))].into_iter()
    }
}
