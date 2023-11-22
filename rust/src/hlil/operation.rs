use binaryninjacore_sys::BNFromVariableIdentifier;
use binaryninjacore_sys::BNGetGotoLabelName;
use binaryninjacore_sys::BNGetHighLevelILByIndex;
use binaryninjacore_sys::BNHighLevelILInstruction;
use binaryninjacore_sys::BNHighLevelILOperation;

use crate::function::Function;
use crate::rc::Ref;
use crate::types::{
    ConstantData, ILIntrinsic, RegisterValue, RegisterValueType, SSAVariable, Variable,
};

use super::{HighLevelILFunction, HighLevelILInstruction, HighLevelILLiftedInstruction};

pub enum HighLevelILOperand {
    ConstantData(ConstantData),
    Expr(HighLevelILInstruction),
    ExprList(OperandExprList),
    Float(f64),
    Int(u64),
    IntList(OperandList),
    Intrinsic(ILIntrinsic),
    Label(GotoLabel),
    MemberIndex(Option<usize>),
    Var(Variable),
    VarSsa(SSAVariable),
    VarSsaList(OperandSSAVariableList),
}

// Iterator for the get_list, this is better then a inline iterator because
// this also implement ExactSizeIterator, what a inline iterator does not.
pub struct OperandList {
    function: Ref<HighLevelILFunction>,
    remaining: usize,
    next_node_idx: Option<usize>,

    current_node: core::array::IntoIter<u64, 4>,
}
impl OperandList {
    fn new(function: &HighLevelILFunction, idx: usize, number: usize) -> Self {
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
    fn double(self) -> OperandDubleList {
        assert_eq!(self.len() % 2, 0);
        OperandDubleList(self)
    }
    fn map_expr(self) -> OperandExprList {
        OperandExprList(self)
    }
    fn map_ssa_var(self) -> OperandSSAVariableList {
        OperandSSAVariableList(self.double())
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
        let node = get_raw_operation(&self.function, next_idx);
        assert_eq!(node.operation, BNHighLevelILOperation::HLIL_UNDEF);

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
    type Item = HighLevelILInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|idx| get_instruction(&self.0.function, idx as usize))
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

fn get_instruction(function: &HighLevelILFunction, idx: usize) -> HighLevelILInstruction {
    function.instruction_from_idx(idx)
}

fn get_instruction_list(function: &HighLevelILFunction, list: (usize, usize)) -> OperandExprList {
    OperandList::new(function, list.1, list.0).map_expr()
}

fn get_int_list(function: &HighLevelILFunction, list: (usize, usize)) -> OperandList {
    OperandList::new(function, list.1, list.0)
}

fn get_raw_operation(function: &HighLevelILFunction, idx: usize) -> BNHighLevelILInstruction {
    unsafe { BNGetHighLevelILByIndex(function.handle, idx, function.full_ast) }
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

fn get_var_ssa_list(
    function: &HighLevelILFunction,
    list: (usize, usize),
) -> OperandSSAVariableList {
    OperandList::new(function, list.1, list.0).map_ssa_var()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GotoLabel {
    function: Ref<Function>,
    target: u64,
}

impl GotoLabel {
    pub fn name(&self) -> &str {
        let raw_str = unsafe { BNGetGotoLabelName(self.function.handle, self.target) };
        let c_str = unsafe { core::ffi::CStr::from_ptr(raw_str) };
        c_str.to_str().unwrap()
    }
}

// ADC, SBB, RLC, RRC
#[derive(Clone)]
pub struct BinaryOpCarry {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    left: usize,
    right: usize,
    carry: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOpCarry {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub left: Box<HighLevelILLiftedInstruction>,
    pub right: Box<HighLevelILLiftedInstruction>,
    pub carry: Box<HighLevelILLiftedInstruction>,
}
impl BinaryOpCarry {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
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
    pub fn left(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.left)
    }
    pub fn right(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.right)
    }
    pub fn carry(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.carry)
    }
    pub fn lift(&self) -> LiftedBinaryOpCarry {
        LiftedBinaryOpCarry {
            function: self.function.to_owned(),
            address: self.address,
            left: Box::new(self.left().lift()),
            right: Box::new(self.right().lift()),
            carry: Box::new(self.carry().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("left", Expr(self.left())),
            1usize => ("right", Expr(self.right())),
            2usize => ("carry", Expr(self.carry())),
            _ => unreachable!(),
        })
    }
}
// ADD, SUB, AND, OR, XOR, LSL, LSR, ASR, ROL, ROR, MUL, MULU_DP, MULS_DP, DIVU, DIVU_DP, DIVS, DIVS_DP, MODU, MODU_DP, MODS, MODS_DP, CMP_E, CMP_NE, CMP_SLT, CMP_ULT, CMP_SLE, CMP_ULE, CMP_SGE, CMP_UGE, CMP_SGT, CMP_UGT, TEST_BIT, ADD_OVERFLOW, FADD, FSUB, FMUL, FDIV, FCMP_E, FCMP_NE, FCMP_LT, FCMP_LE, FCMP_GE, FCMP_GT, FCMP_O, FCMP_UO
#[derive(Clone)]
pub struct BinaryOp {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    left: usize,
    right: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOp {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub left: Box<HighLevelILLiftedInstruction>,
    pub right: Box<HighLevelILLiftedInstruction>,
}
impl BinaryOp {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
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
    pub fn left(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.left)
    }
    pub fn right(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.right)
    }
    pub fn lift(&self) -> LiftedBinaryOp {
        LiftedBinaryOp {
            function: self.function.to_owned(),
            address: self.address,
            left: Box::new(self.left().lift()),
            right: Box::new(self.right().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("left", Expr(self.left())),
            1usize => ("right", Expr(self.right())),
            _ => unreachable!(),
        })
    }
}
// ARRAY_INDEX
#[derive(Clone)]
pub struct ArrayIndex {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    src: usize,
    index: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedArrayIndex {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub index: Box<HighLevelILLiftedInstruction>,
}
impl ArrayIndex {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        src: usize,
        index: usize,
    ) -> Self {
        Self {
            function,
            address,
            src,
            index,
        }
    }
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn index(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.index)
    }
    pub fn lift(&self) -> LiftedArrayIndex {
        LiftedArrayIndex {
            function: self.function.to_owned(),
            address: self.address,
            src: Box::new(self.src().lift()),
            index: Box::new(self.index().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("src", Expr(self.src())),
            1usize => ("index", Expr(self.index())),
            _ => unreachable!(),
        })
    }
}
// ARRAY_INDEX_SSA
#[derive(Clone)]
pub struct ArrayIndexSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    src: usize,
    src_memory: u64,
    index: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedArrayIndexSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
    pub index: Box<HighLevelILLiftedInstruction>,
}
impl ArrayIndexSsa {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        src: usize,
        src_memory: u64,
        index: usize,
    ) -> Self {
        Self {
            function,
            address,
            src,
            src_memory,
            index,
        }
    }
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn index(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.index)
    }
    pub fn lift(&self) -> LiftedArrayIndexSsa {
        LiftedArrayIndexSsa {
            function: self.function.to_owned(),
            address: self.address,
            src: Box::new(self.src().lift()),
            src_memory: self.src_memory,
            index: Box::new(self.index().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("src", Expr(self.src())),
            1usize => ("src_memory", Int(self.src_memory())),
            2usize => ("index", Expr(self.index())),
            _ => unreachable!(),
        })
    }
}
// ASSIGN
#[derive(Clone)]
pub struct Assign {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    dest: usize,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssign {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub src: Box<HighLevelILLiftedInstruction>,
}
impl Assign {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
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
    pub fn dest(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.dest)
    }
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedAssign {
        LiftedAssign {
            function: self.function.to_owned(),
            address: self.address,
            dest: Box::new(self.dest().lift()),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", Expr(self.dest())),
            1usize => ("src", Expr(self.src())),
            _ => unreachable!(),
        })
    }
}
// ASSIGN_MEM_SSA
#[derive(Clone)]
pub struct AssignMemSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    dest: usize,
    dest_memory: u64,
    src: usize,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignMemSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl AssignMemSsa {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        dest: usize,
        dest_memory: u64,
        src: usize,
        src_memory: u64,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            dest_memory,
            src,
            src_memory,
        }
    }
    pub fn dest(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.dest)
    }
    pub fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self) -> LiftedAssignMemSsa {
        LiftedAssignMemSsa {
            function: self.function.to_owned(),
            address: self.address,
            dest: Box::new(self.dest().lift()),
            dest_memory: self.dest_memory,
            src: Box::new(self.src().lift()),
            src_memory: self.src_memory,
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("dest", Expr(self.dest())),
            1usize => ("dest_memory", Int(self.dest_memory())),
            2usize => ("src", Expr(self.src())),
            3usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
    }
}
// ASSIGN_UNPACK
#[derive(Clone)]
pub struct AssignUnpack {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    dest: (usize, usize),
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignUnpack {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub dest: Vec<HighLevelILLiftedInstruction>,
    pub src: Box<HighLevelILLiftedInstruction>,
}
impl AssignUnpack {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        dest: (usize, usize),
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            src,
        }
    }
    pub fn dest(&self) -> OperandExprList {
        get_instruction_list(&self.function, self.dest)
    }
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedAssignUnpack {
        LiftedAssignUnpack {
            function: self.function.to_owned(),
            address: self.address,
            dest: self.dest().map(|x| x.lift()).collect(),
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", ExprList(self.dest())),
            1usize => ("src", Expr(self.src())),
            _ => unreachable!(),
        })
    }
}
// ASSIGN_UNPACK_MEM_SSA
#[derive(Clone)]
pub struct AssignUnpackMemSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    dest: (usize, usize),
    dest_memory: u64,
    src: usize,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignUnpackMemSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub dest: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl AssignUnpackMemSsa {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        dest: (usize, usize),
        dest_memory: u64,
        src: usize,
        src_memory: u64,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            dest_memory,
            src,
            src_memory,
        }
    }
    pub fn dest(&self) -> OperandExprList {
        get_instruction_list(&self.function, self.dest)
    }
    pub fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self) -> LiftedAssignUnpackMemSsa {
        LiftedAssignUnpackMemSsa {
            function: self.function.to_owned(),
            address: self.address,
            dest: self.dest().map(|x| x.lift()).collect(),
            dest_memory: self.dest_memory,
            src: Box::new(self.src().lift()),
            src_memory: self.src_memory,
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("dest", ExprList(self.dest())),
            1usize => ("dest_memory", Int(self.dest_memory())),
            2usize => ("src", Expr(self.src())),
            3usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
    }
}
// BLOCK
#[derive(Clone)]
pub struct Block {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    body: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBlock {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub body: Vec<HighLevelILLiftedInstruction>,
}
impl Block {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        body: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            body,
        }
    }
    pub fn body(&self) -> OperandExprList {
        get_instruction_list(&self.function, self.body)
    }
    pub fn lift(&self) -> LiftedBlock {
        LiftedBlock {
            function: self.function.to_owned(),
            address: self.address,
            body: self.body().map(|x| x.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("body", ExprList(self.body())),
            _ => unreachable!(),
        })
    }
}
// CALL, TAILCALL
#[derive(Clone)]
pub struct Call {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    dest: usize,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCall {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub params: Vec<HighLevelILLiftedInstruction>,
}
impl Call {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        dest: usize,
        params: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            dest,
            params,
        }
    }
    pub fn dest(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.dest)
    }
    pub fn params(&self) -> OperandExprList {
        get_instruction_list(&self.function, self.params)
    }
    pub fn lift(&self) -> LiftedCall {
        LiftedCall {
            function: self.function.to_owned(),
            address: self.address,
            dest: Box::new(self.dest().lift()),
            params: self.params().map(|x| x.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", Expr(self.dest())),
            1usize => ("params", ExprList(self.params())),
            _ => unreachable!(),
        })
    }
}
// CALL_SSA
#[derive(Clone)]
pub struct CallSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    dest: usize,
    params: (usize, usize),
    dest_memory: u64,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub params: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
}
impl CallSsa {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        dest: usize,
        params: (usize, usize),
        dest_memory: u64,
        src_memory: u64,
    ) -> Self {
        Self {
            function,
            address,
            dest,
            params,
            dest_memory,
            src_memory,
        }
    }
    pub fn dest(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.dest)
    }
    pub fn params(&self) -> OperandExprList {
        get_instruction_list(&self.function, self.params)
    }
    pub fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self) -> LiftedCallSsa {
        LiftedCallSsa {
            function: self.function.to_owned(),
            address: self.address,
            dest: Box::new(self.dest().lift()),
            params: self.params().map(|x| x.lift()).collect(),
            dest_memory: self.dest_memory,
            src_memory: self.src_memory,
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("dest", Expr(self.dest())),
            1usize => ("params", ExprList(self.params())),
            2usize => ("dest_memory", Int(self.dest_memory())),
            3usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
    }
}
// CASE
#[derive(Clone)]
pub struct Case {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    values: (usize, usize),
    body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCase {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub values: Vec<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}
impl Case {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        values: (usize, usize),
        body: usize,
    ) -> Self {
        Self {
            function,
            address,
            values,
            body,
        }
    }
    pub fn values(&self) -> OperandExprList {
        get_instruction_list(&self.function, self.values)
    }
    pub fn body(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.body)
    }
    pub fn lift(&self) -> LiftedCase {
        LiftedCase {
            function: self.function.to_owned(),
            address: self.address,
            values: self.values().map(|x| x.lift()).collect(),
            body: Box::new(self.body().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("values", ExprList(self.values())),
            1usize => ("body", Expr(self.body())),
            _ => unreachable!(),
        })
    }
}
// CONST, CONST_PTR, IMPORT
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Const {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub constant: u64,
}
impl Const {
    pub(crate) fn new(function: Ref<HighLevelILFunction>, address: u64, constant: u64) -> Self {
        Self {
            function,
            address,
            constant,
        }
    }
    pub fn constant(&self) -> u64 {
        self.constant
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("constant", Int(self.constant())),
            _ => unreachable!(),
        })
    }
}
// CONST_DATA
#[derive(Clone)]
pub struct ConstData {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    constant_data: (u32, u64, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedConstantData {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub constant_data: ConstantData,
}
impl ConstData {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        constant_data: (u32, u64, usize),
    ) -> Self {
        Self {
            function,
            address,
            constant_data,
        }
    }
    pub fn constant_data(&self) -> ConstantData {
        let register_value = RegisterValue {
            state: RegisterValueType::from_raw_value(self.constant_data.0).unwrap(),
            value: self.constant_data.1 as i64,
            offset: 0,
            size: self.constant_data.2,
        };
        ConstantData::new(self.function.get_function(), register_value)
    }
    pub fn lift(&self) -> LiftedConstantData {
        LiftedConstantData {
            function: self.function.to_owned(),
            address: self.address,
            constant_data: self.constant_data(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("constant_data", ConstantData(self.constant_data())),
            _ => unreachable!(),
        })
    }
}
// DEREF, ADDRESS_OF, NEG, NOT, SX, ZX, LOW_PART, BOOL_TO_INT, UNIMPL_MEM, FSQRT, FNEG, FABS, FLOAT_TO_INT, INT_TO_FLOAT, FLOAT_CONV, ROUND_TO_INT, FLOOR, CEIL, FTRUNC
#[derive(Clone)]
pub struct UnaryOp {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedUnaryOp {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
}
impl UnaryOp {
    pub(crate) fn new(function: Ref<HighLevelILFunction>, address: u64, src: usize) -> Self {
        Self {
            function,
            address,
            src,
        }
    }
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedUnaryOp {
        LiftedUnaryOp {
            function: self.function.to_owned(),
            address: self.address,
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("src", Expr(self.src())),
            _ => unreachable!(),
        })
    }
}
// DEREF_FIELD_SSA
#[derive(Clone)]
pub struct DerefFieldSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    src: usize,
    src_memory: u64,
    offset: u64,
    member_index: Option<usize>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedDerefFieldSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
    pub offset: u64,
    pub member_index: Option<usize>,
}
impl DerefFieldSsa {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        src: usize,
        src_memory: u64,
        offset: u64,
        member_index: u64,
    ) -> Self {
        Self {
            function,
            address,
            src,
            src_memory,
            offset,
            member_index: get_member_index(member_index),
        }
    }
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn member_index(&self) -> Option<usize> {
        self.member_index
    }
    pub fn lift(&self) -> LiftedDerefFieldSsa {
        LiftedDerefFieldSsa {
            function: self.function.to_owned(),
            address: self.address,
            src: Box::new(self.src().lift()),
            src_memory: self.src_memory,
            offset: self.offset,
            member_index: self.member_index,
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("src", Expr(self.src())),
            1usize => ("src_memory", Int(self.src_memory())),
            2usize => ("offset", Int(self.offset())),
            3usize => ("member_index", MemberIndex(self.member_index())),
            _ => unreachable!(),
        })
    }
}
// DEREF_SSA
#[derive(Clone)]
pub struct DerefSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    src: usize,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedDerefSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl DerefSsa {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
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
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self) -> LiftedDerefSsa {
        LiftedDerefSsa {
            function: self.function.to_owned(),
            address: self.address,
            src: Box::new(self.src().lift()),
            src_memory: self.src_memory,
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("src", Expr(self.src())),
            1usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
    }
}
// EXTERN_PTR
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ExternPtr {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub constant: u64,
    pub offset: u64,
}
impl ExternPtr {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
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
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("constant", Int(self.constant())),
            1usize => ("offset", Int(self.offset())),
            _ => unreachable!(),
        })
    }
}
// FLOAT_CONST
#[derive(Clone, Debug, PartialEq)]
pub struct FloatConst {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub constant: f64,
}
impl FloatConst {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
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
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("constant", Float(self.constant())),
            _ => unreachable!(),
        })
    }
}
// FOR
#[derive(Clone)]
pub struct ForLoop {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    init: usize,
    condition: usize,
    update: usize,
    body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedForLoop {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub init: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub update: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}
impl ForLoop {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        init: usize,
        condition: usize,
        update: usize,
        body: usize,
    ) -> Self {
        Self {
            function,
            address,
            init,
            condition,
            update,
            body,
        }
    }
    pub fn init(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.init)
    }
    pub fn condition(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.condition)
    }
    pub fn update(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.update)
    }
    pub fn body(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.body)
    }
    pub fn lift(&self) -> LiftedForLoop {
        LiftedForLoop {
            function: self.function.to_owned(),
            address: self.address,
            init: Box::new(self.init().lift()),
            condition: Box::new(self.condition().lift()),
            update: Box::new(self.update().lift()),
            body: Box::new(self.body().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("init", Expr(self.init())),
            1usize => ("condition", Expr(self.condition())),
            2usize => ("update", Expr(self.update())),
            3usize => ("body", Expr(self.body())),
            _ => unreachable!(),
        })
    }
}
// FOR_SSA
#[derive(Clone)]
pub struct ForLoopSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    init: usize,
    condition_phi: usize,
    condition: usize,
    update: usize,
    body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedForLoopSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub init: Box<HighLevelILLiftedInstruction>,
    pub condition_phi: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub update: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}
impl ForLoopSsa {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        init: usize,
        condition_phi: usize,
        condition: usize,
        update: usize,
        body: usize,
    ) -> Self {
        Self {
            function,
            address,
            init,
            condition_phi,
            condition,
            update,
            body,
        }
    }
    pub fn init(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.init)
    }
    pub fn condition_phi(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.condition_phi)
    }
    pub fn condition(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.condition)
    }
    pub fn update(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.update)
    }
    pub fn body(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.body)
    }
    pub fn lift(&self) -> LiftedForLoopSsa {
        LiftedForLoopSsa {
            function: self.function.to_owned(),
            address: self.address,
            init: Box::new(self.init().lift()),
            condition_phi: Box::new(self.condition_phi().lift()),
            condition: Box::new(self.condition().lift()),
            update: Box::new(self.update().lift()),
            body: Box::new(self.body().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..5usize).map(move |i| match i {
            0usize => ("init", Expr(self.init())),
            1usize => ("condition_phi", Expr(self.condition_phi())),
            2usize => ("condition", Expr(self.condition())),
            3usize => ("update", Expr(self.update())),
            4usize => ("body", Expr(self.body())),
            _ => unreachable!(),
        })
    }
}
// GOTO, LABEL
#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub target: u64,
}
impl Label {
    pub(crate) fn new(function: Ref<HighLevelILFunction>, address: u64, target: u64) -> Self {
        Self {
            function,
            address,
            target,
        }
    }
    pub fn target(&self) -> GotoLabel {
        GotoLabel {
            function: self.function.get_function(),
            target: self.target,
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("target", Label(self.target())),
            _ => unreachable!(),
        })
    }
}
// IF
#[derive(Clone)]
pub struct If {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    condition: usize,
    cond_true: usize,
    cond_false: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIf {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub cond_true: Box<HighLevelILLiftedInstruction>,
    pub cond_false: Box<HighLevelILLiftedInstruction>,
}
impl If {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        condition: usize,
        cond_true: usize,
        cond_false: usize,
    ) -> Self {
        Self {
            function,
            address,
            condition,
            cond_true,
            cond_false,
        }
    }
    pub fn condition(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.condition)
    }
    pub fn cond_true(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.cond_true)
    }
    pub fn cond_false(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.cond_false)
    }
    pub fn lift(&self) -> LiftedIf {
        LiftedIf {
            function: self.function.to_owned(),
            address: self.address,
            condition: Box::new(self.condition().lift()),
            cond_true: Box::new(self.cond_true().lift()),
            cond_false: Box::new(self.cond_false().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("condition", Expr(self.condition())),
            1usize => ("cond_true", Expr(self.cond_true())),
            2usize => ("cond_false", Expr(self.cond_false())),
            _ => unreachable!(),
        })
    }
}
// INTRINSIC
#[derive(Clone)]
pub struct Intrinsic {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    intrinsic: u32,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsic {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub intrinsic: ILIntrinsic,
    pub params: Vec<HighLevelILLiftedInstruction>,
}
impl Intrinsic {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        intrinsic: u32,
        params: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            intrinsic,
            params,
        }
    }
    pub fn intrinsic(&self) -> ILIntrinsic {
        ILIntrinsic::new(self.function.get_function().arch(), self.intrinsic)
    }
    pub fn params(&self) -> OperandExprList {
        get_instruction_list(&self.function, self.params)
    }
    pub fn lift(&self) -> LiftedIntrinsic {
        LiftedIntrinsic {
            function: self.function.to_owned(),
            address: self.address,
            intrinsic: self.intrinsic(),
            params: self.params().map(|x| x.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("intrinsic", Intrinsic(self.intrinsic())),
            1usize => ("params", ExprList(self.params())),
            _ => unreachable!(),
        })
    }
}
// INTRINSIC_SSA
#[derive(Clone)]
pub struct IntrinsicSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    intrinsic: u32,
    params: (usize, usize),
    dest_memory: u64,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsicSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub intrinsic: ILIntrinsic,
    pub params: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
}
impl IntrinsicSsa {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        intrinsic: u32,
        params: (usize, usize),
        dest_memory: u64,
        src_memory: u64,
    ) -> Self {
        Self {
            function,
            address,
            intrinsic,
            params,
            dest_memory,
            src_memory,
        }
    }
    pub fn intrinsic(&self) -> ILIntrinsic {
        ILIntrinsic::new(self.function.get_function().arch(), self.intrinsic)
    }
    pub fn params(&self) -> OperandExprList {
        get_instruction_list(&self.function, self.params)
    }
    pub fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self) -> LiftedIntrinsicSsa {
        LiftedIntrinsicSsa {
            function: self.function.to_owned(),
            address: self.address,
            intrinsic: self.intrinsic(),
            params: self.params().map(|x| x.lift()).collect(),
            dest_memory: self.dest_memory,
            src_memory: self.src_memory,
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("intrinsic", Intrinsic(self.intrinsic())),
            1usize => ("params", ExprList(self.params())),
            2usize => ("dest_memory", Int(self.dest_memory())),
            3usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
    }
}
// JUMP
#[derive(Clone, Debug, PartialEq)]
pub struct Jump {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub dest: usize,
}
impl Jump {
    pub(crate) fn new(function: Ref<HighLevelILFunction>, address: u64, dest: usize) -> Self {
        Self {
            function,
            address,
            dest,
        }
    }
    pub fn dest(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.dest)
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("dest", Expr(self.dest())),
            _ => unreachable!(),
        })
    }
}
// MEM_PHI
#[derive(Clone)]
pub struct MemPhi {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    dest: u64,
    src: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedMemPhi {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub dest: u64,
    pub src: Vec<u64>,
}
impl MemPhi {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        dest: u64,
        src: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            dest,
            src,
        }
    }
    pub fn dest(&self) -> u64 {
        self.dest
    }
    pub fn src(&self) -> OperandList {
        get_int_list(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedMemPhi {
        LiftedMemPhi {
            function: self.function.to_owned(),
            address: self.address,
            dest: self.dest,
            src: self.src().collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", Int(self.dest())),
            1usize => ("src", IntList(self.src())),
            _ => unreachable!(),
        })
    }
}
// NOP, BREAK, CONTINUE, NORET, UNREACHABLE, BP, UNDEF, UNIMPL
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct NoArgs {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
}
impl NoArgs {
    pub(crate) fn new(function: Ref<HighLevelILFunction>, address: u64) -> Self {
        Self { function, address }
    }
    // NOTE self is not required, it's present just in case data is added to
    // the struct in the future
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        [].into_iter()
    }
}
// RET
#[derive(Clone)]
pub struct Ret {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    src: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedRet {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub src: Vec<HighLevelILLiftedInstruction>,
}
impl Ret {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
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
        get_instruction_list(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedRet {
        LiftedRet {
            function: self.function.to_owned(),
            address: self.address,
            src: self.src().map(|x| x.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("src", ExprList(self.src())),
            _ => unreachable!(),
        })
    }
}
// SPLIT
#[derive(Clone)]
pub struct Split {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    high: usize,
    low: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSplit {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub high: Box<HighLevelILLiftedInstruction>,
    pub low: Box<HighLevelILLiftedInstruction>,
}
impl Split {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        high: usize,
        low: usize,
    ) -> Self {
        Self {
            function,
            address,
            high,
            low,
        }
    }
    pub fn high(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.high)
    }
    pub fn low(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.low)
    }
    pub fn lift(&self) -> LiftedSplit {
        LiftedSplit {
            function: self.function.to_owned(),
            address: self.address,
            high: Box::new(self.high().lift()),
            low: Box::new(self.low().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("high", Expr(self.high())),
            1usize => ("low", Expr(self.low())),
            _ => unreachable!(),
        })
    }
}
// STRUCT_FIELD, DEREF_FIELD
#[derive(Clone)]
pub struct StructField {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    src: usize,
    offset: u64,
    member_index: Option<usize>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStructField {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub offset: u64,
    pub member_index: Option<usize>,
}
impl StructField {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        src: usize,
        offset: u64,
        member_index: u64,
    ) -> Self {
        Self {
            function,
            address,
            src,
            offset,
            member_index: get_member_index(member_index),
        }
    }
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn member_index(&self) -> Option<usize> {
        self.member_index
    }
    pub fn lift(&self) -> LiftedStructField {
        LiftedStructField {
            function: self.function.to_owned(),
            address: self.address,
            src: Box::new(self.src().lift()),
            offset: self.offset,
            member_index: self.member_index,
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("src", Expr(self.src())),
            1usize => ("offset", Int(self.offset())),
            2usize => ("member_index", MemberIndex(self.member_index())),
            _ => unreachable!(),
        })
    }
}
// SWITCH
#[derive(Clone)]
pub struct Switch {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    condition: usize,
    default: usize,
    cases: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSwitch {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub default: Box<HighLevelILLiftedInstruction>,
    pub cases: Vec<HighLevelILLiftedInstruction>,
}
impl Switch {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        condition: usize,
        default: usize,
        cases: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            condition,
            default,
            cases,
        }
    }
    pub fn condition(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.condition)
    }
    pub fn default(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.default)
    }
    pub fn cases(&self) -> OperandExprList {
        get_instruction_list(&self.function, self.cases)
    }
    pub fn lift(&self) -> LiftedSwitch {
        LiftedSwitch {
            function: self.function.to_owned(),
            address: self.address,
            condition: Box::new(self.condition().lift()),
            default: Box::new(self.default().lift()),
            cases: self.cases().map(|x| x.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("condition", Expr(self.condition())),
            1usize => ("default", Expr(self.default())),
            2usize => ("cases", ExprList(self.cases())),
            _ => unreachable!(),
        })
    }
}
// SYSCALL
#[derive(Clone)]
pub struct Syscall {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscall {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub params: Vec<HighLevelILLiftedInstruction>,
}
impl Syscall {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        params: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            params,
        }
    }
    pub fn params(&self) -> OperandExprList {
        get_instruction_list(&self.function, self.params)
    }
    pub fn lift(&self) -> LiftedSyscall {
        LiftedSyscall {
            function: self.function.to_owned(),
            address: self.address,
            params: self.params().map(|x| x.lift()).collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("params", ExprList(self.params())),
            _ => unreachable!(),
        })
    }
}
// SYSCALL_SSA
#[derive(Clone)]
pub struct SyscallSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    params: (usize, usize),
    dest_memory: u64,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub params: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
}
impl SyscallSsa {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        params: (usize, usize),
        dest_memory: u64,
        src_memory: u64,
    ) -> Self {
        Self {
            function,
            address,
            params,
            dest_memory,
            src_memory,
        }
    }
    pub fn params(&self) -> OperandExprList {
        get_instruction_list(&self.function, self.params)
    }
    pub fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    pub fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self) -> LiftedSyscallSsa {
        LiftedSyscallSsa {
            function: self.function.to_owned(),
            address: self.address,
            params: self.params().map(|x| x.lift()).collect(),
            dest_memory: self.dest_memory,
            src_memory: self.src_memory,
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("params", ExprList(self.params())),
            1usize => ("dest_memory", Int(self.dest_memory())),
            2usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
    }
}
// TRAP
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Trap {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub vector: u64,
}
impl Trap {
    pub(crate) fn new(function: Ref<HighLevelILFunction>, address: u64, vector: u64) -> Self {
        Self {
            function,
            address,
            vector,
        }
    }
    pub fn vector(&self) -> u64 {
        self.vector
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("vector", Int(self.vector())),
            _ => unreachable!(),
        })
    }
}
// VAR_DECLARE, VAR
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Var {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub var: Variable,
}
impl Var {
    pub(crate) fn new(function: Ref<HighLevelILFunction>, address: u64, var: u64) -> Self {
        Self {
            function,
            address,
            var: get_var(var),
        }
    }
    pub fn var(&self) -> Variable {
        self.var
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("var", Var(self.var())),
            _ => unreachable!(),
        })
    }
}
// VAR_INIT
#[derive(Clone)]
pub struct VarInit {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    dest: Variable,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedVarInit {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub dest: Variable,
    pub src: Box<HighLevelILLiftedInstruction>,
}
impl VarInit {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        dest: u64,
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest: get_var(dest),
            src,
        }
    }
    pub fn dest(&self) -> Variable {
        self.dest
    }
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedVarInit {
        LiftedVarInit {
            function: self.function.to_owned(),
            address: self.address,
            dest: self.dest,
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", Var(self.dest())),
            1usize => ("src", Expr(self.src())),
            _ => unreachable!(),
        })
    }
}
// VAR_INIT_SSA
#[derive(Clone)]
pub struct VarInitSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    dest: SSAVariable,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedVarInitSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub dest: SSAVariable,
    pub src: Box<HighLevelILLiftedInstruction>,
}
impl VarInitSsa {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        dest: (u64, usize),
        src: usize,
    ) -> Self {
        Self {
            function,
            address,
            dest: get_var_ssa(dest),
            src,
        }
    }
    pub fn dest(&self) -> SSAVariable {
        self.dest
    }
    pub fn src(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedVarInitSsa {
        LiftedVarInitSsa {
            function: self.function.to_owned(),
            address: self.address,
            dest: self.dest,
            src: Box::new(self.src().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", VarSsa(self.dest())),
            1usize => ("src", Expr(self.src())),
            _ => unreachable!(),
        })
    }
}
// VAR_PHI
#[derive(Clone)]
pub struct VarPhi {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    dest: SSAVariable,
    src: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedVarPhi {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub dest: SSAVariable,
    pub src: Vec<SSAVariable>,
}
impl VarPhi {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        dest: (u64, usize),
        src: (usize, usize),
    ) -> Self {
        Self {
            function,
            address,
            dest: get_var_ssa(dest),
            src,
        }
    }
    pub fn dest(&self) -> SSAVariable {
        self.dest
    }
    pub fn src(&self) -> OperandSSAVariableList {
        get_var_ssa_list(&self.function, self.src)
    }
    pub fn lift(&self) -> LiftedVarPhi {
        LiftedVarPhi {
            function: self.function.to_owned(),
            address: self.address,
            dest: self.dest,
            src: self.src().collect(),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", VarSsa(self.dest())),
            1usize => ("src", VarSsaList(self.src())),
            _ => unreachable!(),
        })
    }
}
// VAR_SSA
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub var: SSAVariable,
}
impl VarSsa {
    pub(crate) fn new(function: Ref<HighLevelILFunction>, address: u64, var: (u64, usize)) -> Self {
        Self {
            function,
            address,
            var: get_var_ssa(var),
        }
    }
    pub fn var(&self) -> SSAVariable {
        self.var
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("var", VarSsa(self.var())),
            _ => unreachable!(),
        })
    }
}
// WHILE, DO_WHILE
#[derive(Clone)]
pub struct While {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    condition: usize,
    body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedWhile {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}
impl While {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        condition: usize,
        body: usize,
    ) -> Self {
        Self {
            function,
            address,
            condition,
            body,
        }
    }
    pub fn condition(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.condition)
    }
    pub fn body(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.body)
    }
    pub fn lift(&self) -> LiftedWhile {
        LiftedWhile {
            function: self.function.to_owned(),
            address: self.address,
            condition: Box::new(self.condition().lift()),
            body: Box::new(self.body().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("condition", Expr(self.condition())),
            1usize => ("body", Expr(self.body())),
            _ => unreachable!(),
        })
    }
}
// WHILE_SSA, DO_WHILE_SSA
#[derive(Clone)]
pub struct WhileSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    condition_phi: usize,
    condition: usize,
    body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedWhileSsa {
    pub function: Ref<HighLevelILFunction>,
    pub address: u64,
    pub condition_phi: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}
impl WhileSsa {
    pub(crate) fn new(
        function: Ref<HighLevelILFunction>,
        address: u64,
        condition_phi: usize,
        condition: usize,
        body: usize,
    ) -> Self {
        Self {
            function,
            address,
            condition_phi,
            condition,
            body,
        }
    }
    pub fn condition_phi(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.condition_phi)
    }
    pub fn condition(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.condition)
    }
    pub fn body(&self) -> HighLevelILInstruction {
        get_instruction(&self.function, self.body)
    }
    pub fn lift(&self) -> LiftedWhileSsa {
        LiftedWhileSsa {
            function: self.function.to_owned(),
            address: self.address,
            condition_phi: Box::new(self.condition_phi().lift()),
            condition: Box::new(self.condition().lift()),
            body: Box::new(self.body().lift()),
        }
    }
    pub fn operands(&self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + '_ {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("condition_phi", Expr(self.condition_phi())),
            1usize => ("condition", Expr(self.condition())),
            2usize => ("body", Expr(self.body())),
            _ => unreachable!(),
        })
    }
}
