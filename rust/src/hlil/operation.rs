use binaryninjacore_sys::BNFromVariableIdentifier;
use binaryninjacore_sys::BNGetHighLevelILByIndex;
use binaryninjacore_sys::BNHighLevelILInstruction;
use binaryninjacore_sys::BNHighLevelILOperation;

use crate::rc::Ref;
use crate::types::{SSAVariable, Variable};

use super::{HighLevelILFunction, HighLevelILInstruction, HighLevelILLiftedInstruction};

pub enum HighLevelILOperand {
    ConstantData(()),
    Expr(HighLevelILInstruction),
    ExprList(OperandExprList),
    Float(f64),
    Int(u64),
    IntList(OperandList),
    Intrinsic(()),
    Label(u64),
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
    fn duble(self) -> OperandDubleList {
        assert_eq!(self.len() % 2, 0);
        OperandDubleList(self)
    }
    fn map_expr(self) -> OperandExprList {
        OperandExprList(self)
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

// TODO implement ConstantData
fn get_constant_data(_function: &HighLevelILFunction, _constant_data: (u64, u64, usize)) -> ! {
    todo!()
}

// TODO implement Intrinsic
fn get_intrinsic(_function: &HighLevelILFunction, _idx: u64) -> ! {
    todo!()
}

fn get_instruction(function: &HighLevelILFunction, idx: usize) -> HighLevelILInstruction {
    function.instruction_from_idx(idx)
}

fn get_instruction_list(function: &HighLevelILFunction, list: (usize, usize)) -> OperandExprList {
    OperandList::new(function, list.0, list.1).map_expr()
}

fn get_int_list(function: &HighLevelILFunction, list: (usize, usize)) -> OperandList {
    OperandList::new(function, list.0, list.1)
}

fn get_raw_operation(function: &HighLevelILFunction, idx: usize) -> BNHighLevelILInstruction {
    // TODO full_ast configuration
    unsafe { BNGetHighLevelILByIndex(function.handle, idx, true) }
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
    OperandList::new(function, list.0, list.1).map_ssa_var()
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
    pub left: Box<HighLevelILLiftedInstruction>,
    pub right: Box<HighLevelILLiftedInstruction>,
    pub carry: Box<HighLevelILLiftedInstruction>,
}
impl BinaryOpCarry {
    pub fn new(left: usize, right: usize, carry: usize) -> Self {
        Self { left, right, carry }
    }
    fn left(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.left)
    }
    fn right(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.right)
    }
    fn carry(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.carry)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedBinaryOpCarry {
        LiftedBinaryOpCarry {
            left: Box::new(self.left(function).lift()),
            right: Box::new(self.right(function).lift()),
            carry: Box::new(self.carry(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("left", Expr(self.left(function))),
            1usize => ("right", Expr(self.right(function))),
            2usize => ("carry", Expr(self.carry(function))),
            _ => unreachable!(),
        })
    }
}
// ADD, SUB, AND, OR, XOR, LSL, LSR, ASR, ROL, ROR, MUL, MULU_DP, MULS_DP, DIVU, DIVU_DP, DIVS, DIVS_DP, MODU, MODU_DP, MODS, MODS_DP, CMP_E, CMP_NE, CMP_SLT, CMP_ULT, CMP_SLE, CMP_ULE, CMP_SGE, CMP_UGE, CMP_SGT, CMP_UGT, TEST_BIT, ADD_OVERFLOW, FADD, FSUB, FMUL, FDIV, FCMP_E, FCMP_NE, FCMP_LT, FCMP_LE, FCMP_GE, FCMP_GT, FCMP_O, FCMP_UO
#[derive(Copy, Clone)]
pub struct BinaryOp {
    left: usize,
    right: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBinaryOp {
    pub left: Box<HighLevelILLiftedInstruction>,
    pub right: Box<HighLevelILLiftedInstruction>,
}
impl BinaryOp {
    pub fn new(left: usize, right: usize) -> Self {
        Self { left, right }
    }
    fn left(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.left)
    }
    fn right(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.right)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedBinaryOp {
        LiftedBinaryOp {
            left: Box::new(self.left(function).lift()),
            right: Box::new(self.right(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("left", Expr(self.left(function))),
            1usize => ("right", Expr(self.right(function))),
            _ => unreachable!(),
        })
    }
}
// ARRAY_INDEX
#[derive(Copy, Clone)]
pub struct ArrayIndex {
    src: usize,
    index: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedArrayIndex {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub index: Box<HighLevelILLiftedInstruction>,
}
impl ArrayIndex {
    pub fn new(src: usize, index: usize) -> Self {
        Self { src, index }
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    fn index(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.index)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedArrayIndex {
        LiftedArrayIndex {
            src: Box::new(self.src(function).lift()),
            index: Box::new(self.index(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("src", Expr(self.src(function))),
            1usize => ("index", Expr(self.index(function))),
            _ => unreachable!(),
        })
    }
}
// ARRAY_INDEX_SSA
#[derive(Copy, Clone)]
pub struct ArrayIndexSsa {
    src: usize,
    src_memory: u64,
    index: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedArrayIndexSsa {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
    pub index: Box<HighLevelILLiftedInstruction>,
}
impl ArrayIndexSsa {
    pub fn new(src: usize, src_memory: u64, index: usize) -> Self {
        Self {
            src,
            src_memory,
            index,
        }
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    fn src_memory(&self) -> u64 {
        self.src_memory
    }
    fn index(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.index)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedArrayIndexSsa {
        LiftedArrayIndexSsa {
            src: Box::new(self.src(function).lift()),
            src_memory: self.src_memory,
            index: Box::new(self.index(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("src", Expr(self.src(function))),
            1usize => ("src_memory", Int(self.src_memory())),
            2usize => ("index", Expr(self.index(function))),
            _ => unreachable!(),
        })
    }
}
// ASSIGN
#[derive(Copy, Clone)]
pub struct Assign {
    dest: usize,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssign {
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub src: Box<HighLevelILLiftedInstruction>,
}
impl Assign {
    pub fn new(dest: usize, src: usize) -> Self {
        Self { dest, src }
    }
    fn dest(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.dest)
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedAssign {
        LiftedAssign {
            dest: Box::new(self.dest(function).lift()),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", Expr(self.dest(function))),
            1usize => ("src", Expr(self.src(function))),
            _ => unreachable!(),
        })
    }
}
// ASSIGN_MEM_SSA
#[derive(Copy, Clone)]
pub struct AssignMemSsa {
    dest: usize,
    dest_memory: u64,
    src: usize,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignMemSsa {
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl AssignMemSsa {
    pub fn new(dest: usize, dest_memory: u64, src: usize, src_memory: u64) -> Self {
        Self {
            dest,
            dest_memory,
            src,
            src_memory,
        }
    }
    fn dest(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.dest)
    }
    fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedAssignMemSsa {
        LiftedAssignMemSsa {
            dest: Box::new(self.dest(function).lift()),
            dest_memory: self.dest_memory,
            src: Box::new(self.src(function).lift()),
            src_memory: self.src_memory,
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("dest", Expr(self.dest(function))),
            1usize => ("dest_memory", Int(self.dest_memory())),
            2usize => ("src", Expr(self.src(function))),
            3usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
    }
}
// ASSIGN_UNPACK
#[derive(Copy, Clone)]
pub struct AssignUnpack {
    dest: (usize, usize),
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignUnpack {
    pub dest: Vec<HighLevelILLiftedInstruction>,
    pub src: Box<HighLevelILLiftedInstruction>,
}
impl AssignUnpack {
    pub fn new(dest: (usize, usize), src: usize) -> Self {
        Self { dest, src }
    }
    fn dest(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.dest)
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedAssignUnpack {
        LiftedAssignUnpack {
            dest: self.dest(function).map(|x| x.lift()).collect(),
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", ExprList(self.dest(function))),
            1usize => ("src", Expr(self.src(function))),
            _ => unreachable!(),
        })
    }
}
// ASSIGN_UNPACK_MEM_SSA
#[derive(Copy, Clone)]
pub struct AssignUnpackMemSsa {
    dest: (usize, usize),
    dest_memory: u64,
    src: usize,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedAssignUnpackMemSsa {
    pub dest: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl AssignUnpackMemSsa {
    pub fn new(dest: (usize, usize), dest_memory: u64, src: usize, src_memory: u64) -> Self {
        Self {
            dest,
            dest_memory,
            src,
            src_memory,
        }
    }
    fn dest(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.dest)
    }
    fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedAssignUnpackMemSsa {
        LiftedAssignUnpackMemSsa {
            dest: self.dest(function).map(|x| x.lift()).collect(),
            dest_memory: self.dest_memory,
            src: Box::new(self.src(function).lift()),
            src_memory: self.src_memory,
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("dest", ExprList(self.dest(function))),
            1usize => ("dest_memory", Int(self.dest_memory())),
            2usize => ("src", Expr(self.src(function))),
            3usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
    }
}
// BLOCK
#[derive(Copy, Clone)]
pub struct Block {
    body: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedBlock {
    pub body: Vec<HighLevelILLiftedInstruction>,
}
impl Block {
    pub fn new(body: (usize, usize)) -> Self {
        Self { body }
    }
    fn body(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.body)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedBlock {
        LiftedBlock {
            body: self.body(function).map(|x| x.lift()).collect(),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("body", ExprList(self.body(function))),
            _ => unreachable!(),
        })
    }
}
// CALL, TAILCALL
#[derive(Copy, Clone)]
pub struct Call {
    dest: usize,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCall {
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub params: Vec<HighLevelILLiftedInstruction>,
}
impl Call {
    pub fn new(dest: usize, params: (usize, usize)) -> Self {
        Self { dest, params }
    }
    fn dest(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.dest)
    }
    fn params(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.params)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedCall {
        LiftedCall {
            dest: Box::new(self.dest(function).lift()),
            params: self.params(function).map(|x| x.lift()).collect(),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", Expr(self.dest(function))),
            1usize => ("params", ExprList(self.params(function))),
            _ => unreachable!(),
        })
    }
}
// CALL_SSA
#[derive(Copy, Clone)]
pub struct CallSsa {
    dest: usize,
    params: (usize, usize),
    dest_memory: u64,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCallSsa {
    pub dest: Box<HighLevelILLiftedInstruction>,
    pub params: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
}
impl CallSsa {
    pub fn new(dest: usize, params: (usize, usize), dest_memory: u64, src_memory: u64) -> Self {
        Self {
            dest,
            params,
            dest_memory,
            src_memory,
        }
    }
    fn dest(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.dest)
    }
    fn params(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.params)
    }
    fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedCallSsa {
        LiftedCallSsa {
            dest: Box::new(self.dest(function).lift()),
            params: self.params(function).map(|x| x.lift()).collect(),
            dest_memory: self.dest_memory,
            src_memory: self.src_memory,
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("dest", Expr(self.dest(function))),
            1usize => ("params", ExprList(self.params(function))),
            2usize => ("dest_memory", Int(self.dest_memory())),
            3usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
    }
}
// CASE
#[derive(Copy, Clone)]
pub struct Case {
    values: (usize, usize),
    body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedCase {
    pub values: Vec<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}
impl Case {
    pub fn new(values: (usize, usize), body: usize) -> Self {
        Self { values, body }
    }
    fn values(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.values)
    }
    fn body(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.body)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedCase {
        LiftedCase {
            values: self.values(function).map(|x| x.lift()).collect(),
            body: Box::new(self.body(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("values", ExprList(self.values(function))),
            1usize => ("body", Expr(self.body(function))),
            _ => unreachable!(),
        })
    }
}
// CONST, CONST_PTR, IMPORT
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Const {
    pub constant: u64,
}
impl Const {
    pub fn new(constant: u64) -> Self {
        Self { constant }
    }
    fn constant(&self) -> u64 {
        self.constant
    }
    pub fn operands<'a>(&'a self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("constant", Int(self.constant())),
            _ => unreachable!(),
        })
    }
}
// CONST_DATA
#[derive(Copy, Clone)]
pub struct ConstData {
    constant_data: (u64, u64, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedConstantData {
    constant_data: (),
}
impl ConstData {
    pub fn new(constant_data: (u64, u64, usize)) -> Self {
        Self { constant_data }
    }
    fn constant_data(&self, function: &HighLevelILFunction) -> ! {
        get_constant_data(function, self.constant_data)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedConstantData {
        LiftedConstantData {
            constant_data: self.constant_data(function),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("constant_data", ConstantData(self.constant_data(function))),
            _ => unreachable!(),
        })
    }
}
// DEREF, ADDRESS_OF, NEG, NOT, SX, ZX, LOW_PART, BOOL_TO_INT, UNIMPL_MEM, FSQRT, FNEG, FABS, FLOAT_TO_INT, INT_TO_FLOAT, FLOAT_CONV, ROUND_TO_INT, FLOOR, CEIL, FTRUNC
#[derive(Copy, Clone)]
pub struct UnaryOp {
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedUnaryOp {
    pub src: Box<HighLevelILLiftedInstruction>,
}
impl UnaryOp {
    pub fn new(src: usize) -> Self {
        Self { src }
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedUnaryOp {
        LiftedUnaryOp {
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("src", Expr(self.src(function))),
            _ => unreachable!(),
        })
    }
}
// DEREF_FIELD_SSA
#[derive(Copy, Clone)]
pub struct DerefFieldSsa {
    src: usize,
    src_memory: u64,
    offset: u64,
    member_index: Option<usize>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedDerefFieldSsa {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
    pub offset: u64,
    pub member_index: Option<usize>,
}
impl DerefFieldSsa {
    pub fn new(src: usize, src_memory: u64, offset: u64, member_index: u64) -> Self {
        Self {
            src,
            src_memory,
            offset,
            member_index: get_member_index(member_index),
        }
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    fn src_memory(&self) -> u64 {
        self.src_memory
    }
    fn offset(&self) -> u64 {
        self.offset
    }
    fn member_index(&self) -> Option<usize> {
        self.member_index
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedDerefFieldSsa {
        LiftedDerefFieldSsa {
            src: Box::new(self.src(function).lift()),
            src_memory: self.src_memory,
            offset: self.offset,
            member_index: self.member_index,
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("src", Expr(self.src(function))),
            1usize => ("src_memory", Int(self.src_memory())),
            2usize => ("offset", Int(self.offset())),
            3usize => ("member_index", MemberIndex(self.member_index())),
            _ => unreachable!(),
        })
    }
}
// DEREF_SSA
#[derive(Copy, Clone)]
pub struct DerefSsa {
    src: usize,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedDerefSsa {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub src_memory: u64,
}
impl DerefSsa {
    pub fn new(src: usize, src_memory: u64) -> Self {
        Self { src, src_memory }
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedDerefSsa {
        LiftedDerefSsa {
            src: Box::new(self.src(function).lift()),
            src_memory: self.src_memory,
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("src", Expr(self.src(function))),
            1usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
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
    fn constant(&self) -> u64 {
        self.constant
    }
    fn offset(&self) -> u64 {
        self.offset
    }
    pub fn operands<'a>(&'a self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("constant", Int(self.constant())),
            1usize => ("offset", Int(self.offset())),
            _ => unreachable!(),
        })
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
    fn constant(&self) -> f64 {
        self.constant
    }
    pub fn operands<'a>(&'a self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("constant", Float(self.constant())),
            _ => unreachable!(),
        })
    }
}
// FOR
#[derive(Copy, Clone)]
pub struct GroupRef19 {
    init: usize,
    condition: usize,
    update: usize,
    body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct GroupOwned19 {
    pub init: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub update: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}
impl GroupRef19 {
    pub fn new(init: usize, condition: usize, update: usize, body: usize) -> Self {
        Self {
            init,
            condition,
            update,
            body,
        }
    }
    fn init(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.init)
    }
    fn condition(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.condition)
    }
    fn update(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.update)
    }
    fn body(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.body)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> GroupOwned19 {
        GroupOwned19 {
            init: Box::new(self.init(function).lift()),
            condition: Box::new(self.condition(function).lift()),
            update: Box::new(self.update(function).lift()),
            body: Box::new(self.body(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("init", Expr(self.init(function))),
            1usize => ("condition", Expr(self.condition(function))),
            2usize => ("update", Expr(self.update(function))),
            3usize => ("body", Expr(self.body(function))),
            _ => unreachable!(),
        })
    }
}
// FOR_SSA
#[derive(Copy, Clone)]
pub struct GroupRef20 {
    init: usize,
    condition_phi: usize,
    condition: usize,
    update: usize,
    body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct GroupOwned20 {
    pub init: Box<HighLevelILLiftedInstruction>,
    pub condition_phi: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub update: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}
impl GroupRef20 {
    pub fn new(
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
    fn init(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.init)
    }
    fn condition_phi(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.condition_phi)
    }
    fn condition(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.condition)
    }
    fn update(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.update)
    }
    fn body(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.body)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> GroupOwned20 {
        GroupOwned20 {
            init: Box::new(self.init(function).lift()),
            condition_phi: Box::new(self.condition_phi(function).lift()),
            condition: Box::new(self.condition(function).lift()),
            update: Box::new(self.update(function).lift()),
            body: Box::new(self.body(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..5usize).map(move |i| match i {
            0usize => ("init", Expr(self.init(function))),
            1usize => ("condition_phi", Expr(self.condition_phi(function))),
            2usize => ("condition", Expr(self.condition(function))),
            3usize => ("update", Expr(self.update(function))),
            4usize => ("body", Expr(self.body(function))),
            _ => unreachable!(),
        })
    }
}
// GOTO, LABEL
#[derive(Copy, Clone)]
pub struct Label {
    target: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedLabel {
    // TODO lifted label
    target: u64,
}
impl Label {
    pub fn new(target: u64) -> Self {
        Self { target }
    }
    fn target(&self) -> u64 {
        self.target
    }
    pub fn lift(&self, _function: &HighLevelILFunction) -> LiftedLabel {
        LiftedLabel {
            target: self.target,
        }
    }
    pub fn operands<'a>(&'a self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("target", Label(self.target())),
            _ => unreachable!(),
        })
    }
}
// IF
#[derive(Copy, Clone)]
pub struct If {
    condition: usize,
    cond_true: usize,
    cond_false: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIf {
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub cond_true: Box<HighLevelILLiftedInstruction>,
    pub cond_false: Box<HighLevelILLiftedInstruction>,
}
impl If {
    pub fn new(condition: usize, cond_true: usize, cond_false: usize) -> Self {
        Self {
            condition,
            cond_true,
            cond_false,
        }
    }
    fn condition(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.condition)
    }
    fn cond_true(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.cond_true)
    }
    fn cond_false(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.cond_false)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedIf {
        LiftedIf {
            condition: Box::new(self.condition(function).lift()),
            cond_true: Box::new(self.cond_true(function).lift()),
            cond_false: Box::new(self.cond_false(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("condition", Expr(self.condition(function))),
            1usize => ("cond_true", Expr(self.cond_true(function))),
            2usize => ("cond_false", Expr(self.cond_false(function))),
            _ => unreachable!(),
        })
    }
}
// INTRINSIC
#[derive(Copy, Clone)]
pub struct Intrinsic {
    intrinsic: u64,
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsic {
    intrinsic: (),
    pub params: Vec<HighLevelILLiftedInstruction>,
}
impl Intrinsic {
    pub fn new(intrinsic: u64, params: (usize, usize)) -> Self {
        Self { intrinsic, params }
    }
    fn intrinsic(&self, function: &HighLevelILFunction) -> ! {
        get_intrinsic(function, self.intrinsic)
    }
    fn params(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.params)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedIntrinsic {
        LiftedIntrinsic {
            intrinsic: self.intrinsic(function),
            params: self.params(function).map(|x| x.lift()).collect(),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("intrinsic", Intrinsic(self.intrinsic(function))),
            1usize => ("params", ExprList(self.params(function))),
            _ => unreachable!(),
        })
    }
}
// INTRINSIC_SSA
#[derive(Copy, Clone)]
pub struct IntrinsicSsa {
    intrinsic: u64,
    params: (usize, usize),
    dest_memory: u64,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedIntrinsicSsa {
    intrinsic: (),
    pub params: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
}
impl IntrinsicSsa {
    pub fn new(intrinsic: u64, params: (usize, usize), dest_memory: u64, src_memory: u64) -> Self {
        Self {
            intrinsic,
            params,
            dest_memory,
            src_memory,
        }
    }
    fn intrinsic(&self, function: &HighLevelILFunction) -> ! {
        get_intrinsic(function, self.intrinsic)
    }
    fn params(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.params)
    }
    fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedIntrinsicSsa {
        LiftedIntrinsicSsa {
            intrinsic: self.intrinsic(function),
            params: self.params(function).map(|x| x.lift()).collect(),
            dest_memory: self.dest_memory,
            src_memory: self.src_memory,
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..4usize).map(move |i| match i {
            0usize => ("intrinsic", Intrinsic(self.intrinsic(function))),
            1usize => ("params", ExprList(self.params(function))),
            2usize => ("dest_memory", Int(self.dest_memory())),
            3usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
    }
}
// JUMP
#[derive(Copy, Clone)]
pub struct Jump {
    dest: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedJump {
    // TODO how to handle two jumps pointing to each other
    dest: Box<HighLevelILLiftedInstruction>,
}
impl Jump {
    pub fn new(dest: usize) -> Self {
        Self { dest }
    }
    fn dest(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.dest)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedJump {
        LiftedJump {
            dest: Box::new(self.dest(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("dest", Expr(self.dest(function))),
            _ => unreachable!(),
        })
    }
}
// MEM_PHI
#[derive(Copy, Clone)]
pub struct MemPhi {
    dest: u64,
    src: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedMemPhi {
    pub dest: u64,
    pub src: Vec<u64>,
}
impl MemPhi {
    pub fn new(dest: u64, src: (usize, usize)) -> Self {
        Self { dest, src }
    }
    fn dest(&self) -> u64 {
        self.dest
    }
    fn src(&self, function: &HighLevelILFunction) -> OperandList {
        get_int_list(function, self.src)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedMemPhi {
        LiftedMemPhi {
            dest: self.dest,
            src: self.src(function).collect(),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", Int(self.dest())),
            1usize => ("src", IntList(self.src(function))),
            _ => unreachable!(),
        })
    }
}
// NOP, BREAK, CONTINUE, NORET, UNREACHABLE, BP, UNDEF, UNIMPL
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct NoArgs {}
impl NoArgs {
    pub fn new() -> Self {
        Self {}
    }
    pub fn operands<'a>(&'a self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        [].into_iter()
    }
}
// RET
#[derive(Copy, Clone)]
pub struct Ret {
    src: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedRet {
    pub src: Vec<HighLevelILLiftedInstruction>,
}
impl Ret {
    pub fn new(src: (usize, usize)) -> Self {
        Self { src }
    }
    fn src(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.src)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedRet {
        LiftedRet {
            src: self.src(function).map(|x| x.lift()).collect(),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("src", ExprList(self.src(function))),
            _ => unreachable!(),
        })
    }
}
// SPLIT
#[derive(Copy, Clone)]
pub struct Split {
    high: usize,
    low: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSplit {
    pub high: Box<HighLevelILLiftedInstruction>,
    pub low: Box<HighLevelILLiftedInstruction>,
}
impl Split {
    pub fn new(high: usize, low: usize) -> Self {
        Self { high, low }
    }
    fn high(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.high)
    }
    fn low(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.low)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedSplit {
        LiftedSplit {
            high: Box::new(self.high(function).lift()),
            low: Box::new(self.low(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("high", Expr(self.high(function))),
            1usize => ("low", Expr(self.low(function))),
            _ => unreachable!(),
        })
    }
}
// STRUCT_FIELD, DEREF_FIELD
#[derive(Copy, Clone)]
pub struct StructField {
    src: usize,
    offset: u64,
    member_index: Option<usize>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedStructField {
    pub src: Box<HighLevelILLiftedInstruction>,
    pub offset: u64,
    pub member_index: Option<usize>,
}
impl StructField {
    pub fn new(src: usize, offset: u64, member_index: u64) -> Self {
        Self {
            src,
            offset,
            member_index: get_member_index(member_index),
        }
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    fn offset(&self) -> u64 {
        self.offset
    }
    fn member_index(&self) -> Option<usize> {
        self.member_index
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedStructField {
        LiftedStructField {
            src: Box::new(self.src(function).lift()),
            offset: self.offset,
            member_index: self.member_index,
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("src", Expr(self.src(function))),
            1usize => ("offset", Int(self.offset())),
            2usize => ("member_index", MemberIndex(self.member_index())),
            _ => unreachable!(),
        })
    }
}
// SWITCH
#[derive(Copy, Clone)]
pub struct Switch {
    condition: usize,
    default: usize,
    cases: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSwitch {
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub default: Box<HighLevelILLiftedInstruction>,
    pub cases: Vec<HighLevelILLiftedInstruction>,
}
impl Switch {
    pub fn new(condition: usize, default: usize, cases: (usize, usize)) -> Self {
        Self {
            condition,
            default,
            cases,
        }
    }
    fn condition(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.condition)
    }
    fn default(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.default)
    }
    fn cases(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.cases)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedSwitch {
        LiftedSwitch {
            condition: Box::new(self.condition(function).lift()),
            default: Box::new(self.default(function).lift()),
            cases: self.cases(function).map(|x| x.lift()).collect(),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("condition", Expr(self.condition(function))),
            1usize => ("default", Expr(self.default(function))),
            2usize => ("cases", ExprList(self.cases(function))),
            _ => unreachable!(),
        })
    }
}
// SYSCALL
#[derive(Copy, Clone)]
pub struct Syscall {
    params: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscall {
    pub params: Vec<HighLevelILLiftedInstruction>,
}
impl Syscall {
    pub fn new(params: (usize, usize)) -> Self {
        Self { params }
    }
    fn params(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.params)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedSyscall {
        LiftedSyscall {
            params: self.params(function).map(|x| x.lift()).collect(),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("params", ExprList(self.params(function))),
            _ => unreachable!(),
        })
    }
}
// SYSCALL_SSA
#[derive(Copy, Clone)]
pub struct SyscallSsa {
    params: (usize, usize),
    dest_memory: u64,
    src_memory: u64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedSyscallSsa {
    pub params: Vec<HighLevelILLiftedInstruction>,
    pub dest_memory: u64,
    pub src_memory: u64,
}
impl SyscallSsa {
    pub fn new(params: (usize, usize), dest_memory: u64, src_memory: u64) -> Self {
        Self {
            params,
            dest_memory,
            src_memory,
        }
    }
    fn params(&self, function: &HighLevelILFunction) -> OperandExprList {
        get_instruction_list(function, self.params)
    }
    fn dest_memory(&self) -> u64 {
        self.dest_memory
    }
    fn src_memory(&self) -> u64 {
        self.src_memory
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedSyscallSsa {
        LiftedSyscallSsa {
            params: self.params(function).map(|x| x.lift()).collect(),
            dest_memory: self.dest_memory,
            src_memory: self.src_memory,
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("params", ExprList(self.params(function))),
            1usize => ("dest_memory", Int(self.dest_memory())),
            2usize => ("src_memory", Int(self.src_memory())),
            _ => unreachable!(),
        })
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
    fn vector(&self) -> u64 {
        self.vector
    }
    pub fn operands<'a>(&'a self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("vector", Int(self.vector())),
            _ => unreachable!(),
        })
    }
}
// VAR_DECLARE, VAR
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Var {
    var: Variable,
}
impl Var {
    pub fn new(var: u64) -> Self {
        Self { var: get_var(var) }
    }
    fn var(&self) -> Variable {
        self.var
    }
    pub fn operands<'a>(&'a self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("var", Var(self.var())),
            _ => unreachable!(),
        })
    }
}
// VAR_INIT
#[derive(Copy, Clone)]
pub struct VarInit {
    dest: Variable,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedVarInit {
    pub dest: Variable,
    pub src: Box<HighLevelILLiftedInstruction>,
}
impl VarInit {
    pub fn new(dest: u64, src: usize) -> Self {
        Self {
            dest: get_var(dest),
            src,
        }
    }
    fn dest(&self) -> Variable {
        self.dest
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedVarInit {
        LiftedVarInit {
            dest: self.dest,
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", Var(self.dest())),
            1usize => ("src", Expr(self.src(function))),
            _ => unreachable!(),
        })
    }
}
// VAR_INIT_SSA
#[derive(Copy, Clone)]
pub struct VarInitSsa {
    dest: SSAVariable,
    src: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedVarInitSsa {
    pub dest: SSAVariable,
    pub src: Box<HighLevelILLiftedInstruction>,
}
impl VarInitSsa {
    pub fn new(dest: (u64, usize), src: usize) -> Self {
        Self {
            dest: get_var_ssa(dest),
            src,
        }
    }
    fn dest(&self) -> SSAVariable {
        self.dest
    }
    fn src(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.src)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedVarInitSsa {
        LiftedVarInitSsa {
            dest: self.dest,
            src: Box::new(self.src(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", VarSsa(self.dest())),
            1usize => ("src", Expr(self.src(function))),
            _ => unreachable!(),
        })
    }
}
// VAR_PHI
#[derive(Copy, Clone)]
pub struct VarPhi {
    dest: SSAVariable,
    src: (usize, usize),
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedVarPhi {
    pub dest: SSAVariable,
    pub src: Vec<SSAVariable>,
}
impl VarPhi {
    pub fn new(dest: (u64, usize), src: (usize, usize)) -> Self {
        Self {
            dest: get_var_ssa(dest),
            src,
        }
    }
    fn dest(&self) -> SSAVariable {
        self.dest
    }
    fn src(&self, function: &HighLevelILFunction) -> OperandSSAVariableList {
        get_var_ssa_list(function, self.src)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedVarPhi {
        LiftedVarPhi {
            dest: self.dest,
            src: self.src(function).collect(),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("dest", VarSsa(self.dest())),
            1usize => ("src", VarSsaList(self.src(function))),
            _ => unreachable!(),
        })
    }
}
// VAR_SSA
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarSsa {
    pub var: SSAVariable,
}
impl VarSsa {
    pub fn new(var: (u64, usize)) -> Self {
        Self {
            var: get_var_ssa(var),
        }
    }
    fn var(&self) -> SSAVariable {
        self.var
    }
    pub fn operands<'a>(&'a self) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..1usize).map(move |i| match i {
            0usize => ("var", VarSsa(self.var())),
            _ => unreachable!(),
        })
    }
}
// WHILE, DO_WHILE
#[derive(Copy, Clone)]
pub struct While {
    condition: usize,
    body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedWhile {
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}
impl While {
    pub fn new(condition: usize, body: usize) -> Self {
        Self { condition, body }
    }
    fn condition(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.condition)
    }
    fn body(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.body)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedWhile {
        LiftedWhile {
            condition: Box::new(self.condition(function).lift()),
            body: Box::new(self.body(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..2usize).map(move |i| match i {
            0usize => ("condition", Expr(self.condition(function))),
            1usize => ("body", Expr(self.body(function))),
            _ => unreachable!(),
        })
    }
}
// WHILE_SSA, DO_WHILE_SSA
#[derive(Copy, Clone)]
pub struct WhileSsa {
    condition_phi: usize,
    condition: usize,
    body: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LiftedWhileSsa {
    pub condition_phi: Box<HighLevelILLiftedInstruction>,
    pub condition: Box<HighLevelILLiftedInstruction>,
    pub body: Box<HighLevelILLiftedInstruction>,
}
impl WhileSsa {
    pub fn new(condition_phi: usize, condition: usize, body: usize) -> Self {
        Self {
            condition_phi,
            condition,
            body,
        }
    }
    fn condition_phi(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.condition_phi)
    }
    fn condition(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.condition)
    }
    fn body(&self, function: &HighLevelILFunction) -> HighLevelILInstruction {
        get_instruction(function, self.body)
    }
    pub fn lift(&self, function: &HighLevelILFunction) -> LiftedWhileSsa {
        LiftedWhileSsa {
            condition_phi: Box::new(self.condition_phi(function).lift()),
            condition: Box::new(self.condition(function).lift()),
            body: Box::new(self.body(function).lift()),
        }
    }
    pub fn operands<'a>(
        &'a self,
        function: &'a HighLevelILFunction,
    ) -> impl Iterator<Item = (&'static str, HighLevelILOperand)> + 'a {
        use HighLevelILOperand::*;
        (0..3usize).map(move |i| match i {
            0usize => ("condition_phi", Expr(self.condition_phi(function))),
            1usize => ("condition", Expr(self.condition(function))),
            2usize => ("body", Expr(self.body(function))),
            _ => unreachable!(),
        })
    }
}
