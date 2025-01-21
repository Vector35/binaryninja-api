use binaryninjacore_sys::BNGetHighLevelILByIndex;
use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNHighLevelILOperation;
use binaryninjacore_sys::BNMediumLevelILOperation;

use crate::high_level_il::{
    HighLevelILFunction, HighLevelILInstruction, HighLevelInstructionIndex,
};
use crate::medium_level_il::{
    MediumLevelILFunction, MediumLevelILInstruction, MediumLevelInstructionIndex,
};
use crate::rc::{Ref, RefCountable};
use crate::variable::{SSAVariable, Variable};

// TODO: This code needs to go away IMO, we have the facilities to do this for each IL already!

pub trait ILFunction {
    type Instruction;
    type InstructionIndex: From<u64>;

    // TODO Actually this is il expression from index!
    fn il_instruction_from_index(&self, instr_index: Self::InstructionIndex) -> Self::Instruction;
    fn operands_from_index(&self, instr_index: Self::InstructionIndex) -> [u64; 5];
}

impl ILFunction for MediumLevelILFunction {
    type Instruction = MediumLevelILInstruction;
    type InstructionIndex = MediumLevelInstructionIndex;

    fn il_instruction_from_index(&self, instr_index: Self::InstructionIndex) -> Self::Instruction {
        self.instruction_from_expr_index(instr_index).unwrap()
    }

    fn operands_from_index(&self, instr_index: Self::InstructionIndex) -> [u64; 5] {
        // TODO: WTF?!?!?!
        let node = unsafe { BNGetMediumLevelILByIndex(self.handle, instr_index.0) };
        assert_eq!(node.operation, BNMediumLevelILOperation::MLIL_UNDEF);
        node.operands
    }
}

impl ILFunction for HighLevelILFunction {
    type Instruction = HighLevelILInstruction;
    type InstructionIndex = HighLevelInstructionIndex;

    fn il_instruction_from_index(&self, instr_index: Self::InstructionIndex) -> Self::Instruction {
        self.instruction_from_expr_index(instr_index).unwrap()
    }

    fn operands_from_index(&self, instr_index: Self::InstructionIndex) -> [u64; 5] {
        let node = unsafe { BNGetHighLevelILByIndex(self.handle, instr_index.0, self.full_ast) };
        assert_eq!(node.operation, BNHighLevelILOperation::HLIL_UNDEF);
        node.operands
    }
}

pub struct OperandIter<F: ILFunction + RefCountable> {
    function: Ref<F>,
    remaining: usize,
    next_iter_idx: Option<usize>,
    current_iter: OperandIterInner,
}

impl<F: ILFunction + RefCountable> OperandIter<F> {
    pub(crate) fn new(function: &F, idx: usize, number: usize) -> Self {
        // Zero-length lists immediately finish iteration
        let next_iter_idx = if number > 0 { Some(idx) } else { None };
        Self {
            function: function.to_owned(),
            remaining: number,
            next_iter_idx,
            current_iter: OperandIterInner::empty(),
        }
    }

    pub fn pairs(self) -> OperandPairIter<F> {
        assert_eq!(self.len() % 2, 0);
        OperandPairIter(self)
    }

    pub fn exprs(self) -> OperandExprIter<F> {
        OperandExprIter(self)
    }

    pub fn vars(self) -> OperandVarIter<F> {
        OperandVarIter(self)
    }

    pub fn ssa_vars(self) -> OperandSSAVarIter<F> {
        OperandSSAVarIter(self.pairs())
    }
}

impl<F: ILFunction + RefCountable> Iterator for OperandIter<F> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.current_iter.next() {
            self.remaining -= 1;
            Some(item)
        } else {
            // Will short-circuit and return `None` once iter is exhausted
            let iter_idx = self.next_iter_idx?;
            let iter_idx = F::InstructionIndex::from(iter_idx as u64);
            let operands = self.function.operands_from_index(iter_idx);

            let next = if self.remaining > 4 {
                self.next_iter_idx = Some(operands[4] as usize);
                &operands[..4]
            } else {
                self.next_iter_idx = None;
                &operands[..self.remaining]
            };

            self.current_iter = OperandIterInner::from_slice(next);
            self.next()
        }
    }
}

impl<F: ILFunction + RefCountable> ExactSizeIterator for OperandIter<F> {
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

pub struct OperandPairIter<F: ILFunction + RefCountable>(OperandIter<F>);

impl<F: ILFunction + RefCountable> Iterator for OperandPairIter<F> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let first = self.0.next()?;
        let second = self.0.next()?;
        Some((first, second))
    }
}
impl<F: ILFunction + RefCountable> ExactSizeIterator for OperandPairIter<F> {
    fn len(&self) -> usize {
        self.0.len() / 2
    }
}

pub struct OperandExprIter<F: ILFunction + RefCountable>(OperandIter<F>);

impl<F: ILFunction + RefCountable> Iterator for OperandExprIter<F> {
    type Item = F::Instruction;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(F::InstructionIndex::from)
            .map(|idx| self.0.function.il_instruction_from_index(idx))
    }
}

impl<F: ILFunction + RefCountable> ExactSizeIterator for OperandExprIter<F> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct OperandVarIter<F: ILFunction + RefCountable>(OperandIter<F>);

impl<F: ILFunction + RefCountable> Iterator for OperandVarIter<F> {
    type Item = Variable;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Variable::from_identifier)
    }
}
impl<F: ILFunction + RefCountable> ExactSizeIterator for OperandVarIter<F> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct OperandSSAVarIter<F: ILFunction + RefCountable>(OperandPairIter<F>);

impl<F: ILFunction + RefCountable> Iterator for OperandSSAVarIter<F> {
    type Item = SSAVariable;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(id, version)| {
            let var = Variable::from_identifier(id);
            SSAVariable::new(var, version as _)
        })
    }
}

impl<F: ILFunction + RefCountable> ExactSizeIterator for OperandSSAVarIter<F> {
    fn len(&self) -> usize {
        self.0.len()
    }
}
