use std::ops::Range;

use crate::basic_block::{BasicBlock, BlockContext};
use crate::rc::Ref;

use super::{HighLevelILFunction, HighLevelILInstruction, HighLevelInstructionIndex};

pub struct HighLevelILBlockIter {
    function: Ref<HighLevelILFunction>,
    range: Range<usize>,
}

impl Iterator for HighLevelILBlockIter {
    type Item = HighLevelILInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        self.range
            .next()
            .map(HighLevelInstructionIndex)
            // TODO: Is this already MAPPED>!>?!? If so we map twice that is BAD!!!!
            .and_then(|i| self.function.instruction_from_index(i))
    }
}

pub struct HighLevelILBlock {
    pub(crate) function: Ref<HighLevelILFunction>,
}

impl core::fmt::Debug for HighLevelILBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        // TODO: Actual basic block please
        write!(f, "mlil_bb {:?}", self.function)
    }
}

impl BlockContext for HighLevelILBlock {
    type Instruction = HighLevelILInstruction;
    type InstructionIndex = HighLevelInstructionIndex;
    type Iter = HighLevelILBlockIter;

    fn start(&self, block: &BasicBlock<Self>) -> HighLevelILInstruction {
        // TODO: Is this start index already mappedd?????
        self.function
            .instruction_from_index(block.start_index())
            .unwrap()
    }

    fn iter(&self, block: &BasicBlock<Self>) -> HighLevelILBlockIter {
        HighLevelILBlockIter {
            function: self.function.to_owned(),
            range: block.start_index().0..block.end_index().0,
        }
    }
}

impl Clone for HighLevelILBlock {
    fn clone(&self) -> Self {
        HighLevelILBlock {
            function: self.function.to_owned(),
        }
    }
}
