use crate::basic_block::{BasicBlock, BlockContext};
use crate::rc::Ref;
use std::ops::Range;

use super::{MediumLevelILFunction, MediumLevelILInstruction, MediumLevelInstructionIndex};

pub struct MediumLevelILBlock {
    pub(crate) function: Ref<MediumLevelILFunction>,
}

impl BlockContext for MediumLevelILBlock {
    type Instruction = MediumLevelILInstruction;
    type InstructionIndex = MediumLevelInstructionIndex;
    type Iter = MediumLevelILBlockIter;

    fn start(&self, block: &BasicBlock<Self>) -> MediumLevelILInstruction {
        // TODO: instruction_from_index says that it is not mapped and will do the call
        // TODO: What if this IS already MAPPED!?!?!?
        self.function
            .instruction_from_index(block.start_index())
            .unwrap()
    }

    fn iter(&self, block: &BasicBlock<Self>) -> MediumLevelILBlockIter {
        MediumLevelILBlockIter {
            function: self.function.to_owned(),
            range: block.start_index().0..block.end_index().0,
        }
    }
}

impl std::fmt::Debug for MediumLevelILBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("MediumLevelILBlock")
            .field("function", &self.function)
            .finish()
    }
}

impl Clone for MediumLevelILBlock {
    fn clone(&self) -> Self {
        MediumLevelILBlock {
            function: self.function.to_owned(),
        }
    }
}

pub struct MediumLevelILBlockIter {
    function: Ref<MediumLevelILFunction>,
    range: Range<usize>,
}

impl Iterator for MediumLevelILBlockIter {
    type Item = MediumLevelILInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        self.range
            .next()
            .map(MediumLevelInstructionIndex)
            .and_then(|i| self.function.instruction_from_index(i))
    }
}
