use std::ops::Range;

use binaryninjacore_sys::BNGetMediumLevelILIndexForInstruction;

use crate::basicblock::{BasicBlock, BlockContext};
use crate::rc::Ref;

use super::{MediumLevelILFunction, MediumLevelILInstruction};

pub struct MediumLevelILBlock {
    pub(crate) function: Ref<MediumLevelILFunction>,
}

impl BlockContext for MediumLevelILBlock {
    type Instruction = MediumLevelILInstruction;
    type Iter = MediumLevelILBlockIter;

    fn start(&self, block: &BasicBlock<Self>) -> MediumLevelILInstruction {
        self.function.instruction_from_instruction_idx(block.raw_start() as usize)
    }

    fn iter(&self, block: &BasicBlock<Self>) -> MediumLevelILBlockIter {
        MediumLevelILBlockIter {
            function: self.function.to_owned(),
            range: block.raw_start()..block.raw_end(),
        }
    }
}

impl std::fmt::Debug for MediumLevelILBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        // TODO: Make this better
        write!(f, "mlil_bb {:?}", self.function)
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
    range: Range<u64>,
}

impl Iterator for MediumLevelILBlockIter {
    type Item = MediumLevelILInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        self.range
            .next()
            .map(|i| self.function.instruction_from_instruction_idx(i as usize))
    }
}
