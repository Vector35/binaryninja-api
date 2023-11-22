use std::ops::Range;

use binaryninjacore_sys::BNGetMediumLevelILIndexForInstruction;

use crate::basicblock::{BasicBlock, BlockContext};
use crate::rc::Ref;

use super::{MediumLevelILFunction, MediumLevelILInstruction};

pub struct MediumLevelILBlockIter {
    function: Ref<MediumLevelILFunction>,
    range: Range<u64>,
}

impl Iterator for MediumLevelILBlockIter {
    type Item = MediumLevelILInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        self.range
            .next()
            .map(|i| unsafe {
                BNGetMediumLevelILIndexForInstruction(self.function.handle, i as usize)
            })
            .map(|i| MediumLevelILInstruction::new(self.function.to_owned(), i))
    }
}

pub struct MediumLevelILBlock {
    pub(crate) function: Ref<MediumLevelILFunction>,
}

impl core::fmt::Debug for MediumLevelILBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "mlil_bb {:?}", self.function)
    }
}

impl BlockContext for MediumLevelILBlock {
    type Iter = MediumLevelILBlockIter;
    type Instruction = MediumLevelILInstruction;

    fn start(&self, block: &BasicBlock<Self>) -> MediumLevelILInstruction {
        let expr_idx = unsafe {
            BNGetMediumLevelILIndexForInstruction(self.function.handle, block.raw_start() as usize)
        };
        MediumLevelILInstruction::new(self.function.to_owned(), expr_idx)
    }

    fn iter(&self, block: &BasicBlock<Self>) -> MediumLevelILBlockIter {
        MediumLevelILBlockIter {
            function: self.function.to_owned(),
            range: block.raw_start()..block.raw_end(),
        }
    }
}

impl Clone for MediumLevelILBlock {
    fn clone(&self) -> Self {
        MediumLevelILBlock {
            function: self.function.to_owned(),
        }
    }
}
