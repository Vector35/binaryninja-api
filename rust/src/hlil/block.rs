use std::ops::Range;

use binaryninjacore_sys::BNGetHighLevelILIndexForInstruction;

use crate::basicblock::{BasicBlock, BlockContext};
use crate::rc::Ref;

use super::{HighLevelILFunction, HighLevelILInstruction};

pub struct HighLevelILBlockIter {
    function: Ref<HighLevelILFunction>,
    range: Range<u64>,
}

impl Iterator for HighLevelILBlockIter {
    type Item = HighLevelILInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        self.range
            .next()
            .map(|i| unsafe {
                BNGetHighLevelILIndexForInstruction(self.function.handle, i as usize)
            })
            .map(|i| HighLevelILInstruction::new(&self.function, i))
    }
}

pub struct HighLevelILBlock {
    pub(crate) function: Ref<HighLevelILFunction>,
}

impl core::fmt::Debug for HighLevelILBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "mlil_bb {:?}", self.function)
    }
}

impl BlockContext for HighLevelILBlock {
    type Iter = HighLevelILBlockIter;
    type Instruction = HighLevelILInstruction;

    fn start(&self, block: &BasicBlock<Self>) -> HighLevelILInstruction {
        let expr_idx = unsafe {
            BNGetHighLevelILIndexForInstruction(self.function.handle, block.raw_start() as usize)
        };
        HighLevelILInstruction::new(&self.function, expr_idx)
    }

    fn iter(&self, block: &BasicBlock<Self>) -> HighLevelILBlockIter {
        HighLevelILBlockIter {
            function: self.function.to_owned(),
            range: block.raw_start()..block.raw_end(),
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
