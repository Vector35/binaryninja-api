use std::ops::Range;

use binaryninjacore_sys::BNGetMediumLevelILIndexForInstruction;

use crate::basicblock::{BasicBlock, BlockContext};
use crate::rc::Ref;

use super::{Form, MediumLevelILFunction, MediumLevelILInstruction};

pub struct MediumLevelILBlockIter<I> {
    function: Ref<MediumLevelILFunction<I>>,
    range: Range<u64>,
}

impl<I: Form> Iterator for MediumLevelILBlockIter<I> {
    type Item = MediumLevelILInstruction<I>;

    fn next(&mut self) -> Option<Self::Item> {
        self.range
            .next()
            .map(|i| unsafe {
                BNGetMediumLevelILIndexForInstruction(self.function.handle, i as usize)
            })
            .map(|i| MediumLevelILInstruction::new(self.function.to_owned(), i))
    }
}

pub struct MediumLevelILBlock<I> {
    pub(crate) function: Ref<MediumLevelILFunction<I>>,
}

impl<I> core::fmt::Debug for MediumLevelILBlock<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "mlil_bb {:?}", self.function)
    }
}

impl<I: Form> BlockContext for MediumLevelILBlock<I> {
    type Iter = MediumLevelILBlockIter<I>;
    type Instruction = MediumLevelILInstruction<I>;

    fn start(&self, block: &BasicBlock<Self>) -> MediumLevelILInstruction<I> {
        let expr_idx = unsafe {
            BNGetMediumLevelILIndexForInstruction(self.function.handle, block.raw_start() as usize)
        };
        MediumLevelILInstruction::new(self.function.to_owned(), expr_idx)
    }

    fn iter(&self, block: &BasicBlock<Self>) -> MediumLevelILBlockIter<I> {
        MediumLevelILBlockIter {
            function: self.function.to_owned(),
            range: block.raw_start()..block.raw_end(),
        }
    }
}

impl<I> Clone for MediumLevelILBlock<I> {
    fn clone(&self) -> Self {
        MediumLevelILBlock {
            function: self.function.to_owned(),
        }
    }
}
