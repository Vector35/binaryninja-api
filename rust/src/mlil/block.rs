use std::ops::Range;

use crate::{
    basicblock::{BasicBlock, BlockContext},
    rc::Ref,
};

use super::*;

pub struct BlockIter<F: FunctionForm> {
    function: Ref<Function<F>>,
    range: Range<u64>,
}

impl<F: FunctionForm> Iterator for BlockIter<F> {
    type Item = Instruction<F>;

    fn next(&mut self) -> Option<Self::Item> {
        self.range.next().map(|i| Instruction {
            function: self.function.to_owned(),
            instr_idx: i as usize,
        })
    }
}

pub struct Block<F: FunctionForm> {
    pub(crate) function: Ref<Function<F>>,
}

impl<F: FunctionForm> fmt::Debug for Block<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "mlil_bb {:?}", self.function)
    }
}

impl<F: FunctionForm> BlockContext for Block<F> {
    type Iter = BlockIter<F>;
    type Instruction = Instruction<F>;

    fn start(&self, block: &BasicBlock<Self>) -> Instruction<F> {
        Instruction {
            function: self.function.to_owned(),
            instr_idx: block.raw_start() as usize,
        }
    }

    fn iter(&self, block: &BasicBlock<Self>) -> BlockIter<F> {
        BlockIter {
            function: self.function.to_owned(),
            range: block.raw_start()..block.raw_end(),
        }
    }
}

impl<F: FunctionForm> Clone for Block<F> {
    fn clone(&self) -> Self {
        Block {
            function: self.function.to_owned(),
        }
    }
}
