use std::ops::Range;

use crate::basicblock::{BasicBlock, BlockContext};
use crate::rc::Ref;

use super::*;

pub struct BlockIter {
    function: Ref<Function>,
    range: Range<u64>,
}

impl Iterator for BlockIter {
    type Item = Expression;

    fn next(&mut self) -> Option<Self::Item> {
        self.range.next().map(|i| Expression {
            function: self.function.to_owned(),
            expr_idx: i as usize,
        })
    }
}

pub struct Block {
    pub(crate) function: Ref<Function>,
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "mlil_bb {:?}", self.function)
    }
}

impl BlockContext for Block {
    type Iter = BlockIter;
    type Instruction = Expression;

    fn start(&self, block: &BasicBlock<Self>) -> Expression {
        Expression {
            function: self.function.to_owned(),
            expr_idx: block.raw_start() as usize,
        }
    }

    fn iter(&self, block: &BasicBlock<Self>) -> BlockIter {
        BlockIter {
            function: self.function.to_owned(),
            range: block.raw_start()..block.raw_end(),
        }
    }
}

impl Clone for Block {
    fn clone(&self) -> Self {
        Block {
            function: self.function.to_owned(),
        }
    }
}
