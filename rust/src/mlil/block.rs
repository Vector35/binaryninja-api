// Copyright 2021 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::ops::Range;

use crate::architecture::Architecture;
use crate::basicblock::{BasicBlock, BlockContext};

use super::*;

pub struct BlockIter<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    function: &'func Function<A, M, F>,
    range: Range<u64>,
}

impl<'func, A, M, F> Iterator for BlockIter<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    type Item = Instruction<'func, A, M, F>;

    fn next(&mut self) -> Option<Self::Item> {
        self.range.next().map(|i| Instruction {
            function: self.function,
            instr_idx: i as usize,
        })
    }
}

pub struct Block<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) function: &'func Function<A, M, F>,
}

impl<'func, A, M, F> fmt::Debug for Block<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "mlil_bb {:?}", self.function)
    }
}

impl<'func, A, M, F> BlockContext for Block<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    type Iter = BlockIter<'func, A, M, F>;
    type Instruction = Instruction<'func, A, M, F>;

    fn start(&self, block: &BasicBlock<Self>) -> Instruction<'func, A, M, F> {
        Instruction {
            function: self.function,
            instr_idx: block.raw_start() as usize,
        }
    }

    fn iter(&self, block: &BasicBlock<Self>) -> BlockIter<'func, A, M, F> {
        BlockIter {
            function: self.function,
            range: block.raw_start()..block.raw_end(),
        }
    }
}

impl<'func, A, M, F> Clone for Block<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn clone(&self) -> Self {
        Block {
            function: self.function,
        }
    }
}
