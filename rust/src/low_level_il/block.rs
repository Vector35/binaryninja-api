// Copyright 2021-2024 Vector 35 Inc.
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

use std::fmt::Debug;
use std::ops::Range;

use crate::architecture::Architecture;
use crate::basic_block::{BasicBlock, BlockContext};

use super::*;

#[derive(Copy)]
pub struct LowLevelILBlock<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) function: &'func LowLevelILFunction<A, M, F>,
}

impl<'func, A, M, F> BlockContext for LowLevelILBlock<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    type Instruction = LowLevelILInstruction<'func, A, M, F>;
    type InstructionIndex = LowLevelInstructionIndex;
    type Iter = LowLevelILBlockIter<'func, A, M, F>;

    fn start(&self, block: &BasicBlock<Self>) -> LowLevelILInstruction<'func, A, M, F> {
        self.function
            .instruction_from_index(block.start_index())
            .unwrap()
    }

    fn iter(&self, block: &BasicBlock<Self>) -> LowLevelILBlockIter<'func, A, M, F> {
        LowLevelILBlockIter {
            function: self.function,
            range: (block.start_index().0)..(block.end_index().0),
        }
    }
}

impl<'func, A, M, F> Debug for LowLevelILBlock<'func, A, M, F>
where
    A: 'func + Architecture + Debug,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LowLevelILBlock")
            .field("function", &self.function)
            .finish()
    }
}

impl<'func, A, M, F> Clone for LowLevelILBlock<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn clone(&self) -> Self {
        LowLevelILBlock {
            function: self.function,
        }
    }
}

pub struct LowLevelILBlockIter<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    function: &'func LowLevelILFunction<A, M, F>,
    // TODO: Once step_trait is stable we can do Range<InstructionIndex>
    range: Range<usize>,
}

impl<'func, A, M, F> Iterator for LowLevelILBlockIter<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    type Item = LowLevelILInstruction<'func, A, M, F>;

    fn next(&mut self) -> Option<Self::Item> {
        self.range
            .next()
            .map(LowLevelInstructionIndex)
            .and_then(|idx| self.function.instruction_from_index(idx))
    }
}
