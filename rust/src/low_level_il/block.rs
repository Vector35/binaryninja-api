// Copyright 2021-2025 Vector 35 Inc.
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

use crate::basic_block::{BasicBlock, BlockContext};

use super::*;

#[derive(Copy, Clone)]
pub struct LowLevelILBlock<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) function: &'func LowLevelILFunction<M, F>,
}

impl<'func, M, F> BlockContext for LowLevelILBlock<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    type Instruction = LowLevelILInstruction<'func, M, F>;
    type InstructionIndex = LowLevelInstructionIndex;
    type Iter = LowLevelILBlockIter<'func, M, F>;

    fn start(&self, block: &BasicBlock<Self>) -> LowLevelILInstruction<'func, M, F> {
        self.function
            .instruction_from_index(block.start_index())
            .unwrap()
    }

    fn iter(&self, block: &BasicBlock<Self>) -> LowLevelILBlockIter<'func, M, F> {
        LowLevelILBlockIter {
            function: self.function,
            range: (block.start_index().0)..(block.end_index().0),
        }
    }
}

impl<M, F> Debug for LowLevelILBlock<'_, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LowLevelILBlock")
            .field("function", &self.function)
            .finish()
    }
}

pub struct LowLevelILBlockIter<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    function: &'func LowLevelILFunction<M, F>,
    // TODO: Once step_trait is stable we can do Range<InstructionIndex>
    range: Range<usize>,
}

impl<'func, M, F> Iterator for LowLevelILBlockIter<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    type Item = LowLevelILInstruction<'func, M, F>;

    fn next(&mut self) -> Option<Self::Item> {
        self.range
            .next()
            .map(LowLevelInstructionIndex)
            .and_then(|idx| self.function.instruction_from_index(idx))
    }
}
