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

use crate::architecture::CoreArchitecture;
use crate::function::Function;
use crate::rc::*;
use crate::BranchType;
use binaryninjacore_sys::*;
use std::fmt;
use std::fmt::Debug;

enum EdgeDirection {
    Incoming,
    Outgoing,
}

pub struct Edge<'a, C: 'a + BlockContext> {
    pub branch: BranchType,
    pub back_edge: bool,
    pub source: Guard<'a, BasicBlock<C>>,
    target: Guard<'a, BasicBlock<C>>,
}

impl<'a, C: 'a + fmt::Debug + BlockContext> fmt::Debug for Edge<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} ({}) {:?} -> {:?}",
            self.branch, self.back_edge, &*self.source, &*self.target
        )
    }
}

pub struct EdgeContext<'a, C: 'a + BlockContext> {
    dir: EdgeDirection,
    orig_block: &'a BasicBlock<C>,
}

impl<'a, C: 'a + BlockContext> CoreArrayProvider for Edge<'a, C> {
    type Raw = BNBasicBlockEdge;
    type Context = EdgeContext<'a, C>;
    type Wrapped<'b>
        = Edge<'b, C>
    where
        'a: 'b;
}

unsafe impl<'a, C: 'a + BlockContext> CoreArrayProviderInner for Edge<'a, C> {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeBasicBlockEdgeList(raw, count);
    }

    unsafe fn wrap_raw<'b>(raw: &'b Self::Raw, context: &'b Self::Context) -> Self::Wrapped<'b> {
        let edge_target = Guard::new(
            BasicBlock::from_raw(raw.target, context.orig_block.context.clone()),
            raw,
        );
        let orig_block = Guard::new(
            BasicBlock::from_raw(
                context.orig_block.handle,
                context.orig_block.context.clone(),
            ),
            raw,
        );

        let (source, target) = match context.dir {
            EdgeDirection::Incoming => (edge_target, orig_block),
            EdgeDirection::Outgoing => (orig_block, edge_target),
        };

        Edge {
            branch: raw.type_,
            back_edge: raw.backEdge,
            source,
            target,
        }
    }
}

pub trait BlockContext: Clone + Sync + Send + Sized {
    type Instruction;
    type InstructionIndex: Debug + From<u64>;
    type Iter: Iterator<Item = Self::Instruction>;

    fn start(&self, block: &BasicBlock<Self>) -> Self::Instruction;
    fn iter(&self, block: &BasicBlock<Self>) -> Self::Iter;
}

#[derive(PartialEq, Eq, Hash)]
pub struct BasicBlock<C: BlockContext> {
    pub(crate) handle: *mut BNBasicBlock,
    context: C,
}

impl<C: BlockContext> BasicBlock<C> {
    pub(crate) unsafe fn from_raw(handle: *mut BNBasicBlock, context: C) -> Self {
        Self { handle, context }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNBasicBlock, context: C) -> Ref<Self> {
        Ref::new(Self::from_raw(handle, context))
    }

    // TODO native bb vs il bbs
    pub fn function(&self) -> Ref<Function> {
        unsafe {
            let func = BNGetBasicBlockFunction(self.handle);
            Function::ref_from_raw(func)
        }
    }

    pub fn arch(&self) -> CoreArchitecture {
        unsafe {
            let arch = BNGetBasicBlockArchitecture(self.handle);
            CoreArchitecture::from_raw(arch)
        }
    }

    pub fn iter(&self) -> C::Iter {
        self.context.iter(self)
    }

    pub fn start_index(&self) -> C::InstructionIndex {
        C::InstructionIndex::from(unsafe { BNGetBasicBlockStart(self.handle) })
    }

    pub fn end_index(&self) -> C::InstructionIndex {
        C::InstructionIndex::from(unsafe { BNGetBasicBlockEnd(self.handle) })
    }

    pub fn raw_length(&self) -> u64 {
        unsafe { BNGetBasicBlockLength(self.handle) }
    }

    pub fn incoming_edges(&self) -> Array<Edge<C>> {
        unsafe {
            let mut count = 0;
            let edges = BNGetBasicBlockIncomingEdges(self.handle, &mut count);
            Array::new(
                edges,
                count,
                EdgeContext {
                    dir: EdgeDirection::Incoming,
                    orig_block: self,
                },
            )
        }
    }

    pub fn outgoing_edges(&self) -> Array<Edge<C>> {
        unsafe {
            let mut count = 0;
            let edges = BNGetBasicBlockOutgoingEdges(self.handle, &mut count);
            Array::new(
                edges,
                count,
                EdgeContext {
                    dir: EdgeDirection::Outgoing,
                    orig_block: self,
                },
            )
        }
    }

    // is this valid for il blocks? (it looks like up to MLIL it is)
    pub fn has_undetermined_outgoing_edges(&self) -> bool {
        unsafe { BNBasicBlockHasUndeterminedOutgoingEdges(self.handle) }
    }

    pub fn can_exit(&self) -> bool {
        unsafe { BNBasicBlockCanExit(self.handle) }
    }

    // TODO: Should we new type this? I just cant tell where the consumers of this are.
    pub fn index(&self) -> usize {
        unsafe { BNGetBasicBlockIndex(self.handle) }
    }

    pub fn immediate_dominator(&self) -> Option<Ref<Self>> {
        unsafe {
            // TODO: We don't allow the user to calculate post dominators
            let block = BNGetBasicBlockImmediateDominator(self.handle, false);
            if block.is_null() {
                return None;
            }
            Some(Ref::new(BasicBlock::from_raw(block, self.context.clone())))
        }
    }

    pub fn dominators(&self) -> Array<BasicBlock<C>> {
        unsafe {
            let mut count = 0;
            // TODO: We don't allow the user to calculate post dominators
            let blocks = BNGetBasicBlockDominators(self.handle, &mut count, false);
            Array::new(blocks, count, self.context.clone())
        }
    }

    pub fn strict_dominators(&self) -> Array<BasicBlock<C>> {
        unsafe {
            let mut count = 0;
            // TODO: We don't allow the user to calculate post dominators
            let blocks = BNGetBasicBlockStrictDominators(self.handle, &mut count, false);
            Array::new(blocks, count, self.context.clone())
        }
    }

    pub fn dominator_tree_children(&self) -> Array<BasicBlock<C>> {
        unsafe {
            let mut count = 0;
            // TODO: We don't allow the user to calculate post dominators
            let blocks = BNGetBasicBlockDominatorTreeChildren(self.handle, &mut count, false);
            Array::new(blocks, count, self.context.clone())
        }
    }

    pub fn dominance_frontier(&self) -> Array<BasicBlock<C>> {
        unsafe {
            let mut count = 0;
            // TODO: We don't allow the user to calculate post dominators
            let blocks = BNGetBasicBlockDominanceFrontier(self.handle, &mut count, false);
            Array::new(blocks, count, self.context.clone())
        }
    }

    // TODO iterated dominance frontier
}

impl<C: BlockContext> IntoIterator for &BasicBlock<C> {
    type Item = C::Instruction;
    type IntoIter = C::Iter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<C: BlockContext> IntoIterator for BasicBlock<C> {
    type Item = C::Instruction;
    type IntoIter = C::Iter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<C: fmt::Debug + BlockContext> fmt::Debug for BasicBlock<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BasicBlock")
            .field("context", &self.context)
            .field("start_index", &self.start_index())
            .field("end_index", &self.end_index())
            .field("raw_length", &self.raw_length())
            .finish()
    }
}

impl<C: BlockContext> ToOwned for BasicBlock<C> {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl<C: BlockContext> RefCountable for BasicBlock<C> {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewBasicBlockReference(handle.handle),
            context: handle.context.clone(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeBasicBlock(handle.handle);
    }
}

impl<C: BlockContext> CoreArrayProvider for BasicBlock<C> {
    type Raw = *mut BNBasicBlock;
    type Context = C;
    type Wrapped<'a>
        = Guard<'a, BasicBlock<C>>
    where
        C: 'a;
}

unsafe impl<C: BlockContext> CoreArrayProviderInner for BasicBlock<C> {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeBasicBlockList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(BasicBlock::from_raw(*raw, context.clone()), context)
    }
}

unsafe impl<C: BlockContext> Send for BasicBlock<C> {}
unsafe impl<C: BlockContext> Sync for BasicBlock<C> {}
