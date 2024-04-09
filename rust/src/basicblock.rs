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

use std::fmt;

use crate::architecture::CoreArchitecture;
use crate::function::Function;
use binaryninjacore_sys::*;

use crate::rc::*;

enum EdgeDirection {
    Incoming,
    Outgoing,
}

pub struct Edge<'a, C: 'a + BlockContext> {
    branch: super::BranchType,
    back_edge: bool,
    source: Guard<'a, BasicBlock<C>>,
    target: Guard<'a, BasicBlock<C>>,
}

impl<'a, C: 'a + BlockContext> Edge<'a, C> {
    pub fn branch_type(&self) -> super::BranchType {
        self.branch
    }

    pub fn back_edge(&self) -> bool {
        self.back_edge
    }

    pub fn source(&self) -> &BasicBlock<C> {
        &self.source
    }

    pub fn target(&self) -> &BasicBlock<C> {
        &self.target
    }
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

pub struct BasicBlockEdges<'a, C: BlockContext> {
    edges: *mut BNBasicBlockEdge,
    count: usize,
    dir: EdgeDirection,
    orig_block: &'a BasicBlock<C>,
}

impl<'a, C: BlockContext> ArrayProvider for BasicBlockEdges<'a, C> {
    type Raw = BNBasicBlockEdge;
    type Wrapped<'b> = Edge<'a, C> where 'a: 'b;

    fn raw_parts(&self) -> (*mut Self::Raw, usize) {
        (self.edges, self.count)
    }

    unsafe fn wrap_raw<'b>(&'b self, raw: &'b Self::Raw) -> Self::Wrapped<'b> {
        let edge_target = Guard::new(
            BasicBlock::from_raw(raw.target, self.orig_block.context.clone()),
            raw,
        );
        let orig_block = Guard::new(
            BasicBlock::from_raw(self.orig_block.handle, self.orig_block.context.clone()),
            raw,
        );

        let (source, target) = match self.dir {
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

    unsafe fn free(&mut self) {
        BNFreeBasicBlockEdgeList(self.edges, self.count);
    }
}

impl<'a, 'b, C: BlockContext> IntoIterator for &'a BasicBlockEdges<'b, C> {
    type IntoIter = ArrayIter<'a, BasicBlockEdges<'b, C>>;
    type Item = <BasicBlockEdges<'b, C> as ArrayProvider>::Wrapped<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub trait BlockContext: Clone + Sync + Send + Sized {
    type Instruction;
    type Iter: Iterator<Item = Self::Instruction>;

    fn start(&self, block: &BasicBlock<Self>) -> Self::Instruction;
    fn iter(&self, block: &BasicBlock<Self>) -> Self::Iter;
}

#[derive(PartialEq, Eq, Hash)]
pub struct BasicBlock<C: BlockContext> {
    pub(crate) handle: *mut BNBasicBlock,
    context: C,
}

unsafe impl<C: BlockContext> Send for BasicBlock<C> {}
unsafe impl<C: BlockContext> Sync for BasicBlock<C> {}

impl<C: BlockContext> BasicBlock<C> {
    pub(crate) unsafe fn from_raw(handle: *mut BNBasicBlock, context: C) -> Self {
        Self { handle, context }
    }

    // TODO native bb vs il bbs
    pub fn function(&self) -> Ref<Function> {
        unsafe {
            let func = BNGetBasicBlockFunction(self.handle);
            Function::from_raw(func)
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

    pub fn raw_start(&self) -> u64 {
        unsafe { BNGetBasicBlockStart(self.handle) }
    }

    pub fn raw_end(&self) -> u64 {
        unsafe { BNGetBasicBlockEnd(self.handle) }
    }

    pub fn raw_length(&self) -> u64 {
        unsafe { BNGetBasicBlockLength(self.handle) }
    }

    pub fn incoming_edges(&self) -> BasicBlockEdges<'_, C> {
        unsafe {
            let mut count = 0;
            let edges = BNGetBasicBlockIncomingEdges(self.handle, &mut count);

            BasicBlockEdges {
                edges,
                count,
                dir: EdgeDirection::Incoming,
                orig_block: self,
            }
        }
    }

    pub fn outgoing_edges(&self) -> BasicBlockEdges<'_, C> {
        unsafe {
            let mut count = 0;
            let edges = BNGetBasicBlockOutgoingEdges(self.handle, &mut count);

            BasicBlockEdges {
                edges,
                count,
                dir: EdgeDirection::Outgoing,
                orig_block: self,
            }
        }
    }

    // is this valid for il blocks?
    pub fn has_undetermined_outgoing_edges(&self) -> bool {
        unsafe { BNBasicBlockHasUndeterminedOutgoingEdges(self.handle) }
    }

    pub fn can_exit(&self) -> bool {
        unsafe { BNBasicBlockCanExit(self.handle) }
    }

    pub fn index(&self) -> usize {
        unsafe { BNGetBasicBlockIndex(self.handle) }
    }

    pub fn immediate_dominator(&self) -> Option<Ref<Self>> {
        unsafe {
            let block = BNGetBasicBlockImmediateDominator(self.handle, false);

            if block.is_null() {
                return None;
            }

            Some(Ref::new(BasicBlock::from_raw(block, self.context.clone())))
        }
    }

    pub fn dominators(&self) -> BasicBlocks<C> {
        unsafe {
            let mut count = 0;
            let blocks = BNGetBasicBlockDominators(self.handle, &mut count, false);

            BasicBlocks::new(blocks, count, self.context.clone())
        }
    }

    pub fn strict_dominators(&self) -> BasicBlocks<C> {
        unsafe {
            let mut count = 0;
            let blocks = BNGetBasicBlockStrictDominators(self.handle, &mut count, false);

            BasicBlocks::new(blocks, count, self.context.clone())
        }
    }

    pub fn dominator_tree_children(&self) -> BasicBlocks<C> {
        unsafe {
            let mut count = 0;
            let blocks = BNGetBasicBlockDominatorTreeChildren(self.handle, &mut count, false);

            BasicBlocks::new(blocks, count, self.context.clone())
        }
    }

    pub fn dominance_frontier(&self) -> BasicBlocks<C> {
        unsafe {
            let mut count = 0;
            let blocks = BNGetBasicBlockDominanceFrontier(self.handle, &mut count, false);

            BasicBlocks::new(blocks, count, self.context.clone())
        }
    }

    // TODO iterated dominance frontier
}

impl<'a, C: BlockContext> IntoIterator for &'a BasicBlock<C> {
    type Item = C::Instruction;
    type IntoIter = C::Iter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<C: fmt::Debug + BlockContext> fmt::Debug for BasicBlock<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<bb handle {:p} context {:?} contents: {} -> {}>",
            self.handle,
            &self.context,
            self.raw_start(),
            self.raw_end()
        )
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

pub struct BasicBlocks<C: BlockContext> {
    blocks: *mut *mut BNBasicBlock,
    count: usize,
    context: C,
}

impl<C: BlockContext> BasicBlocks<C> {
    pub fn new(blocks: *mut *mut BNBasicBlock, count: usize, context: C) -> Self {
        Self {
            blocks,
            count,
            context,
        }
    }
}

impl<C: BlockContext> ArrayProvider for BasicBlocks<C> {
    type Raw = *mut BNBasicBlock;
    type Wrapped<'a> = Guard<'a, BasicBlock<C>> where C: 'a;
    fn raw_parts(&self) -> (*mut Self::Raw, usize) {
        (self.blocks, self.count)
    }
    unsafe fn wrap_raw<'a>(&'a self, raw: &'a Self::Raw) -> Self::Wrapped<'a> {
        Guard::new(
            BasicBlock::from_raw(*raw, self.context.clone()),
            &self.context,
        )
    }
    unsafe fn free(&mut self) {
        BNFreeBasicBlockList(self.blocks, self.count);
    }
}

impl<'a, C: BlockContext> IntoIterator for &'a BasicBlocks<C> {
    type IntoIter = ArrayIter<'a, BasicBlocks<C>>;
    type Item = <BasicBlocks<C> as ArrayProvider>::Wrapped<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
