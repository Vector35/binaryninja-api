// Copyright 2021-2023 Vector 35 Inc.
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

//! Interfaces for creating and displaying pretty CFGs in Binary Ninja.

use binaryninjacore_sys::*;

use crate::disassembly::DisassemblyTextLine;

use crate::rc::*;

use std::marker::PhantomData;

pub type BranchType = BNBranchType;
pub type EdgePenStyle = BNEdgePenStyle;
pub type ThemeColor = BNThemeColor;
pub type FlowGraphOption = BNFlowGraphOption;

#[repr(transparent)]
pub struct EdgeStyle(pub(crate) BNEdgeStyle);

impl EdgeStyle {
    pub fn new(style: EdgePenStyle, width: usize, color: ThemeColor) -> Self {
        EdgeStyle(BNEdgeStyle {
            style: style,
            width: width,
            color: color,
        })
    }
}

impl Default for EdgeStyle {
    fn default() -> Self {
        EdgeStyle(BNEdgeStyle {
            style: EdgePenStyle::SolidLine,
            width: 0,
            color: ThemeColor::AddressColor,
        })
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct FlowGraphNode<'a> {
    pub(crate) handle: *mut BNFlowGraphNode,
    _data: PhantomData<&'a ()>,
}

impl<'a> FlowGraphNode<'a> {
    pub(crate) unsafe fn from_raw(raw: *mut BNFlowGraphNode) -> Self {
        Self {
            handle: raw,
            _data: PhantomData,
        }
    }

    pub fn new(graph: &FlowGraph) -> Self {
        unsafe { FlowGraphNode::from_raw(BNCreateFlowGraphNode(graph.as_ref().handle)) }
    }

    pub fn set_disassembly_lines(&self, lines: &'a Vec<DisassemblyTextLine>) {
        unsafe {
            BNSetFlowGraphNodeLines(self.as_ref().handle, lines.as_ptr() as *mut _, lines.len());
            // BNFreeDisassemblyTextLines(lines.as_ptr() as *mut _, lines.len());  // Shouldn't need...would be a double free?
        }
    }

    pub fn set_lines(&self, lines: Vec<&str>) {
        let lines = lines
            .iter()
            .map(|&line| DisassemblyTextLine::from(&vec![line]))
            .collect();
        self.set_disassembly_lines(&lines);
    }

    pub fn add_outgoing_edge(
        &self,
        type_: BranchType,
        target: &'a FlowGraphNode,
        edge_style: &'a EdgeStyle,
    ) {
        unsafe {
            BNAddFlowGraphNodeOutgoingEdge(
                self.as_ref().handle,
                type_,
                target.as_ref().handle,
                edge_style.0,
            )
        }
    }
}

unsafe impl<'a> RefCountable for FlowGraphNode<'a> {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewFlowGraphNodeReference(handle.handle),
            _data: PhantomData,
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeFlowGraphNode(handle.handle);
    }
}

impl<'a> AsRef<FlowGraphNode<'a>> for FlowGraphNode<'a> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'a> ToOwned for FlowGraphNode<'a> {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

// TODO : FlowGraph are RefCounted objects, this needs to be changed to only return Refs to FlowGraph

#[derive(PartialEq, Eq, Hash)]
pub struct FlowGraph {
    pub(crate) handle: *mut BNFlowGraph,
}

impl FlowGraph {
    pub(crate) unsafe fn from_raw(raw: *mut BNFlowGraph) -> Self {
        Self { handle: raw }
    }

    pub fn new() -> Self {
        unsafe { FlowGraph::from_raw(BNCreateFlowGraph()) }
    }

    pub fn append(&self, node: &FlowGraphNode) -> usize {
        unsafe { BNAddFlowGraphNode(self.as_ref().handle, node.handle) }
    }

    pub fn set_option(&self, option: FlowGraphOption, value: bool) {
        unsafe { BNSetFlowGraphOption(self.as_ref().handle, option, value) }
    }

    pub fn is_option_set(&self, option: FlowGraphOption) -> bool {
        unsafe { BNIsFlowGraphOptionSet(self.as_ref().handle, option) }
    }
}

unsafe impl RefCountable for FlowGraph {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewFlowGraphReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeFlowGraph(handle.handle);
    }
}

impl AsRef<FlowGraph> for FlowGraph {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl ToOwned for FlowGraph {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}
