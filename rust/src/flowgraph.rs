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

//! Interfaces for creating and displaying pretty CFGs in Binary Ninja.

use binaryninjacore_sys::*;

use crate::disassembly::DisassemblyTextLine;

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
            style,
            width,
            color,
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
        unsafe { FlowGraphNode::from_raw(BNCreateFlowGraphNode(graph.handle)) }
    }

    pub fn set_disassembly_lines(&self, lines: &'a [DisassemblyTextLine]) {
        unsafe {
            BNSetFlowGraphNodeLines(self.handle, lines.as_ptr() as *mut _, lines.len());
            // BNFreeDisassemblyTextLines(lines.as_ptr() as *mut _, lines.len());  // Shouldn't need...would be a double free?
        }
    }

    pub fn set_lines(&self, lines: Vec<&str>) {
        let lines: Vec<_> = lines
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
        unsafe { BNAddFlowGraphNodeOutgoingEdge(self.handle, type_, target.handle, edge_style.0) }
    }
}

impl<'a> Clone for FlowGraphNode<'a> {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(BNNewFlowGraphNodeReference(self.handle)) }
    }
}

impl<'a> Drop for FlowGraphNode<'a> {
    fn drop(&mut self) {
        unsafe { BNFreeFlowGraphNode(self.handle) }
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
        unsafe { BNAddFlowGraphNode(self.handle, node.handle) }
    }

    pub fn set_option(&self, option: FlowGraphOption, value: bool) {
        unsafe { BNSetFlowGraphOption(self.handle, option, value) }
    }

    pub fn is_option_set(&self, option: FlowGraphOption) -> bool {
        unsafe { BNIsFlowGraphOptionSet(self.handle, option) }
    }
}

impl Clone for FlowGraph {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(BNNewFlowGraphReference(self.handle)) }
    }
}

impl Drop for FlowGraph {
    fn drop(&mut self) {
        unsafe { BNFreeFlowGraph(self.handle) }
    }
}
