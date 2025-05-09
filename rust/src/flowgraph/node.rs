use crate::basic_block::{BasicBlock, BlockContext};
use crate::disassembly::DisassemblyTextLine;
use crate::flowgraph::edge::{EdgeStyle, FlowGraphEdge};
use crate::flowgraph::{BranchType, FlowGraph};
use crate::function::HighlightColor;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use binaryninjacore_sys::*;
use std::fmt::{Debug, Formatter};

#[derive(PartialEq, Eq, Hash)]
pub struct FlowGraphNode {
    pub(crate) handle: *mut BNFlowGraphNode,
}

impl FlowGraphNode {
    pub(crate) unsafe fn from_raw(raw: *mut BNFlowGraphNode) -> Self {
        Self { handle: raw }
    }

    pub(crate) unsafe fn ref_from_raw(raw: *mut BNFlowGraphNode) -> Ref<Self> {
        Ref::new(Self { handle: raw })
    }

    pub fn new(graph: &FlowGraph) -> Ref<Self> {
        unsafe { FlowGraphNode::ref_from_raw(BNCreateFlowGraphNode(graph.handle)) }
    }

    pub fn basic_block<C: BlockContext>(&self, context: C) -> Option<Ref<BasicBlock<C>>> {
        let block_ptr = unsafe { BNGetFlowGraphBasicBlock(self.handle) };
        if block_ptr.is_null() {
            return None;
        }
        Some(unsafe { BasicBlock::ref_from_raw(block_ptr, context) })
    }

    pub fn set_basic_block<C: BlockContext>(&self, block: Option<&BasicBlock<C>>) {
        match block {
            Some(block) => unsafe { BNSetFlowGraphBasicBlock(self.handle, block.handle) },
            None => unsafe { BNSetFlowGraphBasicBlock(self.handle, std::ptr::null_mut()) },
        }
    }

    pub fn lines(&self) -> Array<DisassemblyTextLine> {
        let mut count = 0;
        let result = unsafe { BNGetFlowGraphNodeLines(self.handle, &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn set_lines(&self, lines: impl IntoIterator<Item = DisassemblyTextLine>) {
        // NOTE: This will create allocations and increment tag refs, we must call DisassemblyTextLine::free_raw
        let mut raw_lines: Vec<BNDisassemblyTextLine> = lines
            .into_iter()
            .map(DisassemblyTextLine::into_raw)
            .collect();
        unsafe {
            BNSetFlowGraphNodeLines(self.handle, raw_lines.as_mut_ptr(), raw_lines.len());
            for raw_line in raw_lines {
                DisassemblyTextLine::free_raw(raw_line);
            }
        }
    }

    /// Returns the graph position of the node in X, Y form.
    pub fn position(&self) -> (i32, i32) {
        let pos_x = unsafe { BNGetFlowGraphNodeX(self.handle) };
        let pos_y = unsafe { BNGetFlowGraphNodeY(self.handle) };
        (pos_x, pos_y)
    }

    /// Sets the graph position of the node.
    pub fn set_position(&self, x: i32, y: i32) {
        unsafe { BNFlowGraphNodeSetX(self.handle, x) };
        unsafe { BNFlowGraphNodeSetY(self.handle, y) };
    }

    pub fn highlight_color(&self) -> HighlightColor {
        let raw = unsafe { BNGetFlowGraphNodeHighlight(self.handle) };
        HighlightColor::from(raw)
    }

    pub fn set_highlight_color(&self, highlight: HighlightColor) {
        unsafe { BNSetFlowGraphNodeHighlight(self.handle, highlight.into()) };
    }

    pub fn incoming_edges(&self) -> Array<FlowGraphEdge> {
        let mut count = 0;
        let result = unsafe { BNGetFlowGraphNodeIncomingEdges(self.handle, &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn outgoing_edges(&self) -> Array<FlowGraphEdge> {
        let mut count = 0;
        let result = unsafe { BNGetFlowGraphNodeOutgoingEdges(self.handle, &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Connects two flow graph nodes with an edge.
    pub fn add_outgoing_edge(
        &self,
        type_: BranchType,
        target: &FlowGraphNode,
        edge_style: EdgeStyle,
    ) {
        unsafe {
            BNAddFlowGraphNodeOutgoingEdge(self.handle, type_, target.handle, edge_style.into())
        }
    }
}

impl Debug for FlowGraphNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowGraphNode")
            .field("lines", &self.lines().to_vec())
            .finish()
    }
}

unsafe impl RefCountable for FlowGraphNode {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewFlowGraphNodeReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeFlowGraphNode(handle.handle);
    }
}

impl ToOwned for FlowGraphNode {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

impl CoreArrayProvider for FlowGraphNode {
    type Raw = *mut BNFlowGraphNode;
    type Context = ();
    type Wrapped<'a> = Guard<'a, FlowGraphNode>;
}

unsafe impl CoreArrayProviderInner for FlowGraphNode {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _: &Self::Context) {
        BNFreeFlowGraphNodeList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(*raw), context)
    }
}
