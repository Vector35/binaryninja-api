// Copyright 2021-2026 Vector 35 Inc.
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

use crate::high_level_il::HighLevelILFunction;
use crate::low_level_il::LowLevelILRegularFunction;
use crate::medium_level_il::MediumLevelILFunction;
use crate::rc::*;
use crate::render_layer::CoreRenderLayer;
use binaryninjacore_sys::*;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::time::Duration;

pub mod edge;
pub mod layout;
pub mod node;

use crate::binary_view::BinaryView;
use crate::flowgraph::layout::FlowGraphLayoutRequest;
use crate::function::Function;
use crate::string::IntoCStr;
pub use edge::EdgeStyle;
pub use edge::FlowGraphEdge;
pub use node::FlowGraphNode;

pub type EdgePenStyle = BNEdgePenStyle;
pub type ThemeColor = BNThemeColor;
pub type FlowGraphOption = BNFlowGraphOption;

#[repr(transparent)]
#[derive(PartialEq, Eq, Hash)]
pub struct FlowGraph {
    pub(crate) handle: *mut BNFlowGraph,
}

impl FlowGraph {
    pub(crate) unsafe fn from_raw(raw: *mut BNFlowGraph) -> Self {
        Self { handle: raw }
    }

    pub(crate) unsafe fn ref_from_raw(raw: *mut BNFlowGraph) -> Ref<Self> {
        Ref::new(Self { handle: raw })
    }

    /// Create an empty flowgraph.
    ///
    /// If you instead want to create a flowgraph of a given [`Function`], use [`Function::create_graph`].
    pub fn new() -> Ref<Self> {
        unsafe { FlowGraph::ref_from_raw(BNCreateFlowGraph()) }
    }

    /// Requests the flowgraph to be laid out, positioning nodes and routing edges.
    ///
    /// This function returns immediately, with `on_complete` being called when the layout has been
    /// completed, to wait for the request to be completed use [`FlowGraph::request_layout_and_wait`].
    pub fn request_layout<C: FnOnce() + Send + 'static>(
        &self,
        on_complete: C,
    ) -> Ref<FlowGraphLayoutRequest> {
        let context = Box::into_raw(Box::new(on_complete));
        let request_raw_ptr = unsafe {
            BNStartFlowGraphLayout(self.handle, context as *mut _, Some(cb_on_complete::<C>))
        };
        let request_ptr =
            NonNull::new(request_raw_ptr).expect("BNStartFlowGraphLayout returned null");
        unsafe { FlowGraphLayoutRequest::ref_from_raw(request_ptr) }
    }

    /// Blocks until the flow graph layout is complete or until the `timeout` has elapsed, returning
    /// `true` if the layout completed within the timeout, `false` otherwise.
    ///
    /// Use [`FlowGraph::request_layout`] instead if you want to provide a callback when the layout
    /// has been completed and return immediately.
    pub fn request_layout_and_wait(&self, timeout: Duration) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        // IMPORTANT: named `_request` to keep from dropping before function return.
        let _request = self.request_layout(move || {
            let _ = tx.send(());
        });
        rx.recv_timeout(timeout).is_ok()
    }

    pub fn has_updates(&self) -> bool {
        let query_mode = unsafe { BNFlowGraphUpdateQueryMode(self.handle) };
        match query_mode {
            true => unsafe { BNFlowGraphHasUpdates(self.handle) },
            false => false,
        }
    }

    pub fn update(&self) -> Option<Ref<Self>> {
        let new_graph = unsafe { BNUpdateFlowGraph(self.handle) };
        if new_graph.is_null() {
            return None;
        }
        Some(unsafe { FlowGraph::ref_from_raw(new_graph) })
    }

    /// Sends the [`FlowGraph`] to the interaction handlers to display.
    ///
    /// - On headless this is a no-op unless you register a [`crate::interaction::handler::InteractionHandler`].
    /// - On UI this will create a new tab to display the graph.
    pub fn show(&self, title: &str) {
        let raw_title = title.to_cstr();
        match self.view() {
            None => unsafe {
                BNShowGraphReport(std::ptr::null_mut(), raw_title.as_ptr(), self.handle);
            },
            Some(view) => unsafe {
                BNShowGraphReport(view.handle, raw_title.as_ptr(), self.handle);
            },
        }
    }

    /// Whether the flow graph layout is complete.
    pub fn is_layout_complete(&self) -> bool {
        unsafe { BNIsFlowGraphLayoutComplete(self.handle) }
    }

    // TODO: A [`FlowGraphLayoutRequest::abort`] does not actually abort the layout, it sets a flag
    // TODO: in the associated [`FlowGraph`], but we have no way to observe that flag. See the
    // TODO: issue filed here: https://github.com/Vector35/binaryninja-api/issues/7826.
    // pub fn is_aborted(&self) -> bool {}

    pub fn nodes(&self) -> Array<FlowGraphNode> {
        let mut count: usize = 0;
        let nodes_ptr = unsafe { BNGetFlowGraphNodes(self.handle, &mut count) };
        unsafe { Array::new(nodes_ptr, count, ()) }
    }

    /// Returns the nodes that are partially or fully visible within the given region.
    ///
    /// The node visibility region is set with [`FlowGraphNode::set_visibility_region`] when laying
    /// out the graph.
    pub fn visible_nodes(
        &self,
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    ) -> Array<FlowGraphNode> {
        let mut count: usize = 0;
        let nodes_ptr = unsafe {
            BNGetFlowGraphNodesInRegion(self.handle, left, top, right, bottom, &mut count)
        };
        unsafe { Array::new(nodes_ptr, count, ()) }
    }

    pub fn function(&self) -> Option<Ref<Function>> {
        unsafe {
            let func_ptr = BNGetFunctionForFlowGraph(self.handle);
            match func_ptr.is_null() {
                false => Some(Function::ref_from_raw(func_ptr)),
                true => None,
            }
        }
    }

    pub fn set_function(&self, func: Option<&Function>) {
        let func_ptr = func.map(|f| f.handle).unwrap_or(std::ptr::null_mut());
        unsafe { BNSetFunctionForFlowGraph(self.handle, func_ptr) }
    }

    pub fn view(&self) -> Option<Ref<BinaryView>> {
        unsafe {
            let view_ptr = BNGetViewForFlowGraph(self.handle);
            match view_ptr.is_null() {
                false => Some(BinaryView::ref_from_raw(view_ptr)),
                true => None,
            }
        }
    }

    pub fn set_view(&self, view: Option<&BinaryView>) {
        let view_ptr = view.map(|v| v.handle).unwrap_or(std::ptr::null_mut());
        unsafe { BNSetViewForFlowGraph(self.handle, view_ptr) }
    }

    pub fn lifted_il(&self) -> Option<Ref<LowLevelILRegularFunction>> {
        self.function()?.lifted_il().ok()
    }

    pub fn low_level_il(&self) -> Option<Ref<LowLevelILRegularFunction>> {
        unsafe {
            let llil_ptr = BNGetFlowGraphLowLevelILFunction(self.handle);
            match llil_ptr.is_null() {
                false => Some(LowLevelILRegularFunction::ref_from_raw(llil_ptr)),
                true => None,
            }
        }
    }

    pub fn medium_level_il(&self) -> Option<Ref<MediumLevelILFunction>> {
        unsafe {
            let mlil_ptr = BNGetFlowGraphMediumLevelILFunction(self.handle);
            match mlil_ptr.is_null() {
                false => Some(MediumLevelILFunction::ref_from_raw(mlil_ptr)),
                true => None,
            }
        }
    }

    pub fn high_level_il(&self, full_ast: bool) -> Option<Ref<HighLevelILFunction>> {
        unsafe {
            let hlil_ptr = BNGetFlowGraphHighLevelILFunction(self.handle);
            match hlil_ptr.is_null() {
                false => Some(HighLevelILFunction::ref_from_raw(hlil_ptr, full_ast)),
                true => None,
            }
        }
    }

    pub fn get_node(&self, i: usize) -> Option<Ref<FlowGraphNode>> {
        let node_ptr = unsafe { BNGetFlowGraphNode(self.handle, i) };
        if node_ptr.is_null() {
            None
        } else {
            Some(unsafe { FlowGraphNode::ref_from_raw(node_ptr) })
        }
    }

    pub fn get_node_count(&self) -> usize {
        unsafe { BNGetFlowGraphNodeCount(self.handle) }
    }

    pub fn has_nodes(&self) -> bool {
        unsafe { BNFlowGraphHasNodes(self.handle) }
    }

    /// Returns the graph size in width, height form.
    pub fn size(&self) -> (i32, i32) {
        let width = unsafe { BNGetFlowGraphWidth(self.handle) };
        let height = unsafe { BNGetFlowGraphHeight(self.handle) };
        (width, height)
    }

    /// Set the size of the graph.
    pub fn set_size(&self, width: i32, height: i32) {
        unsafe { BNFlowGraphSetWidth(self.handle, width) };
        unsafe { BNFlowGraphSetHeight(self.handle, height) };
    }

    /// Returns the graph margins between nodes.
    pub fn node_margins(&self) -> (i32, i32) {
        let horizontal = unsafe { BNGetHorizontalFlowGraphNodeMargin(self.handle) };
        let vertical = unsafe { BNGetVerticalFlowGraphNodeMargin(self.handle) };
        (horizontal, vertical)
    }

    /// Sets the graph margins between nodes.
    pub fn set_node_margins(&self, horizontal: i32, vertical: i32) {
        unsafe { BNSetFlowGraphNodeMargins(self.handle, horizontal, vertical) };
    }

    pub fn is_node_valid(&self, node: &FlowGraphNode) -> bool {
        unsafe { BNIsNodeValidForFlowGraph(self.handle, node.handle) }
    }

    /// Add a [`FlowGraphNode`] to the graph, returning its index.
    ///
    /// This only works before the flow graph layout is complete, inside [`layout::FlowGraphLayout::layout`].
    pub fn append(&self, node: &FlowGraphNode) -> usize {
        unsafe { BNAddFlowGraphNode(self.handle, node.handle) }
    }

    /// Replaces the node at the given index with the provided [`FlowGraphNode`].
    ///
    /// This only works before the flow graph layout is complete, inside [`layout::FlowGraphLayout::layout`].
    pub fn replace(&self, index: usize, node: &FlowGraphNode) {
        unsafe { BNReplaceFlowGraphNode(self.handle, index, node.handle) }
    }

    /// Removes all nodes from the graph.
    ///
    /// This only works before the flow graph layout is complete, inside [`layout::FlowGraphLayout::layout`].
    pub fn clear(&self) {
        unsafe { BNClearFlowGraphNodes(self.handle) }
    }

    pub fn set_option(&self, option: FlowGraphOption, value: bool) {
        unsafe { BNSetFlowGraphOption(self.handle, option, value) }
    }

    pub fn is_option_set(&self, option: FlowGraphOption) -> bool {
        unsafe { BNIsFlowGraphOptionSet(self.handle, option) }
    }

    /// A list of the currently applied [`CoreRenderLayer`]'s
    pub fn render_layers(&self) -> Array<CoreRenderLayer> {
        let mut count: usize = 0;
        unsafe {
            let handles = BNGetFlowGraphRenderLayers(self.handle, &mut count);
            Array::new(handles, count, ())
        }
    }

    /// Add a Render Layer to be applied to this [`FlowGraph`].
    ///
    /// NOTE: Layers will be applied in the order in which they are added.
    pub fn add_render_layer(&self, layer: &CoreRenderLayer) {
        unsafe { BNAddFlowGraphRenderLayer(self.handle, layer.handle.as_ptr()) };
    }

    /// Remove a Render Layer from being applied to this [`FlowGraph`].
    pub fn remove_render_layer(&self, layer: &CoreRenderLayer) {
        unsafe { BNRemoveFlowGraphRenderLayer(self.handle, layer.handle.as_ptr()) };
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

impl ToOwned for FlowGraph {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe extern "C" fn cb_on_complete<C: FnOnce()>(ctxt: *mut c_void) {
    // Take ownership of the ctxt so that we do not leak, we assume this callback to always
    // be called so that the ctxt may be freed.
    let ctxt: Box<C> = unsafe { Box::from_raw(ctxt as *mut C) };
    ctxt();
}
