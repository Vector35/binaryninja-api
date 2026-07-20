//! The [`FlowGraphLayout`] trait allows you to customize the layout of flow graphs.

use crate::flowgraph::{FlowGraph, FlowGraphNode};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref, RefCountable};
use crate::string::{BnString, IntoCStr};
use binaryninjacore_sys::*;
use std::ffi::c_void;
use std::ptr::NonNull;

/// Registers a custom [`FlowGraphLayout`], this allows you to customize the layout of flow graphs.
pub fn register_flowgraph_layout<C: FlowGraphLayout>(
    name: &str,
    custom: C,
) -> (&'static C, CoreFlowGraphLayout) {
    let renderer = Box::leak(Box::new(custom));
    let mut callbacks = BNCustomFlowGraphLayout {
        context: renderer as *mut _ as *mut c_void,
        layout: Some(cb_layout::<C>),
    };
    let name_raw = name.to_cstr();
    let result = unsafe { BNRegisterFlowGraphLayout(name_raw.as_ptr(), &mut callbacks) };
    let core = unsafe { CoreFlowGraphLayout::from_raw(NonNull::new(result).unwrap()) };
    (renderer, core)
}

/// The interface responsible for laying out a [`FlowGraph`].
pub trait FlowGraphLayout: Sized + Sync + Send + 'static {
    /// Perform the flow graph layout, returning `true` if successful.
    ///
    /// The implementation is responsible for doing four main things (usually in this order):
    ///
    /// 1. Adjusting `nodes` positions using [`FlowGraphNode::set_position`].
    /// 2. Setting the edge points (e.g. the lines between nodes) using [`FlowGraphNode::set_outgoing_edge_points`].
    /// 3. Setting the `nodes` visibility region using [`FlowGraphNode::set_visibility_region`].
    /// 4. Setting the size of the graph using [`FlowGraph::set_size`].
    fn layout(&self, graph: &FlowGraph, nodes: &[FlowGraphNode]) -> bool;
}

pub struct CoreFlowGraphLayout {
    pub(crate) handle: NonNull<BNFlowGraphLayout>,
}

impl CoreFlowGraphLayout {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNFlowGraphLayout>) -> CoreFlowGraphLayout {
        Self { handle }
    }

    pub fn all() -> Array<CoreFlowGraphLayout> {
        let mut count = 0;
        let result = unsafe { BNGetFlowGraphLayouts(&mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn by_name(name: &str) -> Option<CoreFlowGraphLayout> {
        let name_raw = name.to_cstr();
        let layout_ptr = unsafe { BNGetFlowGraphLayoutByName(name_raw.as_ptr()) };
        Some(unsafe { CoreFlowGraphLayout::from_raw(NonNull::new(layout_ptr)?) })
    }

    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNGetFlowGraphLayoutName(self.handle.as_ptr())) }
    }
}

impl FlowGraphLayout for CoreFlowGraphLayout {
    fn layout(&self, graph: &FlowGraph, nodes: &[FlowGraphNode]) -> bool {
        // SAFETY: FlowGraphNode to *mut BNFlowGraphNode is safe (repr transparent)
        unsafe {
            BNFlowGraphLayoutLayout(
                self.handle.as_ptr(),
                graph.handle,
                nodes.as_ptr() as *mut _,
                nodes.len(),
            )
        }
    }
}

impl CoreArrayProvider for CoreFlowGraphLayout {
    type Raw = *mut BNFlowGraphLayout;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CoreFlowGraphLayout {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        unsafe { BNFreeFlowGraphLayoutList(raw) }
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        unsafe {
            // TODO: Because handle is a NonNull we should prob make Self::Raw that as well...
            let handle = NonNull::new(*raw).unwrap();
            CoreFlowGraphLayout::from_raw(handle)
        }
    }
}

unsafe impl Send for CoreFlowGraphLayout {}
unsafe impl Sync for CoreFlowGraphLayout {}

/// Represents a queued flow graph layout request, given out by [`FlowGraph::request_layout`].
pub struct FlowGraphLayoutRequest {
    pub(crate) handle: NonNull<BNFlowGraphLayoutRequest>,
}

impl FlowGraphLayoutRequest {
    pub(crate) unsafe fn ref_from_raw(
        handle: NonNull<BNFlowGraphLayoutRequest>,
    ) -> Ref<FlowGraphLayoutRequest> {
        unsafe { Ref::new(Self { handle }) }
    }

    /// The flow graph that this request is for.
    pub fn graph(&self) -> Ref<FlowGraph> {
        unsafe {
            FlowGraph::ref_from_raw(BNGetGraphForFlowGraphLayoutRequest(self.handle.as_ptr()))
        }
    }

    /// Returns `true` if the layout request has completed.
    pub fn is_complete(&self) -> bool {
        unsafe { BNIsFlowGraphLayoutRequestComplete(self.handle.as_ptr()) }
    }

    /// Removes the request from the flow graphs layout queue, and sets [`FlowGraph::is_layout_complete`]
    pub fn abort(&self) {
        unsafe { BNAbortFlowGraphLayoutRequest(self.handle.as_ptr()) }
    }
}

impl ToOwned for FlowGraphLayoutRequest {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for FlowGraphLayoutRequest {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        unsafe {
            Ref::new(Self {
                handle: NonNull::new(BNNewFlowGraphLayoutRequestReference(handle.handle.as_ptr()))
                    .unwrap(),
            })
        }
    }

    unsafe fn dec_ref(handle: &Self) {
        unsafe {
            BNFreeFlowGraphLayoutRequest(handle.handle.as_ptr());
        }
    }
}

unsafe extern "C" fn cb_layout<C: FlowGraphLayout>(
    ctxt: *mut c_void,
    graph: *mut BNFlowGraph,
    nodes: *mut *mut BNFlowGraphNode,
    node_count: usize,
) -> bool {
    unsafe {
        let ctxt = ctxt as *mut C;
        let nodes_slice = core::slice::from_raw_parts(nodes, node_count);
        let nodes: Vec<_> = nodes_slice
            .iter()
            .map(|ptr| FlowGraphNode::from_raw(*ptr))
            .collect();
        (*ctxt).layout(&FlowGraph::from_raw(graph), &nodes)
    }
}
