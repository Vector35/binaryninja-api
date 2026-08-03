use super::node::SimilaritySessionNode;
use super::SimilaritySessionNodeId;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use binaryninjacore_sys::*;
use std::ffi::c_void;

/// Receives notifications after nodes or edges are added to or removed from a session graph.
pub trait SimilaritySessionGraphReceiver: Send + Sync + 'static {
    fn on_graph_changed(&self);
}

/// A core-backed session graph receiver.
pub struct CoreSimilaritySessionGraphReceiver {
    pub(crate) handle: *mut BNSimilaritySessionGraphReceiver,
}

impl CoreSimilaritySessionGraphReceiver {
    pub unsafe fn from_raw(handle: *mut BNSimilaritySessionGraphReceiver) -> Self {
        Self { handle }
    }

    pub unsafe fn ref_from_raw(handle: *mut BNSimilaritySessionGraphReceiver) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    pub fn create<C: SimilaritySessionGraphReceiver>(
        receiver: C,
    ) -> Ref<CoreSimilaritySessionGraphReceiver> {
        let receiver = Box::into_raw(Box::new(receiver));
        let mut callbacks = BNCustomSimilaritySessionGraphReceiver {
            context: receiver.cast(),
            externalRefTaken: None,
            externalRefReleased: None,
            onGraphChanged: Some(cb_on_graph_changed::<C>),
            free: Some(cb_receiver_free::<C>),
        };
        let raw_receiver = unsafe { BNCreateCustomSimilaritySessionGraphReceiver(&mut callbacks) };
        unsafe { CoreSimilaritySessionGraphReceiver::ref_from_raw(raw_receiver) }
    }
}

impl SimilaritySessionGraphReceiver for CoreSimilaritySessionGraphReceiver {
    fn on_graph_changed(&self) {
        unsafe { BNSimilaritySessionGraphReceiverNotifyGraphChanged(self.handle) }
    }
}

unsafe impl Send for CoreSimilaritySessionGraphReceiver {}
unsafe impl Sync for CoreSimilaritySessionGraphReceiver {}

impl ToOwned for CoreSimilaritySessionGraphReceiver {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for CoreSimilaritySessionGraphReceiver {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSimilaritySessionGraphReceiverReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSimilaritySessionGraphReceiver(handle.handle);
    }
}

impl CoreArrayProvider for CoreSimilaritySessionGraphReceiver {
    type Raw = *mut BNSimilaritySessionGraphReceiver;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for CoreSimilaritySessionGraphReceiver {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSimilaritySessionGraphReceiverList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(*raw), context)
    }
}

unsafe extern "C" fn cb_on_graph_changed<C: SimilaritySessionGraphReceiver>(ctxt: *mut c_void) {
    ffi_wrap!("SimilaritySessionGraphReceiver::on_graph_changed", unsafe {
        let ctxt: &C = &*(ctxt as *const C);
        ctxt.on_graph_changed();
    })
}

unsafe extern "C" fn cb_receiver_free<C: SimilaritySessionGraphReceiver>(ctxt: *mut c_void) {
    ffi_wrap!("SimilaritySessionGraphReceiver::free", unsafe {
        let _ = Box::from_raw(ctxt as *mut C);
    })
}

/// A graph that controls node processing order and cannot contain cycles.
///
/// Nodes and edges cannot be changed during a run.
pub struct SimilaritySessionGraph {
    pub(crate) handle: *mut BNSimilaritySessionGraph,
}

impl SimilaritySessionGraph {
    pub unsafe fn ref_from_raw(handle: *mut BNSimilaritySessionGraph) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Adds a node, moving it from its current graph if necessary.
    ///
    /// If either graph is running, the node is unchanged.
    pub fn add_node(&self, node: &SimilaritySessionNode) {
        unsafe { BNSimilaritySessionGraphAddNode(self.handle, node.handle) }
    }

    /// Removes a node and its edges from the graph.
    pub fn remove_node(&self, node: &SimilaritySessionNode) {
        unsafe { BNSimilaritySessionGraphRemoveNode(self.handle, node.handle) }
    }

    /// Returns a node by ID.
    pub fn node(&self, id: SimilaritySessionNodeId) -> Option<Ref<SimilaritySessionNode>> {
        let handle = unsafe { BNSimilaritySessionGraphGetNode(self.handle, id.into()) };
        match handle.is_null() {
            true => None,
            false => Some(unsafe { SimilaritySessionNode::ref_from_raw(handle) }),
        }
    }

    /// Returns all nodes in the graph.
    pub fn nodes(&self) -> Array<SimilaritySessionNode> {
        let mut count = 0;
        let result = unsafe { BNSimilaritySessionGraphGetNodes(self.handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Returns whether an edge can be added without creating a cycle.
    pub fn is_valid_edge(&self, from: &SimilaritySessionNode, to: &SimilaritySessionNode) -> bool {
        unsafe { BNSimilaritySessionGraphIsValidEdge(self.handle, from.handle, to.handle) }
    }

    /// Adds an edge if both nodes are present and it would not create a cycle.
    pub fn add_edge(&self, from: &SimilaritySessionNode, to: &SimilaritySessionNode) -> bool {
        unsafe { BNSimilaritySessionGraphAddEdge(self.handle, from.handle, to.handle) }
    }

    /// Removes an edge from the graph.
    pub fn remove_edge(&self, from: &SimilaritySessionNode, to: &SimilaritySessionNode) -> bool {
        unsafe { BNSimilaritySessionGraphRemoveEdge(self.handle, from.handle, to.handle) }
    }

    /// Adds a graph-change receiver.
    pub fn add_receiver(&self, receiver: &CoreSimilaritySessionGraphReceiver) {
        unsafe { BNSimilaritySessionGraphAddReceiver(self.handle, receiver.handle) }
    }

    /// Removes a graph-change receiver.
    pub fn remove_receiver(&self, receiver: &CoreSimilaritySessionGraphReceiver) {
        unsafe { BNSimilaritySessionGraphRemoveReceiver(self.handle, receiver.handle) }
    }

    /// Returns the graph-change receivers registered with this graph.
    pub fn receivers(&self) -> Array<CoreSimilaritySessionGraphReceiver> {
        let mut count = 0;
        let result = unsafe { BNSimilaritySessionGraphGetReceivers(self.handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Returns groups of nodes in processing order. Nodes in the same group may run in parallel.
    pub fn schedule(&self) -> Vec<Vec<Ref<SimilaritySessionNode>>> {
        let mut level_count = 0;
        let mut node_counts_ptr: *mut usize = std::ptr::null_mut();
        let raw_schedule = unsafe {
            BNSimilaritySessionGraphGetSchedule(self.handle, &mut node_counts_ptr, &mut level_count)
        };

        let mut result = Vec::with_capacity(level_count);
        unsafe {
            let raw_levels = std::slice::from_raw_parts(raw_schedule, level_count);
            let node_counts = std::slice::from_raw_parts(node_counts_ptr, level_count);
            for (&raw_level, &count) in raw_levels.iter().zip(node_counts) {
                let level = std::slice::from_raw_parts(raw_level, count)
                    .iter()
                    .map(|&node| {
                        SimilaritySessionNode::ref_from_raw(BNNewSimilaritySessionNodeReference(
                            node,
                        ))
                    })
                    .collect();
                result.push(level);
            }
            BNFreeSimilaritySessionNodeSchedule(raw_schedule, node_counts_ptr, level_count);
        }
        result
    }
}

impl ToOwned for SimilaritySessionGraph {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for SimilaritySessionGraph {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSimilaritySessionGraphReference(handle.handle),
        })
    }
    unsafe fn dec_ref(handle: &Self) {
        BNFreeSimilaritySessionGraph(handle.handle);
    }
}
