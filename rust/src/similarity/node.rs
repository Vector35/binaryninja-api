use super::{
    SimilarityApplyStatus, SimilarityEntityId, SimilarityEntityInfo, SimilarityEntityRef,
    SimilarityResult, SimilarityResultId, SimilaritySessionNodeId,
};
use crate::binary_view::BinaryView;
use crate::file_metadata::FileMetadata;
use crate::function::Function;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::settings::Settings;
use binaryninjacore_sys::*;
use std::ffi::{CStr, CString};

/// The main unit of similarity processing.
pub struct SimilaritySessionNode {
    pub(crate) handle: *mut BNSimilaritySessionNode,
}

impl SimilaritySessionNode {
    /// Creates a node for an open view and schedules its functions.
    pub fn new(view: &BinaryView) -> Ref<Self> {
        let handle = unsafe { BNCreateSimilaritySessionNode(view.handle) };
        unsafe { Ref::new(Self { handle }) }
    }

    /// Creates a node that opens its view and schedules its functions when run.
    ///
    /// The session closes the view when the run no longer needs it, so the view may be unavailable at
    /// other times.
    pub fn new_from_file(file: &FileMetadata) -> Ref<Self> {
        let handle = unsafe { BNCreateSimilaritySessionNodeFromFile(file.handle) };
        unsafe { Ref::new(Self { handle }) }
    }

    pub unsafe fn from_raw(handle: *mut BNSimilaritySessionNode) -> Self {
        Self { handle }
    }

    pub unsafe fn ref_from_raw(handle: *mut BNSimilaritySessionNode) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Returns the node's open view if one is available.
    ///
    /// If the node was created with [`SimilaritySessionNode::new_from_file`], its view may be
    /// unavailable outside a session run. The session closes the view when the run no longer needs
    /// it.
    pub fn view(&self) -> Option<Ref<BinaryView>> {
        let view = unsafe { BNSimilaritySessionNodeGetView(self.handle) };
        if view.is_null() {
            None
        } else {
            Some(unsafe { BinaryView::ref_from_raw(view) })
        }
    }

    /// Replaces the node's view and creates entities for its functions.
    ///
    /// A view backed by a different [`FileMetadata`] is ignored. Do not mix files.
    pub fn set_view(&self, view: Option<&BinaryView>) {
        unsafe {
            BNSimilaritySessionNodeSetView(
                self.handle,
                view.map(|view| view.handle).unwrap_or(std::ptr::null_mut()),
            )
        }
    }

    /// Returns the file used by the node.
    pub fn file(&self) -> Ref<FileMetadata> {
        let file = unsafe { BNSimilaritySessionNodeGetFile(self.handle) };
        FileMetadata::ref_from_raw(file)
    }

    /// Returns the settings used when this node opens its view.
    ///
    /// Modify the returned settings before running the session.
    pub fn load_options(&self) -> Ref<Settings> {
        let settings = unsafe { BNSimilaritySessionNodeGetLoadOptions(self.handle) };
        unsafe { Settings::ref_from_raw(settings) }
    }

    /// Returns the node's ID.
    pub fn id(&self) -> SimilaritySessionNodeId {
        unsafe { BNSimilaritySessionNodeGetId(self.handle) }.into()
    }

    /// Adds an entity without scheduling it.
    ///
    /// An existing entity with the same type and address is reused. A non-empty name refreshes its
    /// display name.
    pub fn create_entity(&self, info: SimilarityEntityInfo) -> SimilarityEntityId {
        let name =
            CString::new(info.name).expect("similarity entity names cannot contain null bytes");
        let raw_info = BNSimilarityEntityInfo {
            type_: info.entity_type,
            address: info.address,
            name: name.as_ptr(),
        };
        unsafe { BNSimilaritySessionNodeCreateEntity(self.handle, &raw_info) }.into()
    }

    /// Removes an entity, its schedule, its provider results, and its selected result.
    ///
    /// If you are looking to unschedule an entity, use [`SimilaritySessionNode::remove_scheduled_entity`].
    pub fn remove_entity(&self, id: SimilarityEntityId) -> bool {
        unsafe { BNSimilaritySessionNodeRemoveEntity(self.handle, id.into()) }
    }

    /// Returns information about an entity.
    pub fn entity(&self, id: SimilarityEntityId) -> Option<SimilarityEntityInfo> {
        let mut info = BNSimilarityEntityInfo::default();
        let success =
            unsafe { BNSimilaritySessionNodeGetEntity(self.handle, id.into(), &mut info) };
        if success {
            let result = SimilarityEntityInfo {
                entity_type: info.type_,
                address: info.address,
                name: if info.name.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(info.name) }
                        .to_string_lossy()
                        .into_owned()
                },
            };
            unsafe { BNFreeSimilarityEntityInfo(&mut info) };
            Some(result)
        } else {
            None
        }
    }

    /// Returns all entities in the node, including entities used only as match targets.
    pub fn entities(&self) -> Array<SimilarityEntityId> {
        let mut count = 0;
        let entities = unsafe { BNSimilaritySessionNodeGetEntities(self.handle, &mut count) };
        unsafe { Array::new(entities, count, ()) }
    }

    /// Schedules an entity for the next provider round.
    ///
    /// The session consumes each scheduled batch before resolution. Resolvers can schedule an entity again to
    /// request another round.
    ///
    /// New nodes schedule all available entities, so this is mainly needed for entities added later.
    pub fn add_scheduled_entity(&self, id: SimilarityEntityId) -> bool {
        unsafe { BNSimilaritySessionNodeAddScheduledEntity(self.handle, id.into()) }
    }

    /// Unschedules an entity without removing it from the node.
    ///
    /// If you are looking to remove an entity, use [`SimilaritySessionNode::remove_entity`].
    pub fn remove_scheduled_entity(&self, id: SimilarityEntityId) -> bool {
        unsafe { BNSimilaritySessionNodeRemoveScheduledEntity(self.handle, id.into()) }
    }

    /// Returns the entities waiting for provider processing.
    pub fn scheduled_entities(&self) -> Array<SimilarityEntityId> {
        let mut count = 0;
        let entities =
            unsafe { BNSimilaritySessionNodeGetScheduledEntities(self.handle, &mut count) };
        unsafe { Array::new(entities, count, ()) }
    }

    /// Returns the function represented by an entity, if it is available.
    pub fn entity_function(&self, id: SimilarityEntityId) -> Option<Ref<Function>> {
        let function = unsafe { BNSimilaritySessionNodeGetEntityFunction(self.handle, id.into()) };
        if function.is_null() {
            None
        } else {
            Some(unsafe { Function::ref_from_raw(function) })
        }
    }

    /// Returns the result IDs for an entity.
    pub fn results(&self, entity: SimilarityEntityId) -> Vec<SimilarityResultId> {
        let mut count = 0;
        let results =
            unsafe { BNSimilaritySessionNodeGetResults(self.handle, entity.into(), &mut count) };
        let output = unsafe { std::slice::from_raw_parts(results, count) }
            .iter()
            .copied()
            .map(SimilarityResultId::from)
            .collect();
        unsafe { BNFreeSimilarityResultIdList(results) };
        output
    }

    /// Returns a stored result by its ID, which is unique within the node.
    pub fn result(&self, result: SimilarityResultId) -> Option<SimilarityResult> {
        let mut output = BNSimilarityResult::default();
        unsafe {
            BNSimilaritySessionNodeGetResult(self.handle, result.into(), &mut output)
                .then(|| output.into())
        }
    }

    /// Applies the standard metadata transfer from a target entity.
    pub fn apply_target(
        &self,
        entity: SimilarityEntityId,
        target: SimilarityEntityRef,
    ) -> SimilarityApplyStatus {
        let target = target.into();
        unsafe { BNSimilaritySessionNodeApplyTarget(self.handle, entity.into(), &target) }
    }

    /// Selects a provider result for an entity.
    ///
    pub fn set_resolved_result(
        &self,
        entity: SimilarityEntityId,
        result: SimilarityResultId,
    ) -> bool {
        unsafe {
            BNSimilaritySessionNodeSetResolvedResult(self.handle, entity.into(), result.into())
        }
    }

    /// Returns the selected result for an entity.
    pub fn resolved_result(&self, entity: SimilarityEntityId) -> Option<SimilarityResultId> {
        let mut result = BNSimilarityResultId::default();
        let success = unsafe {
            BNSimilaritySessionNodeGetResolvedResult(self.handle, entity.into(), &mut result)
        };
        success.then(|| result.into())
    }

    /// Clears the selected result for an entity.
    pub fn clear_resolved_result(&self, entity: SimilarityEntityId) -> bool {
        unsafe { BNSimilaritySessionNodeClearResolvedResult(self.handle, entity.into()) }
    }

    /// Returns the IDs of nodes with edges into this node, in ascending order.
    pub fn incoming_edges(&self) -> Vec<SimilaritySessionNodeId> {
        let mut count = 0;
        let edges = unsafe { BNSimilaritySessionNodeGetIncomingEdges(self.handle, &mut count) };
        let result = unsafe { std::slice::from_raw_parts(edges, count) }
            .iter()
            .copied()
            .map(Into::into)
            .collect();
        unsafe { BNFreeSimilaritySessionNodeEdgeList(edges) };
        result
    }

    /// Returns the IDs of nodes with edges out of this node, in ascending order.
    pub fn outgoing_edges(&self) -> Vec<SimilaritySessionNodeId> {
        let mut count = 0;
        let edges = unsafe { BNSimilaritySessionNodeGetOutgoingEdges(self.handle, &mut count) };
        let result = unsafe { std::slice::from_raw_parts(edges, count) }
            .iter()
            .copied()
            .map(Into::into)
            .collect();
        unsafe { BNFreeSimilaritySessionNodeEdgeList(edges) };
        result
    }

    /// Returns nodes with edges into this node, ordered by ID.
    pub fn incoming_nodes(&self) -> Array<SimilaritySessionNode> {
        let mut count = 0;
        let result = unsafe { BNSimilaritySessionNodeGetIncomingNodes(self.handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Returns nodes with edges out of this node, ordered by ID.
    pub fn outgoing_nodes(&self) -> Array<SimilaritySessionNode> {
        let mut count = 0;
        let result = unsafe { BNSimilaritySessionNodeGetOutgoingNodes(self.handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }
}

unsafe impl RefCountable for SimilaritySessionNode {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSimilaritySessionNodeReference(handle.handle),
        })
    }
    unsafe fn dec_ref(handle: &Self) {
        BNFreeSimilaritySessionNode(handle.handle);
    }
}

impl ToOwned for SimilaritySessionNode {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

impl CoreArrayProvider for SimilaritySessionNode {
    type Raw = *mut BNSimilaritySessionNode;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

impl CoreArrayProvider for SimilarityEntityId {
    type Raw = BNSimilarityEntityId;
    type Context = ();
    type Wrapped<'a> = SimilarityEntityId;
}

unsafe impl CoreArrayProviderInner for SimilarityEntityId {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeSimilarityEntityList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        (*raw).into()
    }
}

unsafe impl CoreArrayProviderInner for SimilaritySessionNode {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSimilaritySessionNodeList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(*raw), context)
    }
}
