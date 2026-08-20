use super::{SimilarityAnnotationType, SimilarityEntityRef, SimilarityViewType};
use crate::binary_view::BinaryView;
use crate::flowgraph::FlowGraph;
use crate::function::{Function, FunctionViewType};
use crate::linear_view::LinearViewObject;
use crate::rc::{Ref, RefCountable};
use crate::string::{BnString, IntoCStr};
use binaryninjacore_sys::*;

/// A graph or linear view used to display a similarity result.
pub struct SimilarityView {
    /// The group used to arrange related views.
    pub group: String,
    /// The kind of view stored in this entry.
    pub view_type: SimilarityViewType,
    /// The flow graph, when `view_type` is a graph.
    pub graph: Option<Ref<FlowGraph>>,
    /// The binary view backing a linear view.
    pub data: Option<Ref<BinaryView>>,
    /// The linear view object, when `view_type` is linear.
    pub linear_view: Option<Ref<LinearViewObject>>,
    /// The session entity for this view, if its renderer provided one.
    pub entity: Option<SimilarityEntityRef>,
}

/// An added, removed, or changed address range `[start, end)`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SimilarityRangeAnnotation {
    pub start: u64,
    pub end: u64,
    pub annotation_type: SimilarityAnnotationType,
}

/// Holds the views used to display a similarity result.
pub struct SimilarityRenderContext {
    pub(crate) handle: *mut BNSimilarityRenderContext,
}

impl SimilarityRenderContext {
    /// Creates an empty render context.
    pub fn new() -> Ref<Self> {
        unsafe { Self::ref_from_raw(BNCreateSimilarityRenderContext()) }
    }

    pub unsafe fn from_raw(handle: *mut BNSimilarityRenderContext) -> Self {
        Self { handle }
    }

    pub unsafe fn ref_from_raw(handle: *mut BNSimilarityRenderContext) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Sets the function representation preferred by renderers writing to this context.
    pub fn set_preferred_view_type(&self, view_type: FunctionViewType) {
        let raw = FunctionViewType::into_raw(view_type);
        unsafe { BNSimilarityRenderContextSetPreferredViewType(self.handle, raw) };
        FunctionViewType::free_raw(raw);
    }

    /// Returns the function representation preferred by renderers writing to this context.
    pub fn preferred_view_type(&self) -> FunctionViewType {
        let type_ = unsafe { BNSimilarityRenderContextGetPreferredViewType(self.handle) };
        let name = if type_ == BNFunctionGraphType::HighLevelLanguageRepresentationFunctionGraph {
            unsafe { BNSimilarityRenderContextGetPreferredViewTypeName(self.handle) }
        } else {
            std::ptr::null_mut()
        };
        FunctionViewType::from_owned_raw(BNFunctionViewType { type_, name }).unwrap()
    }

    /// Adds a flow graph to a view group.
    pub fn add_flow_graph(&self, group: &str, graph: &FlowGraph) {
        let group = group.to_cstr();
        unsafe { BNSimilarityRenderContextAddFlowGraph(self.handle, group.as_ptr(), graph.handle) }
    }

    /// Adds a flow graph for a session entity to a view group.
    pub fn add_flow_graph_for_entity(
        &self,
        group: &str,
        graph: &FlowGraph,
        entity: SimilarityEntityRef,
    ) {
        let group = group.to_cstr();
        let entity = BNSimilarityEntityRef::from(entity);
        unsafe {
            BNSimilarityRenderContextAddFlowGraphForEntity(
                self.handle,
                group.as_ptr(),
                graph.handle,
                &entity,
            )
        }
    }

    /// Adds a linear view to a view group.
    pub fn add_linear_view(&self, group: &str, data: &BinaryView, linear_view: &LinearViewObject) {
        let group = group.to_cstr();
        unsafe {
            BNSimilarityRenderContextAddLinearView(
                self.handle,
                group.as_ptr(),
                data.handle,
                linear_view.handle,
            )
        }
    }

    /// Adds a linear view for a session entity to a view group.
    pub fn add_linear_view_for_entity(
        &self,
        group: &str,
        data: &BinaryView,
        linear_view: &LinearViewObject,
        entity: SimilarityEntityRef,
    ) {
        let group = group.to_cstr();
        let entity = BNSimilarityEntityRef::from(entity);
        unsafe {
            BNSimilarityRenderContextAddLinearViewForEntity(
                self.handle,
                group.as_ptr(),
                data.handle,
                linear_view.handle,
                &entity,
            )
        }
    }

    /// Returns the views in insertion order.
    pub fn views(&self) -> Vec<SimilarityView> {
        let mut count = 0;
        let raw = unsafe { BNGetSimilarityRenderContextViews(self.handle, &mut count) };
        let views = unsafe { std::slice::from_raw_parts(raw, count) };
        let result = views
            .iter()
            .map(|view| {
                let view = *view;
                let graph = unsafe { BNSimilarityViewGetFlowGraph(view) };
                let data = unsafe { BNSimilarityViewGetLinearViewData(view) };
                let linear_view = unsafe { BNSimilarityViewGetLinearView(view) };
                let mut entity = std::mem::MaybeUninit::uninit();
                let entity = unsafe { BNSimilarityViewGetEntity(view, entity.as_mut_ptr()) }
                    .then(|| unsafe { entity.assume_init().into() });
                SimilarityView {
                    group: unsafe { BnString::into_string(BNSimilarityViewGetGroup(view)) },
                    view_type: unsafe { BNSimilarityViewGetType(view) },
                    graph: (!graph.is_null()).then(|| unsafe { FlowGraph::ref_from_raw(graph) }),
                    data: (!data.is_null()).then(|| unsafe { BinaryView::ref_from_raw(data) }),
                    linear_view: (!linear_view.is_null())
                        .then(|| unsafe { LinearViewObject::ref_from_raw(linear_view) }),
                    entity,
                }
            })
            .collect();
        unsafe { BNFreeSimilarityViewList(raw, count) };
        result
    }
}

impl ToOwned for SimilarityRenderContext {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for SimilarityRenderContext {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSimilarityRenderContextReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSimilarityRenderContext(handle.handle)
    }
}

/// Renders graph and linear views with range annotations.
pub struct DiffRenderer {
    handle: *mut BNDiffRenderer,
}

impl DiffRenderer {
    /// Creates a renderer without annotations.
    pub fn new() -> Ref<Self> {
        unsafe {
            Ref::new(Self {
                handle: BNCreateDiffRenderer(),
            })
        }
    }

    /// Adds a range annotation to later renders.
    ///
    /// NOTE: Empty ranges are ignored.
    pub fn add_range_annotation(&self, annotation: SimilarityRangeAnnotation) {
        unsafe {
            BNDiffRendererAddRangeAnnotation(
                self.handle,
                annotation.start,
                annotation.end,
                annotation.annotation_type,
            )
        }
    }

    /// Renders the graph and linear views for a function.
    pub fn render_function(&self, context: &SimilarityRenderContext, function: &Function) {
        unsafe { BNDiffRendererRenderFunction(self.handle, context.handle, function.handle) }
    }

    /// Renders graph and linear views for a function and session entity.
    pub fn render_function_for_entity(
        &self,
        context: &SimilarityRenderContext,
        function: &Function,
        entity: SimilarityEntityRef,
    ) {
        let entity = BNSimilarityEntityRef::from(entity);
        unsafe {
            BNDiffRendererRenderFunctionForEntity(
                self.handle,
                context.handle,
                function.handle,
                &entity,
            )
        }
    }

    /// Renders an annotated flow graph.
    pub fn render_flow_graph(
        &self,
        context: &SimilarityRenderContext,
        group: &str,
        graph: &FlowGraph,
    ) {
        let group = group.to_cstr();
        unsafe {
            BNDiffRendererRenderFlowGraph(self.handle, context.handle, group.as_ptr(), graph.handle)
        }
    }

    /// Renders an annotated flow graph for a session entity.
    pub fn render_flow_graph_for_entity(
        &self,
        context: &SimilarityRenderContext,
        group: &str,
        graph: &FlowGraph,
        entity: SimilarityEntityRef,
    ) {
        let group = group.to_cstr();
        let entity = BNSimilarityEntityRef::from(entity);
        unsafe {
            BNDiffRendererRenderFlowGraphForEntity(
                self.handle,
                context.handle,
                group.as_ptr(),
                graph.handle,
                &entity,
            )
        }
    }

    /// Renders an annotated linear view.
    pub fn render_linear_view(
        &self,
        context: &SimilarityRenderContext,
        group: &str,
        data: &BinaryView,
        linear_view: &LinearViewObject,
    ) {
        let group = group.to_cstr();
        unsafe {
            BNDiffRendererRenderLinearView(
                self.handle,
                context.handle,
                group.as_ptr(),
                data.handle,
                linear_view.handle,
            )
        }
    }

    /// Renders an annotated linear view for a session entity.
    pub fn render_linear_view_for_entity(
        &self,
        context: &SimilarityRenderContext,
        group: &str,
        data: &BinaryView,
        linear_view: &LinearViewObject,
        entity: SimilarityEntityRef,
    ) {
        let group = group.to_cstr();
        let entity = BNSimilarityEntityRef::from(entity);
        unsafe {
            BNDiffRendererRenderLinearViewForEntity(
                self.handle,
                context.handle,
                group.as_ptr(),
                data.handle,
                linear_view.handle,
                &entity,
            )
        }
    }
}

impl ToOwned for DiffRenderer {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for DiffRenderer {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewDiffRendererReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeDiffRenderer(handle.handle)
    }
}
