use binaryninjacore_sys::*;

use crate::basic_block::BasicBlock;
use crate::binary_view::BinaryView;
use crate::flowgraph::FlowGraph;
use crate::function::{Function, NativeBlock};
use crate::high_level_il::HighLevelILFunction;
use crate::low_level_il::{LowLevelILMutableFunction, LowLevelILRegularFunction};
use crate::medium_level_il::MediumLevelILFunction;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnString, IntoCStr};
use std::ffi::c_char;
use std::ptr;
use std::ptr::NonNull;

pub mod activity;
pub use activity::Activity;

#[repr(transparent)]
/// The AnalysisContext struct is used to represent the current state of
/// analysis for a given function. It allows direct modification of IL and other
/// analysis information.
pub struct AnalysisContext {
    handle: NonNull<BNAnalysisContext>,
}

impl AnalysisContext {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNAnalysisContext>) -> Self {
        Self { handle }
    }

    #[allow(unused)]
    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNAnalysisContext>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// BinaryView for the current AnalysisContext
    pub fn view(&self) -> Ref<BinaryView> {
        let result = unsafe { BNAnalysisContextGetBinaryView(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BinaryView::ref_from_raw(result) }
    }

    /// [`Function`] for the current AnalysisContext
    pub fn function(&self) -> Ref<Function> {
        let result = unsafe { BNAnalysisContextGetFunction(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { Function::ref_from_raw(result) }
    }

    /// [`LowLevelILMutableFunction`] used to represent Lifted Level IL
    pub unsafe fn lifted_il_function(&self) -> Option<Ref<LowLevelILMutableFunction>> {
        let result = unsafe { BNAnalysisContextGetLiftedILFunction(self.handle.as_ptr()) };
        unsafe {
            Some(LowLevelILMutableFunction::ref_from_raw(
                NonNull::new(result)?.as_ptr(),
            ))
        }
    }

    pub fn set_lifted_il_function(&self, value: &LowLevelILRegularFunction) {
        unsafe { BNSetLiftedILFunction(self.handle.as_ptr(), value.handle) }
    }

    /// [`LowLevelILMutableFunction`] used to represent Low Level IL
    pub unsafe fn llil_function(&self) -> Option<Ref<LowLevelILMutableFunction>> {
        let result = unsafe { BNAnalysisContextGetLowLevelILFunction(self.handle.as_ptr()) };
        unsafe {
            Some(LowLevelILMutableFunction::ref_from_raw(
                NonNull::new(result)?.as_ptr(),
            ))
        }
    }

    pub fn set_llil_function(&self, value: &LowLevelILRegularFunction) {
        unsafe { BNSetLowLevelILFunction(self.handle.as_ptr(), value.handle) }
    }

    /// [`MediumLevelILFunction`] used to represent Medium Level IL
    pub fn mlil_function(&self) -> Option<Ref<MediumLevelILFunction>> {
        let result = unsafe { BNAnalysisContextGetMediumLevelILFunction(self.handle.as_ptr()) };
        unsafe {
            Some(MediumLevelILFunction::ref_from_raw(
                NonNull::new(result)?.as_ptr(),
            ))
        }
    }

    pub fn set_mlil_function(&self, value: &MediumLevelILFunction) {
        // TODO: Mappings FFI
        unsafe {
            BNSetMediumLevelILFunction(
                self.handle.as_ptr(),
                value.handle,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
            )
        }
    }

    /// [`HighLevelILFunction`] used to represent High Level IL
    pub fn hlil_function(&self, full_ast: bool) -> Option<Ref<HighLevelILFunction>> {
        let result = unsafe { BNAnalysisContextGetHighLevelILFunction(self.handle.as_ptr()) };
        unsafe {
            Some(HighLevelILFunction::ref_from_raw(
                NonNull::new(result)?.as_ptr(),
                full_ast,
            ))
        }
    }

    pub fn inform(&self, request: &str) -> bool {
        let request = request.to_cstr();
        unsafe { BNAnalysisContextInform(self.handle.as_ptr(), request.as_ptr()) }
    }

    pub fn set_basic_blocks<I>(&self, blocks: I)
    where
        I: IntoIterator<Item = BasicBlock<NativeBlock>>,
    {
        let blocks: Vec<_> = blocks.into_iter().collect();
        let mut blocks_raw: Vec<*mut BNBasicBlock> =
            blocks.iter().map(|block| block.handle).collect();
        unsafe { BNSetBasicBlockList(self.handle.as_ptr(), blocks_raw.as_mut_ptr(), blocks.len()) }
    }
}

impl ToOwned for AnalysisContext {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for AnalysisContext {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewAnalysisContextReference(handle.handle.as_ptr()))
                .expect("valid handle"),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeAnalysisContext(handle.handle.as_ptr());
    }
}

#[repr(transparent)]
pub struct Workflow {
    handle: NonNull<BNWorkflow>,
}

impl Workflow {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNWorkflow>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNWorkflow>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Create a new unregistered [Workflow] with no activities.
    /// Returns a [WorkflowBuilder] that can be used to configure and register the new [Workflow].
    ///
    /// To get a copy of an existing registered [Workflow] use [Workflow::clone_to].
    pub fn build(name: &str) -> WorkflowBuilder {
        let name = name.to_cstr();
        let result = unsafe { BNCreateWorkflow(name.as_ptr()) };
        WorkflowBuilder {
            handle: unsafe { Workflow::ref_from_raw(NonNull::new(result).unwrap()) },
        }
    }

    /// Make a new unregistered [Workflow], copying all activities and the execution strategy.
    /// Returns a [WorkflowBuilder] that can be used to configure and register the new [Workflow].
    ///
    /// * `name` - the name for the new [Workflow]
    pub fn clone_to(&self, name: &str) -> WorkflowBuilder {
        self.clone_to_with_root(name, "")
    }

    /// Make a new unregistered [Workflow], copying all activities, within `root_activity`, and the execution strategy.
    ///
    /// * `name` - the name for the new [Workflow]
    /// * `root_activity` - perform the clone operation with this activity as the root
    pub fn clone_to_with_root(&self, name: &str, root_activity: &str) -> WorkflowBuilder {
        let raw_name = name.to_cstr();
        let activity = root_activity.to_cstr();
        let workflow = unsafe {
            Self::ref_from_raw(
                NonNull::new(BNWorkflowClone(
                    self.handle.as_ptr(),
                    raw_name.as_ptr(),
                    activity.as_ptr(),
                ))
                .unwrap(),
            )
        };
        WorkflowBuilder { handle: workflow }
    }

    /// Get an existing [Workflow] by name.
    pub fn get(name: &str) -> Option<Ref<Workflow>> {
        let name = name.to_cstr();
        let result = unsafe { BNWorkflowGet(name.as_ptr()) };
        let handle = NonNull::new(result)?;
        Some(unsafe { Workflow::ref_from_raw(handle) })
    }

    /// Clone the existing [Workflow] named `name`.
    /// Returns a [WorkflowBuilder] that can be used to configure and register the new [Workflow].
    pub fn cloned(name: &str) -> Option<WorkflowBuilder> {
        Self::get(name).map(|workflow| workflow.clone_to(name))
    }

    /// List of all registered [Workflow]'s
    pub fn list() -> Array<Workflow> {
        let mut count = 0;
        let result = unsafe { BNGetWorkflowList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn name(&self) -> String {
        let result = unsafe { BNGetWorkflowName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Determine if an Activity exists in this [Workflow].
    pub fn contains(&self, activity: &str) -> bool {
        let activity = activity.to_cstr();
        unsafe { BNWorkflowContains(self.handle.as_ptr(), activity.as_ptr()) }
    }

    /// Retrieve the configuration as an adjacency list in JSON for the [Workflow].
    pub fn configuration(&self) -> String {
        self.configuration_with_activity("")
    }

    /// Retrieve the configuration as an adjacency list in JSON for the
    /// [Workflow], just for the given `activity`.
    ///
    /// `activity` - return the configuration for the `activity`
    pub fn configuration_with_activity(&self, activity: &str) -> String {
        let activity = activity.to_cstr();
        let result = unsafe { BNWorkflowGetConfiguration(self.handle.as_ptr(), activity.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Whether this [Workflow] is registered or not. A [Workflow] becomes immutable once registered.
    pub fn registered(&self) -> bool {
        unsafe { BNWorkflowIsRegistered(self.handle.as_ptr()) }
    }

    pub fn size(&self) -> usize {
        unsafe { BNWorkflowSize(self.handle.as_ptr()) }
    }

    /// Retrieve the Activity object for the specified `name`.
    pub fn activity(&self, name: &str) -> Option<Ref<Activity>> {
        let name = name.to_cstr();
        let result = unsafe { BNWorkflowGetActivity(self.handle.as_ptr(), name.as_ptr()) };
        NonNull::new(result).map(|a| unsafe { Activity::ref_from_raw(a) })
    }

    /// Retrieve the list of activity roots for the [Workflow], or if
    /// specified just for the given `activity`.
    ///
    /// * `activity` - if specified, return the roots for the `activity`
    pub fn activity_roots(&self, activity: &str) -> Array<BnString> {
        let activity = activity.to_cstr();
        let mut count = 0;
        let result = unsafe {
            BNWorkflowGetActivityRoots(self.handle.as_ptr(), activity.as_ptr(), &mut count)
        };
        assert!(!result.is_null());
        unsafe { Array::new(result as *mut *mut c_char, count, ()) }
    }

    /// Retrieve the list of all activities, or optionally a filtered list.
    ///
    /// * `activity` - if specified, return the direct children and optionally the descendants of the `activity` (includes `activity`)
    /// * `immediate` - whether to include only direct children of `activity` or all descendants
    pub fn subactivities(&self, activity: &str, immediate: bool) -> Array<BnString> {
        let activity = activity.to_cstr();
        let mut count = 0;
        let result = unsafe {
            BNWorkflowGetSubactivities(
                self.handle.as_ptr(),
                activity.as_ptr(),
                immediate,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result as *mut *mut c_char, count, ()) }
    }

    /// Generate a FlowGraph object for the current [Workflow] and optionally show it in the UI.
    ///
    /// * `activity` - if specified, generate the Flowgraph using `activity` as the root
    /// * `sequential` - whether to generate a **Composite** or **Sequential** style graph
    pub fn graph(&self, activity: &str, sequential: Option<bool>) -> Option<Ref<FlowGraph>> {
        let sequential = sequential.unwrap_or(false);
        let activity = activity.to_cstr();
        let graph =
            unsafe { BNWorkflowGetGraph(self.handle.as_ptr(), activity.as_ptr(), sequential) };
        if graph.is_null() {
            return None;
        }
        Some(unsafe { FlowGraph::ref_from_raw(graph) })
    }

    /// Not yet implemented.
    pub fn show_metrics(&self) {
        unsafe { BNWorkflowShowReport(self.handle.as_ptr(), c"metrics".as_ptr()) }
    }

    /// Show the Workflow topology in the UI.
    pub fn show_topology(&self) {
        unsafe { BNWorkflowShowReport(self.handle.as_ptr(), c"topology".as_ptr()) }
    }

    /// Not yet implemented.
    pub fn show_trace(&self) {
        unsafe { BNWorkflowShowReport(self.handle.as_ptr(), c"trace".as_ptr()) }
    }
}

impl ToOwned for Workflow {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Workflow {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewWorkflowReference(handle.handle.as_ptr()))
                .expect("valid handle"),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeWorkflow(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for Workflow {
    type Raw = *mut BNWorkflow;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Workflow>;
}

unsafe impl CoreArrayProviderInner for Workflow {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeWorkflowList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(
            Workflow::from_raw(NonNull::new(*raw).expect("valid handle")),
            context,
        )
    }
}

#[must_use = "Workflow is not registered until `register` is called"]
pub struct WorkflowBuilder {
    handle: Ref<Workflow>,
}

impl WorkflowBuilder {
    fn raw_handle(&self) -> *mut BNWorkflow {
        self.handle.handle.as_ptr()
    }

    /// Register an [Activity] with this Workflow and insert it before the designated position.
    ///
    /// * `activity` - the [Activity] to register
    /// * `sibling` - the activity to insert the new activity before
    pub fn activity_before(self, activity: &Activity, sibling: &str) -> Result<Self, ()> {
        self.register_activity(activity)?
            .insert(sibling, vec![activity.name()])
    }

    /// Register an [Activity] with this Workflow and insert it in the designated position.
    ///
    /// * `activity` - the [Activity] to register
    /// * `sibling` - the activity to insert the new activity after
    pub fn activity_after(self, activity: &Activity, sibling: &str) -> Result<Self, ()> {
        self.register_activity(activity)?
            .insert_after(sibling, vec![activity.name()])
    }

    /// Register an [Activity] with this Workflow.
    ///
    /// * `activity` - the [Activity] to register
    pub fn register_activity(self, activity: &Activity) -> Result<Self, ()> {
        self.register_activity_with_subactivities::<Vec<String>>(activity, vec![])
    }

    /// Register an [Activity] with this Workflow.
    ///
    /// * `activity` - the [Activity] to register
    /// * `subactivities` - the list of Activities to assign
    pub fn register_activity_with_subactivities<I>(
        self,
        activity: &Activity,
        subactivities: I,
    ) -> Result<Self, ()>
    where
        I: IntoIterator,
        I::Item: IntoCStr,
    {
        let subactivities_raw: Vec<_> = subactivities.into_iter().map(|x| x.to_cstr()).collect();
        let mut subactivities_ptr: Vec<*const _> =
            subactivities_raw.iter().map(|x| x.as_ptr()).collect();
        let result = unsafe {
            BNWorkflowRegisterActivity(
                self.raw_handle(),
                activity.handle.as_ptr(),
                subactivities_ptr.as_mut_ptr(),
                subactivities_ptr.len(),
            )
        };
        let Some(activity_ptr) = NonNull::new(result) else {
            return Err(());
        };
        let _ = unsafe { Activity::ref_from_raw(activity_ptr) };
        Ok(self)
    }

    /// Register this [Workflow], making it immutable and available for use.
    pub fn register(self) -> Result<Ref<Workflow>, ()> {
        self.register_with_config("")
    }

    /// Register this [Workflow], making it immutable and available for use.
    ///
    /// * `configuration` - a JSON representation of the workflow configuration
    pub fn register_with_config(self, config: &str) -> Result<Ref<Workflow>, ()> {
        // TODO: We need to hide the JSON here behind a sensible/typed API.
        let config = config.to_cstr();
        if unsafe { BNRegisterWorkflow(self.raw_handle(), config.as_ptr()) } {
            Ok(self.handle)
        } else {
            Err(())
        }
    }

    /// Assign the list of `activities` as the new set of children for the specified `activity`.
    ///
    /// * `activity` - the Activity node to assign children
    /// * `activities` - the list of Activities to assign
    pub fn subactivities<I>(self, activity: &str, activities: I) -> Result<Self, ()>
    where
        I: IntoIterator,
        I::Item: IntoCStr,
    {
        let activity = activity.to_cstr();
        let input_list: Vec<_> = activities.into_iter().map(|a| a.to_cstr()).collect();
        let mut input_list_ptr: Vec<*const _> = input_list.iter().map(|x| x.as_ptr()).collect();
        let result = unsafe {
            BNWorkflowAssignSubactivities(
                self.raw_handle(),
                activity.as_ptr(),
                input_list_ptr.as_mut_ptr(),
                input_list.len(),
            )
        };
        if result {
            Ok(self)
        } else {
            Err(())
        }
    }

    /// Remove all Activity nodes from this [Workflow].
    pub fn clear(self) -> Result<Self, ()> {
        let result = unsafe { BNWorkflowClear(self.raw_handle()) };
        if result {
            Ok(self)
        } else {
            Err(())
        }
    }

    /// Insert the list of `activities` before the specified `activity` and at the same level.
    ///
    /// * `activity` - the Activity node for which to insert `activities` before
    /// * `activities` - the list of Activities to insert
    pub fn insert<I>(self, activity: &str, activities: I) -> Result<Self, ()>
    where
        I: IntoIterator,
        I::Item: IntoCStr,
    {
        let activity = activity.to_cstr();
        let input_list: Vec<_> = activities.into_iter().map(|a| a.to_cstr()).collect();
        let mut input_list_ptr: Vec<*const _> = input_list.iter().map(|x| x.as_ptr()).collect();
        let result = unsafe {
            BNWorkflowInsert(
                self.raw_handle(),
                activity.as_ptr(),
                input_list_ptr.as_mut_ptr(),
                input_list.len(),
            )
        };
        if result {
            Ok(self)
        } else {
            Err(())
        }
    }

    /// Insert the list of `activities` after the specified `activity` and at the same level.
    ///
    /// * `activity` - the Activity node for which to insert `activities` after
    /// * `activities` - the list of Activities to insert
    pub fn insert_after<I>(self, activity: &str, activities: I) -> Result<Self, ()>
    where
        I: IntoIterator,
        I::Item: IntoCStr,
    {
        let activity = activity.to_cstr();
        let input_list: Vec<_> = activities.into_iter().map(|a| a.to_cstr()).collect();
        let mut input_list_ptr: Vec<*const _> = input_list.iter().map(|x| x.as_ptr()).collect();
        let result = unsafe {
            BNWorkflowInsertAfter(
                self.raw_handle(),
                activity.as_ptr(),
                input_list_ptr.as_mut_ptr(),
                input_list.len(),
            )
        };
        if result {
            Ok(self)
        } else {
            Err(())
        }
    }

    /// Remove the specified `activity`
    pub fn remove(self, activity: &str) -> Result<Self, ()> {
        let activity = activity.to_cstr();
        let result = unsafe { BNWorkflowRemove(self.raw_handle(), activity.as_ptr()) };
        if result {
            Ok(self)
        } else {
            Err(())
        }
    }

    /// Replace the specified `activity`.
    ///
    /// * `activity` - the Activity to replace
    /// * `new_activity` - the replacement Activity
    pub fn replace(self, activity: &str, new_activity: &str) -> Result<Self, ()> {
        let activity = activity.to_cstr();
        let new_activity = new_activity.to_cstr();
        let result = unsafe {
            BNWorkflowReplace(self.raw_handle(), activity.as_ptr(), new_activity.as_ptr())
        };
        if result {
            Ok(self)
        } else {
            Err(())
        }
    }
}
