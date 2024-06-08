use std::{ffi, ptr};

use binaryninjacore_sys::*;

use crate::architecture::CoreArchitecture;
use crate::basicblock::BasicBlock;
use crate::flowgraph::FlowGraph;
use crate::function::{Function, NativeBlock};
use crate::llil::{self, FunctionForm, FunctionMutability};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{BnStrCompatible, BnString};
use crate::{hlil, mlil};

#[repr(transparent)]
/// The AnalysisContext struct is used to represent the current state of
/// analysis for a given function. It allows direct modification of IL and other
/// analysis information.
pub struct AnalysisContext {
    handle: ptr::NonNull<BNAnalysisContext>,
}

impl AnalysisContext {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNAnalysisContext>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNAnalysisContext) -> &Self {
        assert!(!handle.is_null());
        core::mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub fn as_raw(&self) -> &mut BNAnalysisContext {
        unsafe { &mut *self.handle.as_ptr() }
    }

    /// Function for the current AnalysisContext
    pub fn function(&self) -> Ref<Function> {
        let result = unsafe { BNAnalysisContextGetFunction(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { Function::from_raw(result) }
    }

    /// LowLevelILFunction used to represent Low Level IL
    pub unsafe fn llil_function<M: FunctionMutability, F: FunctionForm>(
        &self,
    ) -> Ref<llil::Function<CoreArchitecture, M, F>> {
        let result = unsafe { BNAnalysisContextGetLowLevelILFunction(self.as_raw()) };
        assert!(!result.is_null());
        let arch = self.function().arch();
        unsafe { llil::Function::from_raw(arch, result) }
    }

    pub fn set_llil_function<M: FunctionMutability, F: FunctionForm>(
        &self,
        value: &llil::Function<CoreArchitecture, M, F>,
    ) {
        unsafe { BNSetLiftedILFunction(self.as_raw(), value.handle) }
    }

    /// MediumLevelILFunction used to represent Medium Level IL
    pub fn mlil_function(&self) -> Ref<mlil::MediumLevelILFunction> {
        let result = unsafe { BNAnalysisContextGetMediumLevelILFunction(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { mlil::MediumLevelILFunction::ref_from_raw(result) }
    }

    pub fn set_mlil_function(&self, value: &mlil::MediumLevelILFunction) {
        unsafe { BNSetMediumLevelILFunction(self.as_raw(), value.handle) }
    }

    /// HighLevelILFunction used to represent High Level IL
    pub fn hlil_function(&self, full_ast: bool) -> Ref<hlil::HighLevelILFunction> {
        let result = unsafe { BNAnalysisContextGetHighLevelILFunction(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { hlil::HighLevelILFunction::ref_from_raw(result, full_ast) }
    }

    pub fn inform<S: BnStrCompatible>(&self, request: S) -> bool {
        let request = request.into_bytes_with_nul();
        unsafe {
            BNAnalysisContextInform(
                self.as_raw(),
                request.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn set_basic_blocks<I>(&self, blocks: I)
    where
        I: IntoIterator<Item = BasicBlock<NativeBlock>>,
    {
        let blocks: Vec<_> = blocks.into_iter().map(|block| block).collect();
        let mut blocks_raw: Vec<*mut BNBasicBlock> =
            blocks.iter().map(|block| block.handle).collect();
        unsafe { BNSetBasicBlockList(self.as_raw(), blocks_raw.as_mut_ptr(), blocks.len()) }
    }
}

impl Clone for AnalysisContext {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewAnalysisContextReference(self.as_raw())).unwrap())
        }
    }
}

impl Drop for AnalysisContext {
    fn drop(&mut self) {
        unsafe { BNFreeAnalysisContext(self.as_raw()) }
    }
}

#[repr(transparent)]
pub struct Activity {
    handle: ptr::NonNull<BNActivity>,
}

impl Activity {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNActivity>) -> Self {
        Self { handle }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn as_raw(&self) -> &mut BNActivity {
        unsafe { &mut *self.handle.as_ptr() }
    }

    pub fn new<S: BnStrCompatible>(config: S) -> Self {
        unsafe extern "C" fn cb_action_nop(_: *mut ffi::c_void, _: *mut BNAnalysisContext) {}
        let config = config.into_bytes_with_nul();
        let result = unsafe {
            BNCreateActivity(
                config.as_ref().as_ptr() as *const ffi::c_char,
                ptr::null_mut(),
                Some(cb_action_nop),
            )
        };
        unsafe { Activity::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    pub fn new_with_action<S, F>(config: S, mut action: F) -> Self
    where
        S: BnStrCompatible,
        F: FnMut(&AnalysisContext),
    {
        unsafe extern "C" fn cb_action<F: FnMut(&AnalysisContext)>(
            ctxt: *mut ffi::c_void,
            analysis: *mut BNAnalysisContext,
        ) {
            let ctxt: &mut F = core::mem::transmute(ctxt);
            ctxt(AnalysisContext::ref_from_raw(&analysis))
        }
        let config = config.into_bytes_with_nul();
        let result = unsafe {
            BNCreateActivity(
                config.as_ref().as_ptr() as *const ffi::c_char,
                &mut action as *mut F as *mut ffi::c_void,
                Some(cb_action::<F>),
            )
        };
        unsafe { Activity::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNActivityGetName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }
}

impl Clone for Activity {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(ptr::NonNull::new(BNNewActivityReference(self.as_raw())).unwrap()) }
    }
}

impl Drop for Activity {
    fn drop(&mut self) {
        unsafe { BNFreeActivity(self.as_raw()) }
    }
}

pub trait IntoActivityName {
    fn activity_name(self) -> BnString;
}

impl IntoActivityName for &Activity {
    fn activity_name(self) -> BnString {
        self.name()
    }
}

impl<S: BnStrCompatible> IntoActivityName for S {
    fn activity_name(self) -> BnString {
        BnString::new(self)
    }
}

#[repr(transparent)]
pub struct Workflow {
    handle: ptr::NonNull<BNWorkflow>,
}

impl Workflow {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNWorkflow>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNWorkflow) -> &Self {
        core::mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub fn as_raw(&self) -> &mut BNWorkflow {
        unsafe { &mut *self.handle.as_ptr() }
    }

    pub fn new<S: BnStrCompatible>(name: S) -> Self {
        let name = name.into_bytes_with_nul();
        let result = unsafe { BNCreateWorkflow(name.as_ref().as_ptr() as *const ffi::c_char) };
        unsafe { Workflow::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    pub fn instance<S: BnStrCompatible>(name: S) -> Workflow {
        let result = unsafe {
            BNWorkflowInstance(name.into_bytes_with_nul().as_ref().as_ptr() as *const ffi::c_char)
        };
        unsafe { Workflow::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    /// Make a new Workflow, copying all Activities and the execution strategy.
    ///
    /// * `name` - the name for the new Workflow
    /// * `activity` - if specified, perform the clone operation using
    /// ``activity`` as the root
    #[must_use]
    pub fn new_from_copy<S: BnStrCompatible, A: IntoActivityName>(
        &self,
        name: S,
        activity: A,
    ) -> Workflow {
        let name = name.into_bytes_with_nul();
        let activity = activity.activity_name();
        unsafe {
            Self::from_raw(
                ptr::NonNull::new(BNWorkflowClone(
                    self.as_raw(),
                    name.as_ref().as_ptr() as *const ffi::c_char,
                    activity.as_ref().as_ptr() as *const ffi::c_char,
                ))
                .unwrap(),
            )
        }
    }

    /// List of all Workflows
    pub fn list() -> Array<Workflow> {
        let mut count = 0;
        let result = unsafe { BNGetWorkflowList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNGetWorkflowName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Register this Workflow, making it immutable and available for use.
    ///
    /// * `configuration` - a JSON representation of the workflow configuration
    pub fn register<S: BnStrCompatible>(&self, config: S) -> Result<(), ()> {
        let config = config.into_bytes_with_nul();
        if unsafe {
            BNRegisterWorkflow(
                self.as_raw(),
                config.as_ref().as_ptr() as *const ffi::c_char,
            )
        } {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Register an Activity with this Workflow.
    ///
    /// * `activity` - the Activity to register
    /// * `subactivities` - the list of Activities to assign
    pub fn register_activity<I>(&self, activity: &Activity, subactivities: I) -> Result<Activity, ()>
    where
        I: IntoIterator,
        I::Item: IntoActivityName,
    {
        let subactivities_raw: Vec<BnString> = subactivities
            .into_iter()
            .map(|x| x.activity_name())
            .collect();
        let mut subactivities_ptr: Vec<*const _> =
            subactivities_raw.iter().map(|x| x.as_ptr()).collect();
        let result = unsafe {
            BNWorkflowRegisterActivity(
                self.as_raw(),
                activity.as_raw(),
                subactivities_ptr.as_mut_ptr(),
                subactivities_ptr.len(),
            )
        };
        let activity_ptr = ptr::NonNull::new(result).ok_or(())?;
        unsafe { Ok(Activity::from_raw(activity_ptr)) }
    }

    /// Determine if an Activity exists in this Workflow.
    pub fn contains<A: IntoActivityName>(&self, activity: A) -> bool {
        unsafe { BNWorkflowContains(self.as_raw(), activity.activity_name().as_ptr()) }
    }

    /// Retrieve the configuration as an adjacency list in JSON for the
    /// Workflow, or if specified just for the given `activity`.
    ///
    /// `activity` - if specified, return the configuration for the `activity`
    pub fn configuration<A: IntoActivityName>(&self, activity: A) -> BnString {
        let result =
            unsafe { BNWorkflowGetConfiguration(self.as_raw(), activity.activity_name().as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Whether this Workflow is registered or not. A Workflow becomes immutable
    /// once it is registered.
    pub fn registered(&self) -> bool {
        unsafe { BNWorkflowIsRegistered(self.as_raw()) }
    }

    pub fn size(&self) -> usize {
        unsafe { BNWorkflowSize(self.as_raw()) }
    }

    /// Retrieve the Activity object for the specified `name`.
    pub fn activity<A: BnStrCompatible>(&self, name: A) -> Option<Activity> {
        let name = name.into_bytes_with_nul();
        let result = unsafe {
            BNWorkflowGetActivity(self.as_raw(), name.as_ref().as_ptr() as *const ffi::c_char)
        };
        ptr::NonNull::new(result).map(|a| unsafe { Activity::from_raw(a) })
    }

    /// Retrieve the list of activity roots for the Workflow, or if
    /// specified just for the given `activity`.
    ///
    /// * `activity` - if specified, return the roots for the `activity`
    pub fn activity_roots<A: IntoActivityName>(&self, activity: A) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe {
            BNWorkflowGetActivityRoots(self.as_raw(), activity.activity_name().as_ptr(), &mut count)
        };
        assert!(!result.is_null());
        unsafe { Array::new(result as *mut *mut ffi::c_char, count, ()) }
    }

    /// Retrieve the list of all activities, or optionally a filtered list.
    ///
    /// * `activity` - if specified, return the direct children and optionally the descendants of the `activity` (includes `activity`)
    /// * `immediate` - whether to include only direct children of `activity` or all descendants
    pub fn subactivities<A: IntoActivityName>(
        &self,
        activity: A,
        immediate: bool,
    ) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe {
            BNWorkflowGetSubactivities(
                self.as_raw(),
                activity.activity_name().as_ptr(),
                immediate,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result as *mut *mut _, count, ()) }
    }

    /// Assign the list of `activities` as the new set of children for the specified `activity`.
    ///
    /// * `activity` - the Activity node to assign children
    /// * `activities` - the list of Activities to assign
    pub fn assign_subactivities<A, I>(&self, activity: A, activities: I) -> bool
    where
        A: IntoActivityName,
        I: IntoIterator,
        I::Item: IntoActivityName,
    {
        let mut input_list: Vec<BnString> =
            activities.into_iter().map(|a| a.activity_name()).collect();
        // SAFETY: this works because BnString and *mut ffi::c_char are
        // transmutable
        let input_list_ptr = input_list.as_mut_ptr() as *mut *const ffi::c_char;
        unsafe {
            BNWorkflowAssignSubactivities(
                self.as_raw(),
                activity.activity_name().as_ptr(),
                input_list_ptr,
                input_list.len(),
            )
        }
    }

    /// Remove all Activity nodes from this Workflow.
    pub fn clear(&self) -> bool {
        unsafe { BNWorkflowClear(self.as_raw()) }
    }

    /// Insert the list of `activities` before the specified `activity` and at the same level.
    ///
    /// * `activity` - the Activity node for which to insert `activities` before
    /// * `activities` - the list of Activities to insert
    pub fn insert<A, I>(&self, activity: A, activities: I) -> bool
    where
        A: IntoActivityName,
        I: IntoIterator,
        I::Item: IntoActivityName,
    {
        let mut input_list: Vec<BnString> =
            activities.into_iter().map(|a| a.activity_name()).collect();
        // SAFETY: this works because BnString and *mut ffi::c_char are
        // transmutable
        let input_list_ptr = input_list.as_mut_ptr() as *mut *const ffi::c_char;
        unsafe {
            BNWorkflowInsert(
                self.as_raw(),
                activity.activity_name().as_ptr(),
                input_list_ptr,
                input_list.len(),
            )
        }
    }

    /// Remove the specified `activity`
    pub fn remove<A: IntoActivityName>(self, activity: A) -> bool {
        unsafe { BNWorkflowRemove(self.as_raw(), activity.activity_name().as_ptr()) }
    }

    /// Replace the specified `activity`.
    ///
    /// * `activity` - the Activity to replace
    /// * `new_activity` - the replacement Activity
    pub fn replace<A: IntoActivityName, N: IntoActivityName>(
        self,
        activity: A,
        new_activity: N,
    ) -> bool {
        unsafe {
            BNWorkflowReplace(
                self.as_raw(),
                activity.activity_name().as_ptr(),
                new_activity.activity_name().as_ptr(),
            )
        }
    }

    /// Generate a FlowGraph object for the current Workflow and optionally show it in the UI.
    ///
    /// * `activity` - if specified, generate the Flowgraph using `activity` as the root
    /// * `sequential` - whether to generate a **Composite** or **Sequential** style graph
    pub fn graph<A: IntoActivityName>(
        self,
        activity: A,
        sequential: Option<bool>,
    ) -> Option<FlowGraph> {
        let sequential = sequential.unwrap_or(false);
        let activity_name = activity.activity_name();
        let graph =
            unsafe { BNWorkflowGetGraph(self.as_raw(), activity_name.as_ptr(), sequential) };
        if graph.is_null() {
            return None;
        }
        Some(unsafe { FlowGraph::from_raw(graph) })
    }

    /// Not yet implemented.
    pub fn show_metrics(&self) {
        unsafe {
            BNWorkflowShowReport(self.as_raw(), b"metrics\x00".as_ptr() as *const ffi::c_char)
        }
    }

    /// Show the Workflow topology in the UI.
    pub fn show_topology(&self) {
        unsafe {
            BNWorkflowShowReport(
                self.as_raw(),
                b"topology\x00".as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Not yet implemented.
    pub fn show_trace(&self) {
        unsafe { BNWorkflowShowReport(self.as_raw(), b"trace\x00".as_ptr() as *const ffi::c_char) }
    }
}

impl Clone for Workflow {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(ptr::NonNull::new(BNNewWorkflowReference(self.as_raw())).unwrap()) }
    }
}

impl Drop for Workflow {
    fn drop(&mut self) {
        unsafe { BNFreeWorkflow(self.as_raw()) }
    }
}

impl CoreArrayProvider for Workflow {
    type Raw = *mut BNWorkflow;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for Workflow {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeWorkflowList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Workflow::ref_from_raw(raw)
    }
}
