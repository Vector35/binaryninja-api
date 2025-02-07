use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void};
use std::ptr::NonNull;

use crate::architecture::CoreArchitecture;
use crate::basic_block::BasicBlock;
use crate::binary_view::BinaryView;
use crate::flowgraph::FlowGraph;
use crate::function::{Function, NativeBlock};
use crate::high_level_il::HighLevelILFunction;
use crate::low_level_il::function::{LowLevelILFunction, Mutable, NonSSA, NonSSAVariant};
use crate::low_level_il::MutableLiftedILFunction;
use crate::medium_level_il::MediumLevelILFunction;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};

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

    /// [`LowLevelILFunction`] used to represent Low Level IL
    pub unsafe fn lifted_il_function(
        &self,
    ) -> Option<Ref<MutableLiftedILFunction<CoreArchitecture>>> {
        let func = self.function();
        let result = unsafe { BNGetFunctionLiftedIL(func.handle) };
        let arch = self.function().arch();
        unsafe {
            Some(LowLevelILFunction::ref_from_raw(
                arch,
                NonNull::new(result)?.as_ptr(),
            ))
        }
    }

    pub fn set_lifted_il_function(&self, value: &MutableLiftedILFunction<CoreArchitecture>) {
        unsafe { BNSetLiftedILFunction(self.handle.as_ptr(), value.handle) }
    }

    // TODO: This returns LiftedNonSSA because the lifting code was written before we could patch the IL
    // TODO: At some point we need to take the lifting code and make it available to regular IL.
    /// [`LowLevelILFunction`] used to represent Low Level IL
    pub unsafe fn llil_function<V: NonSSAVariant>(
        &self,
    ) -> Option<Ref<LowLevelILFunction<CoreArchitecture, Mutable, NonSSA<V>>>> {
        let result = unsafe { BNAnalysisContextGetLowLevelILFunction(self.handle.as_ptr()) };
        let arch = self.function().arch();
        unsafe {
            Some(LowLevelILFunction::ref_from_raw(
                arch,
                NonNull::new(result)?.as_ptr(),
            ))
        }
    }

    // TODO: This returns LiftedNonSSA because the lifting code was written before we could patch the IL
    // TODO: At some point we need to take the lifting code and make it available to regular IL.
    pub fn set_llil_function<V: NonSSAVariant>(
        &self,
        value: &LowLevelILFunction<CoreArchitecture, Mutable, NonSSA<V>>,
    ) {
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
        unsafe { BNSetMediumLevelILFunction(self.handle.as_ptr(), value.handle) }
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

    pub fn inform<S: BnStrCompatible>(&self, request: S) -> bool {
        let request = request.into_bytes_with_nul();
        unsafe {
            BNAnalysisContextInform(
                self.handle.as_ptr(),
                request.as_ref().as_ptr() as *const c_char,
            )
        }
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

// TODO: This needs to be made into a trait similar to that of `Command`.
#[repr(transparent)]
pub struct Activity {
    handle: NonNull<BNActivity>,
}

impl Activity {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNActivity>) -> Self {
        Self { handle }
    }

    #[allow(unused)]
    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNActivity>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    pub fn new<S: BnStrCompatible>(config: S) -> Self {
        unsafe extern "C" fn cb_action_nop(_: *mut c_void, _: *mut BNAnalysisContext) {}
        let config = config.into_bytes_with_nul();
        let result = unsafe {
            BNCreateActivity(
                config.as_ref().as_ptr() as *const c_char,
                std::ptr::null_mut(),
                Some(cb_action_nop),
            )
        };
        unsafe { Activity::from_raw(NonNull::new(result).unwrap()) }
    }

    pub fn new_with_action<S, F>(config: S, mut action: F) -> Self
    where
        S: BnStrCompatible,
        F: FnMut(&AnalysisContext),
    {
        unsafe extern "C" fn cb_action<F: FnMut(&AnalysisContext)>(
            ctxt: *mut c_void,
            analysis: *mut BNAnalysisContext,
        ) {
            let ctxt = &mut *(ctxt as *mut F);
            if let Some(analysis) = NonNull::new(analysis) {
                ctxt(&AnalysisContext::from_raw(analysis))
            }
        }
        let config = config.into_bytes_with_nul();
        let result = unsafe {
            BNCreateActivity(
                config.as_ref().as_ptr() as *const c_char,
                &mut action as *mut F as *mut c_void,
                Some(cb_action::<F>),
            )
        };
        unsafe { Activity::from_raw(NonNull::new(result).unwrap()) }
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNActivityGetName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }
}

impl ToOwned for Activity {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Activity {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewActivityReference(handle.handle.as_ptr()))
                .expect("valid handle"),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeActivity(handle.handle.as_ptr());
    }
}

// TODO: We need to hide the JSON here behind a sensible/typed API.
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
    ///
    /// To get a copy of an existing registered [Workflow] use [Workflow::clone].
    pub fn new<S: BnStrCompatible>(name: S) -> Self {
        let name = name.into_bytes_with_nul();
        let result = unsafe { BNCreateWorkflow(name.as_ref().as_ptr() as *const c_char) };
        unsafe { Workflow::from_raw(NonNull::new(result).unwrap()) }
    }

    /// Make a new unregistered [Workflow], copying all activities and the execution strategy.
    ///
    /// * `name` - the name for the new [Workflow]
    #[must_use]
    pub fn clone<S: BnStrCompatible + Clone>(&self, name: S) -> Workflow {
        self.clone_with_root(name, "")
    }

    /// Make a new unregistered [Workflow], copying all activities, within `root_activity`, and the execution strategy.
    ///
    /// * `name` - the name for the new [Workflow]
    /// * `root_activity` - perform the clone operation with this activity as the root
    #[must_use]
    pub fn clone_with_root<S: BnStrCompatible, A: BnStrCompatible>(
        &self,
        name: S,
        root_activity: A,
    ) -> Workflow {
        let raw_name = name.into_bytes_with_nul();
        let activity = root_activity.into_bytes_with_nul();
        unsafe {
            Self::from_raw(
                NonNull::new(BNWorkflowClone(
                    self.handle.as_ptr(),
                    raw_name.as_ref().as_ptr() as *const c_char,
                    activity.as_ref().as_ptr() as *const c_char,
                ))
                .unwrap(),
            )
        }
    }

    pub fn instance<S: BnStrCompatible>(name: S) -> Workflow {
        let result = unsafe {
            BNWorkflowInstance(name.into_bytes_with_nul().as_ref().as_ptr() as *const c_char)
        };
        unsafe { Workflow::from_raw(NonNull::new(result).unwrap()) }
    }

    /// List of all registered [Workflow]'s
    pub fn list() -> Array<Workflow> {
        let mut count = 0;
        let result = unsafe { BNGetWorkflowList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNGetWorkflowName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Register this [Workflow], making it immutable and available for use.
    pub fn register(&self) -> Result<(), ()> {
        self.register_with_config("")
    }

    /// Register this [Workflow], making it immutable and available for use.
    ///
    /// * `configuration` - a JSON representation of the workflow configuration
    pub fn register_with_config<S: BnStrCompatible>(&self, config: S) -> Result<(), ()> {
        let config = config.into_bytes_with_nul();
        if unsafe {
            BNRegisterWorkflow(
                self.handle.as_ptr(),
                config.as_ref().as_ptr() as *const c_char,
            )
        } {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Register an [Activity] with this Workflow.
    ///
    /// * `activity` - the [Activity] to register
    pub fn register_activity(&self, activity: &Activity) -> Result<Activity, ()> {
        self.register_activity_with_subactivities::<Vec<String>>(activity, vec![])
    }

    /// Register an [Activity] with this Workflow.
    ///
    /// * `activity` - the [Activity] to register
    /// * `subactivities` - the list of Activities to assign
    pub fn register_activity_with_subactivities<I>(
        &self,
        activity: &Activity,
        subactivities: I,
    ) -> Result<Activity, ()>
    where
        I: IntoIterator,
        I::Item: BnStrCompatible,
    {
        let subactivities_raw: Vec<_> = subactivities
            .into_iter()
            .map(|x| x.into_bytes_with_nul())
            .collect();
        let mut subactivities_ptr: Vec<*const _> = subactivities_raw
            .iter()
            .map(|x| x.as_ref().as_ptr() as *const c_char)
            .collect();
        let result = unsafe {
            BNWorkflowRegisterActivity(
                self.handle.as_ptr(),
                activity.handle.as_ptr(),
                subactivities_ptr.as_mut_ptr(),
                subactivities_ptr.len(),
            )
        };
        let activity_ptr = NonNull::new(result).ok_or(())?;
        unsafe { Ok(Activity::from_raw(activity_ptr)) }
    }

    /// Determine if an Activity exists in this [Workflow].
    pub fn contains<A: BnStrCompatible>(&self, activity: A) -> bool {
        unsafe {
            BNWorkflowContains(
                self.handle.as_ptr(),
                activity.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Retrieve the configuration as an adjacency list in JSON for the [Workflow].
    pub fn configuration(&self) -> BnString {
        self.configuration_with_activity("")
    }

    /// Retrieve the configuration as an adjacency list in JSON for the
    /// [Workflow], just for the given `activity`.
    ///
    /// `activity` - return the configuration for the `activity`
    pub fn configuration_with_activity<A: BnStrCompatible>(&self, activity: A) -> BnString {
        let result = unsafe {
            BNWorkflowGetConfiguration(
                self.handle.as_ptr(),
                activity.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
            )
        };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Whether this [Workflow] is registered or not. A [Workflow] becomes immutable once registered.
    pub fn registered(&self) -> bool {
        unsafe { BNWorkflowIsRegistered(self.handle.as_ptr()) }
    }

    pub fn size(&self) -> usize {
        unsafe { BNWorkflowSize(self.handle.as_ptr()) }
    }

    /// Retrieve the Activity object for the specified `name`.
    pub fn activity<A: BnStrCompatible>(&self, name: A) -> Option<Activity> {
        let name = name.into_bytes_with_nul();
        let result = unsafe {
            BNWorkflowGetActivity(
                self.handle.as_ptr(),
                name.as_ref().as_ptr() as *const c_char,
            )
        };
        NonNull::new(result).map(|a| unsafe { Activity::from_raw(a) })
    }

    /// Retrieve the list of activity roots for the [Workflow], or if
    /// specified just for the given `activity`.
    ///
    /// * `activity` - if specified, return the roots for the `activity`
    pub fn activity_roots<A: BnStrCompatible>(&self, activity: A) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe {
            BNWorkflowGetActivityRoots(
                self.handle.as_ptr(),
                activity.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result as *mut *mut c_char, count, ()) }
    }

    /// Retrieve the list of all activities, or optionally a filtered list.
    ///
    /// * `activity` - if specified, return the direct children and optionally the descendants of the `activity` (includes `activity`)
    /// * `immediate` - whether to include only direct children of `activity` or all descendants
    pub fn subactivities<A: BnStrCompatible>(
        &self,
        activity: A,
        immediate: bool,
    ) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe {
            BNWorkflowGetSubactivities(
                self.handle.as_ptr(),
                activity.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
                immediate,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result as *mut *mut c_char, count, ()) }
    }

    /// Assign the list of `activities` as the new set of children for the specified `activity`.
    ///
    /// * `activity` - the Activity node to assign children
    /// * `activities` - the list of Activities to assign
    pub fn assign_subactivities<A, I>(&self, activity: A, activities: I) -> bool
    where
        A: BnStrCompatible,
        I: IntoIterator,
        I::Item: BnStrCompatible,
    {
        let input_list: Vec<_> = activities
            .into_iter()
            .map(|a| a.into_bytes_with_nul())
            .collect();
        let mut input_list_ptr: Vec<*const _> = input_list
            .iter()
            .map(|x| x.as_ref().as_ptr() as *const c_char)
            .collect();
        unsafe {
            BNWorkflowAssignSubactivities(
                self.handle.as_ptr(),
                activity.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
                input_list_ptr.as_mut_ptr(),
                input_list.len(),
            )
        }
    }

    /// Remove all Activity nodes from this [Workflow].
    pub fn clear(&self) -> bool {
        unsafe { BNWorkflowClear(self.handle.as_ptr()) }
    }

    /// Insert the list of `activities` before the specified `activity` and at the same level.
    ///
    /// * `activity` - the Activity node for which to insert `activities` before
    /// * `activities` - the list of Activities to insert
    pub fn insert<A, I>(&self, activity: A, activities: I) -> bool
    where
        A: BnStrCompatible,
        I: IntoIterator,
        I::Item: BnStrCompatible,
    {
        let input_list: Vec<_> = activities
            .into_iter()
            .map(|a| a.into_bytes_with_nul())
            .collect();
        let mut input_list_ptr: Vec<*const _> = input_list
            .iter()
            .map(|x| x.as_ref().as_ptr() as *const c_char)
            .collect();
        unsafe {
            BNWorkflowInsert(
                self.handle.as_ptr(),
                activity.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
                input_list_ptr.as_mut_ptr(),
                input_list.len(),
            )
        }
    }

    /// Remove the specified `activity`
    pub fn remove<A: BnStrCompatible>(&self, activity: A) -> bool {
        unsafe {
            BNWorkflowRemove(
                self.handle.as_ptr(),
                activity.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Replace the specified `activity`.
    ///
    /// * `activity` - the Activity to replace
    /// * `new_activity` - the replacement Activity
    pub fn replace<A: BnStrCompatible, N: BnStrCompatible>(
        &self,
        activity: A,
        new_activity: N,
    ) -> bool {
        unsafe {
            BNWorkflowReplace(
                self.handle.as_ptr(),
                activity.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
                new_activity.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Generate a FlowGraph object for the current [Workflow] and optionally show it in the UI.
    ///
    /// * `activity` - if specified, generate the Flowgraph using `activity` as the root
    /// * `sequential` - whether to generate a **Composite** or **Sequential** style graph
    pub fn graph<A: BnStrCompatible>(
        &self,
        activity: A,
        sequential: Option<bool>,
    ) -> Option<Ref<FlowGraph>> {
        let sequential = sequential.unwrap_or(false);
        let activity_name = activity.into_bytes_with_nul();
        let graph = unsafe {
            BNWorkflowGetGraph(
                self.handle.as_ptr(),
                activity_name.as_ref().as_ptr() as *const c_char,
                sequential,
            )
        };
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
