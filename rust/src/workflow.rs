use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::slice;

use binaryninjacore_sys::*;

use crate::activity::Activity;
use crate::flowgraph::FlowGraph;
use crate::rc::*;
use crate::string::*;

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct Workflow(pub(crate) *mut BNWorkflow);

impl ToOwned for Workflow {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Workflow {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self(BNNewWorkflowReference(handle.0)))
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeWorkflow(handle.0);
    }
}

unsafe impl CoreOwnedArrayProvider for Workflow {
    type Raw = *mut BNWorkflow;
    type Context = ();

    unsafe fn free(raw: *mut *mut BNWorkflow, count: usize, _context: &()) {
        BNFreeWorkflowList(raw, count);
    }
}

unsafe impl<'a> CoreOwnedArrayWrapper<'a> for Workflow {
    type Wrapped = Guard<'a, Workflow>;

    unsafe fn wrap_raw(
        raw: &'a *mut BNWorkflow,
        context: &'a (),
    ) -> Guard<'a, Self> {
        Guard::new(Self::from_raw(*raw), context)
    }
}

impl AsRef<Workflow> for Workflow {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Workflow {
    pub(crate) unsafe fn from_raw(p: *mut BNWorkflow) -> Self {
        Self(p)
    }

    pub fn new() -> Ref<Self> {
        let name_with_nul = cstr!("");

        unsafe {
            let p = BNCreateWorkflow(name_with_nul.as_ptr());

            Ref::new(Self(p))
        }
    }

    pub fn with_name(name: &str) -> Ref<Self> {
        let name_with_nul = CString::new(name).unwrap();

        unsafe {
            let p = BNCreateWorkflow(name_with_nul.as_ptr());

            Ref::new(Self(p))
        }
    }

    pub fn instance() -> Ref<Self> {
        Self::instance_with_activity("")
    }

    pub fn instance_with_activity(activity: &str) -> Ref<Self> {
        let activity_with_nul = CString::new(activity).unwrap();

        unsafe { Ref::new(Self::from_raw(BNWorkflowInstance(activity_with_nul.as_ptr()))) }
    }

    pub fn list_all() -> Array<Workflow> {
        let mut count = 0;

        unsafe {
            let handles = BNGetWorkflowList(&mut count);

            Array::new(handles, count, ())
        }
    }

    // clone, but renamed to avoid confusion with rust's Clone trait
    pub fn duplicate(&self, name: &str) -> Ref<Self> {
        self.duplicate_with_activity(name, "")
    }

    pub fn duplicate_with_activity(&self, name: &str, activity: &str) -> Ref<Self> {
        let name_with_nul = CString::new(name).unwrap();
        let activity_with_nul = CString::new(activity).unwrap();

        unsafe {
            let ww = BNWorkflowClone(self.0, name_with_nul.as_ptr(), activity_with_nul.as_ptr());
            Ref::new(Self::from_raw(ww))
        }
    }

    pub fn register_activity(&self, activity: Ref<Activity>) -> bool {
        self.register_activity_with_options(activity, &[], "")
    }

    pub fn register_activity_with_options(&self, activity: Ref<Activity>, subactivities: &[&str], desc: &str) -> bool {
        let desc_with_nul = CString::new(desc).unwrap();

        let mut buf: Vec<*mut i8> = subactivities.iter()
            .map(|sa| unsafe {
                let sa_with_nul = CString::new(*sa).unwrap();
                BNAllocString(sa_with_nul.as_ptr())
            })
            .collect();

        unsafe { 
            let rr = BNWorkflowRegisterActivity(self.0, activity.0, buf.as_mut_ptr() as _, buf.len(), desc_with_nul.as_ptr());

            for s in buf {
                BNFreeString(s);
            }

            rr
        }
    }

    pub fn contains(&self, activity: &str) -> bool {
        let activity_with_nul = CString::new(activity).unwrap();

        unsafe { BNWorkflowContains(self.0, activity_with_nul.as_ptr()) }
    }

    pub fn configuration(&self, activity: &str) -> Cow<str> {
        let activity_with_nul = CString::new(activity).unwrap();

        unsafe {
            let cfg = BNWorkflowGetConfiguration(self.0, activity_with_nul.as_ptr());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(cfg);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(cfg);

            res
        }
    }

    pub fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetWorkflowName(self.0);

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    pub fn registered(&self) -> bool {
        unsafe { BNWorkflowIsRegistered(self.0) }
    }

    pub fn size(&self) -> usize {
        unsafe { BNWorkflowSize(self.0) }
    }

    pub fn activity(&self, activity: &str) -> Ref<Activity> {
        let activity_with_nul = CString::new(activity).unwrap();

        unsafe {
            let p = BNWorkflowGetActivity(self.0, activity_with_nul.as_ptr());
            Ref::new(Activity::from_raw(p))   
        }
    }

    pub fn activity_roots(&self) -> impl Iterator<Item=Cow<str>> {
        self.activity_roots_with_activity("")
    }

    pub fn activity_roots_with_activity(&self, activity: &str) -> impl Iterator<Item=Cow<str>> {
        let activity_with_nul = CString::new(activity).unwrap();

        let mut count = 0;

        unsafe {
            let list = BNWorkflowGetActivityRoots(self.0, activity_with_nul.as_ptr(), &mut count);

            let activities = slice::from_raw_parts_mut(list, count);

            let rr: Vec<Cow<str>> = activities.into_iter()
                .map(|aa| CStr::from_ptr(*aa as _).to_string_lossy().into_owned().into())
                .collect();

            BNFreeStringList(activities.as_mut_ptr() as _, activities.len());

            rr.into_iter()
        }
    }

    pub fn subactivities(&self) -> Array<BnString> {
        self.subactivities_with_options("", true)
    }

    pub fn subactivities_with_options(&self, activity: &str, immediate: bool) -> Array<BnString> {
        let activity_with_nul = CString::new(activity).unwrap();

        let mut count = 0;

        unsafe {
            let handles = BNWorkflowGetSubactivities(self.0, activity_with_nul.as_ptr(), immediate, &mut count);

            Array::new(handles as *mut *mut std::os::raw::c_char, count, ())
        }
    }

    pub fn set_subactivities(&self, activity: &str) -> bool {
        self.set_subactivities_with_activities(activity, &[])
    }

    pub fn set_subactivities_with_activities(&self, activity: &str, subactivities: &[&str]) -> bool {
        let activity_with_nul = CString::new(activity).unwrap();

        let mut buf: Vec<*mut i8> = subactivities.iter()
            .map(|sa| unsafe {
                let sa_with_nul = CString::new(*sa).unwrap();
                BNAllocString(sa_with_nul.as_ptr())
            })
            .collect();

        unsafe { 
            let rr = BNWorkflowAssignSubactivities(self.0, activity_with_nul.as_ptr(), buf.as_mut_ptr() as _, buf.len());

            for sa in buf {
                BNFreeString(sa);
            }

            rr
        }
    }

    pub fn clear(&self) -> bool {
        unsafe { BNWorkflowClear(self.0) }
    }

    pub fn insert(&self, activity: &str, activities: &[&str]) -> bool {
        let activity_with_nul = CString::new(activity).unwrap();

        let mut buf: Vec<*mut i8> = activities.iter()
            .map(|sa| unsafe {
                let sa_with_nul = CString::new(*sa).unwrap();
                BNAllocString(sa_with_nul.as_ptr())
            })
            .collect();

        unsafe { 
            let rr = BNWorkflowInsert(self.0, activity_with_nul.as_ptr(), buf.as_mut_ptr() as _, buf.len());

            for sa in buf {
                BNFreeString(sa);
            }

            rr
        }
    }

    pub fn remove(&self, activity: &str) -> bool {
        let activity_with_nul = CString::new(activity).unwrap();

        unsafe { BNWorkflowRemove(self.0, activity_with_nul.as_ptr()) }
    }

    pub fn replace(&self, old: &str, new: &str) -> bool {
        let old_with_nul = CString::new(old).unwrap();
        let new_with_nul = CString::new(new).unwrap();

        unsafe { BNWorkflowReplace(self.0, old_with_nul.as_ptr(), new_with_nul.as_ptr()) }
    }

    pub fn graph(&self) -> Option<Ref<FlowGraph>> {
        self.graph_with_options("", false)
    }

    pub fn graph_with_options(&self, activity: &str, seq: bool) -> Option<Ref<FlowGraph>> {
        let activity_with_nul = CString::new(activity).unwrap();

        let p = unsafe { BNWorkflowGetGraph(self.0, activity_with_nul.as_ptr(), seq) };

        if p.is_null() {
            return None;
        }

        unsafe { Some(Ref::new(FlowGraph::from_raw(p))) }
    }

    pub fn show_report(&self, name: &str) {
        let name_with_nul = CString::new(name).unwrap();

        unsafe { BNWorkflowShowReport(self.0, name_with_nul.as_ptr()) }
    }
}

pub fn register_workflow(ww: Ref<Workflow>) -> bool {
    register_workflow_with_description(ww, "")
}

pub fn register_workflow_with_description(ww: Ref<Workflow>, descr: &str) -> bool {
    let descr_with_nul = CString::new(descr).unwrap();

    unsafe { BNRegisterWorkflow(ww.0, descr_with_nul.as_ptr()) }
}
