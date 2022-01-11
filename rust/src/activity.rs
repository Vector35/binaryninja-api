use std::borrow::Cow;
use std::ffi::{c_void, CString, CStr};

use binaryninjacore_sys::*;

use crate::analysiscontext::AnalysisContext;
use crate::rc::*;

pub trait ActivityFn: 'static + Sync {
    fn run(&self, ac: &AnalysisContext);
}

impl<T> ActivityFn for T
where
    T: 'static + Sync + Fn(&AnalysisContext),
{
    fn run(&self, ac: &AnalysisContext) {
        self(ac)
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct Activity(pub(crate) *mut BNActivity);

impl ToOwned for Activity {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Activity {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self(BNNewActivityReference(handle.0)))
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeActivity(handle.0);
    }
}


impl Activity {
    pub(crate) unsafe fn from_raw(a: *mut BNActivity) -> Self {
        Self(a)
    }

    pub fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNActivityGetName(self.0);

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }
}

extern "C" fn activity_run<A: ActivityFn>(ctxt: *mut c_void, ac: *mut BNAnalysisContext) {
    assert!(!ac.is_null());

    ffi_wrap!("Activity::run", unsafe {
        let activity = &*(ctxt as *const A);

        let analysis_context = AnalysisContext::from_raw(ac);

        activity.run(&analysis_context);
    });
}

pub fn register_activity<A: ActivityFn>(name: &str, a: A) -> Ref<Activity> {
    let cstr = CString::new(name).unwrap();

    let b = Box::new(a);

    let p = unsafe { BNCreateActivity(cstr.as_ptr(), Box::into_raw(b) as *mut c_void, Some(activity_run::<A>)) };

    unsafe { Ref::new(Activity::from_raw(p)) }
}