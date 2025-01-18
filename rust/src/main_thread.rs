use crate::rc::{Ref, RefCountable};
use binaryninjacore_sys::{
    BNExecuteMainThreadAction, BNExecuteOnMainThread, BNExecuteOnMainThreadAndWait,
    BNFreeMainThreadAction, BNIsMainThreadActionDone, BNMainThreadAction, BNMainThreadCallbacks,
    BNNewMainThreadActionReference, BNRegisterMainThread, BNWaitForMainThreadAction,
};
use std::ffi::c_void;

pub struct MainThreadActionExecutor {
    func: Box<dyn Fn()>,
}

impl MainThreadActionExecutor {
    unsafe extern "C" fn cb_execute(ctx: *mut c_void) {
        let f: Box<Self> = Box::from_raw(ctx as *mut Self);
        f.execute();
    }

    pub fn execute(&self) {
        (self.func)();
    }
}

/// Execute passed function on the main thread. Returns `None` if already running on the main thread.
///
/// When not running in headless this will block the UI.
pub fn execute_on_main_thread<F: Fn() + 'static>(f: F) -> Option<Ref<MainThreadAction>> {
    let boxed_executor = Box::new(MainThreadActionExecutor { func: Box::new(f) });
    let raw_executor = Box::into_raw(boxed_executor);
    let raw_action = unsafe {
        BNExecuteOnMainThread(
            raw_executor as *mut c_void,
            Some(MainThreadActionExecutor::cb_execute),
        )
    };
    match raw_action.is_null() {
        false => Some(MainThreadAction::ref_from_raw(raw_action)),
        true => None,
    }
}

/// Execute passed function on the main thread and wait until the function is finished.
///
/// When not running in headless this will block the UI.
pub fn execute_on_main_thread_and_wait<F: Fn() + 'static>(f: F) {
    let boxed_executor = Box::new(MainThreadActionExecutor { func: Box::new(f) });
    let raw_executor = Box::into_raw(boxed_executor);
    unsafe {
        BNExecuteOnMainThreadAndWait(
            raw_executor as *mut c_void,
            Some(MainThreadActionExecutor::cb_execute),
        )
    };
}

/// The trait required for receiving main thread actions
pub trait MainThreadHandler: Sized {
    fn add_action(&self, _view: Ref<MainThreadAction>);

    unsafe extern "C" fn cb_add_action(ctxt: *mut c_void, action: *mut BNMainThreadAction) {
        ffi_wrap!("MainThread::add_action", {
            let main_thread = &*(ctxt as *mut Self);
            let action = MainThreadAction::ref_from_raw(action);
            main_thread.add_action(action);
        })
    }

    /// Register the main thread handler. Leaking [`Self`] in the process.
    ///
    /// NOTE: This MUST be called from **within** the main thread.
    fn register(self) {
        // NOTE: We leak self here.
        let raw = Box::into_raw(Box::new(self));
        let mut callbacks = BNMainThreadCallbacks {
            context: raw as *mut c_void,
            addAction: Some(Self::cb_add_action),
        };
        unsafe { BNRegisterMainThread(&mut callbacks) };
    }
}

pub struct MainThreadAction {
    pub handle: *mut BNMainThreadAction,
}

impl MainThreadAction {
    pub fn from_raw(handle: *mut BNMainThreadAction) -> Self {
        assert!(!handle.is_null());
        Self { handle }
    }

    pub fn ref_from_raw(handle: *mut BNMainThreadAction) -> Ref<Self> {
        unsafe { Ref::new(Self::from_raw(handle)) }
    }

    pub fn execute(&self) {
        unsafe { BNExecuteMainThreadAction(self.handle) }
    }

    pub fn is_done(&self) -> bool {
        unsafe { BNIsMainThreadActionDone(self.handle) }
    }

    pub fn wait(&self) {
        unsafe { BNWaitForMainThreadAction(self.handle) }
    }
}

impl ToOwned for MainThreadAction {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for MainThreadAction {
    unsafe fn inc_ref(action: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewMainThreadActionReference(action.handle),
        })
    }

    unsafe fn dec_ref(action: &Self) {
        BNFreeMainThreadAction(action.handle);
    }
}

unsafe impl Send for MainThreadAction {}
