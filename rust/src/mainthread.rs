//! This module provides two ways to execute "jobs":
//!
//! 1. On the Binary Ninja main thread (the UI event thread when running in the GUI application):
//!    * [execute_on_main_thread]
//!    * [execute_on_main_thread_and_wait]
//! 2. On a worker thread
//!
//! Any manipulation of the GUI should be performed on the main thread, but any
//! non-GUI work is generally better to be performed using a worker. This is
//! especially true for any longer-running work, as the user interface will
//! be unable to update itself while a job is executing on the main thread.
//!
//! There are three worker queues, in order of decreasing priority:
//!
//!    1. The Interactive Queue ([worker_interactive_enqueue])
//!    2. The Priority Queue ([worker_priority_enqueue])
//!    3. The Worker Queue ([worker_enqueue])
//!
//! All of these queues are serviced by the same pool of worker threads. The
//! difference between the queues is basically one of priority: one queue must
//! be empty of jobs before a worker thread will execute a job from a lower
//! priority queue.
//!
//! The default maximum number of concurrent worker threads is controlled by the
//! `analysis.limits.workerThreadCount` setting but can be adjusted at runtime via
//! [set_worker_thread_count].
//!
//! The worker threads are native threads, managed by the Binary Ninja core. If
//! more control over the thread is required, consider using the
//! [crate::backgroundtask::BackgroundTask] class.

use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use crate::string::BnStrCompatible;

#[repr(transparent)]
pub struct MainThreadAction {
    handle: ptr::NonNull<BNMainThreadAction>,
}

impl Clone for MainThreadAction {
    fn clone(&self) -> Self {
        let result = unsafe { BNNewMainThreadActionReference(self.as_raw()) };
        unsafe { Self::from_raw(ptr::NonNull::new(result).unwrap()) }
    }
}

impl Drop for MainThreadAction {
    fn drop(&mut self) {
        unsafe { BNFreeMainThreadAction(self.as_raw()) }
    }
}

impl MainThreadAction {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNMainThreadAction>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNMainThreadAction) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNMainThreadAction {
        &mut *self.handle.as_ptr()
    }

    pub fn execute(&self) {
        unsafe { BNExecuteMainThreadAction(self.as_raw()) }
    }

    pub fn is_done(&self) -> bool {
        unsafe { BNIsMainThreadActionDone(self.as_raw()) }
    }

    pub fn wait(&self) {
        unsafe { BNWaitForMainThreadAction(self.as_raw()) }
    }
}

/// Takes a single parameter which is a function that will be executed
/// on the main Binary Ninja thread.
///
/// <div class="warning">
///
/// May be required for some GUI operations, but should be used sparingly as it can block the UI.
///
/// </div>
pub fn execute_on_main_thread<F: FnMut() + 'static>(action: F) -> Option<MainThreadAction> {
    let action = Box::leak(Box::new(action));
    let result = unsafe {
        BNExecuteOnMainThread(
            action as *mut F as *mut ffi::c_void,
            Some(cb_execute_with_drop::<F>),
        )
    };
    ptr::NonNull::new(result).map(|h| unsafe { MainThreadAction::from_raw(h) })
}

/// Takes a single parameter which is a function that will be
/// executed on the main Binary Ninja thread and will block execution of further python until the function returns.
///
/// <div class="warning">
///
/// May be required for some GUI operations, but should be used sparingly as it can block the UI.
///
/// </div>
pub fn execute_on_main_thread_and_wait<F: FnMut() + 'static>(mut action: F) {
    unsafe {
        BNExecuteOnMainThreadAndWait(
            &mut action as *mut F as *mut ffi::c_void,
            Some(cb_execute_without_drop::<F>),
        )
    }
}

pub fn worker_enqueue<F: FnMut() + 'static, S: BnStrCompatible>(action: F, name: S) {
    let action = Box::leak(Box::new(action));
    let name = name.into_bytes_with_nul();
    unsafe {
        BNWorkerEnqueueNamed(
            action as *mut F as *mut ffi::c_void,
            Some(cb_execute_with_drop::<F>),
            name.as_ref().as_ptr() as *const ffi::c_char,
        )
    }
}

pub fn worker_priority_enqueue<F: FnMut() + 'static, S: BnStrCompatible>(action: F, name: S) {
    let action = Box::leak(Box::new(action));
    let name = name.into_bytes_with_nul();
    unsafe {
        BNWorkerPriorityEnqueueNamed(
            action as *mut F as *mut ffi::c_void,
            Some(cb_execute_with_drop::<F>),
            name.as_ref().as_ptr() as *const ffi::c_char,
        )
    }
}

pub fn worker_interactive_enqueue<F: FnMut() + 'static, S: BnStrCompatible>(action: F, name: S) {
    let action = Box::leak(Box::new(action));
    let name = name.into_bytes_with_nul();
    unsafe {
        BNWorkerInteractiveEnqueueNamed(
            action as *mut F as *mut ffi::c_void,
            Some(cb_execute_with_drop::<F>),
            name.as_ref().as_ptr() as *const ffi::c_char,
        )
    }
}

/// Returns the number of worker threads that are currently running.
/// By default, this is the number of cores on the system minus one, however this can be changed with
/// [set_worker_thread_count].
pub fn get_worker_thread_count() -> usize {
    unsafe { BNGetWorkerThreadCount() }
}

/// Sets the number of worker threads that are currently running.
/// By default, this is the number of cores on the system minus one.
pub fn set_worker_thread_count(count: usize) {
    unsafe { BNSetWorkerThreadCount(count) }
}

pub fn is_main_thread() -> bool {
    unsafe { BNIsMainThread() }
}

pub trait MainThreadProvider {
    fn add_action(&self, action: &MainThreadAction);
}

pub fn register_main_thread<T: MainThreadProvider>(action: T) {
    // SAFETY new main thread provider is never freed
    let context = Box::leak(Box::new(action));
    let mut callback = BNMainThreadCallbacks {
        context: context as *mut T as *mut ffi::c_void,
        addAction: Some(cb_add_action::<T>),
    };
    unsafe { BNRegisterMainThread(&mut callback) }
}

unsafe extern "C" fn cb_add_action<T: MainThreadProvider>(
    ctxt: *mut ffi::c_void,
    action: *mut BNMainThreadAction,
) {
    let ctxt = &mut *(ctxt as *mut T);
    ctxt.add_action(MainThreadAction::ref_from_raw(&action))
}

unsafe extern "C" fn cb_execute_without_drop<F: FnMut() + 'static>(ctxt: *mut ffi::c_void) {
    let ctxt = &mut *(ctxt as *mut F);
    ctxt()
}

unsafe extern "C" fn cb_execute_with_drop<F: FnMut() + 'static>(ctxt: *mut ffi::c_void) {
    let mut ctxt = Box::from_raw(ctxt as *mut F);
    ctxt();
    drop(ctxt);
}
