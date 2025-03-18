use crate::string::BnStrCompatible;
use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void};

pub struct WorkerThreadActionExecutor {
    func: Box<dyn Fn()>,
}

impl WorkerThreadActionExecutor {
    unsafe extern "C" fn cb_execute(ctx: *mut c_void) {
        let f: Box<Self> = Box::from_raw(ctx as *mut Self);
        f.execute();
    }

    pub fn execute(&self) {
        (self.func)();
    }
}

pub fn execute_on_worker_thread<F: Fn() + 'static, S: BnStrCompatible>(name: S, f: F) {
    let boxed_executor = Box::new(WorkerThreadActionExecutor { func: Box::new(f) });
    let raw_executor = Box::into_raw(boxed_executor);
    let name = name.into_bytes_with_nul();
    unsafe {
        BNWorkerEnqueueNamed(
            raw_executor as *mut c_void,
            Some(WorkerThreadActionExecutor::cb_execute),
            name.as_ref().as_ptr() as *const c_char,
        )
    }
}

pub fn execute_on_worker_thread_priority<F: Fn() + 'static, S: BnStrCompatible>(name: S, f: F) {
    let boxed_executor = Box::new(WorkerThreadActionExecutor { func: Box::new(f) });
    let raw_executor = Box::into_raw(boxed_executor);
    let name = name.into_bytes_with_nul();
    unsafe {
        BNWorkerPriorityEnqueueNamed(
            raw_executor as *mut c_void,
            Some(WorkerThreadActionExecutor::cb_execute),
            name.as_ref().as_ptr() as *const c_char,
        )
    }
}

pub fn execute_on_worker_thread_interactive<F: Fn() + 'static, S: BnStrCompatible>(name: S, f: F) {
    let boxed_executor = Box::new(WorkerThreadActionExecutor { func: Box::new(f) });
    let raw_executor = Box::into_raw(boxed_executor);
    let name = name.into_bytes_with_nul();
    unsafe {
        BNWorkerInteractiveEnqueueNamed(
            raw_executor as *mut c_void,
            Some(WorkerThreadActionExecutor::cb_execute),
            name.as_ref().as_ptr() as *const c_char,
        )
    }
}

/// Returns the number of worker threads that are currently running.
/// By default, this is the number of cores on the system minus one
///
/// To set the worker thread count use [`set_worker_thread_count`].
pub fn worker_thread_count() -> usize {
    unsafe { BNGetWorkerThreadCount() }
}

/// Sets the number of worker threads that are currently running.
/// By default, this is the number of cores on the system minus one.
pub fn set_worker_thread_count(count: usize) {
    unsafe { BNSetWorkerThreadCount(count) }
}
