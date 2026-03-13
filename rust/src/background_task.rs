// Copyright 2021-2026 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Background tasks provide plugins the ability to inform the core of long-running background tasks.

use binaryninjacore_sys::*;
use std::fmt::Debug;

use std::result;

use crate::rc::*;
use crate::string::*;

pub type Result<R> = result::Result<R, ()>;

/// An RAII guard for [`BackgroundTask`] to finish the task when dropped.
pub struct OwnedBackgroundTaskGuard {
    pub(crate) task: Ref<BackgroundTask>,
}

impl OwnedBackgroundTaskGuard {
    pub fn cancel(&self) {
        self.task.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.task.is_cancelled()
    }

    pub fn set_progress_text(&self, text: &str) {
        self.task.set_progress_text(text);
    }
}

impl Drop for OwnedBackgroundTaskGuard {
    fn drop(&mut self) {
        self.task.finish();
    }
}

/// A [`BackgroundTask`] does not actually execute any code, only act as a handler, primarily to query
/// the status of the task, and to cancel the task.
///
/// If you are looking to execute code in the background, consider using rusts threading API, or if you
/// want the core to execute the task on a worker thread, instead use the [`crate::worker_thread`] API.
///
/// NOTE: If you do not call [`BackgroundTask::finish`] or [`BackgroundTask::cancel`], the task will
/// persist even _after_ it has been dropped, use [`OwnedBackgroundTaskGuard`] to ensure the task is
/// finished, see [`BackgroundTask::enter`] for usage.
#[derive(PartialEq, Eq, Hash)]
pub struct BackgroundTask {
    pub(crate) handle: *mut BNBackgroundTask,
}

impl BackgroundTask {
    pub(crate) unsafe fn from_raw(handle: *mut BNBackgroundTask) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    /// Begin the [`BackgroundTask`], you must manually finish the task by calling [`BackgroundTask::finish`].
    ///
    /// If you wish to automatically finish the task when leaving the scope, use [`BackgroundTask::enter`].
    pub fn new(initial_text: &str, can_cancel: bool) -> Ref<Self> {
        let text = initial_text.to_cstr();
        let handle = unsafe { BNBeginBackgroundTask(text.as_ptr(), can_cancel) };
        // We should always be returned a valid task.
        assert!(!handle.is_null());
        unsafe { Ref::new(Self { handle }) }
    }

    /// Creates a [`OwnedBackgroundTaskGuard`] that is responsible for finishing the background task
    /// once dropped. Because the status of a task does not dictate the underlying objects' lifetime,
    /// this can be safely done without requiring exclusive ownership.
    pub fn enter(&self) -> OwnedBackgroundTaskGuard {
        OwnedBackgroundTaskGuard {
            task: self.to_owned(),
        }
    }

    pub fn can_cancel(&self) -> bool {
        unsafe { BNCanCancelBackgroundTask(self.handle) }
    }

    pub fn is_cancelled(&self) -> bool {
        unsafe { BNIsBackgroundTaskCancelled(self.handle) }
    }

    pub fn cancel(&self) {
        unsafe { BNCancelBackgroundTask(self.handle) }
    }

    pub fn is_finished(&self) -> bool {
        unsafe { BNIsBackgroundTaskFinished(self.handle) }
    }

    pub fn finish(&self) {
        unsafe { BNFinishBackgroundTask(self.handle) }
    }

    pub fn progress_text(&self) -> String {
        unsafe { BnString::into_string(BNGetBackgroundTaskProgressText(self.handle)) }
    }

    pub fn set_progress_text(&self, text: &str) {
        let progress_text = text.to_cstr();
        unsafe { BNSetBackgroundTaskProgressText(self.handle, progress_text.as_ptr()) }
    }

    pub fn running_tasks() -> Array<BackgroundTask> {
        unsafe {
            let mut count = 0;
            let handles = BNGetRunningBackgroundTasks(&mut count);
            Array::new(handles, count, ())
        }
    }
}

impl Debug for BackgroundTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackgroundTask")
            .field("progress_text", &self.progress_text())
            .field("can_cancel", &self.can_cancel())
            .field("is_cancelled", &self.is_cancelled())
            .field("is_finished", &self.is_finished())
            .finish()
    }
}

unsafe impl RefCountable for BackgroundTask {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewBackgroundTaskReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeBackgroundTask(handle.handle);
    }
}

impl CoreArrayProvider for BackgroundTask {
    type Raw = *mut BNBackgroundTask;
    type Context = ();
    type Wrapped<'a> = Guard<'a, BackgroundTask>;
}

unsafe impl CoreArrayProviderInner for BackgroundTask {
    unsafe fn free(raw: *mut *mut BNBackgroundTask, count: usize, _context: &()) {
        BNFreeBackgroundTaskList(raw, count);
    }
    unsafe fn wrap_raw<'a>(raw: &'a *mut BNBackgroundTask, context: &'a ()) -> Self::Wrapped<'a> {
        Guard::new(BackgroundTask::from_raw(*raw), context)
    }
}

impl ToOwned for BackgroundTask {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl Send for BackgroundTask {}
unsafe impl Sync for BackgroundTask {}
