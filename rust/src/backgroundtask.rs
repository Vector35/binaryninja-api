// Copyright 2021-2024 Vector 35 Inc.
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

//! Background tasks provide plugins the ability to run tasks in the background so they don't hand the UI

use binaryninjacore_sys::*;

use std::result;

use crate::rc::*;
use crate::string::*;

pub type Result<R> = result::Result<R, ()>;

#[derive(PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BackgroundTask {
    handle: *mut BNBackgroundTask,
}

impl BackgroundTask {
    pub fn new(initial_text: impl AsCStr, can_cancel: bool) -> Result<Ref<Self>> {
        let handle = unsafe { BNBeginBackgroundTask(initial_text.as_cstr().as_ptr(), can_cancel) };

        if handle.is_null() {
            return Err(());
        }

        unsafe { Ok(Ref::new(Self { handle })) }
    }

    pub fn can_cancel(&self) -> bool {
        unsafe { BNCanCancelBackgroundTask(self.handle) }
    }

    pub fn is_cancelled(&self) -> bool {
        unsafe { BNIsBackgroundTaskCancelled(self.handle) }
    }

    pub fn is_finished(&self) -> bool {
        unsafe { BNIsBackgroundTaskFinished(self.handle) }
    }

    pub fn get_progress_text(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetBackgroundTaskProgressText(self.handle)) }
    }

    pub fn cancel(&self) {
        unsafe { BNCancelBackgroundTask(self.handle) }
    }

    pub fn finish(&self) {
        unsafe { BNFinishBackgroundTask(self.handle) }
    }

    pub fn set_progress_text(&self, text: impl AsCStr) {
        unsafe { BNSetBackgroundTaskProgressText(self.handle, text.as_cstr().as_ptr()) }
    }

    pub fn running_tasks() -> Array<BackgroundTask> {
        unsafe {
            let mut count = 0;
            let handles = BNGetRunningBackgroundTasks(&mut count);

            Array::new(handles, count, ())
        }
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
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for BackgroundTask {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeBackgroundTaskList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        debug_assert!(!raw.is_null());
        // SAFETY: `BackgroundTask` is repr(transparent)
        unsafe { &*(raw as *const _ as *const Self) }
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
