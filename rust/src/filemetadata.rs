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

use binaryninjacore_sys::{
    BNBeginUndoActions,
    BNCloseFile,
    BNCommitUndoActions,
    BNCreateDatabase,
    BNCreateFileMetadata,
    BNFileMetadata,
    BNFreeFileMetadata,
    BNGetCurrentOffset,
    BNGetCurrentView,
    //BNSetFileMetadataNavigationHandler,
    BNGetFileMetadataDatabase,
    BNGetFileViewOfType,
    BNGetFilename,
    BNIsAnalysisChanged,
    BNIsBackedByDatabase,
    BNIsFileModified,
    BNMarkFileModified,
    BNMarkFileSaved,
    BNNavigate,
    BNNewFileReference,
    BNOpenDatabaseForConfiguration,
    BNOpenExistingDatabase,
    BNRedo,
    BNRevertUndoActions,
    BNSaveAutoSnapshot,
    BNSetFilename,
    BNUndo,
};
use binaryninjacore_sys::{BNCreateDatabaseWithProgress, BNOpenExistingDatabaseWithProgress};
use std::ffi::c_void;

use crate::binaryview::BinaryView;
use crate::database::Database;

use crate::rc::*;
use crate::string::*;

use std::ptr;

#[derive(PartialEq, Eq, Hash)]
pub struct FileMetadata {
    pub(crate) handle: *mut BNFileMetadata,
}

unsafe impl Send for FileMetadata {}
unsafe impl Sync for FileMetadata {}

impl FileMetadata {
    pub(crate) fn from_raw(handle: *mut BNFileMetadata) -> Self {
        Self { handle }
    }

    pub fn new() -> Ref<Self> {
        unsafe {
            Ref::new(Self {
                handle: BNCreateFileMetadata(),
            })
        }
    }

    pub fn with_filename(name: impl AsCStr) -> Ref<Self> {
        let ret = FileMetadata::new();
        ret.set_filename(name);
        ret
    }

    pub fn close(&self) {
        unsafe {
            BNCloseFile(self.handle);
        }
    }

    pub fn filename(&self) -> BnString {
        unsafe {
            let raw = BNGetFilename(self.handle);
            BnString::from_raw(raw)
        }
    }

    pub fn set_filename(&self, name: impl AsCStr) {
        unsafe { BNSetFilename(self.handle, name.as_cstr().as_ptr()) }
    }

    pub fn modified(&self) -> bool {
        unsafe { BNIsFileModified(self.handle) }
    }

    pub fn mark_modified(&self) {
        unsafe {
            BNMarkFileModified(self.handle);
        }
    }

    pub fn mark_saved(&self) {
        unsafe {
            BNMarkFileSaved(self.handle);
        }
    }

    pub fn is_analysis_changed(&self) -> bool {
        unsafe { BNIsAnalysisChanged(self.handle) }
    }

    pub fn is_database_backed(&self, view_type: impl AsCStr) -> bool {
        unsafe { BNIsBackedByDatabase(self.handle, view_type.as_cstr().as_ptr()) }
    }

    pub fn run_undoable_transaction<F: FnOnce() -> Result<T, E>, T, E>(
        &self,
        func: F,
    ) -> Result<T, E> {
        let undo = self.begin_undo_actions(false);
        let result = func();
        match result {
            Ok(t) => {
                self.commit_undo_actions(undo);
                Ok(t)
            }
            Err(e) => {
                self.revert_undo_actions(undo);
                Err(e)
            }
        }
    }

    pub fn begin_undo_actions(&self, anonymous_allowed: bool) -> BnString {
        unsafe { BnString::from_raw(BNBeginUndoActions(self.handle, anonymous_allowed)) }
    }

    pub fn commit_undo_actions(&self, id: impl AsCStr) {
        unsafe { BNCommitUndoActions(self.handle, id.as_cstr().as_ptr()) }
    }

    pub fn revert_undo_actions(&self, id: impl AsCStr) {
        unsafe { BNRevertUndoActions(self.handle, id.as_cstr().as_ptr()) }
    }

    pub fn undo(&self) {
        unsafe {
            BNUndo(self.handle);
        }
    }

    pub fn redo(&self) {
        unsafe {
            BNRedo(self.handle);
        }
    }

    pub fn current_view(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetCurrentView(self.handle)) }
    }

    pub fn current_offset(&self) -> u64 {
        unsafe { BNGetCurrentOffset(self.handle) }
    }

    pub fn navigate_to(&self, view: impl AsCStr, offset: u64) -> Result<(), ()> {
        unsafe {
            if BNNavigate(self.handle, view.as_cstr().as_ptr(), offset) {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    pub fn get_view_of_type(&self, view: impl AsCStr) -> Result<Ref<BinaryView>, ()> {
        unsafe {
            let res = BNGetFileViewOfType(self.handle, view.as_cstr().as_ptr());

            if res.is_null() {
                Err(())
            } else {
                Ok(BinaryView::from_raw(res))
            }
        }
    }

    pub fn create_database(
        &self,
        filename: impl AsCStr,
        progress_func: Option<fn(usize, usize) -> bool>,
    ) -> bool {
        let filename = filename.as_cstr();

        let handle = unsafe { BNGetFileViewOfType(self.handle, c"Raw".as_ptr()) };
        match progress_func {
            None => unsafe { BNCreateDatabase(handle, filename.as_ptr(), ptr::null_mut()) },
            Some(func) => unsafe {
                BNCreateDatabaseWithProgress(
                    handle,
                    filename.as_ptr(),
                    func as *mut c_void,
                    Some(cb_progress_func),
                    ptr::null_mut(),
                )
            },
        }
    }

    pub fn save_auto_snapshot(&self) -> bool {
        unsafe {
            BNSaveAutoSnapshot(
                BNGetFileViewOfType(self.handle, c"Raw".as_ptr()),
                ptr::null_mut(),
            )
        }
    }

    pub fn open_database_for_configuration(
        &self,
        filename: impl AsCStr,
    ) -> Result<Ref<BinaryView>, ()> {
        unsafe {
            let bv = BNOpenDatabaseForConfiguration(self.handle, filename.as_cstr().as_ptr());

            if bv.is_null() {
                Err(())
            } else {
                Ok(BinaryView::from_raw(bv))
            }
        }
    }

    pub fn open_database(
        &self,
        filename: impl AsCStr,
        progress_func: Option<fn(usize, usize) -> bool>,
    ) -> Result<Ref<BinaryView>, ()> {
        let filename_ptr = filename.as_cstr().as_ptr();

        let view = match progress_func {
            None => unsafe { BNOpenExistingDatabase(self.handle, filename_ptr) },
            Some(func) => unsafe {
                BNOpenExistingDatabaseWithProgress(
                    self.handle,
                    filename_ptr,
                    func as *mut c_void,
                    Some(cb_progress_func),
                )
            },
        };

        if view.is_null() {
            Err(())
        } else {
            Ok(unsafe { BinaryView::from_raw(view) })
        }
    }

    /// Get the current database
    pub fn database(&self) -> Option<Database> {
        let result = unsafe { BNGetFileMetadataDatabase(self.handle) };
        ptr::NonNull::new(result).map(|handle| unsafe { Database::from_raw(handle) })
    }
}

impl ToOwned for FileMetadata {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for FileMetadata {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewFileReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeFileMetadata(handle.handle);
    }
}

unsafe extern "C" fn cb_progress_func(
    ctxt: *mut ::std::os::raw::c_void,
    progress: usize,
    total: usize,
) -> bool {
    let func: fn(usize, usize) -> bool = core::mem::transmute(ctxt);
    func(progress, total)
}
