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

use std::ffi::c_void;
use binaryninjacore_sys::{BNBeginUndoActions, BNCloseFile, BNCommitUndoActions, BNCreateDatabase, BNCreateFileMetadata, BNFileMetadata, BNFileMetadataGetSessionId, BNFreeFileMetadata, BNGetCurrentOffset, BNGetCurrentView, BNGetFileMetadataDatabase, BNGetFileViewOfType, BNGetFilename, BNGetProjectFile, BNIsAnalysisChanged, BNIsBackedByDatabase, BNIsFileModified, BNMarkFileModified, BNMarkFileSaved, BNNavigate, BNNewFileReference, BNOpenDatabaseForConfiguration, BNOpenExistingDatabase, BNRedo, BNRevertUndoActions, BNSaveAutoSnapshot, BNSetFilename, BNUndo};
use binaryninjacore_sys::{BNCreateDatabaseWithProgress, BNOpenExistingDatabaseWithProgress};

use crate::binaryview::BinaryView;
use crate::database::Database;
use crate::project::ProjectFile;

use crate::rc::*;
use crate::string::*;

use std::ptr::{self, NonNull};

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

    pub fn with_filename<S: BnStrCompatible>(name: S) -> Ref<Self> {
        let ret = FileMetadata::new();
        ret.set_filename(name);
        ret
    }

    pub fn close(&self) {
        unsafe {
            BNCloseFile(self.handle);
        }
    }
    
    pub fn session_id(&self) -> usize {
        unsafe {
            BNFileMetadataGetSessionId(self.handle)
        }
    }

    pub fn filename(&self) -> BnString {
        unsafe {
            let raw = BNGetFilename(self.handle);
            BnString::from_raw(raw)
        }
    }

    pub fn set_filename<S: BnStrCompatible>(&self, name: S) {
        let name = name.into_bytes_with_nul();

        unsafe {
            BNSetFilename(self.handle, name.as_ref().as_ptr() as *mut _);
        }
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

    pub fn is_database_backed<S: BnStrCompatible>(&self, view_type: S) -> bool {
        let view_type = view_type.into_bytes_with_nul();

        unsafe { BNIsBackedByDatabase(self.handle, view_type.as_ref().as_ptr() as *const _) }
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

    pub fn commit_undo_actions<S: BnStrCompatible>(&self, id: S) {
        let id = id.into_bytes_with_nul();
        unsafe {
            BNCommitUndoActions(self.handle, id.as_ref().as_ptr() as *const _);
        }
    }

    pub fn revert_undo_actions<S: BnStrCompatible>(&self, id: S) {
        let id = id.into_bytes_with_nul();
        unsafe {
            BNRevertUndoActions(self.handle, id.as_ref().as_ptr() as *const _);
        }
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

    pub fn navigate_to<S: BnStrCompatible>(&self, view: S, offset: u64) -> Result<(), ()> {
        let view = view.into_bytes_with_nul();

        unsafe {
            if BNNavigate(self.handle, view.as_ref().as_ptr() as *const _, offset) {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    pub fn get_view_of_type<S: BnStrCompatible>(&self, view: S) -> Result<Ref<BinaryView>, ()> {
        let view = view.into_bytes_with_nul();

        unsafe {
            let res = BNGetFileViewOfType(self.handle, view.as_ref().as_ptr() as *const _);

            if res.is_null() {
                Err(())
            } else {
                Ok(BinaryView::from_raw(res))
            }
        }
    }

    pub fn get_project_file(&self) -> Option<ProjectFile> {
        unsafe {
            let res = NonNull::new(BNGetProjectFile(self.handle))?;
            Some(ProjectFile::from_raw(res))
        }
    }

    pub fn create_database<S: BnStrCompatible>(
        &self,
        filename: S,
        progress_func: Option<fn(usize, usize) -> bool>,
    ) -> bool {
        let filename = filename.into_bytes_with_nul();
        let filename_ptr = filename.as_ref().as_ptr() as *mut _;
        let raw = "Raw".into_bytes_with_nul();
        let raw_ptr = raw.as_ptr() as *mut _;

        let handle = unsafe { BNGetFileViewOfType(self.handle, raw_ptr) };
        match progress_func {
            None => unsafe { BNCreateDatabase(handle, filename_ptr, ptr::null_mut()) },
            Some(func) => unsafe {
                BNCreateDatabaseWithProgress(
                    handle,
                    filename_ptr,
                    func as *mut c_void,
                    Some(cb_progress_func),
                    ptr::null_mut(),
                )
            },
        }
    }

    pub fn save_auto_snapshot(&self) -> bool {
        let raw = "Raw".into_bytes_with_nul();
        unsafe {
            BNSaveAutoSnapshot(
                BNGetFileViewOfType(self.handle, raw.as_ptr() as *mut _),
                ptr::null_mut() as *mut _,
            )
        }
    }

    pub fn open_database_for_configuration<S: BnStrCompatible>(
        &self,
        filename: S,
    ) -> Result<Ref<BinaryView>, ()> {
        let filename = filename.into_bytes_with_nul();
        unsafe {
            let bv =
                BNOpenDatabaseForConfiguration(self.handle, filename.as_ref().as_ptr() as *const _);

            if bv.is_null() {
                Err(())
            } else {
                Ok(BinaryView::from_raw(bv))
            }
        }
    }

    pub fn open_database<S: BnStrCompatible>(
        &self,
        filename: S,
        progress_func: Option<fn(usize, usize) -> bool>,
    ) -> Result<Ref<BinaryView>, ()> {
        let filename = filename.into_bytes_with_nul();
        let filename_ptr = filename.as_ref().as_ptr() as *mut _;

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
