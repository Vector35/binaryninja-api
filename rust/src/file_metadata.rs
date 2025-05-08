// Copyright 2021-2025 Vector 35 Inc.
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

use crate::binary_view::BinaryView;
use crate::database::Database;
use crate::rc::*;
use crate::string::*;
use binaryninjacore_sys::{
    BNBeginUndoActions, BNCloseFile, BNCommitUndoActions, BNCreateDatabase, BNCreateFileMetadata,
    BNFileMetadata, BNFileMetadataGetSessionId, BNFreeFileMetadata, BNGetCurrentOffset,
    BNGetCurrentView, BNGetExistingViews, BNGetFileMetadataDatabase, BNGetFileViewOfType,
    BNGetFilename, BNGetProjectFile, BNIsAnalysisChanged, BNIsBackedByDatabase, BNIsFileModified,
    BNMarkFileModified, BNMarkFileSaved, BNNavigate, BNNewFileReference,
    BNOpenDatabaseForConfiguration, BNOpenExistingDatabase, BNRedo, BNRevertUndoActions,
    BNSaveAutoSnapshot, BNSetFilename, BNUndo,
};
use binaryninjacore_sys::{BNCreateDatabaseWithProgress, BNOpenExistingDatabaseWithProgress};
use std::ffi::c_void;
use std::fmt::Debug;
use std::path::Path;

use crate::progress::ProgressCallback;
use crate::project::file::ProjectFile;
use std::ptr::{self, NonNull};

#[derive(PartialEq, Eq, Hash)]
pub struct FileMetadata {
    pub(crate) handle: *mut BNFileMetadata,
}

impl FileMetadata {
    pub(crate) fn from_raw(handle: *mut BNFileMetadata) -> Self {
        Self { handle }
    }

    pub(crate) fn ref_from_raw(handle: *mut BNFileMetadata) -> Ref<Self> {
        unsafe { Ref::new(Self { handle }) }
    }

    pub fn new() -> Ref<Self> {
        Self::ref_from_raw(unsafe { BNCreateFileMetadata() })
    }

    pub fn with_filename(name: &str) -> Ref<Self> {
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
        unsafe { BNFileMetadataGetSessionId(self.handle) }
    }

    pub fn filename(&self) -> String {
        unsafe {
            let raw = BNGetFilename(self.handle);
            BnString::into_string(raw)
        }
    }

    pub fn set_filename(&self, name: &str) {
        let name = name.to_cstr();

        unsafe {
            BNSetFilename(self.handle, name.as_ptr());
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

    pub fn is_database_backed(&self) -> bool {
        self.is_database_backed_for_view_type("")
    }

    pub fn is_database_backed_for_view_type(&self, view_type: &str) -> bool {
        let view_type = view_type.to_cstr();

        unsafe { BNIsBackedByDatabase(self.handle, view_type.as_ref().as_ptr() as *const _) }
    }

    /// Runs a failable function where the failure state will revert any undo actions that occurred
    /// during the time of the function's execution.
    ///
    /// NOTE: This will commit or undo any actions that occurred on **any** thread as this state is not thread local.
    ///
    /// NOTE: This is **NOT** thread safe, if you are holding any locks that might be held by both the main thread
    /// and the thread executing this function, you can deadlock. You should also never call this function
    /// on multiple threads at a time. See the following issues:
    ///  - https://github.com/Vector35/binaryninja-api/issues/6289
    ///  - https://github.com/Vector35/binaryninja-api/issues/6325
    pub fn run_undoable_transaction<F: FnOnce() -> Result<T, E>, T, E>(
        &self,
        func: F,
    ) -> Result<T, E> {
        let undo = self.begin_undo_actions(false);
        let result = func();
        match result {
            Ok(t) => {
                self.commit_undo_actions(&undo);
                Ok(t)
            }
            Err(e) => {
                self.revert_undo_actions(&undo);
                Err(e)
            }
        }
    }

    /// Creates a new undo entry, any undo actions after this will be added to this entry.
    ///
    /// NOTE: This is **NOT** thread safe, if you are holding any locks that might be held by both the main thread
    /// and the thread executing this function, you can deadlock. You should also never call this function
    /// on multiple threads at a time. See the following issues:
    ///  - https://github.com/Vector35/binaryninja-api/issues/6289
    ///  - https://github.com/Vector35/binaryninja-api/issues/6325
    pub fn begin_undo_actions(&self, anonymous_allowed: bool) -> String {
        unsafe { BnString::into_string(BNBeginUndoActions(self.handle, anonymous_allowed)) }
    }

    /// Commits the undo entry with the id to the undo buffer.
    ///
    /// NOTE: This is **NOT** thread safe, if you are holding any locks that might be held by both the main thread
    /// and the thread executing this function, you can deadlock. You should also never call this function
    /// on multiple threads at a time. See the following issues:
    ///  - https://github.com/Vector35/binaryninja-api/issues/6289
    ///  - https://github.com/Vector35/binaryninja-api/issues/6325
    pub fn commit_undo_actions(&self, id: &str) {
        let id = id.to_cstr();
        unsafe {
            BNCommitUndoActions(self.handle, id.as_ref().as_ptr() as *const _);
        }
    }

    /// Reverts the undo actions committed in the undo entry.
    ///
    /// NOTE: This is **NOT** thread safe, if you are holding any locks that might be held by both the main thread
    /// and the thread executing this function, you can deadlock. You should also never call this function
    /// on multiple threads at a time. See the following issues:
    ///  - https://github.com/Vector35/binaryninja-api/issues/6289
    ///  - https://github.com/Vector35/binaryninja-api/issues/6325
    pub fn revert_undo_actions(&self, id: &str) {
        let id = id.to_cstr();
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

    pub fn current_view(&self) -> String {
        unsafe { BnString::into_string(BNGetCurrentView(self.handle)) }
    }

    pub fn current_offset(&self) -> u64 {
        unsafe { BNGetCurrentOffset(self.handle) }
    }

    pub fn navigate_to(&self, view: &str, offset: u64) -> Result<(), ()> {
        let view = view.to_cstr();

        unsafe {
            if BNNavigate(self.handle, view.as_ref().as_ptr() as *const _, offset) {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    pub fn view_of_type(&self, view: &str) -> Option<Ref<BinaryView>> {
        let view = view.to_cstr();

        unsafe {
            let raw_view_ptr = BNGetFileViewOfType(self.handle, view.as_ref().as_ptr() as *const _);
            match raw_view_ptr.is_null() {
                false => Some(BinaryView::ref_from_raw(raw_view_ptr)),
                true => None,
            }
        }
    }

    pub fn view_types(&self) -> Array<BnString> {
        let mut count = 0;
        unsafe {
            let types = BNGetExistingViews(self.handle, &mut count);
            Array::new(types, count, ())
        }
    }

    /// Get the [`ProjectFile`] for the [`FileMetadata`].
    pub fn project_file(&self) -> Option<Ref<ProjectFile>> {
        unsafe {
            let res = NonNull::new(BNGetProjectFile(self.handle))?;
            Some(ProjectFile::ref_from_raw(res))
        }
    }

    pub fn create_database(&self, file_path: impl AsRef<Path>) -> bool {
        // Databases are created with the root view (Raw).
        let Some(raw_view) = self.view_of_type("Raw") else {
            return false;
        };

        let file_path = file_path.as_ref().to_cstr();
        unsafe {
            BNCreateDatabase(
                raw_view.handle,
                file_path.as_ptr() as *mut _,
                ptr::null_mut(),
            )
        }
    }

    // TODO: Pass settings?
    pub fn create_database_with_progress<P: ProgressCallback>(
        &self,
        file_path: impl AsRef<Path>,
        mut progress: P,
    ) -> bool {
        // Databases are created with the root view (Raw).
        let Some(raw_view) = self.view_of_type("Raw") else {
            return false;
        };
        let file_path = file_path.as_ref().to_cstr();
        unsafe {
            BNCreateDatabaseWithProgress(
                raw_view.handle,
                file_path.as_ptr() as *mut _,
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
                ptr::null_mut(),
            )
        }
    }

    pub fn save_auto_snapshot(&self) -> bool {
        // Snapshots are saved with the root view (Raw).
        let Some(raw_view) = self.view_of_type("Raw") else {
            return false;
        };

        unsafe { BNSaveAutoSnapshot(raw_view.handle, ptr::null_mut() as *mut _) }
    }

    pub fn open_database_for_configuration(&self, file: &Path) -> Result<Ref<BinaryView>, ()> {
        let file = file.to_cstr();
        unsafe {
            let bv =
                BNOpenDatabaseForConfiguration(self.handle, file.as_ref().as_ptr() as *const _);

            if bv.is_null() {
                Err(())
            } else {
                Ok(BinaryView::ref_from_raw(bv))
            }
        }
    }

    pub fn open_database(&self, file: &Path) -> Result<Ref<BinaryView>, ()> {
        let file = file.to_cstr();
        let view = unsafe { BNOpenExistingDatabase(self.handle, file.as_ptr()) };

        if view.is_null() {
            Err(())
        } else {
            Ok(unsafe { BinaryView::ref_from_raw(view) })
        }
    }

    pub fn open_database_with_progress<P: ProgressCallback>(
        &self,
        file: &Path,
        mut progress: P,
    ) -> Result<Ref<BinaryView>, ()> {
        let file = file.to_cstr();

        let view = unsafe {
            BNOpenExistingDatabaseWithProgress(
                self.handle,
                file.as_ptr(),
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
            )
        };

        if view.is_null() {
            Err(())
        } else {
            Ok(unsafe { BinaryView::ref_from_raw(view) })
        }
    }

    /// Get the current database
    pub fn database(&self) -> Option<Ref<Database>> {
        let result = unsafe { BNGetFileMetadataDatabase(self.handle) };
        NonNull::new(result).map(|handle| unsafe { Database::ref_from_raw(handle) })
    }
}

impl Debug for FileMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileMetadata")
            .field("filename", &self.filename())
            .field("session_id", &self.session_id())
            .field("modified", &self.modified())
            .field("is_analysis_changed", &self.is_analysis_changed())
            .field("current_view_type", &self.current_view())
            .field("current_offset", &self.current_offset())
            .field("view_types", &self.view_types().to_vec())
            .finish()
    }
}

unsafe impl Send for FileMetadata {}
unsafe impl Sync for FileMetadata {}

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
