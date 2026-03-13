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

//! The [`FileMetadata`] struct provides information about a file and owns its available [`BinaryView`]s.

use crate::binary_view::BinaryView;
use crate::database::Database;
use crate::rc::*;
use crate::string::*;
use binaryninjacore_sys::*;
use binaryninjacore_sys::{BNCreateDatabaseWithProgress, BNOpenExistingDatabaseWithProgress};
use std::ffi::c_void;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::project::file::ProjectFile;
use std::ptr::NonNull;

#[allow(unused_imports)]
use crate::custom_binary_view::BinaryViewType;

new_id_type!(SessionId, usize);

pub type SaveOption = BNSaveOption;

/// Settings to alter the behavior of creating snapshots saved within a [`Database`].
pub struct SaveSettings {
    pub(crate) handle: *mut BNSaveSettings,
}

impl SaveSettings {
    pub fn new() -> Ref<Self> {
        Self::ref_from_raw(unsafe { BNCreateSaveSettings() })
    }

    fn ref_from_raw(handle: *mut BNSaveSettings) -> Ref<Self> {
        unsafe { Ref::new(Self { handle }) }
    }

    /// Sets the specified `option` to `true` and returns a ref counted `SaveSettings` that can
    /// continued to be chained.
    pub fn with_option(&self, option: SaveOption) -> Ref<Self> {
        self.set_option(option, true);
        self.to_owned()
    }

    pub fn set_option(&self, option: SaveOption, value: bool) {
        unsafe { BNSetSaveSettingsOption(self.handle, option, value) }
    }

    pub fn option(&self, option: SaveOption) -> bool {
        unsafe { BNIsSaveSettingsOptionSet(self.handle, option) }
    }

    /// When saving an automatic snapshot via [`FileMetadata::save_auto_snapshot`] this name will be
    /// used for the newly written snapshot.
    pub fn snapshot_name(&self) -> String {
        unsafe { BnString::into_string(BNGetSaveSettingsName(self.handle)) }
    }

    pub fn set_snapshot_name(&self, name: &str) {
        let name = name.to_cstr();
        unsafe { BNSetSaveSettingsName(self.handle, name.as_ptr()) }
    }
}

unsafe impl Send for SaveSettings {}
unsafe impl Sync for SaveSettings {}

impl ToOwned for SaveSettings {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for SaveSettings {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSaveSettingsReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSaveSettings(handle.handle);
    }
}

/// File metadata provides information about a file in the context of Binary Ninja. It contains no
/// analysis information, only information useful for identifying a file, such as the [`FileMetadata::file_path`].
///
/// Another responsibility of the [`FileMetadata`] is to own the available [`BinaryView`]s for the
/// file, such as the "Raw" view and any other views that may be created for the file.
///
/// **Important**: Because [`FileMetadata`] holds a strong reference to the [`BinaryView`]s and those
/// views hold a strong reference to the file metadata, to end the cyclic reference a call to the
/// [`FileMetadata::close`] is required.
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

    /// Create an empty [`FileMetadata`] with no associated file path.
    ///
    /// Unless you are creating an ephemeral file with no backing, prefer [`FileMetadata::with_file_path`].
    pub fn new() -> Ref<Self> {
        Self::ref_from_raw(unsafe { BNCreateFileMetadata() })
    }

    /// Build a [`FileMetadata`] with the given `path`.
    pub fn with_file_path(path: &Path) -> Ref<Self> {
        let ret = FileMetadata::new();
        ret.set_file_path(path);
        ret
    }

    /// Closes the [`FileMetadata`] allowing any [`BinaryView`] parented to it to be freed.
    pub fn close(&self) {
        unsafe {
            BNCloseFile(self.handle);
        }
    }

    /// An id unique to this [`FileMetadata`], mostly used for associating logs with a specific file.
    pub fn session_id(&self) -> SessionId {
        let raw = unsafe { BNFileMetadataGetSessionId(self.handle) };
        SessionId(raw)
    }

    /// The path to the [`FileMetadata`] on disk.
    ///
    /// This will not point to the original file on disk, in the event that the file was saved
    /// as a BNDB. When a BNDB is opened, the FileMetadata will contain the file path to the database.
    ///
    /// If you need the original binary file path, use [`FileMetadata::original_file_path`] instead.
    ///
    /// If you just want a name to present to the user, use [`FileMetadata::display_name`].
    pub fn file_path(&self) -> PathBuf {
        unsafe {
            let raw = BNGetFilename(self.handle);
            PathBuf::from(BnString::into_string(raw))
        }
    }

    // TODO: To prevent issues we will not allow users to set the file path as it really should be
    // TODO: derived at construction and not modified later.
    /// Set the files path on disk.
    ///
    /// This should always be a valid path.
    pub(crate) fn set_file_path(&self, name: &Path) {
        let name = name.to_cstr();
        unsafe {
            BNSetFilename(self.handle, name.as_ptr());
        }
    }

    /// The display name of the file. Useful for presenting to the user. Can differ from the original
    /// name of the file and can be overridden with [`FileMetadata::set_display_name`].
    pub fn display_name(&self) -> String {
        let raw_name = unsafe {
            let raw = BNGetDisplayName(self.handle);
            BnString::into_string(raw)
        };
        // Sometimes this display name may return a full path, which is not the intended purpose.
        raw_name
            .split('/')
            .next_back()
            .unwrap_or(&raw_name)
            .to_string()
    }

    /// Set the display name of the file.
    ///
    /// This can be anything and will not be used for any purpose other than presentation.
    pub fn set_display_name(&self, name: &str) {
        let name = name.to_cstr();
        unsafe {
            BNSetDisplayName(self.handle, name.as_ptr());
        }
    }

    /// The path to the original file on disk, if any.
    ///
    /// It may not be present if the BNDB was saved without it or cleared via [`FileMetadata::clear_original_file_path`].
    ///
    /// If this [`FileMetadata`] is a database within a project, it may not have a "consumable" original
    /// file path. Instead, this might return the path to the on disk file path of the project file that
    /// this database was created from, for projects you should query through [`FileMetadata::project_file`].
    ///
    /// Only prefer this over [`FileMetadata::file_path`] if you require the original binary location.
    pub fn original_file_path(&self) -> Option<PathBuf> {
        let raw_name = unsafe {
            let raw = BNGetOriginalFilename(self.handle);
            PathBuf::from(BnString::into_string(raw))
        };
        // If the original file path is empty, or the original file path is pointing to the same file
        // as the database itself, we know the original file path does not exist.
        if raw_name.as_os_str().is_empty()
            || self.is_database_backed() && raw_name == self.file_path()
        {
            None
        } else {
            Some(raw_name)
        }
    }

    /// Set the original file path inside the database. Useful if it has since been cleared from the
    /// database, or you have moved the original file.
    pub fn set_original_file_path(&self, path: &Path) {
        let name = path.to_cstr();
        unsafe {
            BNSetOriginalFilename(self.handle, name.as_ptr());
        }
    }

    /// Clear the original file path inside the database. This is useful since the original file path
    /// may be sensitive information you wish to not share with others.
    pub fn clear_original_file_path(&self) {
        unsafe {
            BNSetOriginalFilename(self.handle, std::ptr::null());
        }
    }

    /// The non-filesystem path that describes how this file was derived from the container
    /// transform system, detailing the sequence of transform steps and selection names.
    ///
    /// NOTE: Returns `None` if this [`FileMetadata`] was not processed by the transform system and
    /// does not differ from that of the "physical" file path reported by [`FileMetadata::file_path`].
    pub fn virtual_path(&self) -> Option<String> {
        unsafe {
            let raw = BNGetVirtualPath(self.handle);
            let path = BnString::into_string(raw);
            // For whatever reason the core may report there being a virtual path as the file path.
            // In the case where that occurs, we wish not to report there being one to the user.
            match path.is_empty() || path == self.file_path() {
                true => None,
                false => Some(path),
            }
        }
    }

    /// Sets the non-filesystem path that describes how this file was derived from the container
    /// transform system.
    pub fn set_virtual_path(&self, path: &str) {
        let path = path.to_cstr();
        unsafe {
            BNSetVirtualPath(self.handle, path.as_ptr());
        }
    }

    /// Whether the file is currently flagged as modified.
    ///
    /// When this returns `true`, the UI will prompt to save the database on close, as well as display
    /// a dot in the files tab.
    pub fn is_modified(&self) -> bool {
        unsafe { BNIsFileModified(self.handle) }
    }

    /// Marks the file as modified such that we can prompt to save the database on close.
    pub fn mark_modified(&self) {
        unsafe {
            BNMarkFileModified(self.handle);
        }
    }

    /// Marks the file as saved such that [`FileMetadata::is_modified`] and [`FileMetadata::is_analysis_changed`]
    /// will return `false` and the undo buffer associated with this [`FileMetadata`] will be updated.
    pub fn mark_saved(&self) {
        unsafe {
            BNMarkFileSaved(self.handle);
        }
    }

    pub fn is_analysis_changed(&self) -> bool {
        unsafe { BNIsAnalysisChanged(self.handle) }
    }

    /// Checks to see if the database exists for the file.
    pub fn is_database_backed(&self) -> bool {
        // TODO: This seems to be a useless function. Replace with a call to file.database().is_some()?
        self.is_database_backed_for_view_type("")
    }

    /// Checks to see if the file metadata has a [`Database`], and then checks to see if the `view_type`
    /// is available.
    ///
    /// NOTE: Passing an empty string will simply check if the database exists.
    pub fn is_database_backed_for_view_type(&self, view_type: &str) -> bool {
        let view_type = view_type.to_cstr();
        // TODO: This seems to be a useless function. Replace with a call to file.database().is_some()?
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
    ///  - <https://github.com/Vector35/binaryninja-api/issues/6289>
    ///  - <https://github.com/Vector35/binaryninja-api/issues/6325>
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
    ///  - <https://github.com/Vector35/binaryninja-api/issues/6289>
    ///  - <https://github.com/Vector35/binaryninja-api/issues/6325>
    pub fn begin_undo_actions(&self, anonymous_allowed: bool) -> String {
        unsafe { BnString::into_string(BNBeginUndoActions(self.handle, anonymous_allowed)) }
    }

    /// Commits the undo entry with the id to the undo buffer.
    ///
    /// NOTE: This is **NOT** thread safe, if you are holding any locks that might be held by both the main thread
    /// and the thread executing this function, you can deadlock. You should also never call this function
    /// on multiple threads at a time. See the following issues:
    ///  - <https://github.com/Vector35/binaryninja-api/issues/6289>
    ///  - <https://github.com/Vector35/binaryninja-api/issues/6325>
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
    ///  - <https://github.com/Vector35/binaryninja-api/issues/6289>
    ///  - <https://github.com/Vector35/binaryninja-api/issues/6325>
    pub fn revert_undo_actions(&self, id: &str) {
        let id = id.to_cstr();
        unsafe {
            BNRevertUndoActions(self.handle, id.as_ref().as_ptr() as *const _);
        }
    }

    /// Forgets the undo actions committed in the undo entry.
    ///
    /// NOTE: This is **NOT** thread safe, if you are holding any locks that might be held by both the main thread
    /// and the thread executing this function, you can deadlock. You should also never call this function
    /// on multiple threads at a time. See the following issues:
    ///  - <https://github.com/Vector35/binaryninja-api/issues/6289>
    ///  - <https://github.com/Vector35/binaryninja-api/issues/6325>
    pub fn forget_undo_actions(&self, id: &str) {
        let id = id.to_cstr();
        unsafe {
            BNForgetUndoActions(self.handle, id.as_ref().as_ptr() as *const _);
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

    /// Retrieve the raw view for the file, this should always be present.
    ///
    /// The "Raw" view is a special [`BinaryView`] that holds data required for updating and creating
    /// [`Database`]s such as the view and load settings.
    pub fn raw_view(&self) -> Ref<BinaryView> {
        self.view_of_type("Raw")
            .expect("Raw view should always be present")
    }

    /// The current view for the file.
    ///
    /// For example, opening a PE file and navigating to the linear view will return "Linear:PE".
    pub fn current_view(&self) -> String {
        unsafe { BnString::into_string(BNGetCurrentView(self.handle)) }
    }

    /// The current offset navigated to within the [`FileMetadata::current_view`].
    pub fn current_offset(&self) -> u64 {
        unsafe { BNGetCurrentOffset(self.handle) }
    }

    /// Navigate to an offset for a specific view.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use binaryninja::file_metadata::FileMetadata;
    /// # let file: FileMetadata = unimplemented!();
    /// file.navigate_to("Linear:Raw", 0x0).expect("Linear:Raw should always be present");
    /// ```
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

    /// Get the [`BinaryView`] for the view type.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use binaryninja::file_metadata::FileMetadata;
    /// # let file: FileMetadata = unimplemented!();
    /// file.view_of_type("Raw").expect("Raw type should always be present");
    /// ```
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

    /// The [`BinaryViewType`]s associated with this file.
    ///
    /// For example, opening a PE binary will have the following: "Raw", "PE".
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

    /// Create a database for the file and its views at `file_path`.
    ///
    /// NOTE: Calling this while analysis is running will flag the next load of the database to
    /// regenerate the current analysis.
    pub fn create_database(&self, file_path: impl AsRef<Path>, settings: &SaveSettings) -> bool {
        self.create_database_with_progress(file_path, settings, NoProgressCallback)
    }

    /// Create a database for the file and its views at `file_path`, with a progress callback.
    ///
    /// NOTE: Calling this while analysis is running will flag the next load of the database to
    /// regenerate the current analysis.
    pub fn create_database_with_progress<P: ProgressCallback>(
        &self,
        file_path: impl AsRef<Path>,
        settings: &SaveSettings,
        mut progress: P,
    ) -> bool {
        // Databases are created with the root view (Raw).
        let raw_view = self.raw_view();
        let file_path = file_path.as_ref().to_cstr();
        unsafe {
            BNCreateDatabaseWithProgress(
                raw_view.handle,
                file_path.as_ptr() as *mut _,
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
                settings.handle,
            )
        }
    }

    /// Save a new snapshot of the current file.
    ///
    /// NOTE: Calling this while analysis is running will flag the next load of the database to
    /// regenerate the current analysis.
    pub fn save_auto_snapshot(&self) -> bool {
        // Snapshots are saved with the root view (Raw).
        let raw_view = self.raw_view();
        unsafe { BNSaveAutoSnapshot(raw_view.handle, std::ptr::null_mut() as *mut _) }
    }

    // TODO: Deprecate this function? Does not seem to do anything different than `open_database`.
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

    // TODO: How this relates to `BNLoadFilename`?
    pub fn open_database(&self, file: &Path) -> Result<Ref<BinaryView>, ()> {
        let file = file.to_cstr();
        let view = unsafe { BNOpenExistingDatabase(self.handle, file.as_ptr()) };

        if view.is_null() {
            Err(())
        } else {
            Ok(unsafe { BinaryView::ref_from_raw(view) })
        }
    }

    // TODO: How this relates to `BNLoadFilename`?
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

    /// Get the database attached to this file.
    ///
    /// Only available if this file is a database, or [`FileMetadata::create_database`] has previously
    /// been called on this file.
    pub fn database(&self) -> Option<Ref<Database>> {
        let result = unsafe { BNGetFileMetadataDatabase(self.handle) };
        NonNull::new(result).map(|handle| unsafe { Database::ref_from_raw(handle) })
    }
}

impl Debug for FileMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileMetadata")
            .field("file_path", &self.file_path())
            .field("display_name", &self.display_name())
            .field("session_id", &self.session_id())
            .field("is_modified", &self.is_modified())
            .field("is_analysis_changed", &self.is_analysis_changed())
            .field("current_view_type", &self.current_view())
            .field("current_offset", &self.current_offset())
            .field("view_types", &self.view_types().to_vec())
            .finish()
    }
}

impl Display for FileMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display_name())
    }
}

impl PartialEq for FileMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.session_id() == other.session_id()
    }
}

impl Eq for FileMetadata {}

impl Hash for FileMetadata {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.session_id().hash(state);
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
