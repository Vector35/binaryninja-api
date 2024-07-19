use core::{ffi, mem, ptr};

use std::time::SystemTime;

use binaryninjacore_sys::*;

use super::{
    databasesync, CollabSnapshot, DatabaseConflictHandler, DatabaseConflictHandlerFail,
    NameChangeset, NameChangesetNop, Remote, RemoteFolder, RemoteProject,
};

use crate::binaryview::{BinaryView, BinaryViewExt};
use crate::database::Database;
use crate::ffi::{ProgressCallback, ProgressCallbackNop, SplitProgressBuilder};
use crate::filemetadata::FileMetadata;
use crate::project::ProjectFile;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{BnStrCompatible, BnString};

pub type RemoteFileType = BNRemoteFileType;

/// Class representing a remote project file. It controls the various
/// snapshots and raw file contents associated with the analysis.
#[repr(transparent)]
pub struct RemoteFile {
    handle: ptr::NonNull<BNRemoteFile>,
}

impl Drop for RemoteFile {
    fn drop(&mut self) {
        unsafe { BNFreeRemoteFile(self.as_raw()) }
    }
}

impl PartialEq for RemoteFile {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for RemoteFile {}

impl Clone for RemoteFile {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewRemoteFileReference(self.as_raw())).unwrap())
        }
    }
}

impl RemoteFile {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNRemoteFile>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNRemoteFile) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNRemoteFile {
        &mut *self.handle.as_ptr()
    }

    /// Look up the remote File for a local database, or None if there is no matching
    /// remote File found.
    /// See [RemoteFile::get_for_binary_view] to load from a [BinaryView].
    pub fn get_for_local_database(database: &Database) -> Result<Option<RemoteFile>, ()> {
        if !databasesync::pull_files(database)? {
            return Ok(None);
        }
        databasesync::get_remote_file_for_local_database(database)
    }

    /// Look up the remote File for a local BinaryView, or None if there is no matching
    /// remote File found.
    pub fn get_for_binary_view(bv: &BinaryView) -> Result<Option<RemoteFile>, ()> {
        let file = bv.file();
        let Some(database) = file.database() else {
            return Ok(None);
        };
        RemoteFile::get_for_local_database(&database)
    }

    pub fn core_file(&self) -> Result<ProjectFile, ()> {
        let result = unsafe { BNRemoteFileGetCoreFile(self.as_raw()) };
        ptr::NonNull::new(result)
            .map(|handle| unsafe { ProjectFile::from_raw(handle) })
            .ok_or(())
    }

    pub fn project(&self) -> Result<RemoteProject, ()> {
        let result = unsafe { BNRemoteFileGetProject(self.as_raw()) };
        ptr::NonNull::new(result)
            .map(|handle| unsafe { RemoteProject::from_raw(handle) })
            .ok_or(())
    }

    pub fn remote(&self) -> Result<Remote, ()> {
        let result = unsafe { BNRemoteFileGetRemote(self.as_raw()) };
        ptr::NonNull::new(result)
            .map(|handle| unsafe { Remote::from_raw(handle) })
            .ok_or(())
    }

    /// Parent folder, if one exists. None if this is in the root of the project.
    pub fn folder(&self) -> Result<Option<RemoteFolder>, ()> {
        let project = self.project()?;
        if !project.has_pulled_folders() {
            project.pull_folders(ProgressCallbackNop)?;
        }
        let result = unsafe { BNRemoteFileGetFolder(self.as_raw()) };
        Ok(ptr::NonNull::new(result).map(|handle| unsafe { RemoteFolder::from_raw(handle) }))
    }

    /// Set the parent folder of a file.
    pub fn set_folder(&self, folder: Option<&RemoteFolder>) -> Result<(), ()> {
        let folder_raw = folder.map_or(ptr::null_mut(), |folder| unsafe { folder.as_raw() }
            as *mut _);
        let success = unsafe { BNRemoteFileSetFolder(self.as_raw(), folder_raw) };
        success.then_some(()).ok_or(())
    }

    pub fn set_metadata<S: BnStrCompatible>(&self, folder: S) -> Result<(), ()> {
        let folder_raw = folder.into_bytes_with_nul();
        let success = unsafe {
            BNRemoteFileSetMetadata(
                self.as_raw(),
                folder_raw.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Web API endpoint URL
    pub fn url(&self) -> BnString {
        let result = unsafe { BNRemoteFileGetUrl(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Chat log API endpoint URL
    pub fn chat_log_url(&self) -> BnString {
        let result = unsafe { BNRemoteFileGetChatLogUrl(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn user_positions_url(&self) -> BnString {
        let result = unsafe { BNRemoteFileGetUserPositionsUrl(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Unique ID
    pub fn id(&self) -> BnString {
        let result = unsafe { BNRemoteFileGetId(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// All files share the same properties, but files with different types may make different
    /// uses of those properties, or not use some of them at all.
    pub fn file_type(&self) -> RemoteFileType {
        unsafe { BNRemoteFileGetType(self.as_raw()) }
    }

    /// Created date of the file
    pub fn created(&self) -> SystemTime {
        let result = unsafe { BNRemoteFileGetCreated(self.as_raw()) };
        crate::ffi::time_from_bn(result.try_into().unwrap())
    }

    pub fn created_by(&self) -> BnString {
        let result = unsafe { BNRemoteFileGetCreatedBy(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Last modified of the file
    pub fn last_modified(&self) -> SystemTime {
        let result = unsafe { BNRemoteFileGetLastModified(self.as_raw()) };
        crate::ffi::time_from_bn(result.try_into().unwrap())
    }

    /// Date of last snapshot in the file
    pub fn last_snapshot(&self) -> SystemTime {
        let result = unsafe { BNRemoteFileGetLastSnapshot(self.as_raw()) };
        crate::ffi::time_from_bn(result.try_into().unwrap())
    }

    /// Username of user who pushed the last snapshot in the file
    pub fn last_snapshot_by(&self) -> BnString {
        let result = unsafe { BNRemoteFileGetLastSnapshotBy(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn last_snapshot_name(&self) -> BnString {
        let result = unsafe { BNRemoteFileGetLastSnapshotName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Hash of file contents (no algorithm guaranteed)
    pub fn hash(&self) -> BnString {
        let result = unsafe { BNRemoteFileGetHash(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Displayed name of file
    pub fn name(&self) -> BnString {
        let result = unsafe { BNRemoteFileGetName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Set the description of the file. You will need to push the file to update the remote version.
    pub fn set_name<S: BnStrCompatible>(&self, name: S) -> Result<(), ()> {
        let name = name.into_bytes_with_nul();
        let success = unsafe {
            BNRemoteFileSetName(self.as_raw(), name.as_ref().as_ptr() as *const ffi::c_char)
        };
        success.then_some(()).ok_or(())
    }

    /// Desciprtion of the file
    pub fn description(&self) -> BnString {
        let result = unsafe { BNRemoteFileGetDescription(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Set the description of the file. You will need to push the file to update the remote version.
    pub fn set_description<S: BnStrCompatible>(&self, description: S) -> Result<(), ()> {
        let description = description.into_bytes_with_nul();
        let success = unsafe {
            BNRemoteFileSetDescription(
                self.as_raw(),
                description.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        success.then_some(()).ok_or(())
    }

    pub fn metadata(&self) -> BnString {
        let result = unsafe { BNRemoteFileGetMetadata(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Size of raw content of file, in bytes
    pub fn size(&self) -> u64 {
        unsafe { BNRemoteFileGetSize(self.as_raw()) }
    }

    /// Get the default filepath for a remote File. This is based off the Setting for
    /// collaboration.directory, the file's id, the file's project's id, and the file's
    /// remote's id.
    pub fn default_path(&self) -> BnString {
        let result = unsafe { BNCollaborationDefaultFilePath(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// If the file has pulled the snapshots yet
    pub fn has_pulled_snapshots(&self) -> bool {
        unsafe { BNRemoteFileHasPulledSnapshots(self.as_raw()) }
    }

    /// Get the list of snapshots in this file.
    ///
    /// NOTE: If snapshots have not been pulled, they will be pulled upon calling this.
    pub fn snapshots(&self) -> Result<Array<CollabSnapshot>, ()> {
        if !self.has_pulled_snapshots() {
            self.pull_snapshots(ProgressCallbackNop)?;
        }
        let mut count = 0;
        let result = unsafe { BNRemoteFileGetSnapshots(self.as_raw(), &mut count) };
        (!result.is_null())
            .then(|| unsafe { Array::new(result, count, ()) })
            .ok_or(())
    }

    /// Get a specific Snapshot in the File by its id
    ///
    /// NOTE: If snapshots have not been pulled, they will be pulled upon calling this.
    pub fn snapshot_by_id<S: BnStrCompatible>(&self, id: S) -> Result<Option<CollabSnapshot>, ()> {
        if !self.has_pulled_snapshots() {
            self.pull_snapshots(ProgressCallbackNop)?;
        }
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNRemoteFileGetSnapshotById(self.as_raw(), id.as_ref().as_ptr() as *const ffi::c_char)
        };
        Ok(ptr::NonNull::new(result).map(|handle| unsafe { CollabSnapshot::from_raw(handle) }))
    }

    /// Pull the list of Snapshots from the Remote.
    pub fn pull_snapshots<P: ProgressCallback>(&self, mut progress: P) -> Result<(), ()> {
        let success = unsafe {
            BNRemoteFilePullSnapshots(
                self.as_raw(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut ffi::c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Create a new snapshot on the remote (and pull it)
    ///
    /// * `name` - Snapshot name
    /// * `contents` - Snapshot contents
    /// * `analysis_cache_contents` - Contents of analysis cache of snapshot
    /// * `file` - New file contents (if contents changed)
    /// * `parent_ids` - List of ids of parent snapshots (or empty if this is a root snapshot)
    /// * `progress` - Function to call on progress updates
    pub fn create_snapshot<S, I, P>(
        &self,
        name: S,
        contents: &mut [u8],
        analysis_cache_contexts: &mut [u8],
        file: &mut [u8],
        parent_ids: I,
        mut progress: P,
    ) -> Result<CollabSnapshot, ()>
    where
        S: BnStrCompatible,
        P: ProgressCallback,
        I: IntoIterator,
        I::Item: BnStrCompatible,
    {
        let name = name.into_bytes_with_nul();
        let parent_ids: Vec<_> = parent_ids
            .into_iter()
            .map(|id| id.into_bytes_with_nul())
            .collect();
        let mut parent_ids_raw: Vec<_> = parent_ids
            .iter()
            .map(|x| x.as_ref().as_ptr() as *const ffi::c_char)
            .collect();
        let result = unsafe {
            BNRemoteFileCreateSnapshot(
                self.as_raw(),
                name.as_ref().as_ptr() as *const ffi::c_char,
                contents.as_mut_ptr(),
                contents.len(),
                analysis_cache_contexts.as_mut_ptr(),
                analysis_cache_contexts.len(),
                file.as_mut_ptr(),
                file.len(),
                parent_ids_raw.as_mut_ptr(),
                parent_ids_raw.len(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut ffi::c_void,
            )
        };
        let handle = ptr::NonNull::new(result).ok_or(())?;
        Ok(unsafe { CollabSnapshot::from_raw(handle) })
    }

    // Delete a snapshot from the remote
    pub fn delete_snapshot(&self, snapshot: &CollabSnapshot) -> Result<(), ()> {
        let success = unsafe { BNRemoteFileDeleteSnapshot(self.as_raw(), snapshot.as_raw()) };
        success.then_some(()).ok_or(())
    }

    // TODO - This passes and returns a c++ `std::vector<T>`. A BnData can be implement in rust, but the
    // coreAPI need to include a `FreeData` function, similar to `BNFreeString` does.
    // The C++ API just assumes that both use the same allocator, and the python API seems to just leak this
    // memory, never droping it.
    //pub fn download_file<S, F>(&self, mut progress_function: F) -> BnData
    //where
    //    S: BnStrCompatible,
    //    F: ProgressCallback,
    //{
    //    let mut data = ptr::null_mut();
    //    let mut data_len = 0;
    //    let result = unsafe {
    //        BNRemoteFileDownload(
    //            self.as_raw(),
    //            Some(F::cb_progress_callback),
    //            &mut progress_function as *mut _ as *mut ffi::c_void,
    //            &mut data,
    //            &mut data_len,
    //        )
    //    };
    //    todo!()
    //}

    pub fn request_user_positions(&self) -> BnString {
        let result = unsafe { BNRemoteFileRequestUserPositions(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn request_chat_log(&self) -> BnString {
        let result = unsafe { BNRemoteFileRequestChatLog(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Download a file from its remote, saving all snapshots to a database in the
    /// specified location. Returns a FileContext for opening the file later.
    ///
    /// * `db_path` - File path for saved database
    /// * `progress_function` - Function to call for progress updates
    pub fn download<S, F>(&self, db_path: S, mut progress_function: F) -> Ref<FileMetadata>
    where
        S: BnStrCompatible,
        F: ProgressCallback,
    {
        let db_path = db_path.into_bytes_with_nul();
        let result = unsafe {
            BNCollaborationDownloadFile(
                self.as_raw(),
                db_path.as_ref().as_ptr() as *const ffi::c_char,
                Some(F::cb_progress_callback),
                &mut progress_function as *mut _ as *mut ffi::c_void,
            )
        };
        assert!(!result.is_null());
        unsafe { Ref::new(FileMetadata::from_raw(result)) }
    }

    pub fn download_data_for_file<S, F>(
        &self,
        db_path: S,
        force: bool,
        mut progress_function: F,
    ) -> Result<(), ()>
    where
        S: BnStrCompatible,
        F: ProgressCallback,
    {
        let db_path = db_path.into_bytes_with_nul();
        let success = unsafe {
            BNCollaborationDownloadDatabaseForFile(
                self.as_raw(),
                db_path.as_ref().as_ptr() as *const ffi::c_char,
                force,
                Some(F::cb_progress_callback),
                &mut progress_function as *mut _ as *mut ffi::c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Download a remote file and save it to a bndb at the given path.
    /// This calls databasesync.download_file and self.sync to fully prepare the bndb.
    pub fn download_to_bndb<S: BnStrCompatible, P: ProgressCallback>(
        &self,
        path: Option<S>,
        progress: P,
    ) -> Result<Ref<FileMetadata>, ()> {
        let path = path
            .map(|x| BnString::new(x))
            .unwrap_or_else(|| self.default_path());
        let mut progress = progress.split(&[50, 50]);
        let file = databasesync::download_file(self, path, progress.next_subpart().unwrap())?;
        let database = file.database().ok_or(())?;
        self.sync(
            &database,
            DatabaseConflictHandlerFail,
            progress.next_subpart().unwrap(),
            NameChangesetNop,
        )?;
        Ok(file)
    }

    /// Completely sync a file, pushing/pulling/merging/applying changes
    ///
    /// * `bv_or_db` - Binary view or database to sync with
    /// * `conflict_handler` - Function to call to resolve snapshot conflicts
    /// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
    /// * `progress` - Function to call for progress updates
    pub fn sync<C: DatabaseConflictHandler, P: ProgressCallback, N: NameChangeset>(
        &self,
        database: &Database,
        conflict_handler: C,
        progress: P,
        name_changeset: N,
    ) -> Result<(), ()> {
        databasesync::sync_database(database, self, conflict_handler, progress, name_changeset)
    }

    /// Pull updated snapshots from the remote. Merge local changes with remote changes and
    /// potentially create a new snapshot for unsaved changes, named via name_changeset.
    ///
    /// * `bv_or_db` - Binary view or database to sync with
    /// * `conflict_handler` - Function to call to resolve snapshot conflicts
    /// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
    /// * `progress` - Function to call for progress updates
    pub fn pull<C, P, N>(
        &self,
        database: &Database,
        conflict_handler: C,
        progress: P,
        name_changeset: N,
    ) -> Result<usize, ()>
    where
        C: DatabaseConflictHandler,
        P: ProgressCallback,
        N: NameChangeset,
    {
        databasesync::pull_database(database, self, conflict_handler, progress, name_changeset)
    }

    /// Push locally added snapshots to the remote
    ///
    /// * `bv_or_db` - Binary view or database to sync with
    /// * `progress` - Function to call for progress updates
    pub fn push<P>(&self, database: &Database, progress: P) -> Result<usize, ()>
    where
        P: ProgressCallback,
    {
        databasesync::push_database(database, self, progress)
    }
}

impl CoreArrayProvider for RemoteFile {
    type Raw = *mut BNRemoteFile;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for RemoteFile {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeRemoteFileList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}
