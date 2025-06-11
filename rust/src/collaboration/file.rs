use std::ffi::c_void;
use std::fmt::{Debug, Formatter};
use std::path::Path;
use std::ptr::NonNull;
use std::time::SystemTime;

use binaryninjacore_sys::*;

use super::{
    sync, DatabaseConflictHandler, DatabaseConflictHandlerFail, NameChangeset, NoNameChangeset,
    Remote, RemoteFolder, RemoteProject, RemoteSnapshot,
};

use crate::binary_view::{BinaryView, BinaryViewExt};
use crate::database::Database;
use crate::file_metadata::FileMetadata;
use crate::progress::{NoProgressCallback, ProgressCallback, SplitProgressBuilder};
use crate::project::file::ProjectFile;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnString, IntoCStr};

pub type RemoteFileType = BNRemoteFileType;

/// A remote project file. It controls the various snapshots and raw file contents associated with the analysis.
#[repr(transparent)]
pub struct RemoteFile {
    pub(crate) handle: NonNull<BNRemoteFile>,
}

impl RemoteFile {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNRemoteFile>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNRemoteFile>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Look up the remote File for a local database, or None if there is no matching
    /// remote File found.
    /// See [RemoteFile::get_for_binary_view] to load from a [BinaryView].
    pub fn get_for_local_database(database: &Database) -> Result<Option<Ref<RemoteFile>>, ()> {
        // TODO: This sync should be removed?
        if !sync::pull_files(database)? {
            return Ok(None);
        }
        sync::get_remote_file_for_local_database(database)
    }

    /// Look up the [`RemoteFile`] for a local [`BinaryView`], or None if there is no matching
    /// remote File found.
    pub fn get_for_binary_view(bv: &BinaryView) -> Result<Option<Ref<RemoteFile>>, ()> {
        let file = bv.file();
        let Some(database) = file.database() else {
            return Ok(None);
        };
        RemoteFile::get_for_local_database(&database)
    }

    pub fn core_file(&self) -> Result<ProjectFile, ()> {
        let result = unsafe { BNRemoteFileGetCoreFile(self.handle.as_ptr()) };
        NonNull::new(result)
            .map(|handle| unsafe { ProjectFile::from_raw(handle) })
            .ok_or(())
    }

    pub fn project(&self) -> Result<Ref<RemoteProject>, ()> {
        let result = unsafe { BNRemoteFileGetProject(self.handle.as_ptr()) };
        NonNull::new(result)
            .map(|handle| unsafe { RemoteProject::ref_from_raw(handle) })
            .ok_or(())
    }

    pub fn remote(&self) -> Result<Ref<Remote>, ()> {
        let result = unsafe { BNRemoteFileGetRemote(self.handle.as_ptr()) };
        NonNull::new(result)
            .map(|handle| unsafe { Remote::ref_from_raw(handle) })
            .ok_or(())
    }

    /// Parent folder, if one exists. None if this is in the root of the project.
    pub fn folder(&self) -> Result<Option<Ref<RemoteFolder>>, ()> {
        let project = self.project()?;
        if !project.has_pulled_folders() {
            project.pull_folders()?;
        }
        let result = unsafe { BNRemoteFileGetFolder(self.handle.as_ptr()) };
        Ok(NonNull::new(result).map(|handle| unsafe { RemoteFolder::ref_from_raw(handle) }))
    }

    /// Set the parent folder of a file.
    pub fn set_folder(&self, folder: Option<&RemoteFolder>) -> Result<(), ()> {
        let folder_raw = folder.map_or(std::ptr::null_mut(), |f| f.handle.as_ptr());
        let success = unsafe { BNRemoteFileSetFolder(self.handle.as_ptr(), folder_raw) };
        success.then_some(()).ok_or(())
    }

    pub fn set_metadata(&self, folder: &str) -> Result<(), ()> {
        let folder_raw = folder.to_cstr();
        let success = unsafe { BNRemoteFileSetMetadata(self.handle.as_ptr(), folder_raw.as_ptr()) };
        success.then_some(()).ok_or(())
    }

    /// Web API endpoint URL
    pub fn url(&self) -> String {
        let result = unsafe { BNRemoteFileGetUrl(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Chat log API endpoint URL
    pub fn chat_log_url(&self) -> String {
        let result = unsafe { BNRemoteFileGetChatLogUrl(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    pub fn user_positions_url(&self) -> String {
        let result = unsafe { BNRemoteFileGetUserPositionsUrl(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Unique ID
    pub fn id(&self) -> String {
        let result = unsafe { BNRemoteFileGetId(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// All files share the same properties, but files with different types may make different
    /// uses of those properties, or not use some of them at all.
    pub fn file_type(&self) -> RemoteFileType {
        unsafe { BNRemoteFileGetType(self.handle.as_ptr()) }
    }

    /// Created date of the file
    pub fn created(&self) -> SystemTime {
        let result = unsafe { BNRemoteFileGetCreated(self.handle.as_ptr()) };
        crate::ffi::time_from_bn(result.try_into().unwrap())
    }

    pub fn created_by(&self) -> String {
        let result = unsafe { BNRemoteFileGetCreatedBy(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Last modified of the file
    pub fn last_modified(&self) -> SystemTime {
        let result = unsafe { BNRemoteFileGetLastModified(self.handle.as_ptr()) };
        crate::ffi::time_from_bn(result.try_into().unwrap())
    }

    /// Date of last snapshot in the file
    pub fn last_snapshot(&self) -> SystemTime {
        let result = unsafe { BNRemoteFileGetLastSnapshot(self.handle.as_ptr()) };
        crate::ffi::time_from_bn(result.try_into().unwrap())
    }

    /// Username of user who pushed the last snapshot in the file
    pub fn last_snapshot_by(&self) -> String {
        let result = unsafe { BNRemoteFileGetLastSnapshotBy(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    pub fn last_snapshot_name(&self) -> String {
        let result = unsafe { BNRemoteFileGetLastSnapshotName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Hash of file contents (no algorithm guaranteed)
    pub fn hash(&self) -> String {
        let result = unsafe { BNRemoteFileGetHash(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Displayed name of file
    pub fn name(&self) -> String {
        let result = unsafe { BNRemoteFileGetName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Set the description of the file. You will need to push the file to update the remote version.
    pub fn set_name(&self, name: &str) -> Result<(), ()> {
        let name = name.to_cstr();
        let success = unsafe { BNRemoteFileSetName(self.handle.as_ptr(), name.as_ptr()) };
        success.then_some(()).ok_or(())
    }

    /// Desciprtion of the file
    pub fn description(&self) -> String {
        let result = unsafe { BNRemoteFileGetDescription(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Set the description of the file. You will need to push the file to update the remote version.
    pub fn set_description(&self, description: &str) -> Result<(), ()> {
        let description = description.to_cstr();
        let success =
            unsafe { BNRemoteFileSetDescription(self.handle.as_ptr(), description.as_ptr()) };
        success.then_some(()).ok_or(())
    }

    pub fn metadata(&self) -> String {
        let result = unsafe { BNRemoteFileGetMetadata(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Size of raw content of file, in bytes
    pub fn size(&self) -> u64 {
        unsafe { BNRemoteFileGetSize(self.handle.as_ptr()) }
    }

    /// Get the default filepath for a remote File. This is based off the Setting for
    /// collaboration.directory, the file's id, the file's project's id, and the file's
    /// remote's id.
    pub fn default_path(&self) -> String {
        let result = unsafe { BNCollaborationDefaultFilePath(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// If the file has pulled the snapshots yet
    pub fn has_pulled_snapshots(&self) -> bool {
        unsafe { BNRemoteFileHasPulledSnapshots(self.handle.as_ptr()) }
    }

    /// Get the list of snapshots in this file.
    ///
    /// NOTE: If snapshots have not been pulled, they will be pulled upon calling this.
    pub fn snapshots(&self) -> Result<Array<RemoteSnapshot>, ()> {
        // TODO: This sync should be removed?
        if !self.has_pulled_snapshots() {
            self.pull_snapshots()?;
        }
        let mut count = 0;
        let result = unsafe { BNRemoteFileGetSnapshots(self.handle.as_ptr(), &mut count) };
        (!result.is_null())
            .then(|| unsafe { Array::new(result, count, ()) })
            .ok_or(())
    }

    /// Get a specific Snapshot in the File by its id
    ///
    /// NOTE: If snapshots have not been pulled, they will be pulled upon calling this.
    pub fn snapshot_by_id(&self, id: &str) -> Result<Option<Ref<RemoteSnapshot>>, ()> {
        // TODO: This sync should be removed?
        if !self.has_pulled_snapshots() {
            self.pull_snapshots()?;
        }
        let id = id.to_cstr();
        let result = unsafe { BNRemoteFileGetSnapshotById(self.handle.as_ptr(), id.as_ptr()) };
        Ok(NonNull::new(result).map(|handle| unsafe { RemoteSnapshot::ref_from_raw(handle) }))
    }

    /// Pull the list of Snapshots from the Remote.
    pub fn pull_snapshots(&self) -> Result<(), ()> {
        self.pull_snapshots_with_progress(NoProgressCallback)
    }

    /// Pull the list of Snapshots from the Remote.
    pub fn pull_snapshots_with_progress<P: ProgressCallback>(
        &self,
        mut progress: P,
    ) -> Result<(), ()> {
        let success = unsafe {
            BNRemoteFilePullSnapshots(
                self.handle.as_ptr(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
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
    pub fn create_snapshot<I>(
        &self,
        name: &str,
        contents: &mut [u8],
        analysis_cache_contexts: &mut [u8],
        file: &mut [u8],
        parent_ids: I,
    ) -> Result<Ref<RemoteSnapshot>, ()>
    where
        I: IntoIterator<Item = String>,
    {
        self.create_snapshot_with_progress(
            name,
            contents,
            analysis_cache_contexts,
            file,
            parent_ids,
            NoProgressCallback,
        )
    }

    /// Create a new snapshot on the remote (and pull it)
    ///
    /// * `name` - Snapshot name
    /// * `contents` - Snapshot contents
    /// * `analysis_cache_contents` - Contents of analysis cache of snapshot
    /// * `file` - New file contents (if contents changed)
    /// * `parent_ids` - List of ids of parent snapshots (or empty if this is a root snapshot)
    /// * `progress` - Function to call on progress updates
    pub fn create_snapshot_with_progress<I, P>(
        &self,
        name: &str,
        contents: &mut [u8],
        analysis_cache_contexts: &mut [u8],
        file: &mut [u8],
        parent_ids: I,
        mut progress: P,
    ) -> Result<Ref<RemoteSnapshot>, ()>
    where
        I: IntoIterator<Item = String>,
        P: ProgressCallback,
    {
        let name = name.to_cstr();
        let parent_ids: Vec<_> = parent_ids.into_iter().map(|id| id.to_cstr()).collect();
        let mut parent_ids_raw: Vec<_> = parent_ids.iter().map(|x| x.as_ptr()).collect();
        let result = unsafe {
            BNRemoteFileCreateSnapshot(
                self.handle.as_ptr(),
                name.as_ptr(),
                contents.as_mut_ptr(),
                contents.len(),
                analysis_cache_contexts.as_mut_ptr(),
                analysis_cache_contexts.len(),
                file.as_mut_ptr(),
                file.len(),
                parent_ids_raw.as_mut_ptr(),
                parent_ids_raw.len(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };
        let handle = NonNull::new(result).ok_or(())?;
        Ok(unsafe { RemoteSnapshot::ref_from_raw(handle) })
    }

    // Delete a snapshot from the remote
    pub fn delete_snapshot(&self, snapshot: &RemoteSnapshot) -> Result<(), ()> {
        let success =
            unsafe { BNRemoteFileDeleteSnapshot(self.handle.as_ptr(), snapshot.handle.as_ptr()) };
        success.then_some(()).ok_or(())
    }

    // TODO - This passes and returns a c++ `std::vector<T>`. A BnData can be implement in rust, but the
    // coreAPI need to include a `FreeData` function, similar to `BNFreeString` does.
    // The C++ API just assumes that both use the same allocator, and the python API seems to just leak this
    // memory, never dropping it.
    //pub fn download_file<S, F>(&self, mut progress_function: F) -> BnData
    //where
    //    S: BnStrCompatible,
    //    F: ProgressCallback,
    //{
    //    let mut data = ptr::null_mut();
    //    let mut data_len = 0;
    //    let result = unsafe {
    //        BNRemoteFileDownload(
    //            self.handle.as_ptr(),
    //            Some(F::cb_progress_callback),
    //            &mut progress_function as *mut _ as *mut c_void,
    //            &mut data,
    //            &mut data_len,
    //        )
    //    };
    //    todo!()
    //}

    pub fn request_user_positions(&self) -> String {
        let result = unsafe { BNRemoteFileRequestUserPositions(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    pub fn request_chat_log(&self) -> String {
        let result = unsafe { BNRemoteFileRequestChatLog(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    // TODO: AsRef<Path>
    /// Download a file from its remote, saving all snapshots to a database in the
    /// specified location. Returns a FileContext for opening the file later.
    ///
    /// * `db_path` - File path for saved database
    /// * `progress_function` - Function to call for progress updates
    pub fn download(&self, db_path: &Path) -> Result<Ref<FileMetadata>, ()> {
        sync::download_file(self, db_path)
    }

    // TODO: AsRef<Path>
    /// Download a file from its remote, saving all snapshots to a database in the
    /// specified location. Returns a FileContext for opening the file later.
    ///
    /// * `db_path` - File path for saved database
    /// * `progress_function` - Function to call for progress updates
    pub fn download_with_progress<F>(
        &self,
        db_path: &Path,
        progress_function: F,
    ) -> Result<Ref<FileMetadata>, ()>
    where
        F: ProgressCallback,
    {
        sync::download_file_with_progress(self, db_path, progress_function)
    }

    /// Download a remote file and save it to a BNDB at the given `path`, returning the associated [`FileMetadata`].
    pub fn download_database(&self, path: &Path) -> Result<Ref<FileMetadata>, ()> {
        let file = self.download(path)?;
        let database = file.database().ok_or(())?;
        self.sync(&database, DatabaseConflictHandlerFail, NoNameChangeset)?;
        Ok(file)
    }

    // TODO: This might be a bad helper... maybe remove...
    /// Download a remote file and save it to a BNDB at the given `path`.
    pub fn download_database_with_progress(
        &self,
        path: &Path,
        progress: impl ProgressCallback,
    ) -> Result<Ref<FileMetadata>, ()> {
        let mut progress = progress.split(&[50, 50]);
        let file = self.download_with_progress(path, progress.next_subpart().unwrap())?;
        let database = file.database().ok_or(())?;
        self.sync_with_progress(
            &database,
            DatabaseConflictHandlerFail,
            NoNameChangeset,
            progress.next_subpart().unwrap(),
        )?;
        Ok(file)
    }

    /// Completely sync a file, pushing/pulling/merging/applying changes
    ///
    /// * `bv_or_db` - Binary view or database to sync with
    /// * `conflict_handler` - Function to call to resolve snapshot conflicts
    /// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
    pub fn sync<C: DatabaseConflictHandler, N: NameChangeset>(
        &self,
        database: &Database,
        conflict_handler: C,
        name_changeset: N,
    ) -> Result<(), ()> {
        sync::sync_database(database, self, conflict_handler, name_changeset)
    }

    /// Completely sync a file, pushing/pulling/merging/applying changes
    ///
    /// * `bv_or_db` - Binary view or database to sync with
    /// * `conflict_handler` - Function to call to resolve snapshot conflicts
    /// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
    /// * `progress` - Function to call for progress updates
    pub fn sync_with_progress<C: DatabaseConflictHandler, P: ProgressCallback, N: NameChangeset>(
        &self,
        database: &Database,
        conflict_handler: C,
        name_changeset: N,
        progress: P,
    ) -> Result<(), ()> {
        sync::sync_database_with_progress(
            database,
            self,
            conflict_handler,
            name_changeset,
            progress,
        )
    }

    /// Pull updated snapshots from the remote. Merge local changes with remote changes and
    /// potentially create a new snapshot for unsaved changes, named via name_changeset.
    ///
    /// * `bv_or_db` - Binary view or database to sync with
    /// * `conflict_handler` - Function to call to resolve snapshot conflicts
    /// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
    pub fn pull<C, N>(
        &self,
        database: &Database,
        conflict_handler: C,
        name_changeset: N,
    ) -> Result<usize, ()>
    where
        C: DatabaseConflictHandler,
        N: NameChangeset,
    {
        sync::pull_database(database, self, conflict_handler, name_changeset)
    }

    /// Pull updated snapshots from the remote. Merge local changes with remote changes and
    /// potentially create a new snapshot for unsaved changes, named via name_changeset.
    ///
    /// * `bv_or_db` - Binary view or database to sync with
    /// * `conflict_handler` - Function to call to resolve snapshot conflicts
    /// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
    /// * `progress` - Function to call for progress updates
    pub fn pull_with_progress<C, P, N>(
        &self,
        database: &Database,
        conflict_handler: C,
        name_changeset: N,
        progress: P,
    ) -> Result<usize, ()>
    where
        C: DatabaseConflictHandler,
        P: ProgressCallback,
        N: NameChangeset,
    {
        sync::pull_database_with_progress(
            database,
            self,
            conflict_handler,
            name_changeset,
            progress,
        )
    }

    /// Push locally added snapshots to the remote.
    ///
    /// * `bv_or_db` - Binary view or database to sync with
    pub fn push<P>(&self, database: &Database) -> Result<usize, ()>
    where
        P: ProgressCallback,
    {
        sync::push_database(database, self)
    }

    /// Push locally added snapshots to the remote.
    ///
    /// * `bv_or_db` - Binary view or database to sync with
    /// * `progress` - Function to call for progress updates
    pub fn push_with_progress<P>(&self, database: &Database, progress: P) -> Result<usize, ()>
    where
        P: ProgressCallback,
    {
        sync::push_database_with_progress(database, self, progress)
    }
}

impl Debug for RemoteFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteFile")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("description", &self.description())
            .field("metadata", &self.metadata())
            .field("size", &self.size())
            .field(
                "snapshot_count",
                &self.snapshots().map(|s| s.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl PartialEq for RemoteFile {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for RemoteFile {}

impl ToOwned for RemoteFile {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for RemoteFile {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewRemoteFileReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeRemoteFile(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for RemoteFile {
    type Raw = *mut BNRemoteFile;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for RemoteFile {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeRemoteFileList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}
