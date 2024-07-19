use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use super::{
    Changeset, CollabSnapshot, MergeConflict, Remote, RemoteFile, RemoteFolder, RemoteProject,
};

use crate::binaryview::{BinaryView, BinaryViewExt};
use crate::database::{Database, Snapshot};
use crate::ffi::{ProgressCallback, ProgressCallbackNop};
use crate::filemetadata::FileMetadata;
use crate::project::ProjectFile;
use crate::rc::Ref;
use crate::string::{BnStrCompatible, BnString};
use crate::typearchive::{TypeArchive, TypeArchiveMergeConflict};

/// Get the default directory path for a remote Project. This is based off the Setting for
/// collaboration.directory, the project's id, and the project's remote's id.
pub fn default_project_path(project: &RemoteProject) -> Result<BnString, ()> {
    let result = unsafe { BNCollaborationDefaultProjectPath(project.as_raw()) };
    let success = !result.is_null();
    success
        .then(|| unsafe { BnString::from_raw(result) })
        .ok_or(())
}

// Get the default filepath for a remote File. This is based off the Setting for
// collaboration.directory, the file's id, the file's project's id, and the file's
// remote's id.
pub fn default_file_path(file: &RemoteFile) -> Result<BnString, ()> {
    let result = unsafe { BNCollaborationDefaultFilePath(file.as_raw()) };
    let success = !result.is_null();
    success
        .then(|| unsafe { BnString::from_raw(result) })
        .ok_or(())
}

/// Download a file from its remote, saving all snapshots to a database in the
/// specified location. Returns a FileContext for opening the file later.
///
/// * `file` - Remote File to download and open
/// * `db_path` - File path for saved database
/// * `progress` - Function to call for progress updates
pub fn download_file<S: BnStrCompatible, F: ProgressCallback>(
    file: &RemoteFile,
    db_path: S,
    mut progress: F,
) -> Result<Ref<FileMetadata>, ()> {
    let db_path = db_path.into_bytes_with_nul();
    let result = unsafe {
        BNCollaborationDownloadFile(
            file.as_raw(),
            db_path.as_ref().as_ptr() as *const ffi::c_char,
            Some(F::cb_progress_callback),
            &mut progress as *mut F as *mut ffi::c_void,
        )
    };
    let success = !result.is_null();
    success
        .then(|| unsafe { Ref::new(FileMetadata::from_raw(result)) })
        .ok_or(())
}

/// Upload a file, with database, to the remote under the given project
///
/// * `metadata` - Local file with database
/// * `project` - Remote project under which to place the new file
/// * `parent_folder` - Optional parent folder in which to place this file
/// * `progress` - Function to call for progress updates
/// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
pub fn upload_database<P: ProgressCallback, N: NameChangeset>(
    metadata: &FileMetadata,
    project: &RemoteProject,
    parent_folder: Option<&RemoteFolder>,
    mut progress: P,
    mut name_changeset: N,
) -> Result<RemoteFile, ()> {
    let folder_raw = parent_folder.map_or(ptr::null_mut(), |h| unsafe { h.as_raw() } as *mut _);
    let result = unsafe {
        BNCollaborationUploadDatabase(
            metadata.handle,
            project.as_raw(),
            folder_raw,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut ffi::c_void,
            Some(N::cb_name_changeset),
            &mut name_changeset as *mut N as *mut ffi::c_void,
        )
    };
    ptr::NonNull::new(result)
        .map(|raw| unsafe { RemoteFile::from_raw(raw) })
        .ok_or(())
}

/// Test if a database is valid for use in collaboration
pub fn is_collaboration_database(database: &Database) -> bool {
    unsafe { BNCollaborationIsCollaborationDatabase(database.as_raw()) }
}

/// Get the Remote for a Database
pub fn get_remote_for_local_database(database: &Database) -> Result<Option<Remote>, ()> {
    let mut value = ptr::null_mut();
    let success =
        unsafe { BNCollaborationGetRemoteForLocalDatabase(database.as_raw(), &mut value) };
    success
        .then(|| ptr::NonNull::new(value).map(|handle| unsafe { Remote::from_raw(handle) }))
        .ok_or(())
}

/// Get the Remote for a BinaryView
pub fn get_remote_for_binary_view(bv: &BinaryView) -> Result<Option<Remote>, ()> {
    let Some(db) = bv.file().database() else {
        return Ok(None);
    };
    get_remote_for_local_database(&db)
}

/// Get the Remote Project for a Database, returning the Remote project from one of the
/// connected remotes, or None if not found or if projects are not pulled
pub fn get_remote_project_for_local_database(
    database: &Database,
) -> Result<Option<RemoteProject>, ()> {
    let mut value = ptr::null_mut();
    let success =
        unsafe { BNCollaborationGetRemoteProjectForLocalDatabase(database.as_raw(), &mut value) };
    success
        .then(|| ptr::NonNull::new(value).map(|handle| unsafe { RemoteProject::from_raw(handle) }))
        .ok_or(())
}

/// Get the Remote File for a Database
pub fn get_remote_file_for_local_database(database: &Database) -> Result<Option<RemoteFile>, ()> {
    let mut value = ptr::null_mut();
    let success =
        unsafe { BNCollaborationGetRemoteFileForLocalDatabase(database.as_raw(), &mut value) };
    success
        .then(|| ptr::NonNull::new(value).map(|handle| unsafe { RemoteFile::from_raw(handle) }))
        .ok_or(())
}

/// Add a snapshot to the id map in a database
pub fn assign_snapshot_map(
    local_snapshot: &Snapshot,
    remote_snapshot: &CollabSnapshot,
) -> Result<(), ()> {
    let success = unsafe {
        BNCollaborationAssignSnapshotMap(local_snapshot.as_raw(), remote_snapshot.as_raw())
    };
    success.then_some(()).ok_or(())
}

/// Get the remote snapshot associated with a local snapshot (if it exists)
pub fn get_remote_snapshot_from_local(snap: &Snapshot) -> Result<Option<CollabSnapshot>, ()> {
    let mut value = ptr::null_mut();
    let success = unsafe { BNCollaborationGetRemoteSnapshotFromLocal(snap.as_raw(), &mut value) };
    success
        .then(|| ptr::NonNull::new(value).map(|handle| unsafe { CollabSnapshot::from_raw(handle) }))
        .ok_or(())
}

/// Get the local snapshot associated with a remote snapshot (if it exists)
pub fn get_local_snapshot_for_remote(
    snapshot: &CollabSnapshot,
    database: &Database,
) -> Result<Option<Snapshot>, ()> {
    let mut value = ptr::null_mut();
    let success = unsafe {
        BNCollaborationGetLocalSnapshotFromRemote(snapshot.as_raw(), database.as_raw(), &mut value)
    };
    success
        .then(|| ptr::NonNull::new(value).map(|handle| unsafe { Snapshot::from_raw(handle) }))
        .ok_or(())
}

/// Completely sync a database, pushing/pulling/merging/applying changes
///
/// * `database` - Database to sync
/// * `file` - File to sync with
/// * `conflict_handler` - Function to call to resolve snapshot conflicts
/// * `progress` - Function to call for progress updates
/// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
pub fn sync_database<C: DatabaseConflictHandler, P: ProgressCallback, N: NameChangeset>(
    database: &Database,
    file: &RemoteFile,
    mut conflict_handler: C,
    mut progress: P,
    mut name_changeset: N,
) -> Result<(), ()> {
    let success = unsafe {
        BNCollaborationSyncDatabase(
            database.as_raw(),
            file.as_raw(),
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut ffi::c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut ffi::c_void,
            Some(N::cb_name_changeset),
            &mut name_changeset as *mut N as *mut ffi::c_void,
        )
    };
    success.then_some(()).ok_or(())
}

/// Pull updated snapshots from the remote. Merge local changes with remote changes and
/// potentially create a new snapshot for unsaved changes, named via name_changeset.
///
/// * `database` - Database to pull
/// * `file` - Remote File to pull to
/// * `conflict_handler` - Function to call to resolve snapshot conflicts
/// * `progress` - Function to call for progress updates
/// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
pub fn pull_database<C: DatabaseConflictHandler, P: ProgressCallback, N: NameChangeset>(
    database: &Database,
    file: &RemoteFile,
    mut conflict_handler: C,
    mut progress: P,
    mut name_changeset: N,
) -> Result<usize, ()> {
    let mut count = 0;
    let success = unsafe {
        BNCollaborationPullDatabase(
            database.as_raw(),
            file.as_raw(),
            &mut count,
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut ffi::c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut ffi::c_void,
            Some(N::cb_name_changeset),
            &mut name_changeset as *mut N as *mut ffi::c_void,
        )
    };
    success.then_some(count).ok_or(())
}

/// Merge all leaf snapshots in a database down to a single leaf snapshot.
///
/// * `database` - Database to merge
/// * `conflict_handler` - Function to call for progress updates
/// * `progress` - Function to call to resolve snapshot conflicts
pub fn merge_database<C: DatabaseConflictHandler, P: ProgressCallback>(
    database: &Database,
    mut conflict_handler: C,
    mut progress: P,
) -> Result<(), ()> {
    let success = unsafe {
        BNCollaborationMergeDatabase(
            database.as_raw(),
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut ffi::c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut ffi::c_void,
        )
    };
    success.then_some(()).ok_or(())
}

/// Push locally added snapshots to the remote
///
/// * `database` - Database to push
/// * `file` - Remote File to push to
/// * `progress` - Function to call for progress updates
pub fn push_database<P: ProgressCallback>(
    database: &Database,
    file: &RemoteFile,
    mut progress: P,
) -> Result<usize, ()> {
    let mut count = 0;
    let success = unsafe {
        BNCollaborationPushDatabase(
            database.as_raw(),
            file.as_raw(),
            &mut count,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut ffi::c_void,
        )
    };
    success.then_some(count).ok_or(())
}

/// Print debug information about a database to stdout
pub fn dump_database(database: &Database) -> Result<(), ()> {
    let success = unsafe { BNCollaborationDumpDatabase(database.as_raw()) };
    success.then_some(()).ok_or(())
}

/// Ignore a snapshot from database syncing operations
///
/// * `database` - Parent database
/// * `snapshot` - Snapshot to ignore
pub fn ignore_snapshot(database: &Database, snapshot: &Snapshot) -> Result<(), ()> {
    let success = unsafe { BNCollaborationIgnoreSnapshot(database.as_raw(), snapshot.as_raw()) };
    success.then_some(()).ok_or(())
}

/// Test if a snapshot is ignored from the database
///
/// * `database` - Parent database
/// * `snapshot` - Snapshot to test
pub fn is_snapshot_ignored(database: &Database, snapshot: &Snapshot) -> bool {
    unsafe { BNCollaborationIsSnapshotIgnored(database.as_raw(), snapshot.as_raw()) }
}

/// Get the remote author of a local snapshot
///
/// * `database` - Parent database
/// * `snapshot` - Snapshot to query
pub fn get_snapshot_author(
    database: &Database,
    snapshot: &Snapshot,
) -> Result<Option<BnString>, ()> {
    let mut value = ptr::null_mut();
    let success = unsafe {
        BNCollaborationGetSnapshotAuthor(database.as_raw(), snapshot.as_raw(), &mut value)
    };
    success
        .then(|| (!value.is_null()).then(|| unsafe { BnString::from_raw(value) }))
        .ok_or(())
}

/// Set the remote author of a local snapshot (does not upload)
///
/// * `database` - Parent database
/// * `snapshot` - Snapshot to edit
/// * `author` - Target author
pub fn set_snapshot_author<S: BnStrCompatible>(
    database: &Database,
    snapshot: &Snapshot,
    author: S,
) -> Result<(), ()> {
    let author = author.into_bytes_with_nul();
    let success = unsafe {
        BNCollaborationSetSnapshotAuthor(
            database.as_raw(),
            snapshot.as_raw(),
            author.as_ref().as_ptr() as *const ffi::c_char,
        )
    };
    success.then_some(()).ok_or(())
}

pub(crate) fn pull_projects(database: &Database) -> Result<bool, ()> {
    let Some(remote) = get_remote_for_local_database(database)? else {
        return Ok(false);
    };
    if !remote.has_pulled_projects() {
        remote.pull_projects(ProgressCallbackNop)?;
    }
    Ok(true)
}

pub(crate) fn pull_files(database: &Database) -> Result<bool, ()> {
    if !pull_projects(database)? {
        return Ok(false);
    }
    let Some(project) = get_remote_project_for_local_database(database)? else {
        return Ok(false);
    };
    if !project.has_pulled_files() {
        project.pull_files(ProgressCallbackNop)?;
    }
    Ok(true)
}

/// Completely sync a type archive, pushing/pulling/merging/applying changes
///
/// * `type_archive` - TypeArchive to sync
/// * `file` - File to sync with
/// * `conflict_handler` - Function to call to resolve snapshot conflicts
/// * `progress` - Function to call for progress updates
pub fn sync_type_archive<C: TypeArchiveConflictHandler, P: ProgressCallback>(
    type_archive: &TypeArchive,
    file: &RemoteFile,
    mut conflict_handler: C,
    mut progress: P,
) -> Result<(), ()> {
    let success = unsafe {
        BNCollaborationSyncTypeArchive(
            type_archive.as_raw(),
            file.as_raw(),
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut ffi::c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut ffi::c_void,
        )
    };
    success.then_some(()).ok_or(())
}

/// Push locally added snapshots to the remote
///
/// * `type_archive` - TypeArchive to push
/// * `file` - Remote File to push to
/// * `progress` - Function to call for progress updates
pub fn push_type_archive<P: ProgressCallback>(
    type_archive: &TypeArchive,
    file: &RemoteFile,
    mut progress: P,
) -> Result<usize, ()> {
    let mut count = 0;
    let success = unsafe {
        BNCollaborationPushTypeArchive(
            type_archive.as_raw(),
            file.as_raw(),
            &mut count,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut ffi::c_void,
        )
    };
    success.then_some(count).ok_or(())
}

/// Pull updated snapshots from the remote. Merge local changes with remote changes and
/// potentially create a new snapshot for unsaved changes, named via name_changeset.
///
/// * `type_archive` - TypeArchive to pull
/// * `file` - Remote File to pull to
/// * `conflict_handler` - Function to call to resolve snapshot conflicts
/// * `progress` - Function to call for progress updates
/// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
pub fn pull_type_archive<C: TypeArchiveConflictHandler, P: ProgressCallback>(
    type_archive: &TypeArchive,
    file: &RemoteFile,
    mut conflict_handler: C,
    mut progress: P,
) -> Result<usize, ()> {
    let mut count = 0;
    let success = unsafe {
        BNCollaborationPullTypeArchive(
            type_archive.as_raw(),
            file.as_raw(),
            &mut count,
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut ffi::c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut ffi::c_void,
        )
    };
    success.then_some(count).ok_or(())
}

/// Test if a type archive is valid for use in collaboration
pub fn is_collaboration_type_archive(type_archive: &TypeArchive) -> bool {
    unsafe { BNCollaborationIsCollaborationTypeArchive(type_archive.as_raw()) }
}

/// Get the Remote for a Type Archive
pub fn get_remote_for_local_type_archive(type_archive: &TypeArchive) -> Option<Remote> {
    let value = unsafe { BNCollaborationGetRemoteForLocalTypeArchive(type_archive.as_raw()) };
    ptr::NonNull::new(value).map(|handle| unsafe { Remote::from_raw(handle) })
}

/// Get the Remote Project for a Type Archive
pub fn get_remote_project_for_local_type_archive(database: &TypeArchive) -> Option<RemoteProject> {
    let value = unsafe { BNCollaborationGetRemoteProjectForLocalTypeArchive(database.as_raw()) };
    ptr::NonNull::new(value).map(|handle| unsafe { RemoteProject::from_raw(handle) })
}

/// Get the Remote File for a Type Archive
pub fn get_remote_file_for_local_type_archive(database: &TypeArchive) -> Option<RemoteFile> {
    let value = unsafe { BNCollaborationGetRemoteFileForLocalTypeArchive(database.as_raw()) };
    ptr::NonNull::new(value).map(|handle| unsafe { RemoteFile::from_raw(handle) })
}

/// Get the remote snapshot associated with a local snapshot (if it exists) in a Type Archive
pub fn get_remote_snapshot_from_local_type_archive<S: BnStrCompatible>(
    type_archive: &TypeArchive,
    snapshot_id: S,
) -> Option<CollabSnapshot> {
    let snapshot_id = snapshot_id.into_bytes_with_nul();
    let value = unsafe {
        BNCollaborationGetRemoteSnapshotFromLocalTypeArchive(
            type_archive.as_raw(),
            snapshot_id.as_ref().as_ptr() as *const ffi::c_char,
        )
    };
    ptr::NonNull::new(value).map(|handle| unsafe { CollabSnapshot::from_raw(handle) })
}

/// Get the local snapshot associated with a remote snapshot (if it exists) in a Type Archive
pub fn get_local_snapshot_from_remote_type_archive(
    snapshot: &CollabSnapshot,
    type_archive: &TypeArchive,
) -> Option<BnString> {
    let value = unsafe {
        BNCollaborationGetLocalSnapshotFromRemoteTypeArchive(
            snapshot.as_raw(),
            type_archive.as_raw(),
        )
    };
    (!value.is_null()).then(|| unsafe { BnString::from_raw(value) })
}

/// Test if a snapshot is ignored from the archive
pub fn is_type_archive_snapshot_ignored<S: BnStrCompatible>(
    type_archive: &TypeArchive,
    snapshot_id: S,
) -> bool {
    let snapshot_id = snapshot_id.into_bytes_with_nul();
    unsafe {
        BNCollaborationIsTypeArchiveSnapshotIgnored(
            type_archive.as_raw(),
            snapshot_id.as_ref().as_ptr() as *const ffi::c_char,
        )
    }
}

/// Download a type archive from its remote, saving all snapshots to an archive in the
/// specified `location`. Returns a [TypeArchive] for using later.
pub fn download_type_archive<S: BnStrCompatible, F: ProgressCallback>(
    file: &RemoteFile,
    location: S,
    mut progress: F,
) -> Result<Option<TypeArchive>, ()> {
    let mut value = ptr::null_mut();
    let db_path = location.into_bytes_with_nul();
    let success = unsafe {
        BNCollaborationDownloadTypeArchive(
            file.as_raw(),
            db_path.as_ref().as_ptr() as *const ffi::c_char,
            Some(F::cb_progress_callback),
            &mut progress as *mut F as *mut ffi::c_void,
            &mut value,
        )
    };
    success
        .then(|| ptr::NonNull::new(value).map(|handle| unsafe { TypeArchive::from_raw(handle) }))
        .ok_or(())
}

/// Upload a type archive
pub fn upload_type_archive<P: ProgressCallback>(
    archive: &TypeArchive,
    project: &RemoteProject,
    folder: &RemoteFolder,
    mut progress: P,
    core_file: &ProjectFile,
) -> Result<RemoteFile, ()> {
    let mut value = ptr::null_mut();
    let success = unsafe {
        BNCollaborationUploadTypeArchive(
            archive.as_raw(),
            project.as_raw(),
            folder.as_raw(),
            Some(P::cb_progress_callback),
            &mut progress as *const P as *mut ffi::c_void,
            core_file.as_raw(),
            &mut value,
        )
    };
    success
        .then(|| {
            ptr::NonNull::new(value)
                .map(|handle| unsafe { RemoteFile::from_raw(handle) })
                .unwrap()
        })
        .ok_or(())
}

/// Merge a pair of snapshots and create a new snapshot with the result.
pub fn merge_snapshots<C: DatabaseConflictHandler, P: ProgressCallback>(
    first: &Snapshot,
    second: &Snapshot,
    mut conflict_handler: C,
    mut progress: P,
) -> Result<Snapshot, ()> {
    let value = unsafe {
        BNCollaborationMergeSnapshots(
            first.as_raw(),
            second.as_raw(),
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut ffi::c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut ffi::c_void,
        )
    };
    ptr::NonNull::new(value)
        .map(|handle| unsafe { Snapshot::from_raw(handle) })
        .ok_or(())
}

pub trait NameChangeset: Sized {
    fn name_changeset(&mut self, changeset: &Changeset) -> bool;
    unsafe extern "C" fn cb_name_changeset(
        ctxt: *mut ::std::os::raw::c_void,
        changeset: *mut BNCollaborationChangeset,
    ) -> bool {
        let ctxt: &mut Self = &mut *(ctxt as *mut Self);
        ctxt.name_changeset(Changeset::ref_from_raw(&changeset))
    }
}

impl<F> NameChangeset for F
where
    F: for<'a> FnMut(&'a Changeset) -> bool,
{
    fn name_changeset(&mut self, changeset: &Changeset) -> bool {
        self(changeset)
    }
}

pub struct NameChangesetNop;
impl NameChangeset for NameChangesetNop {
    fn name_changeset(&mut self, _changeset: &Changeset) -> bool {
        unreachable!()
    }

    unsafe extern "C" fn cb_name_changeset(
        _ctxt: *mut std::os::raw::c_void,
        _changeset: *mut BNCollaborationChangeset,
    ) -> bool {
        true
    }
}

/// Helper trait that resolves conflicts
pub trait DatabaseConflictHandler: Sized {
    /// Handle any merge conflicts by calling their success() function with a merged value
    ///
    /// * `conflicts` - conflicts ids to conflicts structures
    ///
    /// Return true if all conflicts were successfully merged
    fn handle_conflict(&mut self, keys: &str, conflicts: &MergeConflict) -> bool;
    unsafe extern "C" fn cb_handle_conflict(
        ctxt: *mut ffi::c_void,
        keys: *mut *const ffi::c_char,
        conflicts: *mut *mut BNAnalysisMergeConflict,
        conflict_count: usize,
    ) -> bool {
        let ctxt: &mut Self = &mut *(ctxt as *mut Self);
        let keys = core::slice::from_raw_parts(keys, conflict_count);
        let conflicts = core::slice::from_raw_parts(conflicts, conflict_count);
        keys.iter().zip(conflicts.iter()).all(|(key, conflict)| {
            // NOTE this is a reference, not owned, so ManuallyDrop is required, or just implement `ref_from_raw`
            let key = mem::ManuallyDrop::new(BnString::from_raw(*key as *mut _));
            let conflict = MergeConflict::ref_from_raw(conflict);
            ctxt.handle_conflict(key.as_str(), conflict)
        })
    }
}

impl<F> DatabaseConflictHandler for F
where
    F: for<'a> FnMut(&'a str, &'a MergeConflict) -> bool,
{
    fn handle_conflict(&mut self, keys: &str, conflicts: &MergeConflict) -> bool {
        self(keys, conflicts)
    }
}

pub struct DatabaseConflictHandlerFail;
impl DatabaseConflictHandler for DatabaseConflictHandlerFail {
    fn handle_conflict(&mut self, _keys: &str, _conflicts: &MergeConflict) -> bool {
        unreachable!()
    }

    unsafe extern "C" fn cb_handle_conflict(
        _ctxt: *mut ffi::c_void,
        _keys: *mut *const ffi::c_char,
        _conflicts: *mut *mut BNAnalysisMergeConflict,
        _conflict_count: usize,
    ) -> bool {
        // TODO only fail if _conflict_count is greater then 0?
        //_conflict_count > 0
        false
    }
}

pub trait TypeArchiveConflictHandler: Sized {
    fn handle_conflict(&mut self, conflicts: &TypeArchiveMergeConflict) -> bool;
    unsafe extern "C" fn cb_handle_conflict(
        ctxt: *mut ::std::os::raw::c_void,
        conflicts: *mut *mut BNTypeArchiveMergeConflict,
        conflict_count: usize,
    ) -> bool {
        let slf: &mut Self = &mut *(ctxt as *mut Self);
        core::slice::from_raw_parts(conflicts, conflict_count)
            .iter()
            .all(|conflict| slf.handle_conflict(TypeArchiveMergeConflict::ref_from_raw(conflict)))
    }
}

impl<F> TypeArchiveConflictHandler for F
where
    F: for<'a> FnMut(&'a TypeArchiveMergeConflict) -> bool,
{
    fn handle_conflict(&mut self, conflicts: &TypeArchiveMergeConflict) -> bool {
        self(conflicts)
    }
}

pub struct TypeArchiveConflictHandlerFail;
impl TypeArchiveConflictHandler for TypeArchiveConflictHandlerFail {
    fn handle_conflict(&mut self, _conflicts: &TypeArchiveMergeConflict) -> bool {
        unreachable!()
    }

    unsafe extern "C" fn cb_handle_conflict(
        _ctxt: *mut ffi::c_void,
        _conflicts: *mut *mut BNTypeArchiveMergeConflict,
        _conflict_count: usize,
    ) -> bool {
        // TODO only fail if _conflict_count is greater then 0?
        //_conflict_count > 0
        false
    }
}
