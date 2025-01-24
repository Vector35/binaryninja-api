use super::{
    Changeset, MergeConflict, Remote, RemoteFile, RemoteFolder, RemoteProject, RemoteSnapshot,
};
use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void};
use std::mem::ManuallyDrop;
use std::ptr::NonNull;

use crate::binary_view::{BinaryView, BinaryViewExt};
use crate::database::{snapshot::Snapshot, Database};
use crate::file_metadata::FileMetadata;
use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::project::file::ProjectFile;
use crate::rc::Ref;
use crate::string::{BnStrCompatible, BnString};
use crate::type_archive::{TypeArchive, TypeArchiveMergeConflict};

// TODO: PathBuf
/// Get the default directory path for a remote Project. This is based off the Setting for
/// collaboration.directory, the project's id, and the project's remote's id.
pub fn default_project_path(project: &RemoteProject) -> Result<BnString, ()> {
    let result = unsafe { BNCollaborationDefaultProjectPath(project.handle.as_ptr()) };
    let success = !result.is_null();
    success
        .then(|| unsafe { BnString::from_raw(result) })
        .ok_or(())
}

// TODO: PathBuf
// Get the default filepath for a remote File. This is based off the Setting for
// collaboration.directory, the file's id, the file's project's id, and the file's
// remote's id.
pub fn default_file_path(file: &RemoteFile) -> Result<BnString, ()> {
    let result = unsafe { BNCollaborationDefaultFilePath(file.handle.as_ptr()) };
    let success = !result.is_null();
    success
        .then(|| unsafe { BnString::from_raw(result) })
        .ok_or(())
}

// TODO: AsRef<Path>
/// Download a file from its remote, saving all snapshots to a database in the
/// specified location. Returns a FileContext for opening the file later.
///
/// * `file` - Remote File to download and open
/// * `db_path` - File path for saved database
pub fn download_file<S: BnStrCompatible>(
    file: &RemoteFile,
    db_path: S,
) -> Result<Ref<FileMetadata>, ()> {
    download_file_with_progress(file, db_path, NoProgressCallback)
}

// TODO: AsRef<Path>
/// Download a file from its remote, saving all snapshots to a database in the
/// specified location. Returns a FileContext for opening the file later.
///
/// * `file` - Remote File to download and open
/// * `db_path` - File path for saved database
/// * `progress` - Function to call for progress updates
pub fn download_file_with_progress<S: BnStrCompatible, F: ProgressCallback>(
    file: &RemoteFile,
    db_path: S,
    mut progress: F,
) -> Result<Ref<FileMetadata>, ()> {
    let db_path = db_path.into_bytes_with_nul();
    let result = unsafe {
        BNCollaborationDownloadFile(
            file.handle.as_ptr(),
            db_path.as_ref().as_ptr() as *const c_char,
            Some(F::cb_progress_callback),
            &mut progress as *mut F as *mut c_void,
        )
    };
    let success = !result.is_null();
    success
        .then(|| unsafe { Ref::new(FileMetadata::from_raw(result)) })
        .ok_or(())
}

/// Upload a file, with database, to the remote under the given project
///
/// * `project` - Remote project under which to place the new file
/// * `parent_folder` - Optional parent folder in which to place this file
/// * `metadata` - Local file with database
/// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
pub fn upload_database<N: NameChangeset>(
    project: &RemoteProject,
    parent_folder: Option<&RemoteFolder>,
    metadata: &FileMetadata,
    name_changeset: N,
) -> Result<Ref<RemoteFile>, ()> {
    upload_database_with_progress(
        project,
        parent_folder,
        metadata,
        name_changeset,
        NoProgressCallback,
    )
}

/// Upload a file, with database, to the remote under the given project
///
/// * `metadata` - Local file with database
/// * `project` - Remote project under which to place the new file
/// * `parent_folder` - Optional parent folder in which to place this file
/// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
/// * `progress` - Function to call for progress updates
pub fn upload_database_with_progress<P: ProgressCallback, N: NameChangeset>(
    project: &RemoteProject,
    parent_folder: Option<&RemoteFolder>,
    metadata: &FileMetadata,
    mut name_changeset: N,
    mut progress: P,
) -> Result<Ref<RemoteFile>, ()> {
    let folder_raw = parent_folder.map_or(std::ptr::null_mut(), |h| h.handle.as_ptr());
    let result = unsafe {
        BNCollaborationUploadDatabase(
            metadata.handle,
            project.handle.as_ptr(),
            folder_raw,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
            Some(N::cb_name_changeset),
            &mut name_changeset as *mut N as *mut c_void,
        )
    };
    NonNull::new(result)
        .map(|raw| unsafe { RemoteFile::ref_from_raw(raw) })
        .ok_or(())
}

/// Test if a database is valid for use in collaboration
pub fn is_collaboration_database(database: &Database) -> bool {
    unsafe { BNCollaborationIsCollaborationDatabase(database.handle.as_ptr()) }
}

/// Get the Remote for a Database
pub fn get_remote_for_local_database(database: &Database) -> Result<Option<Ref<Remote>>, ()> {
    let mut value = std::ptr::null_mut();
    let success =
        unsafe { BNCollaborationGetRemoteForLocalDatabase(database.handle.as_ptr(), &mut value) };
    success
        .then(|| NonNull::new(value).map(|handle| unsafe { Remote::ref_from_raw(handle) }))
        .ok_or(())
}

/// Get the Remote for a BinaryView
pub fn get_remote_for_binary_view(bv: &BinaryView) -> Result<Option<Ref<Remote>>, ()> {
    let Some(db) = bv.file().database() else {
        return Ok(None);
    };
    get_remote_for_local_database(&db)
}

/// Get the Remote Project for a Database, returning the Remote project from one of the
/// connected remotes, or None if not found or if projects are not pulled
pub fn get_remote_project_for_local_database(
    database: &Database,
) -> Result<Option<Ref<RemoteProject>>, ()> {
    let mut value = std::ptr::null_mut();
    let success = unsafe {
        BNCollaborationGetRemoteProjectForLocalDatabase(database.handle.as_ptr(), &mut value)
    };
    success
        .then(|| NonNull::new(value).map(|handle| unsafe { RemoteProject::ref_from_raw(handle) }))
        .ok_or(())
}

/// Get the Remote File for a Database
pub fn get_remote_file_for_local_database(
    database: &Database,
) -> Result<Option<Ref<RemoteFile>>, ()> {
    let mut value = std::ptr::null_mut();
    let success = unsafe {
        BNCollaborationGetRemoteFileForLocalDatabase(database.handle.as_ptr(), &mut value)
    };
    success
        .then(|| NonNull::new(value).map(|handle| unsafe { RemoteFile::ref_from_raw(handle) }))
        .ok_or(())
}

/// Add a snapshot to the id map in a database
pub fn assign_snapshot_map(
    local_snapshot: &Snapshot,
    remote_snapshot: &RemoteSnapshot,
) -> Result<(), ()> {
    let success = unsafe {
        BNCollaborationAssignSnapshotMap(
            local_snapshot.handle.as_ptr(),
            remote_snapshot.handle.as_ptr(),
        )
    };
    success.then_some(()).ok_or(())
}

/// Get the remote snapshot associated with a local snapshot (if it exists)
pub fn get_remote_snapshot_from_local(snap: &Snapshot) -> Result<Option<Ref<RemoteSnapshot>>, ()> {
    let mut value = std::ptr::null_mut();
    let success =
        unsafe { BNCollaborationGetRemoteSnapshotFromLocal(snap.handle.as_ptr(), &mut value) };
    success
        .then(|| NonNull::new(value).map(|handle| unsafe { RemoteSnapshot::ref_from_raw(handle) }))
        .ok_or(())
}

/// Get the local snapshot associated with a remote snapshot (if it exists)
pub fn get_local_snapshot_for_remote(
    snapshot: &RemoteSnapshot,
    database: &Database,
) -> Result<Option<Ref<Snapshot>>, ()> {
    let mut value = std::ptr::null_mut();
    let success = unsafe {
        BNCollaborationGetLocalSnapshotFromRemote(
            snapshot.handle.as_ptr(),
            database.handle.as_ptr(),
            &mut value,
        )
    };
    success
        .then(|| NonNull::new(value).map(|handle| unsafe { Snapshot::ref_from_raw(handle) }))
        .ok_or(())
}

pub fn download_database<S>(file: &RemoteFile, location: S, force: bool) -> Result<(), ()>
where
    S: BnStrCompatible,
{
    download_database_with_progress(file, location, force, NoProgressCallback)
}

pub fn download_database_with_progress<S, F>(
    file: &RemoteFile,
    location: S,
    force: bool,
    mut progress: F,
) -> Result<(), ()>
where
    S: BnStrCompatible,
    F: ProgressCallback,
{
    let db_path = location.into_bytes_with_nul();
    let success = unsafe {
        BNCollaborationDownloadDatabaseForFile(
            file.handle.as_ptr(),
            db_path.as_ref().as_ptr() as *const c_char,
            force,
            Some(F::cb_progress_callback),
            &mut progress as *mut _ as *mut c_void,
        )
    };
    success.then_some(()).ok_or(())
}

/// Completely sync a database, pushing/pulling/merging/applying changes
///
/// * `database` - Database to sync
/// * `file` - File to sync with
/// * `conflict_handler` - Function to call to resolve snapshot conflicts
/// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
pub fn sync_database<C: DatabaseConflictHandler, N: NameChangeset>(
    database: &Database,
    file: &RemoteFile,
    conflict_handler: C,
    name_changeset: N,
) -> Result<(), ()> {
    sync_database_with_progress(
        database,
        file,
        conflict_handler,
        name_changeset,
        NoProgressCallback,
    )
}

/// Completely sync a database, pushing/pulling/merging/applying changes
///
/// * `database` - Database to sync
/// * `file` - File to sync with
/// * `conflict_handler` - Function to call to resolve snapshot conflicts
/// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
/// * `progress` - Function to call for progress updates
pub fn sync_database_with_progress<
    C: DatabaseConflictHandler,
    P: ProgressCallback,
    N: NameChangeset,
>(
    database: &Database,
    file: &RemoteFile,
    mut conflict_handler: C,
    mut name_changeset: N,
    mut progress: P,
) -> Result<(), ()> {
    let success = unsafe {
        BNCollaborationSyncDatabase(
            database.handle.as_ptr(),
            file.handle.as_ptr(),
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
            Some(N::cb_name_changeset),
            &mut name_changeset as *mut N as *mut c_void,
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
/// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
pub fn pull_database<C: DatabaseConflictHandler, N: NameChangeset>(
    database: &Database,
    file: &RemoteFile,
    conflict_handler: C,
    name_changeset: N,
) -> Result<usize, ()> {
    pull_database_with_progress(
        database,
        file,
        conflict_handler,
        name_changeset,
        NoProgressCallback,
    )
}

/// Pull updated snapshots from the remote. Merge local changes with remote changes and
/// potentially create a new snapshot for unsaved changes, named via name_changeset.
///
/// * `database` - Database to pull
/// * `file` - Remote File to pull to
/// * `conflict_handler` - Function to call to resolve snapshot conflicts
/// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
/// * `progress` - Function to call for progress updates
pub fn pull_database_with_progress<
    C: DatabaseConflictHandler,
    P: ProgressCallback,
    N: NameChangeset,
>(
    database: &Database,
    file: &RemoteFile,
    mut conflict_handler: C,
    mut name_changeset: N,
    mut progress: P,
) -> Result<usize, ()> {
    let mut count = 0;
    let success = unsafe {
        BNCollaborationPullDatabase(
            database.handle.as_ptr(),
            file.handle.as_ptr(),
            &mut count,
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
            Some(N::cb_name_changeset),
            &mut name_changeset as *mut N as *mut c_void,
        )
    };
    success.then_some(count).ok_or(())
}

/// Merge all leaf snapshots in a database down to a single leaf snapshot.
///
/// * `database` - Database to merge
/// * `conflict_handler` - Function to call for progress updates
pub fn merge_database<C: DatabaseConflictHandler>(
    database: &Database,
    conflict_handler: C,
) -> Result<(), ()> {
    merge_database_with_progress(database, conflict_handler, NoProgressCallback)
}

/// Merge all leaf snapshots in a database down to a single leaf snapshot.
///
/// * `database` - Database to merge
/// * `conflict_handler` - Function to call for progress updates
/// * `progress` - Function to call to resolve snapshot conflicts
pub fn merge_database_with_progress<C: DatabaseConflictHandler, P: ProgressCallback>(
    database: &Database,
    mut conflict_handler: C,
    mut progress: P,
) -> Result<(), ()> {
    let success = unsafe {
        BNCollaborationMergeDatabase(
            database.handle.as_ptr(),
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
        )
    };
    success.then_some(()).ok_or(())
}

/// Push locally added snapshots to the remote
///
/// * `database` - Database to push
/// * `file` - Remote File to push to
pub fn push_database(database: &Database, file: &RemoteFile) -> Result<usize, ()> {
    push_database_with_progress(database, file, NoProgressCallback)
}

/// Push locally added snapshots to the remote
///
/// * `database` - Database to push
/// * `file` - Remote File to push to
/// * `progress` - Function to call for progress updates
pub fn push_database_with_progress<P: ProgressCallback>(
    database: &Database,
    file: &RemoteFile,
    mut progress: P,
) -> Result<usize, ()> {
    let mut count = 0;
    let success = unsafe {
        BNCollaborationPushDatabase(
            database.handle.as_ptr(),
            file.handle.as_ptr(),
            &mut count,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
        )
    };
    success.then_some(count).ok_or(())
}

/// Print debug information about a database to stdout
pub fn dump_database(database: &Database) -> Result<(), ()> {
    let success = unsafe { BNCollaborationDumpDatabase(database.handle.as_ptr()) };
    success.then_some(()).ok_or(())
}

/// Ignore a snapshot from database syncing operations
///
/// * `database` - Parent database
/// * `snapshot` - Snapshot to ignore
pub fn ignore_snapshot(database: &Database, snapshot: &Snapshot) -> Result<(), ()> {
    let success = unsafe {
        BNCollaborationIgnoreSnapshot(database.handle.as_ptr(), snapshot.handle.as_ptr())
    };
    success.then_some(()).ok_or(())
}

/// Test if a snapshot is ignored from the database
///
/// * `database` - Parent database
/// * `snapshot` - Snapshot to test
pub fn is_snapshot_ignored(database: &Database, snapshot: &Snapshot) -> bool {
    unsafe { BNCollaborationIsSnapshotIgnored(database.handle.as_ptr(), snapshot.handle.as_ptr()) }
}

/// Get the remote author of a local snapshot
///
/// * `database` - Parent database
/// * `snapshot` - Snapshot to query
pub fn get_snapshot_author(
    database: &Database,
    snapshot: &Snapshot,
) -> Result<Option<BnString>, ()> {
    let mut value = std::ptr::null_mut();
    let success = unsafe {
        BNCollaborationGetSnapshotAuthor(
            database.handle.as_ptr(),
            snapshot.handle.as_ptr(),
            &mut value,
        )
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
            database.handle.as_ptr(),
            snapshot.handle.as_ptr(),
            author.as_ref().as_ptr() as *const c_char,
        )
    };
    success.then_some(()).ok_or(())
}

// TODO: this needs to be removed imo
pub(crate) fn pull_projects(database: &Database) -> Result<bool, ()> {
    let Some(remote) = get_remote_for_local_database(database)? else {
        return Ok(false);
    };
    remote.pull_projects()?;
    Ok(true)
}

// TODO: This needs to be removed imo
pub(crate) fn pull_files(database: &Database) -> Result<bool, ()> {
    if !pull_projects(database)? {
        return Ok(false);
    }
    let Some(project) = get_remote_project_for_local_database(database)? else {
        return Ok(false);
    };
    project.pull_files()?;
    Ok(true)
}

/// Completely sync a type archive, pushing/pulling/merging/applying changes
///
/// * `type_archive` - TypeArchive to sync
/// * `file` - File to sync with
/// * `conflict_handler` - Function to call to resolve snapshot conflicts
pub fn sync_type_archive<C: TypeArchiveConflictHandler>(
    type_archive: &TypeArchive,
    file: &RemoteFile,
    conflict_handler: C,
) -> Result<(), ()> {
    sync_type_archive_with_progress(type_archive, file, conflict_handler, NoProgressCallback)
}

/// Completely sync a type archive, pushing/pulling/merging/applying changes
///
/// * `type_archive` - TypeArchive to sync
/// * `file` - File to sync with
/// * `conflict_handler` - Function to call to resolve snapshot conflicts
/// * `progress` - Function to call for progress updates
pub fn sync_type_archive_with_progress<C: TypeArchiveConflictHandler, P: ProgressCallback>(
    type_archive: &TypeArchive,
    file: &RemoteFile,
    mut conflict_handler: C,
    mut progress: P,
) -> Result<(), ()> {
    let success = unsafe {
        BNCollaborationSyncTypeArchive(
            type_archive.handle.as_ptr(),
            file.handle.as_ptr(),
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
        )
    };
    success.then_some(()).ok_or(())
}

/// Push locally added snapshots to the remote
///
/// * `type_archive` - TypeArchive to push
/// * `file` - Remote File to push to
pub fn push_type_archive(type_archive: &TypeArchive, file: &RemoteFile) -> Result<usize, ()> {
    push_type_archive_with_progress(type_archive, file, NoProgressCallback)
}

/// Push locally added snapshots to the remote
///
/// * `type_archive` - TypeArchive to push
/// * `file` - Remote File to push to
/// * `progress` - Function to call for progress updates
pub fn push_type_archive_with_progress<P: ProgressCallback>(
    type_archive: &TypeArchive,
    file: &RemoteFile,
    mut progress: P,
) -> Result<usize, ()> {
    let mut count = 0;
    let success = unsafe {
        BNCollaborationPushTypeArchive(
            type_archive.handle.as_ptr(),
            file.handle.as_ptr(),
            &mut count,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
        )
    };
    success.then_some(count).ok_or(())
}

/// Pull updated type archives from the remote.
///
/// * `type_archive` - TypeArchive to pull
/// * `file` - Remote File to pull to
/// * `conflict_handler` - Function to call to resolve snapshot conflicts
pub fn pull_type_archive<C: TypeArchiveConflictHandler>(
    type_archive: &TypeArchive,
    file: &RemoteFile,
    conflict_handler: C,
) -> Result<usize, ()> {
    pull_type_archive_with_progress(type_archive, file, conflict_handler, NoProgressCallback)
}

/// Pull updated type archives from the remote.
///
/// * `type_archive` - TypeArchive to pull
/// * `file` - Remote File to pull to
/// * `conflict_handler` - Function to call to resolve snapshot conflicts
/// * `progress` - Function to call for progress updates
pub fn pull_type_archive_with_progress<C: TypeArchiveConflictHandler, P: ProgressCallback>(
    type_archive: &TypeArchive,
    file: &RemoteFile,
    mut conflict_handler: C,
    mut progress: P,
) -> Result<usize, ()> {
    let mut count = 0;
    let success = unsafe {
        BNCollaborationPullTypeArchive(
            type_archive.handle.as_ptr(),
            file.handle.as_ptr(),
            &mut count,
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
        )
    };
    success.then_some(count).ok_or(())
}

/// Test if a type archive is valid for use in collaboration
pub fn is_collaboration_type_archive(type_archive: &TypeArchive) -> bool {
    unsafe { BNCollaborationIsCollaborationTypeArchive(type_archive.handle.as_ptr()) }
}

/// Get the Remote for a Type Archive
pub fn get_remote_for_local_type_archive(type_archive: &TypeArchive) -> Option<Ref<Remote>> {
    let value =
        unsafe { BNCollaborationGetRemoteForLocalTypeArchive(type_archive.handle.as_ptr()) };
    NonNull::new(value).map(|handle| unsafe { Remote::ref_from_raw(handle) })
}

/// Get the Remote Project for a Type Archive
pub fn get_remote_project_for_local_type_archive(
    database: &TypeArchive,
) -> Option<Ref<RemoteProject>> {
    let value =
        unsafe { BNCollaborationGetRemoteProjectForLocalTypeArchive(database.handle.as_ptr()) };
    NonNull::new(value).map(|handle| unsafe { RemoteProject::ref_from_raw(handle) })
}

/// Get the Remote File for a Type Archive
pub fn get_remote_file_for_local_type_archive(database: &TypeArchive) -> Option<Ref<RemoteFile>> {
    let value =
        unsafe { BNCollaborationGetRemoteFileForLocalTypeArchive(database.handle.as_ptr()) };
    NonNull::new(value).map(|handle| unsafe { RemoteFile::ref_from_raw(handle) })
}

/// Get the remote snapshot associated with a local snapshot (if it exists) in a Type Archive
pub fn get_remote_snapshot_from_local_type_archive<S: BnStrCompatible>(
    type_archive: &TypeArchive,
    snapshot_id: S,
) -> Option<Ref<RemoteSnapshot>> {
    let snapshot_id = snapshot_id.into_bytes_with_nul();
    let value = unsafe {
        BNCollaborationGetRemoteSnapshotFromLocalTypeArchive(
            type_archive.handle.as_ptr(),
            snapshot_id.as_ref().as_ptr() as *const c_char,
        )
    };
    NonNull::new(value).map(|handle| unsafe { RemoteSnapshot::ref_from_raw(handle) })
}

/// Get the local snapshot associated with a remote snapshot (if it exists) in a Type Archive
pub fn get_local_snapshot_from_remote_type_archive(
    snapshot: &RemoteSnapshot,
    type_archive: &TypeArchive,
) -> Option<BnString> {
    let value = unsafe {
        BNCollaborationGetLocalSnapshotFromRemoteTypeArchive(
            snapshot.handle.as_ptr(),
            type_archive.handle.as_ptr(),
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
            type_archive.handle.as_ptr(),
            snapshot_id.as_ref().as_ptr() as *const c_char,
        )
    }
}

/// Download a type archive from its remote, saving all snapshots to an archive in the
/// specified `location`. Returns a [`TypeArchive`] for using later.
pub fn download_type_archive<S: BnStrCompatible>(
    file: &RemoteFile,
    location: S,
) -> Result<Option<TypeArchive>, ()> {
    download_type_archive_with_progress(file, location, NoProgressCallback)
}

/// Download a type archive from its remote, saving all snapshots to an archive in the
/// specified `location`. Returns a [`TypeArchive`] for using later.
pub fn download_type_archive_with_progress<S: BnStrCompatible, F: ProgressCallback>(
    file: &RemoteFile,
    location: S,
    mut progress: F,
) -> Result<Option<TypeArchive>, ()> {
    let mut value = std::ptr::null_mut();
    let db_path = location.into_bytes_with_nul();
    let success = unsafe {
        BNCollaborationDownloadTypeArchive(
            file.handle.as_ptr(),
            db_path.as_ref().as_ptr() as *const c_char,
            Some(F::cb_progress_callback),
            &mut progress as *mut F as *mut c_void,
            &mut value,
        )
    };
    success
        .then(|| NonNull::new(value).map(|handle| unsafe { TypeArchive::from_raw(handle) }))
        .ok_or(())
}

/// Upload a type archive
pub fn upload_type_archive(
    archive: &TypeArchive,
    project: &RemoteProject,
    // TODO: Is this required?
    folder: &RemoteFolder,
    core_file: &ProjectFile,
) -> Result<Ref<RemoteFile>, ()> {
    upload_type_archive_with_progress(archive, project, folder, core_file, NoProgressCallback)
}

/// Upload a type archive
pub fn upload_type_archive_with_progress<P: ProgressCallback>(
    archive: &TypeArchive,
    project: &RemoteProject,
    // TODO: Is this required?
    folder: &RemoteFolder,
    // TODO: I dislike the word "core" just say local?
    core_file: &ProjectFile,
    mut progress: P,
) -> Result<Ref<RemoteFile>, ()> {
    let mut value = std::ptr::null_mut();
    let success = unsafe {
        BNCollaborationUploadTypeArchive(
            archive.handle.as_ptr(),
            project.handle.as_ptr(),
            folder.handle.as_ptr(),
            Some(P::cb_progress_callback),
            &mut progress as *const P as *mut c_void,
            core_file.handle.as_ptr(),
            &mut value,
        )
    };
    success
        .then(|| {
            NonNull::new(value)
                .map(|handle| unsafe { RemoteFile::ref_from_raw(handle) })
                .unwrap()
        })
        .ok_or(())
}

/// Merge a pair of snapshots and create a new snapshot with the result.
pub fn merge_snapshots<C: DatabaseConflictHandler>(
    first: &Snapshot,
    second: &Snapshot,
    conflict_handler: C,
) -> Result<Snapshot, ()> {
    merge_snapshots_with_progress(first, second, conflict_handler, NoProgressCallback)
}

/// Merge a pair of snapshots and create a new snapshot with the result.
pub fn merge_snapshots_with_progress<C: DatabaseConflictHandler, P: ProgressCallback>(
    first: &Snapshot,
    second: &Snapshot,
    mut conflict_handler: C,
    mut progress: P,
) -> Result<Snapshot, ()> {
    let value = unsafe {
        BNCollaborationMergeSnapshots(
            first.handle.as_ptr(),
            second.handle.as_ptr(),
            Some(C::cb_handle_conflict),
            &mut conflict_handler as *mut C as *mut c_void,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
        )
    };
    NonNull::new(value)
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
        let raw_changeset_ptr = NonNull::new(changeset).unwrap();
        // TODO: Do we take ownership with a ref here or not?
        let changeset = Changeset::from_raw(raw_changeset_ptr);
        ctxt.name_changeset(&changeset)
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

pub struct NoNameChangeset;

impl NameChangeset for NoNameChangeset {
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
        ctxt: *mut c_void,
        keys: *mut *const c_char,
        conflicts: *mut *mut BNAnalysisMergeConflict,
        conflict_count: usize,
    ) -> bool {
        let ctxt: &mut Self = &mut *(ctxt as *mut Self);
        let keys = core::slice::from_raw_parts(keys, conflict_count);
        let conflicts = core::slice::from_raw_parts(conflicts, conflict_count);
        keys.iter().zip(conflicts.iter()).all(|(key, conflict)| {
            // NOTE this is a reference, not owned, so ManuallyDrop is required, or just implement `ref_from_raw`
            // TODO: Replace with raw_to_string
            let key = ManuallyDrop::new(BnString::from_raw(*key as *mut _));
            // TODO I guess dont drop here?
            let raw_ptr = NonNull::new(*conflict).unwrap();
            let conflict = MergeConflict::from_raw(raw_ptr);
            ctxt.handle_conflict(key.as_str(), &conflict)
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
        _ctxt: *mut c_void,
        _keys: *mut *const c_char,
        _conflicts: *mut *mut BNAnalysisMergeConflict,
        conflict_count: usize,
    ) -> bool {
        // Fail if we have any conflicts.
        conflict_count > 0
    }
}

pub trait TypeArchiveConflictHandler: Sized {
    fn handle_conflict(&mut self, conflicts: &TypeArchiveMergeConflict) -> bool;
    unsafe extern "C" fn cb_handle_conflict(
        ctxt: *mut ::std::os::raw::c_void,
        conflicts: *mut *mut BNTypeArchiveMergeConflict,
        conflict_count: usize,
    ) -> bool {
        let ctx: &mut Self = &mut *(ctxt as *mut Self);
        // TODO: Verify that we dont own the merge conflict, or this list passed to us.
        let conflicts_raw = core::slice::from_raw_parts(conflicts, conflict_count);
        conflicts_raw
            .iter()
            .map(|t| NonNull::new_unchecked(*t))
            .map(|t| TypeArchiveMergeConflict::from_raw(t))
            .all(|conflict| ctx.handle_conflict(&conflict))
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
        _ctxt: *mut c_void,
        _conflicts: *mut *mut BNTypeArchiveMergeConflict,
        _conflict_count: usize,
    ) -> bool {
        // TODO only fail if _conflict_count is greater then 0?
        //_conflict_count > 0
        false
    }
}
