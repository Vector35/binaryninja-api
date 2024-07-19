use core::{ffi, mem, ptr};

use std::time::SystemTime;

use binaryninjacore_sys::*;

use super::{databasesync, Remote, RemoteFile, RemoteProject};

use crate::binaryview::{BinaryView, BinaryViewExt};
use crate::database::Snapshot;
use crate::ffi::{ProgressCallback, ProgressCallbackNop};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

/// Class representing a remote Snapshot
#[repr(transparent)]
pub struct CollabSnapshot {
    handle: ptr::NonNull<BNCollaborationSnapshot>,
}

impl Drop for CollabSnapshot {
    fn drop(&mut self) {
        unsafe { BNFreeCollaborationSnapshot(self.as_raw()) }
    }
}

impl PartialEq for CollabSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for CollabSnapshot {}

impl Clone for CollabSnapshot {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(
                ptr::NonNull::new(BNNewCollaborationSnapshotReference(self.as_raw())).unwrap(),
            )
        }
    }
}

impl CollabSnapshot {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNCollaborationSnapshot>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNCollaborationSnapshot) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNCollaborationSnapshot {
        &mut *self.handle.as_ptr()
    }

    /// Get the remote snapshot associated with a local snapshot (if it exists)
    pub fn get_for_local_snapshot(snapshot: &Snapshot) -> Result<Option<CollabSnapshot>, ()> {
        databasesync::get_remote_snapshot_from_local(snapshot)
    }

    /// Owning File
    pub fn file(&self) -> Result<RemoteFile, ()> {
        let result = unsafe { BNCollaborationSnapshotGetFile(self.as_raw()) };
        let raw = ptr::NonNull::new(result).ok_or(())?;
        Ok(unsafe { RemoteFile::from_raw(raw) })
    }

    /// Owning Project
    pub fn project(&self) -> Result<RemoteProject, ()> {
        let result = unsafe { BNCollaborationSnapshotGetProject(self.as_raw()) };
        let raw = ptr::NonNull::new(result).ok_or(())?;
        Ok(unsafe { RemoteProject::from_raw(raw) })
    }

    /// Owning Remote
    pub fn remote(&self) -> Result<Remote, ()> {
        let result = unsafe { BNCollaborationSnapshotGetRemote(self.as_raw()) };
        let raw = ptr::NonNull::new(result).ok_or(())?;
        Ok(unsafe { Remote::from_raw(raw) })
    }

    /// Web api endpoint url
    pub fn url(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetUrl(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Unique id
    pub fn id(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetId(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Name of snapshot
    pub fn name(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetName(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Get the title of a snapshot: the first line of its name
    pub fn title(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetTitle(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Get the description of a snapshot: the lines of its name after the first line
    pub fn description(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetDescription(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Get the user id of the author of a snapshot
    pub fn author(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetAuthor(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Get the username of the author of a snapshot, if possible (vs author which is user id)
    pub fn author_username(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetAuthorUsername(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Created date of Snapshot
    pub fn created(&self) -> SystemTime {
        let timestamp = unsafe { BNCollaborationSnapshotGetCreated(self.as_raw()) };
        crate::ffi::time_from_bn(timestamp.try_into().unwrap())
    }

    /// Date of last modification to the snapshot
    pub fn last_modified(&self) -> SystemTime {
        let timestamp = unsafe { BNCollaborationSnapshotGetLastModified(self.as_raw()) };
        crate::ffi::time_from_bn(timestamp.try_into().unwrap())
    }

    /// Hash of snapshot data (analysis and markup, etc)
    /// No specific hash algorithm is guaranteed
    pub fn hash(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetHash(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Hash of file contents in snapshot
    /// No specific hash algorithm is guaranteed
    pub fn snapshot_file_hash(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetSnapshotFileHash(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// If the snapshot has pulled undo entries yet
    pub fn has_pulled_undo_entires(&self) -> bool {
        unsafe { BNCollaborationSnapshotHasPulledUndoEntries(self.as_raw()) }
    }

    /// If the snapshot has been finalized on the server and is no longer editable
    pub fn is_finalized(&self) -> bool {
        unsafe { BNCollaborationSnapshotIsFinalized(self.as_raw()) }
    }

    /// List of ids of all remote parent Snapshots
    pub fn parent_ids(&self) -> Result<Array<BnString>, ()> {
        let mut count = 0;
        let raw = unsafe { BNCollaborationSnapshotGetParentIds(self.as_raw(), &mut count) };
        (!raw.is_null())
            .then(|| unsafe { Array::new(raw, count, ()) })
            .ok_or(())
    }

    /// List of ids of all remote child Snapshots
    pub fn child_ids(&self) -> Result<Array<BnString>, ()> {
        let mut count = 0;
        let raw = unsafe { BNCollaborationSnapshotGetChildIds(self.as_raw(), &mut count) };
        (!raw.is_null())
            .then(|| unsafe { Array::new(raw, count, ()) })
            .ok_or(())
    }

    /// List of all parent Snapshot objects
    pub fn parents(&self) -> Result<Array<CollabSnapshot>, ()> {
        let mut count = 0;
        let raw = unsafe { BNCollaborationSnapshotGetParents(self.as_raw(), &mut count) };
        (!raw.is_null())
            .then(|| unsafe { Array::new(raw, count, ()) })
            .ok_or(())
    }

    /// List of all child Snapshot objects
    pub fn children(&self) -> Result<Array<CollabSnapshot>, ()> {
        let mut count = 0;
        let raw = unsafe { BNCollaborationSnapshotGetChildren(self.as_raw(), &mut count) };
        (!raw.is_null())
            .then(|| unsafe { Array::new(raw, count, ()) })
            .ok_or(())
    }

    /// Get the list of undo entries stored in this snapshot.
    ///
    /// NOTE: If undo entries have not been pulled, they will be pulled upon calling this.
    pub fn undo_entries(&self) -> Result<Array<UndoEntry>, ()> {
        if !self.has_pulled_undo_entires() {
            self.pull_undo_entries(ProgressCallbackNop)?;
        }
        let mut count = 0;
        let raw = unsafe { BNCollaborationSnapshotGetUndoEntries(self.as_raw(), &mut count) };
        (!raw.is_null())
            .then(|| unsafe { Array::new(raw, count, ()) })
            .ok_or(())
    }

    /// Get a specific Undo Entry in the Snapshot by its id
    ///
    /// NOTE: If undo entries have not been pulled, they will be pulled upon calling this.
    pub fn get_undo_entry_by_id(&self, id: u64) -> Result<Option<UndoEntry>, ()> {
        if !self.has_pulled_undo_entires() {
            self.pull_undo_entries(ProgressCallbackNop)?;
        }
        let raw = unsafe { BNCollaborationSnapshotGetUndoEntryById(self.as_raw(), id) };
        Ok(ptr::NonNull::new(raw).map(|handle| unsafe { UndoEntry::from_raw(handle) }))
    }

    /// Pull the list of Undo Entries from the Remote.
    pub fn pull_undo_entries<P: ProgressCallback>(&self, mut progress: P) -> Result<(), ()> {
        let success = unsafe {
            BNCollaborationSnapshotPullUndoEntries(
                self.as_raw(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut ffi::c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Create a new Undo Entry in this snapshot.
    pub fn create_undo_entry<S: BnStrCompatible>(
        &self,
        parent: Option<u64>,
        data: S,
    ) -> Result<UndoEntry, ()> {
        let data = data.into_bytes_with_nul();
        let value = unsafe {
            BNCollaborationSnapshotCreateUndoEntry(
                self.as_raw(),
                parent.is_some(),
                parent.unwrap_or(0),
                data.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        let handle = ptr::NonNull::new(value).ok_or(())?;
        Ok(unsafe { UndoEntry::from_raw(handle) })
    }

    /// Mark a snapshot as Finalized, committing it to the Remote, preventing future updates,
    /// and allowing snapshots to be children of it.
    pub fn finalize(&self) -> Result<(), ()> {
        let success = unsafe { BNCollaborationSnapshotFinalize(self.as_raw()) };
        success.then_some(()).ok_or(())
    }

    // TODO what kind of struct is this and how to free it?
    ///// Download the contents of the file in the Snapshot.
    //pub fn download_snapshot_file<P: ProgressCallback>(
    //    &self,
    //    mut progress: P,
    //) -> Result<BnData, ()> {
    //    let mut data = ptr::null_mut();
    //    let mut count = 0;
    //    let success = unsafe {
    //        BNCollaborationSnapshotDownloadSnapshotFile(
    //            self.as_raw(),
    //            Some(P::cb_progress_callback),
    //            &mut progress as *mut P as *mut ffi::c_void,
    //            &mut data,
    //            &mut count,
    //        )
    //    };
    //    todo!();
    //}
    //
    /////  Download the snapshot fields blob, compatible with KeyValueStore.
    //pub fn download<P: ProgressCallback>(
    //    &self,
    //    mut progress: P,
    //) -> Result<BnData, ()> {
    //    let mut data = ptr::null_mut();
    //    let mut count = 0;
    //    let success = unsafe {
    //        BNCollaborationSnapshotDownload(
    //            self.as_raw(),
    //            Some(P::cb_progress_callback),
    //            &mut progress as *mut P as *mut ffi::c_void,
    //            &mut data,
    //            &mut count,
    //        )
    //    };
    //    todo!();
    //}
    //
    ///// Download the analysis cache fields blob, compatible with KeyValueStore.
    //pub fn download_analysis_cache<P: ProgressCallback>(
    //    &self,
    //    mut progress: P,
    //) -> Result<BnData, ()> {
    //    let mut data = ptr::null_mut();
    //    let mut count = 0;
    //    let success = unsafe {
    //        BNCollaborationSnapshotDownloadAnalysisCache(
    //            self.as_raw(),
    //            Some(P::cb_progress_callback),
    //            &mut progress as *mut P as *mut ffi::c_void,
    //            &mut data,
    //            &mut count,
    //        )
    //    };
    //    todo!();
    //}

    /// Get the local snapshot associated with a remote snapshot (if it exists)
    pub fn get_local_snapshot(&self, bv: &BinaryView) -> Result<Option<Snapshot>, ()> {
        let Some(db) = bv.file().database() else {
            return Ok(None);
        };
        databasesync::get_local_snapshot_for_remote(self, &db)
    }

    pub fn analysis_cache_build_id(&self) -> u64 {
        unsafe { BNCollaborationSnapshotGetAnalysisCacheBuildId(self.as_raw()) }
    }
}

impl CoreArrayProvider for CollabSnapshot {
    type Raw = *mut BNCollaborationSnapshot;
    type Context = ();
    type Wrapped<'a> = &'a CollabSnapshot;
}

unsafe impl CoreArrayProviderInner for CollabSnapshot {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationSnapshotList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

#[repr(transparent)]
pub struct UndoEntry {
    handle: ptr::NonNull<BNCollaborationUndoEntry>,
}

impl Drop for UndoEntry {
    fn drop(&mut self) {
        unsafe { BNFreeCollaborationUndoEntry(self.as_raw()) }
    }
}

impl PartialEq for UndoEntry {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for UndoEntry {}

impl Clone for UndoEntry {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(
                ptr::NonNull::new(BNNewCollaborationUndoEntryReference(self.as_raw())).unwrap(),
            )
        }
    }
}

impl UndoEntry {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNCollaborationUndoEntry>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNCollaborationUndoEntry) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNCollaborationUndoEntry {
        &mut *self.handle.as_ptr()
    }

    /// Owning Snapshot
    pub fn snapshot(&self) -> Result<CollabSnapshot, ()> {
        let value = unsafe { BNCollaborationUndoEntryGetSnapshot(self.as_raw()) };
        let handle = ptr::NonNull::new(value).ok_or(())?;
        Ok(unsafe { CollabSnapshot::from_raw(handle) })
    }

    /// Owning File
    pub fn file(&self) -> Result<RemoteFile, ()> {
        let value = unsafe { BNCollaborationUndoEntryGetFile(self.as_raw()) };
        let handle = ptr::NonNull::new(value).ok_or(())?;
        Ok(unsafe { RemoteFile::from_raw(handle) })
    }

    /// Owning Project
    pub fn project(&self) -> Result<RemoteProject, ()> {
        let value = unsafe { BNCollaborationUndoEntryGetProject(self.as_raw()) };
        let handle = ptr::NonNull::new(value).ok_or(())?;
        Ok(unsafe { RemoteProject::from_raw(handle) })
    }

    /// Owning Remote
    pub fn remote(&self) -> Result<Remote, ()> {
        let value = unsafe { BNCollaborationUndoEntryGetRemote(self.as_raw()) };
        let handle = ptr::NonNull::new(value).ok_or(())?;
        Ok(unsafe { Remote::from_raw(handle) })
    }

    /// Web api endpoint url
    pub fn url(&self) -> BnString {
        let value = unsafe { BNCollaborationUndoEntryGetUrl(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Unique id
    pub fn id(&self) -> u64 {
        unsafe { BNCollaborationUndoEntryGetId(self.as_raw()) }
    }

    /// Id of parent undo entry
    pub fn parent_id(&self) -> Option<u64> {
        let mut value = 0;
        let success = unsafe { BNCollaborationUndoEntryGetParentId(self.as_raw(), &mut value) };
        success.then_some(value)
    }

    /// Undo entry contents data
    pub fn data(&self) -> Result<BnString, ()> {
        let mut value = ptr::null_mut();
        let success = unsafe { BNCollaborationUndoEntryGetData(self.as_raw(), &mut value) };
        if !success {
            return Err(());
        }
        assert!(!value.is_null());
        Ok(unsafe { BnString::from_raw(value) })
    }

    /// Parent Undo Entry object
    pub fn parent(&self) -> Option<UndoEntry> {
        let value = unsafe { BNCollaborationUndoEntryGetParent(self.as_raw()) };
        ptr::NonNull::new(value).map(|handle| unsafe { UndoEntry::from_raw(handle) })
    }
}

impl CoreArrayProvider for UndoEntry {
    type Raw = *mut BNCollaborationUndoEntry;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for UndoEntry {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationUndoEntryList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}
