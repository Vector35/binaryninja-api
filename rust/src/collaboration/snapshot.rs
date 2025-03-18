use std::ffi::{c_char, c_void};
use std::ptr::NonNull;
use std::time::SystemTime;

use super::{sync, Remote, RemoteFile, RemoteProject};
use crate::binary_view::{BinaryView, BinaryViewExt};
use crate::collaboration::undo::{RemoteUndoEntry, RemoteUndoEntryId};
use crate::database::snapshot::Snapshot;
use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};
use binaryninjacore_sys::*;

// TODO: RemoteSnapshotId ?

#[repr(transparent)]
pub struct RemoteSnapshot {
    pub(crate) handle: NonNull<BNCollaborationSnapshot>,
}

impl RemoteSnapshot {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNCollaborationSnapshot>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNCollaborationSnapshot>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Get the remote snapshot associated with a local snapshot (if it exists)
    pub fn get_for_local_snapshot(snapshot: &Snapshot) -> Result<Option<Ref<RemoteSnapshot>>, ()> {
        sync::get_remote_snapshot_from_local(snapshot)
    }

    /// Owning File
    pub fn file(&self) -> Result<Ref<RemoteFile>, ()> {
        let result = unsafe { BNCollaborationSnapshotGetFile(self.handle.as_ptr()) };
        let raw = NonNull::new(result).ok_or(())?;
        Ok(unsafe { RemoteFile::ref_from_raw(raw) })
    }

    /// Owning Project
    pub fn project(&self) -> Result<Ref<RemoteProject>, ()> {
        let result = unsafe { BNCollaborationSnapshotGetProject(self.handle.as_ptr()) };
        let raw = NonNull::new(result).ok_or(())?;
        Ok(unsafe { RemoteProject::ref_from_raw(raw) })
    }

    /// Owning Remote
    pub fn remote(&self) -> Result<Ref<Remote>, ()> {
        let result = unsafe { BNCollaborationSnapshotGetRemote(self.handle.as_ptr()) };
        let raw = NonNull::new(result).ok_or(())?;
        Ok(unsafe { Remote::ref_from_raw(raw) })
    }

    /// Web api endpoint url
    pub fn url(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetUrl(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Unique id
    pub fn id(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetId(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Name of snapshot
    pub fn name(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetName(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Get the title of a snapshot: the first line of its name
    pub fn title(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetTitle(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Get the description of a snapshot: the lines of its name after the first line
    pub fn description(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetDescription(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Get the user id of the author of a snapshot
    pub fn author(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetAuthor(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Get the username of the author of a snapshot, if possible (vs author which is user id)
    pub fn author_username(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetAuthorUsername(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Created date of Snapshot
    pub fn created(&self) -> SystemTime {
        let timestamp = unsafe { BNCollaborationSnapshotGetCreated(self.handle.as_ptr()) };
        crate::ffi::time_from_bn(timestamp.try_into().unwrap())
    }

    /// Date of last modification to the snapshot
    pub fn last_modified(&self) -> SystemTime {
        let timestamp = unsafe { BNCollaborationSnapshotGetLastModified(self.handle.as_ptr()) };
        crate::ffi::time_from_bn(timestamp.try_into().unwrap())
    }

    /// Hash of snapshot data (analysis and markup, etc)
    /// No specific hash algorithm is guaranteed
    pub fn hash(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetHash(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Hash of file contents in snapshot
    /// No specific hash algorithm is guaranteed
    pub fn snapshot_file_hash(&self) -> BnString {
        let value = unsafe { BNCollaborationSnapshotGetSnapshotFileHash(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// If the snapshot has pulled undo entries yet
    pub fn has_pulled_undo_entries(&self) -> bool {
        unsafe { BNCollaborationSnapshotHasPulledUndoEntries(self.handle.as_ptr()) }
    }

    /// If the snapshot has been finalized on the server and is no longer editable
    pub fn is_finalized(&self) -> bool {
        unsafe { BNCollaborationSnapshotIsFinalized(self.handle.as_ptr()) }
    }

    /// List of ids of all remote parent Snapshots
    pub fn parent_ids(&self) -> Result<Array<BnString>, ()> {
        let mut count = 0;
        let raw = unsafe { BNCollaborationSnapshotGetParentIds(self.handle.as_ptr(), &mut count) };
        (!raw.is_null())
            .then(|| unsafe { Array::new(raw, count, ()) })
            .ok_or(())
    }

    /// List of ids of all remote child Snapshots
    pub fn child_ids(&self) -> Result<Array<BnString>, ()> {
        let mut count = 0;
        let raw = unsafe { BNCollaborationSnapshotGetChildIds(self.handle.as_ptr(), &mut count) };
        (!raw.is_null())
            .then(|| unsafe { Array::new(raw, count, ()) })
            .ok_or(())
    }

    /// List of all parent Snapshot objects
    pub fn parents(&self) -> Result<Array<RemoteSnapshot>, ()> {
        let mut count = 0;
        let raw = unsafe { BNCollaborationSnapshotGetParents(self.handle.as_ptr(), &mut count) };
        (!raw.is_null())
            .then(|| unsafe { Array::new(raw, count, ()) })
            .ok_or(())
    }

    /// List of all child Snapshot objects
    pub fn children(&self) -> Result<Array<RemoteSnapshot>, ()> {
        let mut count = 0;
        let raw = unsafe { BNCollaborationSnapshotGetChildren(self.handle.as_ptr(), &mut count) };
        (!raw.is_null())
            .then(|| unsafe { Array::new(raw, count, ()) })
            .ok_or(())
    }

    /// Get the list of undo entries stored in this snapshot.
    ///
    /// NOTE: If undo entries have not been pulled, they will be pulled upon calling this.
    pub fn undo_entries(&self) -> Result<Array<RemoteUndoEntry>, ()> {
        if !self.has_pulled_undo_entries() {
            self.pull_undo_entries()?;
        }
        let mut count = 0;
        let raw =
            unsafe { BNCollaborationSnapshotGetUndoEntries(self.handle.as_ptr(), &mut count) };
        (!raw.is_null())
            .then(|| unsafe { Array::new(raw, count, ()) })
            .ok_or(())
    }

    /// Get a specific Undo Entry in the Snapshot by its id
    ///
    /// NOTE: If undo entries have not been pulled, they will be pulled upon calling this.
    pub fn get_undo_entry_by_id(
        &self,
        id: RemoteUndoEntryId,
    ) -> Result<Option<Ref<RemoteUndoEntry>>, ()> {
        if !self.has_pulled_undo_entries() {
            self.pull_undo_entries()?;
        }
        let raw = unsafe { BNCollaborationSnapshotGetUndoEntryById(self.handle.as_ptr(), id.0) };
        Ok(NonNull::new(raw).map(|handle| unsafe { RemoteUndoEntry::ref_from_raw(handle) }))
    }

    /// Pull the list of Undo Entries from the Remote.
    pub fn pull_undo_entries(&self) -> Result<(), ()> {
        self.pull_undo_entries_with_progress(NoProgressCallback)
    }

    /// Pull the list of Undo Entries from the Remote.
    pub fn pull_undo_entries_with_progress<P: ProgressCallback>(
        &self,
        mut progress: P,
    ) -> Result<(), ()> {
        let success = unsafe {
            BNCollaborationSnapshotPullUndoEntries(
                self.handle.as_ptr(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Create a new Undo Entry in this snapshot.
    pub fn create_undo_entry<S: BnStrCompatible>(
        &self,
        parent: Option<u64>,
        data: S,
    ) -> Result<Ref<RemoteUndoEntry>, ()> {
        let data = data.into_bytes_with_nul();
        let value = unsafe {
            BNCollaborationSnapshotCreateUndoEntry(
                self.handle.as_ptr(),
                parent.is_some(),
                parent.unwrap_or(0),
                data.as_ref().as_ptr() as *const c_char,
            )
        };
        let handle = NonNull::new(value).ok_or(())?;
        Ok(unsafe { RemoteUndoEntry::ref_from_raw(handle) })
    }

    /// Mark a snapshot as Finalized, committing it to the Remote, preventing future updates,
    /// and allowing snapshots to be children of it.
    pub fn finalize(&self) -> Result<(), ()> {
        let success = unsafe { BNCollaborationSnapshotFinalize(self.handle.as_ptr()) };
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
    //            self.handle.as_ptr(),
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
    //            self.handle.as_ptr(),
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
    //            self.handle.as_ptr(),
    //            Some(P::cb_progress_callback),
    //            &mut progress as *mut P as *mut ffi::c_void,
    //            &mut data,
    //            &mut count,
    //        )
    //    };
    //    todo!();
    //}

    /// Get the local snapshot associated with a remote snapshot (if it exists)
    pub fn get_local_snapshot(&self, bv: &BinaryView) -> Result<Option<Ref<Snapshot>>, ()> {
        let Some(db) = bv.file().database() else {
            return Ok(None);
        };
        sync::get_local_snapshot_for_remote(self, &db)
    }

    pub fn analysis_cache_build_id(&self) -> u64 {
        unsafe { BNCollaborationSnapshotGetAnalysisCacheBuildId(self.handle.as_ptr()) }
    }
}

impl PartialEq for RemoteSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for RemoteSnapshot {}

impl ToOwned for RemoteSnapshot {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for RemoteSnapshot {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewCollaborationSnapshotReference(handle.handle.as_ptr()))
                .unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeCollaborationSnapshot(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for RemoteSnapshot {
    type Raw = *mut BNCollaborationSnapshot;
    type Context = ();
    type Wrapped<'a> = Guard<'a, RemoteSnapshot>;
}

unsafe impl CoreArrayProviderInner for RemoteSnapshot {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationSnapshotList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}
