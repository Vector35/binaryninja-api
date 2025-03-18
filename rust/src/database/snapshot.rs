use crate::data_buffer::DataBuffer;
use crate::database::kvs::KeyValueStore;
use crate::database::undo::UndoEntry;
use crate::database::Database;
use crate::progress::ProgressCallback;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};
use binaryninjacore_sys::{
    BNCollaborationFreeSnapshotIdList, BNFreeSnapshot, BNFreeSnapshotList, BNGetSnapshotChildren,
    BNGetSnapshotDatabase, BNGetSnapshotFileContents, BNGetSnapshotFileContentsHash,
    BNGetSnapshotFirstParent, BNGetSnapshotId, BNGetSnapshotName, BNGetSnapshotParents,
    BNGetSnapshotUndoData, BNGetSnapshotUndoEntries, BNGetSnapshotUndoEntriesWithProgress,
    BNIsSnapshotAutoSave, BNNewSnapshotReference, BNReadSnapshotData,
    BNReadSnapshotDataWithProgress, BNSetSnapshotName, BNSnapshot, BNSnapshotHasAncestor,
    BNSnapshotHasContents, BNSnapshotHasUndo, BNSnapshotStoreData,
};
use std::ffi::{c_char, c_void};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::ptr::NonNull;

pub struct Snapshot {
    pub(crate) handle: NonNull<BNSnapshot>,
}

impl Snapshot {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNSnapshot>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNSnapshot>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Get the owning database
    pub fn database(&self) -> Database {
        unsafe {
            Database::from_raw(NonNull::new(BNGetSnapshotDatabase(self.handle.as_ptr())).unwrap())
        }
    }

    /// Get the numerical id
    pub fn id(&self) -> SnapshotId {
        SnapshotId(unsafe { BNGetSnapshotId(self.handle.as_ptr()) })
    }

    /// Get the displayed snapshot name
    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetSnapshotName(self.handle.as_ptr())) }
    }

    /// Set the displayed snapshot name
    pub fn set_name<S: BnStrCompatible>(&self, value: S) {
        let value_raw = value.into_bytes_with_nul();
        let value_ptr = value_raw.as_ref().as_ptr() as *const c_char;
        unsafe { BNSetSnapshotName(self.handle.as_ptr(), value_ptr) }
    }

    /// If the snapshot was the result of an auto-save
    pub fn is_auto_save(&self) -> bool {
        unsafe { BNIsSnapshotAutoSave(self.handle.as_ptr()) }
    }

    /// If the snapshot has contents, and has not been trimmed
    pub fn has_contents(&self) -> bool {
        unsafe { BNSnapshotHasContents(self.handle.as_ptr()) }
    }

    /// If the snapshot has undo data
    pub fn has_undo(&self) -> bool {
        unsafe { BNSnapshotHasUndo(self.handle.as_ptr()) }
    }

    /// Get the first parent of the snapshot, or None if it has no parents
    pub fn first_parent(&self) -> Option<Snapshot> {
        let result = unsafe { BNGetSnapshotFirstParent(self.handle.as_ptr()) };
        NonNull::new(result).map(|s| unsafe { Snapshot::from_raw(s) })
    }

    /// Get a list of all parent snapshots of the snapshot
    pub fn parents(&self) -> Array<Snapshot> {
        let mut count = 0;
        let result = unsafe { BNGetSnapshotParents(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a list of all child snapshots of the snapshot
    pub fn children(&self) -> Array<Snapshot> {
        let mut count = 0;
        let result = unsafe { BNGetSnapshotChildren(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a buffer of the raw data at the time of the snapshot
    pub fn file_contents(&self) -> Option<DataBuffer> {
        self.has_contents().then(|| unsafe {
            let result = BNGetSnapshotFileContents(self.handle.as_ptr());
            assert!(!result.is_null());
            DataBuffer::from_raw(result)
        })
    }

    /// Get a hash of the data at the time of the snapshot
    pub fn file_contents_hash(&self) -> Option<DataBuffer> {
        self.has_contents().then(|| unsafe {
            let result = BNGetSnapshotFileContentsHash(self.handle.as_ptr());
            assert!(!result.is_null());
            DataBuffer::from_raw(result)
        })
    }

    /// Get a list of undo entries at the time of the snapshot
    pub fn undo_entries(&self) -> Array<UndoEntry> {
        assert!(self.has_undo());
        let mut count = 0;
        let result = unsafe { BNGetSnapshotUndoEntries(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn undo_entries_with_progress<P: ProgressCallback>(
        &self,
        mut progress: P,
    ) -> Array<UndoEntry> {
        assert!(self.has_undo());
        let mut count = 0;

        let result = unsafe {
            BNGetSnapshotUndoEntriesWithProgress(
                self.handle.as_ptr(),
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
                &mut count,
            )
        };

        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get the backing kvs data with snapshot fields
    pub fn read_data(&self) -> Ref<KeyValueStore> {
        let result = unsafe { BNReadSnapshotData(self.handle.as_ptr()) };
        unsafe { KeyValueStore::ref_from_raw(NonNull::new(result).unwrap()) }
    }

    pub fn read_data_with_progress<P: ProgressCallback>(
        &self,
        mut progress: P,
    ) -> Ref<KeyValueStore> {
        let result = unsafe {
            BNReadSnapshotDataWithProgress(
                self.handle.as_ptr(),
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
            )
        };

        unsafe { KeyValueStore::ref_from_raw(NonNull::new(result).unwrap()) }
    }

    pub fn undo_data(&self) -> DataBuffer {
        let result = unsafe { BNGetSnapshotUndoData(self.handle.as_ptr()) };
        assert!(!result.is_null());
        DataBuffer::from_raw(result)
    }

    pub fn store_data(&self, data: &KeyValueStore) -> bool {
        unsafe {
            BNSnapshotStoreData(
                self.handle.as_ptr(),
                data.handle.as_ptr(),
                std::ptr::null_mut(),
                None,
            )
        }
    }

    pub fn store_data_with_progress<P: ProgressCallback>(
        &self,
        data: &KeyValueStore,
        mut progress: P,
    ) -> bool {
        unsafe {
            BNSnapshotStoreData(
                self.handle.as_ptr(),
                data.handle.as_ptr(),
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
            )
        }
    }

    /// Determine if this snapshot has another as an ancestor
    pub fn has_ancestor(self, other: &Snapshot) -> bool {
        unsafe { BNSnapshotHasAncestor(self.handle.as_ptr(), other.handle.as_ptr()) }
    }
}

impl Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("is_auto_save", &self.is_auto_save())
            .field("has_contents", &self.has_contents())
            .field("has_undo", &self.has_undo())
            // TODO: This might be too much.
            .field("children", &self.children().to_vec())
            .finish()
    }
}

impl ToOwned for Snapshot {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Snapshot {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewSnapshotReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSnapshot(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for Snapshot {
    type Raw = *mut BNSnapshot;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Snapshot>;
}

unsafe impl CoreArrayProviderInner for Snapshot {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSnapshotList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotId(pub i64);

impl Display for SnapshotId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl CoreArrayProvider for SnapshotId {
    type Raw = i64;
    type Context = ();
    type Wrapped<'a> = SnapshotId;
}

unsafe impl CoreArrayProviderInner for SnapshotId {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNCollaborationFreeSnapshotIdList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        SnapshotId(*raw)
    }
}
