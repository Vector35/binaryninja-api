pub mod kvs;
pub mod snapshot;
pub mod undo;

use binaryninjacore_sys::*;
use std::collections::HashMap;
use std::ffi::{c_char, c_void};
use std::fmt::Debug;
use std::ptr::NonNull;

use crate::binary_view::BinaryView;
use crate::data_buffer::DataBuffer;
use crate::database::kvs::KeyValueStore;
use crate::database::snapshot::{Snapshot, SnapshotId};
use crate::file_metadata::FileMetadata;
use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::rc::{Array, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};

pub struct Database {
    pub(crate) handle: NonNull<BNDatabase>,
}

impl Database {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNDatabase>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNDatabase>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Get a snapshot by its id, or None if no snapshot with that id exists
    pub fn snapshot_by_id(&self, id: SnapshotId) -> Option<Ref<Snapshot>> {
        let result = unsafe { BNGetDatabaseSnapshot(self.handle.as_ptr(), id.0) };
        NonNull::new(result).map(|handle| unsafe { Snapshot::ref_from_raw(handle) })
    }

    /// Get a list of all snapshots in the database
    pub fn snapshots(&self) -> Array<Snapshot> {
        let mut count = 0;
        let result = unsafe { BNGetDatabaseSnapshots(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get the current snapshot
    pub fn current_snapshot(&self) -> Option<Ref<Snapshot>> {
        let result = unsafe { BNGetDatabaseCurrentSnapshot(self.handle.as_ptr()) };
        NonNull::new(result).map(|handle| unsafe { Snapshot::ref_from_raw(handle) })
    }

    /// Equivalent to [`Self::set_current_snapshot_id`].
    pub fn set_current_snapshot(&self, value: &Snapshot) {
        self.set_current_snapshot_id(value.id())
    }

    /// Sets the current snapshot to the [`SnapshotId`].
    ///
    /// **No** validation is done to ensure that the id is valid.
    pub fn set_current_snapshot_id(&self, id: SnapshotId) {
        unsafe { BNSetDatabaseCurrentSnapshot(self.handle.as_ptr(), id.0) }
    }

    pub fn write_snapshot_data<N: BnStrCompatible>(
        &self,
        parents: &[SnapshotId],
        file: &BinaryView,
        name: N,
        data: &KeyValueStore,
        auto_save: bool,
    ) -> SnapshotId {
        self.write_snapshot_data_with_progress(
            parents,
            file,
            name,
            data,
            auto_save,
            NoProgressCallback,
        )
    }

    pub fn write_snapshot_data_with_progress<N, P>(
        &self,
        parents: &[SnapshotId],
        file: &BinaryView,
        name: N,
        data: &KeyValueStore,
        auto_save: bool,
        mut progress: P,
    ) -> SnapshotId
    where
        N: BnStrCompatible,
        P: ProgressCallback,
    {
        let name_raw = name.into_bytes_with_nul();
        let name_ptr = name_raw.as_ref().as_ptr() as *const c_char;

        let new_id = unsafe {
            BNWriteDatabaseSnapshotData(
                self.handle.as_ptr(),
                // SAFETY: SnapshotId is just i64
                parents.as_ptr() as *mut _,
                parents.len(),
                file.handle,
                name_ptr,
                data.handle.as_ptr(),
                auto_save,
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
            )
        };

        SnapshotId(new_id)
    }

    /// Trim a snapshot's contents in the database by id, but leave the parent/child
    /// hierarchy intact. Future references to this snapshot will return False for has_contents
    pub fn trim_snapshot(&self, id: SnapshotId) -> Result<(), ()> {
        if unsafe { BNTrimDatabaseSnapshot(self.handle.as_ptr(), id.0) } {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Remove a snapshot in the database by id, deleting its contents and references.
    /// Attempting to remove a snapshot with children will raise an exception.
    pub fn remove_snapshot(&self, id: SnapshotId) -> Result<(), ()> {
        if unsafe { BNRemoveDatabaseSnapshot(self.handle.as_ptr(), id.0) } {
            Ok(())
        } else {
            Err(())
        }
    }
    pub fn has_global<S: BnStrCompatible>(&self, key: S) -> bool {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const c_char;
        unsafe { BNDatabaseHasGlobal(self.handle.as_ptr(), key_ptr) != 0 }
    }

    /// Get a list of keys for all globals in the database
    pub fn global_keys(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNGetDatabaseGlobalKeys(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a dictionary of all globals
    pub fn globals(&self) -> HashMap<String, String> {
        self.global_keys()
            .iter()
            .filter_map(|key| Some((key.to_string(), self.read_global(key)?.to_string())))
            .collect()
    }

    /// Get a specific global by key
    pub fn read_global<S: BnStrCompatible>(&self, key: S) -> Option<BnString> {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const c_char;
        let result = unsafe { BNReadDatabaseGlobal(self.handle.as_ptr(), key_ptr) };
        unsafe { NonNull::new(result).map(|_| BnString::from_raw(result)) }
    }

    /// Write a global into the database
    pub fn write_global<K: BnStrCompatible, V: BnStrCompatible>(&self, key: K, value: V) -> bool {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const c_char;
        let value_raw = value.into_bytes_with_nul();
        let value_ptr = value_raw.as_ref().as_ptr() as *const c_char;
        unsafe { BNWriteDatabaseGlobal(self.handle.as_ptr(), key_ptr, value_ptr) }
    }

    /// Get a specific global by key, as a binary buffer
    pub fn read_global_data<S: BnStrCompatible>(&self, key: S) -> Option<DataBuffer> {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const c_char;
        let result = unsafe { BNReadDatabaseGlobalData(self.handle.as_ptr(), key_ptr) };
        NonNull::new(result).map(|_| DataBuffer::from_raw(result))
    }

    /// Write a binary buffer into a global in the database
    pub fn write_global_data<K: BnStrCompatible>(&self, key: K, value: &DataBuffer) -> bool {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const c_char;
        unsafe { BNWriteDatabaseGlobalData(self.handle.as_ptr(), key_ptr, value.as_raw()) }
    }

    /// Get the owning FileMetadata
    pub fn file(&self) -> Ref<FileMetadata> {
        let result = unsafe { BNGetDatabaseFile(self.handle.as_ptr()) };
        assert!(!result.is_null());
        FileMetadata::ref_from_raw(result)
    }

    /// Get the backing analysis cache kvs
    pub fn analysis_cache(&self) -> Ref<KeyValueStore> {
        let result = unsafe { BNReadDatabaseAnalysisCache(self.handle.as_ptr()) };
        unsafe { KeyValueStore::ref_from_raw(NonNull::new(result).unwrap()) }
    }

    pub fn reload_connection(&self) {
        unsafe { BNDatabaseReloadConnection(self.handle.as_ptr()) }
    }

    pub fn write_analysis_cache(&self, val: &KeyValueStore) -> Result<(), ()> {
        if unsafe { BNWriteDatabaseAnalysisCache(self.handle.as_ptr(), val.handle.as_ptr()) } {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn snapshot_has_data(&self, id: SnapshotId) -> bool {
        unsafe { BNSnapshotHasData(self.handle.as_ptr(), id.0) }
    }
}

impl Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database")
            .field("current_snapshot", &self.current_snapshot())
            .field("snapshot_count", &self.snapshots().len())
            .field("globals", &self.globals())
            .field("analysis_cache", &self.analysis_cache())
            .finish()
    }
}

impl ToOwned for Database {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Database {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewDatabaseReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeDatabase(handle.handle.as_ptr());
    }
}
