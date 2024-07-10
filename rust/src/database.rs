use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use crate::binaryview::BinaryView;
use crate::databuffer::DataBuffer;
use crate::disassembly::InstructionTextToken;
use crate::filemetadata::FileMetadata;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

#[repr(transparent)]
pub struct Database {
    handle: ptr::NonNull<BNDatabase>,
}

impl Database {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNDatabase>) -> Self {
        Self { handle }
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNDatabase {
        &mut *self.handle.as_ptr()
    }

    /// Get a snapshot by its id, or None if no snapshot with that id exists
    pub fn snapshot(&self, id: i64) -> Option<Snapshot> {
        let result = unsafe { BNGetDatabaseSnapshot(self.as_raw(), id) };
        ptr::NonNull::new(result).map(|handle| unsafe { Snapshot::from_raw(handle) })
    }

    /// Get a list of all snapshots in the database
    pub fn snapshots(&self) -> Array<Snapshot> {
        let mut count = 0;
        let result = unsafe { BNGetDatabaseSnapshots(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get the current snapshot
    pub fn current_snapshot(&self) -> Option<Snapshot> {
        let result = unsafe { BNGetDatabaseCurrentSnapshot(self.as_raw()) };
        ptr::NonNull::new(result).map(|handle| unsafe { Snapshot::from_raw(handle) })
    }

    pub fn set_current_snapshot(&self, value: &Snapshot) {
        unsafe { BNSetDatabaseCurrentSnapshot(self.as_raw(), value.id()) }
    }

    pub fn write_snapshot_data<N: BnStrCompatible>(
        &self,
        parents: &[i64],
        file: &BinaryView,
        name: N,
        data: &KeyValueStore,
        auto_save: bool,
    ) -> i64 {
        let name_raw = name.into_bytes_with_nul();
        let name_ptr = name_raw.as_ref().as_ptr() as *const ffi::c_char;
        unsafe {
            BNWriteDatabaseSnapshotData(
                self.as_raw(),
                parents.as_ptr() as *mut _,
                parents.len(),
                file.handle,
                name_ptr,
                data.as_raw(),
                auto_save,
                ptr::null_mut(),
                Some(cb_progress_nop),
            )
        }
    }

    pub fn write_snapshot_data_with_progress<N, F>(
        &self,
        parents: &[i64],
        file: &BinaryView,
        name: N,
        data: &KeyValueStore,
        auto_save: bool,
        mut progress: F,
    ) -> i64
    where
        N: BnStrCompatible,
        F: FnMut(usize, usize) -> bool,
    {
        let name_raw = name.into_bytes_with_nul();
        let name_ptr = name_raw.as_ref().as_ptr() as *const ffi::c_char;
        let ctxt = &mut progress as *mut _ as *mut ffi::c_void;
        unsafe {
            BNWriteDatabaseSnapshotData(
                self.as_raw(),
                parents.as_ptr() as *mut _,
                parents.len(),
                file.handle,
                name_ptr,
                data.as_raw(),
                auto_save,
                ctxt,
                Some(cb_progress::<F>),
            )
        }
    }

    /// Trim a snapshot's contents in the database by id, but leave the parent/child
    /// hierarchy intact. Future references to this snapshot will return False for has_contents
    pub fn trim_snapshot(&self, id: i64) -> Result<(), ()> {
        if unsafe { BNTrimDatabaseSnapshot(self.as_raw(), id) } {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Remove a snapshot in the database by id, deleting its contents and references.
    /// Attempting to remove a snapshot with children will raise an exception.
    pub fn remove_snapshot(&self, id: i64) -> Result<(), ()> {
        if unsafe { BNRemoveDatabaseSnapshot(self.as_raw(), id) } {
            Ok(())
        } else {
            Err(())
        }
    }
    pub fn has_global<S: BnStrCompatible>(&self, key: S) -> bool {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const ffi::c_char;
        unsafe { BNDatabaseHasGlobal(self.as_raw(), key_ptr) != 0 }
    }

    /// Get a list of keys for all globals in the database
    pub fn global_keys(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNGetDatabaseGlobalKeys(self.as_raw(), &mut count) };
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
        let key_ptr = key_raw.as_ref().as_ptr() as *const ffi::c_char;
        let result = unsafe { BNReadDatabaseGlobal(self.as_raw(), key_ptr) };
        unsafe { ptr::NonNull::new(result).map(|_| BnString::from_raw(result)) }
    }

    /// Write a global into the database
    pub fn write_global<K: BnStrCompatible, V: BnStrCompatible>(&self, key: K, value: V) -> bool {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const ffi::c_char;
        let value_raw = value.into_bytes_with_nul();
        let value_ptr = value_raw.as_ref().as_ptr() as *const ffi::c_char;
        unsafe { BNWriteDatabaseGlobal(self.as_raw(), key_ptr, value_ptr) }
    }

    /// Get a specific global by key, as a binary buffer
    pub fn read_global_data<S: BnStrCompatible>(&self, key: S) -> Option<DataBuffer> {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const ffi::c_char;
        let result = unsafe { BNReadDatabaseGlobalData(self.as_raw(), key_ptr) };
        ptr::NonNull::new(result).map(|_| DataBuffer::from_raw(result))
    }

    /// Write a binary buffer into a global in the database
    pub fn write_global_data<K: BnStrCompatible>(&self, key: K, value: &DataBuffer) -> bool {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const ffi::c_char;
        unsafe { BNWriteDatabaseGlobalData(self.as_raw(), key_ptr, value.as_raw()) }
    }

    /// Get the owning FileMetadata
    pub fn file(&self) -> FileMetadata {
        let result = unsafe { BNGetDatabaseFile(self.as_raw()) };
        assert!(!result.is_null());
        FileMetadata::from_raw(result)
    }

    /// Get the backing analysis cache kvs
    pub fn analysis_cache(&self) -> KeyValueStore {
        let result = unsafe { BNReadDatabaseAnalysisCache(self.as_raw()) };
        unsafe { KeyValueStore::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    pub fn reload_connection(&self) {
        unsafe { BNDatabaseReloadConnection(self.as_raw()) }
    }

    pub fn write_analysis_cache(&self, val: &KeyValueStore) -> Result<(), ()> {
        if unsafe { BNWriteDatabaseAnalysisCache(self.as_raw(), val.as_raw()) } {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn snapshot_has_data(&self, id: i64) -> bool {
        unsafe { BNSnapshotHasData(self.as_raw(), id) }
    }
}

impl Clone for Database {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(ptr::NonNull::new(BNNewDatabaseReference(self.as_raw())).unwrap()) }
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        unsafe { BNFreeDatabase(self.as_raw()) }
    }
}

#[repr(transparent)]
pub struct Snapshot {
    handle: ptr::NonNull<BNSnapshot>,
}

impl Snapshot {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNSnapshot>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNSnapshot) -> &Self {
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNSnapshot {
        &mut *self.handle.as_ptr()
    }

    /// Get the owning database
    pub fn database(&self) -> Database {
        unsafe {
            Database::from_raw(ptr::NonNull::new(BNGetSnapshotDatabase(self.as_raw())).unwrap())
        }
    }

    /// Get the numerical id (read-only)
    pub fn id(&self) -> i64 {
        unsafe { BNGetSnapshotId(self.as_raw()) }
    }

    /// Get the displayed snapshot name
    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetSnapshotName(self.as_raw())) }
    }

    /// Set the displayed snapshot name
    pub fn set_name<S: BnStrCompatible>(&self, value: S) {
        let value_raw = value.into_bytes_with_nul();
        let value_ptr = value_raw.as_ref().as_ptr() as *const ffi::c_char;
        unsafe { BNSetSnapshotName(self.as_raw(), value_ptr) }
    }

    /// If the snapshot was the result of an auto-save
    pub fn is_auto_save(&self) -> bool {
        unsafe { BNIsSnapshotAutoSave(self.as_raw()) }
    }

    /// If the snapshot has contents, and has not been trimmed
    pub fn has_contents(&self) -> bool {
        unsafe { BNSnapshotHasContents(self.as_raw()) }
    }

    /// If the snapshot has undo data
    pub fn has_undo(&self) -> bool {
        unsafe { BNSnapshotHasUndo(self.as_raw()) }
    }

    /// Get the first parent of the snapshot, or None if it has no parents
    pub fn first_parent(&self) -> Option<Snapshot> {
        let result = unsafe { BNGetSnapshotFirstParent(self.as_raw()) };
        ptr::NonNull::new(result).map(|s| unsafe { Snapshot::from_raw(s) })
    }

    /// Get a list of all parent snapshots of the snapshot
    pub fn parents(&self) -> Array<Snapshot> {
        let mut count = 0;
        let result = unsafe { BNGetSnapshotParents(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a list of all child snapshots of the snapshot
    pub fn children(&self) -> Array<Snapshot> {
        let mut count = 0;
        let result = unsafe { BNGetSnapshotChildren(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a buffer of the raw data at the time of the snapshot
    pub fn file_contents(&self) -> Option<DataBuffer> {
        self.has_contents().then(|| unsafe {
            let result = BNGetSnapshotFileContents(self.as_raw());
            assert!(!result.is_null());
            DataBuffer::from_raw(result)
        })
    }

    /// Get a hash of the data at the time of the snapshot
    pub fn file_contents_hash(&self) -> Option<DataBuffer> {
        self.has_contents().then(|| unsafe {
            let result = BNGetSnapshotFileContentsHash(self.as_raw());
            assert!(!result.is_null());
            DataBuffer::from_raw(result)
        })
    }

    /// Get a list of undo entries at the time of the snapshot
    pub fn undo_entries(&self) -> Array<UndoEntry> {
        assert!(self.has_undo());
        let mut count = 0;
        let result = unsafe { BNGetSnapshotUndoEntries(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn undo_entries_with_progress<F: FnMut(usize, usize) -> bool>(
        &self,
        mut progress: F,
    ) -> Array<UndoEntry> {
        assert!(self.has_undo());
        let ctxt = &mut progress as *mut _ as *mut ffi::c_void;
        let mut count = 0;
        let result = unsafe {
            BNGetSnapshotUndoEntriesWithProgress(
                self.as_raw(),
                ctxt,
                Some(cb_progress::<F>),
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get the backing kvs data with snapshot fields
    pub fn read_data(&self) -> KeyValueStore {
        let result = unsafe { BNReadSnapshotData(self.as_raw()) };
        unsafe { KeyValueStore::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    pub fn read_data_with_progress<F: FnMut(usize, usize) -> bool>(
        &self,
        mut progress: F,
    ) -> KeyValueStore {
        let ctxt = &mut progress as *mut _ as *mut ffi::c_void;
        let result =
            unsafe { BNReadSnapshotDataWithProgress(self.as_raw(), ctxt, Some(cb_progress::<F>)) };
        unsafe { KeyValueStore::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    pub fn undo_data(&self) -> DataBuffer {
        let result = unsafe { BNGetSnapshotUndoData(self.as_raw()) };
        assert!(!result.is_null());
        DataBuffer::from_raw(result)
    }

    pub fn store_data<F: FnMut(usize, usize) -> bool>(
        &self,
        data: KeyValueStore,
        mut progress: F,
    ) -> bool {
        let ctxt = &mut progress as *mut _ as *mut ffi::c_void;
        unsafe { BNSnapshotStoreData(self.as_raw(), data.as_raw(), ctxt, Some(cb_progress::<F>)) }
    }

    /// Determine if this snapshot has another as an ancestor
    pub fn has_ancestor(self, other: &Snapshot) -> bool {
        unsafe { BNSnapshotHasAncestor(self.as_raw(), other.as_raw()) }
    }
}

impl Clone for Snapshot {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(ptr::NonNull::new(BNNewSnapshotReference(self.as_raw())).unwrap()) }
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        unsafe { BNFreeSnapshot(self.as_raw()) }
    }
}

impl CoreArrayProvider for Snapshot {
    type Raw = *mut BNSnapshot;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for Snapshot {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSnapshotList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

#[repr(transparent)]
pub struct KeyValueStore {
    handle: ptr::NonNull<BNKeyValueStore>,
}

impl KeyValueStore {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNKeyValueStore>) -> Self {
        Self { handle }
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNKeyValueStore {
        &mut *self.handle.as_ptr()
    }

    /// Get a list of all keys stored in the kvs
    pub fn keys(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNGetKeyValueStoreKeys(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get the value for a single key
    pub fn value<S: BnStrCompatible>(&self, key: S) -> Option<DataBuffer> {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const ffi::c_char;
        let result = unsafe { BNGetKeyValueStoreBuffer(self.as_raw(), key_ptr) };
        ptr::NonNull::new(result).map(|_| DataBuffer::from_raw(result))
    }

    /// Set the value for a single key
    pub fn set_value<S: BnStrCompatible>(&self, key: S, value: &DataBuffer) -> bool {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const ffi::c_char;
        unsafe { BNSetKeyValueStoreBuffer(self.as_raw(), key_ptr, value.as_raw()) }
    }

    /// Get the stored representation of the kvs
    pub fn serialized_data(&self) -> DataBuffer {
        let result = unsafe { BNGetKeyValueStoreSerializedData(self.as_raw()) };
        assert!(!result.is_null());
        DataBuffer::from_raw(result)
    }

    /// Begin storing new keys into a namespace
    pub fn begin_namespace<S: BnStrCompatible>(&self, name: S) {
        let name_raw = name.into_bytes_with_nul();
        let name_ptr = name_raw.as_ref().as_ptr() as *const ffi::c_char;
        unsafe { BNBeginKeyValueStoreNamespace(self.as_raw(), name_ptr) }
    }

    /// End storing new keys into a namespace
    pub fn end_namespace(&self) {
        unsafe { BNEndKeyValueStoreNamespace(self.as_raw()) }
    }

    /// If the kvs is empty
    pub fn empty(&self) -> bool {
        unsafe { BNIsKeyValueStoreEmpty(self.as_raw()) }
    }

    /// Number of values in the kvs
    pub fn value_size(&self) -> usize {
        unsafe { BNGetKeyValueStoreValueSize(self.as_raw()) }
    }

    /// Length of serialized data
    pub fn data_size(&self) -> usize {
        unsafe { BNGetKeyValueStoreDataSize(self.as_raw()) }
    }

    /// Size of all data in storage
    pub fn value_storage_size(self) -> usize {
        unsafe { BNGetKeyValueStoreValueStorageSize(self.as_raw()) }
    }

    /// Number of namespaces pushed with begin_namespace
    pub fn namespace_size(self) -> usize {
        unsafe { BNGetKeyValueStoreNamespaceSize(self.as_raw()) }
    }
}

impl Clone for KeyValueStore {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewKeyValueStoreReference(self.as_raw())).unwrap())
        }
    }
}

impl Drop for KeyValueStore {
    fn drop(&mut self) {
        unsafe { BNFreeKeyValueStore(self.as_raw()) }
    }
}

#[repr(transparent)]
pub struct UndoEntry {
    handle: ptr::NonNull<BNUndoEntry>,
}

impl UndoEntry {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNUndoEntry>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNUndoEntry) -> &Self {
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNUndoEntry {
        &mut *self.handle.as_ptr()
    }

    pub fn id(&self) -> BnString {
        let result = unsafe { BNUndoEntryGetId(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn actions(&self) -> Array<UndoAction> {
        let mut count = 0;
        let result = unsafe { BNUndoEntryGetActions(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn time(&self) -> SystemTime {
        let m = Duration::from_secs(unsafe { BNUndoEntryGetTimestamp(self.as_raw()) });
        UNIX_EPOCH + m
    }
}

impl Clone for UndoEntry {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewUndoEntryReference(self.as_raw())).unwrap())
        }
    }
}

impl Drop for UndoEntry {
    fn drop(&mut self) {
        unsafe { BNFreeUndoEntry(self.as_raw()) }
    }
}

impl CoreArrayProvider for UndoEntry {
    type Raw = *mut BNUndoEntry;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for UndoEntry {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeUndoEntryList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

#[repr(transparent)]
pub struct UndoAction {
    handle: ptr::NonNull<BNUndoAction>,
}

impl UndoAction {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNUndoAction>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNUndoAction) -> &Self {
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNUndoAction {
        &mut *self.handle.as_ptr()
    }

    pub fn summary_text(&self) -> BnString {
        let result = unsafe { BNUndoActionGetSummaryText(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn summary(&self) -> Array<InstructionTextToken> {
        let mut count = 0;
        let result = unsafe { BNUndoActionGetSummary(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }
}

impl Clone for UndoAction {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewUndoActionReference(self.as_raw())).unwrap())
        }
    }
}

impl Drop for UndoAction {
    fn drop(&mut self) {
        unsafe { BNFreeUndoAction(self.as_raw()) }
    }
}

impl CoreArrayProvider for UndoAction {
    type Raw = *mut BNUndoAction;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for UndoAction {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeUndoActionList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

unsafe extern "C" fn cb_progress<F: FnMut(usize, usize) -> bool>(
    ctxt: *mut ffi::c_void,
    arg1: usize,
    arg2: usize,
) -> bool {
    let ctxt: &mut F = &mut *(ctxt as *mut F);
    ctxt(arg1, arg2)
}

unsafe extern "C" fn cb_progress_nop(_ctxt: *mut ffi::c_void, _arg1: usize, _arg2: usize) -> bool {
    true
}
