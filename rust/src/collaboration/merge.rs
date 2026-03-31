use binaryninjacore_sys::*;
use std::collections::HashMap;
use std::ffi::{c_char, c_void};
use std::ptr::NonNull;

use crate::database::{kvs::KeyValueStore, snapshot::Snapshot, Database};
use crate::file_metadata::FileMetadata;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{raw_to_string, BnString, IntoCStr};

pub type MergeConflictDataType = BNMergeConflictDataType;

/// Structure representing an individual merge conflict
#[repr(transparent)]
pub struct MergeConflict {
    handle: NonNull<BNAnalysisMergeConflict>,
}

impl MergeConflict {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNAnalysisMergeConflict>) -> Self {
        Self { handle }
    }

    #[allow(unused)]
    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNAnalysisMergeConflict>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Database backing all snapshots in the merge conflict
    pub fn database(&self) -> Database {
        let result = unsafe { BNAnalysisMergeConflictGetDatabase(self.handle.as_ptr()) };
        unsafe { Database::from_raw(NonNull::new(result).unwrap()) }
    }

    /// Snapshot which is the parent of the two being merged
    pub fn base_snapshot(&self) -> Option<Snapshot> {
        let result = unsafe { BNAnalysisMergeConflictGetBaseSnapshot(self.handle.as_ptr()) };
        NonNull::new(result).map(|handle| unsafe { Snapshot::from_raw(handle) })
    }

    /// First snapshot being merged
    pub fn first_snapshot(&self) -> Option<Snapshot> {
        let result = unsafe { BNAnalysisMergeConflictGetFirstSnapshot(self.handle.as_ptr()) };
        NonNull::new(result).map(|handle| unsafe { Snapshot::from_raw(handle) })
    }

    /// Second snapshot being merged
    pub fn second_snapshot(&self) -> Option<Snapshot> {
        let result = unsafe { BNAnalysisMergeConflictGetSecondSnapshot(self.handle.as_ptr()) };
        NonNull::new(result).map(|handle| unsafe { Snapshot::from_raw(handle) })
    }

    pub fn path_item_string(&self, path: &str) -> Result<BnString, ()> {
        let path = path.to_cstr();
        let result = unsafe {
            BNAnalysisMergeConflictGetPathItemString(self.handle.as_ptr(), path.as_ptr())
        };
        (!result.is_null())
            .then(|| unsafe { BnString::from_raw(result) })
            .ok_or(())
    }

    /// FileMetadata with contents of file for base snapshot
    /// This function is slow! Only use it if you really need it.
    pub fn base_file(&self) -> Option<Ref<FileMetadata>> {
        let result = unsafe { BNAnalysisMergeConflictGetBaseFile(self.handle.as_ptr()) };
        (!result.is_null()).then(|| unsafe { Ref::new(FileMetadata::from_raw(result)) })
    }

    /// FileMetadata with contents of file for first snapshot
    /// This function is slow! Only use it if you really need it.
    pub fn first_file(&self) -> Option<Ref<FileMetadata>> {
        let result = unsafe { BNAnalysisMergeConflictGetFirstFile(self.handle.as_ptr()) };
        (!result.is_null()).then(|| unsafe { Ref::new(FileMetadata::from_raw(result)) })
    }

    /// FileMetadata with contents of file for second snapshot
    /// This function is slow! Only use it if you really need it.
    pub fn second_file(&self) -> Option<Ref<FileMetadata>> {
        let result = unsafe { BNAnalysisMergeConflictGetSecondFile(self.handle.as_ptr()) };
        (!result.is_null()).then(|| unsafe { Ref::new(FileMetadata::from_raw(result)) })
    }

    /// Json String for conflicting data in the base snapshot
    pub fn base(&self) -> Option<BnString> {
        let result = unsafe { BNAnalysisMergeConflictGetBase(self.handle.as_ptr()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Json object for conflicting data in the base snapshot
    pub fn first(&self) -> Option<BnString> {
        let result = unsafe { BNAnalysisMergeConflictGetFirst(self.handle.as_ptr()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Json object for conflicting data in the second snapshot
    pub fn second(&self) -> Option<BnString> {
        let result = unsafe { BNAnalysisMergeConflictGetSecond(self.handle.as_ptr()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Type of data in the conflict, Text/Json/Binary
    pub fn data_type(&self) -> MergeConflictDataType {
        unsafe { BNAnalysisMergeConflictGetDataType(self.handle.as_ptr()) }
    }

    /// String representing the type name of the data, not the same as data_type.
    /// This is like "typeName" or "tag" depending on what object the conflict represents.
    pub fn conflict_type(&self) -> String {
        let result = unsafe { BNAnalysisMergeConflictGetType(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Lookup key for the merge conflict, ideally a tree path that contains the name of the conflict
    /// and all the recursive children leading up to this conflict.
    pub fn key(&self) -> String {
        let result = unsafe { BNAnalysisMergeConflictGetKey(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Call this when you've resolved the conflict to save the result
    pub fn success(&self, value: Option<&str>) -> Result<(), ()> {
        let value = value.map(|v| v.to_cstr());
        let success = unsafe {
            BNAnalysisMergeConflictSuccess(
                self.handle.as_ptr(),
                value
                    .as_ref()
                    .map(|v| v.as_ptr())
                    .unwrap_or(std::ptr::null()),
            )
        };
        success.then_some(()).ok_or(())
    }

    // TODO: Make a safe version of this that checks the path and if it holds a number
    pub unsafe fn get_path_item_number(&self, path_key: &str) -> Option<u64> {
        let path_key = path_key.to_cstr();
        let value =
            unsafe { BNAnalysisMergeConflictGetPathItem(self.handle.as_ptr(), path_key.as_ptr()) };
        match value.is_null() {
            // SAFETY: The path must be a number.
            false => Some(value as u64),
            true => None,
        }
    }

    pub unsafe fn get_path_item_string(&self, path_key: &str) -> Option<BnString> {
        let path_key = path_key.to_cstr();
        let value = unsafe {
            BNAnalysisMergeConflictGetPathItemString(self.handle.as_ptr(), path_key.as_ptr())
        };
        match value.is_null() {
            false => Some(unsafe { BnString::from_raw(value) }),
            true => None,
        }
    }
}

impl ToOwned for MergeConflict {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for MergeConflict {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewAnalysisMergeConflictReference(handle.handle.as_ptr()))
                .unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeAnalysisMergeConflict(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for MergeConflict {
    type Raw = *mut BNAnalysisMergeConflict;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for MergeConflict {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeAnalysisMergeConflictList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}

/// Register a custom [`ConflictSplitter`] with the API.
pub fn register_conflict_splitter<C: ConflictSplitter>(
    splitter: C,
) -> (&'static mut C, CoreConflictSplitter) {
    let splitter = Box::leak(Box::new(splitter));
    let mut callbacks = BNAnalysisMergeConflictSplitterCallbacks {
        context: splitter as *mut C as *mut c_void,
        getName: Some(cb_get_name::<C>),
        reset: Some(cb_reset::<C>),
        finished: Some(cb_finished::<C>),
        canSplit: Some(cb_can_split::<C>),
        split: Some(cb_split::<C>),
        freeName: Some(cb_free_name),
        freeKeyList: Some(cb_free_key_list),
        freeConflictList: Some(cb_free_conflict_list),
    };
    let handle = unsafe { BNRegisterAnalysisMergeConflictSplitter(&mut callbacks) };
    let core = unsafe { CoreConflictSplitter::from_raw(NonNull::new(handle).unwrap()) };
    (splitter, core)
}

/// Helper trait that takes one merge conflict and splits it into multiple conflicts.
///
/// This is used to take a large conflict and subdivide it into smaller conflicts that can be
/// resolved independently.
pub trait ConflictSplitter: Sized {
    /// Get a friendly name for the splitter.
    fn name(&self) -> String;

    /// Reset any internal state the splitter may hold during the merge.
    fn reset(&mut self) {}

    /// Clean up any internal state after the merge operation has finished.
    fn finished(&mut self) {}

    /// Test if the splitter applies to a given conflict.
    fn can_split(&mut self, key: &str, conflict: &MergeConflict) -> bool;

    /// Split a field conflict into any number of alternate conflicts.
    ///
    /// Returned conflicts will also be checked for splitting, so implementations must avoid
    /// producing infinite split loops.
    fn split(
        &mut self,
        original_key: &str,
        original_conflict: &MergeConflict,
        result: &KeyValueStore,
    ) -> Option<HashMap<String, Ref<MergeConflict>>>;
}

#[repr(transparent)]
pub struct CoreConflictSplitter {
    pub(crate) handle: NonNull<BNAnalysisMergeConflictSplitter>,
}

impl CoreConflictSplitter {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNAnalysisMergeConflictSplitter>) -> Self {
        Self { handle }
    }

    /// Get a list of all active conflict splitters.
    pub fn all() -> Array<CoreConflictSplitter> {
        let mut count = 0;
        let result = unsafe { BNGetAnalysisMergeConflictSplitterList(&mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a friendly name for the splitter.
    pub fn name(&self) -> String {
        let result = unsafe { BNAnalysisMergeConflictSplitterGetName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Test if the splitter applies to a given conflict.
    pub fn can_split(&self, key: &str, conflict: &MergeConflict) -> bool {
        let key = key.to_cstr();
        unsafe {
            BNAnalysisMergeConflictSplitterCanSplit(
                self.handle.as_ptr(),
                key.as_ptr(),
                conflict.handle.as_ptr(),
            )
        }
    }

    /// Split a field conflict into any number of alternate conflicts.
    pub fn split(
        &self,
        original_key: &str,
        original_conflict: &MergeConflict,
        result: &KeyValueStore,
    ) -> Option<HashMap<String, Ref<MergeConflict>>> {
        let original_key = original_key.to_cstr();
        let mut new_keys = std::ptr::null_mut();
        let mut new_conflicts = std::ptr::null_mut();
        let mut new_count = 0;
        let success = unsafe {
            BNAnalysisMergeConflictSplitterSplit(
                self.handle.as_ptr(),
                original_key.as_ptr(),
                original_conflict.handle.as_ptr(),
                result.handle.as_ptr(),
                &mut new_keys,
                &mut new_conflicts,
                &mut new_count,
            )
        };
        if !success {
            return None;
        }
        if new_count == 0 {
            if !new_keys.is_null() {
                unsafe { BNFreeStringList(new_keys, 0) };
            }
            if !new_conflicts.is_null() {
                unsafe { BNFreeAnalysisMergeConflictList(new_conflicts, 0) };
            }
            return Some(HashMap::new());
        }

        assert!(!new_keys.is_null());
        assert!(!new_conflicts.is_null());

        let keys: Array<BnString> = unsafe { Array::new(new_keys, new_count, ()) };
        let conflicts: Array<MergeConflict> = unsafe { Array::new(new_conflicts, new_count, ()) };
        Some(
            keys.iter()
                .zip(conflicts.iter())
                .map(|(key, conflict)| (key.to_string(), conflict.clone()))
                .collect(),
        )
    }
}

impl CoreArrayProvider for CoreConflictSplitter {
    type Raw = *mut BNAnalysisMergeConflictSplitter;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CoreConflictSplitter {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeAnalysisMergeConflictSplitterList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Self::from_raw(raw_ptr)
    }
}

unsafe extern "C" fn cb_get_name<C: ConflictSplitter>(ctxt: *mut c_void) -> *mut c_char {
    ffi_wrap!("ConflictSplitter::get_name", unsafe {
        let ctxt: &mut C = &mut *(ctxt as *mut C);
        BnString::into_raw(BnString::new(ctxt.name()))
    })
}

unsafe extern "C" fn cb_reset<C: ConflictSplitter>(ctxt: *mut c_void) {
    ffi_wrap!("ConflictSplitter::reset", unsafe {
        let ctxt: &mut C = &mut *(ctxt as *mut C);
        ctxt.reset();
    })
}

unsafe extern "C" fn cb_finished<C: ConflictSplitter>(ctxt: *mut c_void) {
    ffi_wrap!("ConflictSplitter::finished", unsafe {
        let ctxt: &mut C = &mut *(ctxt as *mut C);
        ctxt.finished();
    })
}

unsafe extern "C" fn cb_can_split<C: ConflictSplitter>(
    ctxt: *mut c_void,
    key: *const c_char,
    conflict: *const BNAnalysisMergeConflict,
) -> bool {
    ffi_wrap!("ConflictSplitter::can_split", unsafe {
        let ctxt: &mut C = &mut *(ctxt as *mut C);
        let Some(key) = raw_to_string(key) else {
            return false;
        };
        let Some(conflict) = NonNull::new(conflict as *mut BNAnalysisMergeConflict) else {
            return false;
        };
        let conflict = MergeConflict::from_raw(conflict);
        ctxt.can_split(&key, &conflict)
    })
}

unsafe extern "C" fn cb_split<C: ConflictSplitter>(
    ctxt: *mut c_void,
    original_key: *const c_char,
    original_conflict: *const BNAnalysisMergeConflict,
    result: *mut BNKeyValueStore,
    new_keys: *mut *mut *mut c_char,
    new_conflicts: *mut *mut *mut BNAnalysisMergeConflict,
    new_count: *mut usize,
) -> bool {
    ffi_wrap!("ConflictSplitter::split", unsafe {
        let ctxt: &mut C = &mut *(ctxt as *mut C);
        *new_keys = std::ptr::null_mut();
        *new_conflicts = std::ptr::null_mut();
        *new_count = 0;

        let Some(original_key) = raw_to_string(original_key) else {
            return false;
        };
        let Some(original_conflict) =
            NonNull::new(original_conflict as *mut BNAnalysisMergeConflict)
        else {
            return false;
        };
        let Some(result) = NonNull::new(result) else {
            return false;
        };

        let original_conflict = MergeConflict::from_raw(original_conflict);
        let result = KeyValueStore { handle: result };
        let Some(split_result) = ctxt.split(&original_key, &original_conflict, &result) else {
            return false;
        };
        if split_result.is_empty() {
            return true;
        }

        let mut keys = Vec::with_capacity(split_result.len());
        let mut conflicts = Vec::with_capacity(split_result.len());
        for (key, conflict) in split_result {
            keys.push(BnString::into_raw(BnString::new(key)));
            conflicts.push(BNNewAnalysisMergeConflictReference(
                conflict.handle.as_ptr(),
            ));
        }

        *new_count = keys.len();
        *new_keys = Box::into_raw(keys.into_boxed_slice()) as *mut *mut c_char;
        *new_conflicts =
            Box::into_raw(conflicts.into_boxed_slice()) as *mut *mut BNAnalysisMergeConflict;
        true
    })
}

unsafe extern "C" fn cb_free_name(_ctxt: *mut c_void, name: *mut c_char) {
    ffi_wrap!("ConflictSplitter::free_name", unsafe {
        BnString::free_raw(name);
    })
}

unsafe extern "C" fn cb_free_key_list(
    _ctxt: *mut c_void,
    key_list: *mut *mut c_char,
    count: usize,
) {
    ffi_wrap!("ConflictSplitter::free_key_list", unsafe {
        if key_list.is_null() {
            return;
        }

        let key_list = Box::from_raw(std::ptr::slice_from_raw_parts_mut(key_list, count));
        for key in key_list.into_vec() {
            BnString::free_raw(key);
        }
    })
}

unsafe extern "C" fn cb_free_conflict_list(
    _ctxt: *mut c_void,
    conflict_list: *mut *mut BNAnalysisMergeConflict,
    count: usize,
) {
    ffi_wrap!("ConflictSplitter::free_conflict_list", unsafe {
        if conflict_list.is_null() {
            return;
        }

        let conflict_list = Box::from_raw(std::ptr::slice_from_raw_parts_mut(conflict_list, count));
        for conflict in conflict_list.into_vec() {
            BNFreeAnalysisMergeConflict(conflict);
        }
    })
}
