use binaryninjacore_sys::*;
use std::ffi::c_char;
use std::ptr::NonNull;

use crate::database::{snapshot::Snapshot, Database};
use crate::file_metadata::FileMetadata;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};

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

    pub fn path_item_string<S: BnStrCompatible>(&self, path: S) -> Result<BnString, ()> {
        let path = path.into_bytes_with_nul();
        let result = unsafe {
            BNAnalysisMergeConflictGetPathItemString(
                self.handle.as_ptr(),
                path.as_ref().as_ptr() as *const c_char,
            )
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
    pub fn conflict_type(&self) -> BnString {
        let result = unsafe { BNAnalysisMergeConflictGetType(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Lookup key for the merge conflict, ideally a tree path that contains the name of the conflict
    /// and all the recursive children leading up to this conflict.
    pub fn key(&self) -> BnString {
        let result = unsafe { BNAnalysisMergeConflictGetKey(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Call this when you've resolved the conflict to save the result
    pub fn success<S: BnStrCompatible>(&self, value: S) -> Result<(), ()> {
        let value = value.into_bytes_with_nul();
        let success = unsafe {
            BNAnalysisMergeConflictSuccess(
                self.handle.as_ptr(),
                value.as_ref().as_ptr() as *const c_char,
            )
        };
        success.then_some(()).ok_or(())
    }

    // TODO: Make a safe version of this that checks the path and if it holds a number
    pub unsafe fn get_path_item_number<S: BnStrCompatible>(&self, path_key: S) -> Option<u64> {
        let path_key = path_key.into_bytes_with_nul();
        let value = unsafe {
            BNAnalysisMergeConflictGetPathItem(
                self.handle.as_ptr(),
                path_key.as_ref().as_ptr() as *const c_char,
            )
        };
        match value.is_null() {
            // SAFETY: The path must be a number.
            false => Some(value as u64),
            true => None,
        }
    }

    pub unsafe fn get_path_item_string<S: BnStrCompatible>(&self, path_key: S) -> Option<BnString> {
        let path_key = path_key.into_bytes_with_nul();
        let value = unsafe {
            BNAnalysisMergeConflictGetPathItemString(
                self.handle.as_ptr(),
                path_key.as_ref().as_ptr() as *const c_char,
            )
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
