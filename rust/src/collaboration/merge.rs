use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use crate::database::{Database, Snapshot};
use crate::filemetadata::FileMetadata;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{BnStrCompatible, BnString};

pub type MergeConflictDataType = BNMergeConflictDataType;

/// Structure representing an individual merge conflict
#[repr(transparent)]
pub struct MergeConflict {
    handle: ptr::NonNull<BNAnalysisMergeConflict>,
}

impl Drop for MergeConflict {
    fn drop(&mut self) {
        unsafe { BNFreeAnalysisMergeConflict(self.as_raw()) }
    }
}

impl Clone for MergeConflict {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(
                ptr::NonNull::new(BNNewAnalysisMergeConflictReference(self.as_raw())).unwrap(),
            )
        }
    }
}

impl MergeConflict {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNAnalysisMergeConflict>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNAnalysisMergeConflict) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNAnalysisMergeConflict {
        &mut *self.handle.as_ptr()
    }

    /// Database backing all snapshots in the merge conflict
    pub fn database(&self) -> Database {
        let result = unsafe { BNAnalysisMergeConflictGetDatabase(self.as_raw()) };
        unsafe { Database::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    /// Snapshot which is the parent of the two being merged
    pub fn base_snapshot(&self) -> Option<Snapshot> {
        let result = unsafe { BNAnalysisMergeConflictGetBaseSnapshot(self.as_raw()) };
        ptr::NonNull::new(result).map(|handle| unsafe { Snapshot::from_raw(handle) })
    }

    /// First snapshot being merged
    pub fn first_snapshot(&self) -> Option<Snapshot> {
        let result = unsafe { BNAnalysisMergeConflictGetFirstSnapshot(self.as_raw()) };
        ptr::NonNull::new(result).map(|handle| unsafe { Snapshot::from_raw(handle) })
    }

    /// Second snapshot being merged
    pub fn second_snapshot(&self) -> Option<Snapshot> {
        let result = unsafe { BNAnalysisMergeConflictGetSecondSnapshot(self.as_raw()) };
        ptr::NonNull::new(result).map(|handle| unsafe { Snapshot::from_raw(handle) })
    }

    pub fn path_item_string<S: BnStrCompatible>(&self, path: S) -> Result<BnString, ()> {
        let path = path.into_bytes_with_nul();
        let result = unsafe {
            BNAnalysisMergeConflictGetPathItemString(
                self.as_raw(),
                path.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        (!result.is_null())
            .then(|| unsafe { BnString::from_raw(result) })
            .ok_or(())
    }

    /// FileMetadata with contents of file for base snapshot
    /// This function is slow! Only use it if you really need it.
    pub fn base_file(&self) -> Option<Ref<FileMetadata>> {
        let result = unsafe { BNAnalysisMergeConflictGetBaseFile(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { Ref::new(FileMetadata::from_raw(result)) })
    }

    /// FileMetadata with contents of file for first snapshot
    /// This function is slow! Only use it if you really need it.
    pub fn first_file(&self) -> Option<Ref<FileMetadata>> {
        let result = unsafe { BNAnalysisMergeConflictGetFirstFile(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { Ref::new(FileMetadata::from_raw(result)) })
    }

    /// FileMetadata with contents of file for second snapshot
    /// This function is slow! Only use it if you really need it.
    pub fn second_file(&self) -> Option<Ref<FileMetadata>> {
        let result = unsafe { BNAnalysisMergeConflictGetSecondFile(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { Ref::new(FileMetadata::from_raw(result)) })
    }

    /// Json String for conflicting data in the base snapshot
    pub fn base(&self) -> Option<BnString> {
        let result = unsafe { BNAnalysisMergeConflictGetBase(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Json object for conflicting data in the base snapshot
    pub fn first(&self) -> Option<BnString> {
        let result = unsafe { BNAnalysisMergeConflictGetFirst(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Json object for conflicting data in the second snapshot
    pub fn second(&self) -> Option<BnString> {
        let result = unsafe { BNAnalysisMergeConflictGetSecond(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Type of data in the conflict, Text/Json/Binary
    pub fn data_type(&self) -> MergeConflictDataType {
        unsafe { BNAnalysisMergeConflictGetDataType(self.as_raw()) }
    }

    /// String representing the type name of the data, not the same as data_type.
    /// This is like "typeName" or "tag" depending on what object the conflict represents.
    pub fn conflict_type(&self) -> BnString {
        let result = unsafe { BNAnalysisMergeConflictGetType(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Lookup key for the merge conflict, ideally a tree path that contains the name of the conflict
    /// and all the recursive children leading up to this conflict.
    pub fn key(&self) -> BnString {
        let result = unsafe { BNAnalysisMergeConflictGetKey(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Call this when you've resolved the conflict to save the result
    pub fn success<S: BnStrCompatible>(&self, value: S) -> Result<(), ()> {
        let value = value.into_bytes_with_nul();
        let success = unsafe {
            BNAnalysisMergeConflictSuccess(
                self.as_raw(),
                value.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        success.then_some(()).ok_or(())
    }

    fn get_path_item_inner<S: BnStrCompatible>(&self, path_key: S) -> *mut ffi::c_void {
        let path_key = path_key.into_bytes_with_nul();
        unsafe {
            BNAnalysisMergeConflictGetPathItem(
                self.as_raw(),
                path_key.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    // TODO - How to downcast into usize/u64? How to free the original pointer? It's unclear how to handle
    // this correctly
    //pub fn get_path_item_number<S: BnStrCompatible>(&self, path_key: S) -> Result<usize, ()> {
    //    Ok(self.get_path_item_inner(path_key) as usize)
    //}

    pub unsafe fn get_path_item_string<S: BnStrCompatible>(
        &self,
        path_key: S,
    ) -> Result<BnString, ()> {
        let value = self.get_path_item_inner(path_key);
        (!value.is_null())
            .then(|| unsafe { BnString::from_raw(value as *mut ffi::c_char) })
            .ok_or(())
    }
}

impl CoreArrayProvider for MergeConflict {
    type Raw = *mut BNAnalysisMergeConflict;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for MergeConflict {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeAnalysisMergeConflictList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}
