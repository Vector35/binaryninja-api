use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use super::{RemoteFile, User};

use crate::database::Database;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

/// Class representing a collection of snapshots in a local database
#[repr(transparent)]
pub struct Changeset {
    handle: ptr::NonNull<BNCollaborationChangeset>,
}

impl Drop for Changeset {
    fn drop(&mut self) {
        unsafe { BNFreeCollaborationChangeset(self.as_raw()) }
    }
}

impl Clone for Changeset {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(
                ptr::NonNull::new(BNNewCollaborationChangesetReference(self.as_raw())).unwrap(),
            )
        }
    }
}

impl Changeset {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNCollaborationChangeset>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNCollaborationChangeset) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNCollaborationChangeset {
        &mut *self.handle.as_ptr()
    }

    /// Owning database for snapshots
    pub fn database(&self) -> Result<Database, ()> {
        let result = unsafe { BNCollaborationChangesetGetDatabase(self.as_raw()) };
        let raw = ptr::NonNull::new(result).ok_or(())?;
        Ok(unsafe { Database::from_raw(raw) })
    }

    /// Relevant remote File object
    pub fn file(&self) -> Result<RemoteFile, ()> {
        let result = unsafe { BNCollaborationChangesetGetFile(self.as_raw()) };
        ptr::NonNull::new(result)
            .map(|raw| unsafe { RemoteFile::from_raw(raw) })
            .ok_or(())
    }

    /// List of snapshot ids in the database
    pub fn snapshot_ids(&self) -> Result<Array<SnapshotId>, ()> {
        let mut count = 0;
        let result = unsafe { BNCollaborationChangesetGetSnapshotIds(self.as_raw(), &mut count) };
        (!result.is_null())
            .then(|| unsafe { Array::new(result, count, ()) })
            .ok_or(())
    }

    /// Relevant remote author User
    pub fn author(&self) -> Result<User, ()> {
        let result = unsafe { BNCollaborationChangesetGetAuthor(self.as_raw()) };
        ptr::NonNull::new(result)
            .map(|raw| unsafe { User::from_raw(raw) })
            .ok_or(())
    }

    /// Changeset name
    pub fn name(&self) -> BnString {
        let result = unsafe { BNCollaborationChangesetGetName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Set the name of the changeset, e.g. in a name changeset function.
    pub fn set_name<S: BnStrCompatible>(&self, value: S) -> bool {
        let value = value.into_bytes_with_nul();
        unsafe {
            BNCollaborationChangesetSetName(
                self.as_raw(),
                value.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }
}

impl CoreArrayProvider for Changeset {
    type Raw = *mut BNCollaborationChangeset;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for Changeset {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationChangesetList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

pub struct SnapshotId;
impl CoreArrayProvider for SnapshotId {
    type Raw = i64;
    type Context = ();
    type Wrapped<'a> = i64;
}

unsafe impl CoreArrayProviderInner for SnapshotId {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNCollaborationFreeSnapshotIdList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        *raw
    }
}
