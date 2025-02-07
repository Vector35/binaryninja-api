use binaryninjacore_sys::*;
use std::ffi::c_char;
use std::ptr::NonNull;

use super::{RemoteFile, RemoteUser};

use crate::database::snapshot::SnapshotId;
use crate::database::Database;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};

/// A collection of snapshots in a local database
#[repr(transparent)]
pub struct Changeset {
    handle: NonNull<BNCollaborationChangeset>,
}

impl Changeset {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNCollaborationChangeset>) -> Self {
        Self { handle }
    }

    #[allow(unused)]
    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNCollaborationChangeset>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Owning database for snapshots
    pub fn database(&self) -> Result<Database, ()> {
        let result = unsafe { BNCollaborationChangesetGetDatabase(self.handle.as_ptr()) };
        let raw = NonNull::new(result).ok_or(())?;
        Ok(unsafe { Database::from_raw(raw) })
    }

    /// Relevant remote File object
    pub fn file(&self) -> Result<Ref<RemoteFile>, ()> {
        let result = unsafe { BNCollaborationChangesetGetFile(self.handle.as_ptr()) };
        NonNull::new(result)
            .map(|raw| unsafe { RemoteFile::ref_from_raw(raw) })
            .ok_or(())
    }

    /// List of snapshot ids in the database
    pub fn snapshot_ids(&self) -> Result<Array<SnapshotId>, ()> {
        let mut count = 0;
        let result =
            unsafe { BNCollaborationChangesetGetSnapshotIds(self.handle.as_ptr(), &mut count) };
        (!result.is_null())
            .then(|| unsafe { Array::new(result, count, ()) })
            .ok_or(())
    }

    /// Relevant remote author User
    pub fn author(&self) -> Result<Ref<RemoteUser>, ()> {
        let result = unsafe { BNCollaborationChangesetGetAuthor(self.handle.as_ptr()) };
        NonNull::new(result)
            .map(|raw| unsafe { RemoteUser::ref_from_raw(raw) })
            .ok_or(())
    }

    /// Changeset name
    pub fn name(&self) -> BnString {
        let result = unsafe { BNCollaborationChangesetGetName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Set the name of the changeset, e.g. in a name changeset function.
    pub fn set_name<S: BnStrCompatible>(&self, value: S) -> bool {
        let value = value.into_bytes_with_nul();
        unsafe {
            BNCollaborationChangesetSetName(
                self.handle.as_ptr(),
                value.as_ref().as_ptr() as *const c_char,
            )
        }
    }
}

impl ToOwned for Changeset {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Changeset {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewCollaborationChangesetReference(handle.handle.as_ptr()))
                .unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeCollaborationChangeset(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for Changeset {
    type Raw = *mut BNCollaborationChangeset;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for Changeset {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationChangesetList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}
