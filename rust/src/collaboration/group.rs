use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use super::Remote;

use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

/// Struct representing a remote Group
#[repr(transparent)]
pub struct Group {
    handle: ptr::NonNull<BNCollaborationGroup>,
}

impl Drop for Group {
    fn drop(&mut self) {
        unsafe { BNFreeCollaborationGroup(self.as_raw()) }
    }
}

impl PartialEq for Group {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for Group {}

impl Clone for Group {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(
                ptr::NonNull::new(BNNewCollaborationGroupReference(self.as_raw())).unwrap(),
            )
        }
    }
}

impl Group {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNCollaborationGroup>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNCollaborationGroup) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNCollaborationGroup {
        &mut *self.handle.as_ptr()
    }

    /// Owning Remote
    pub fn remote(&self) -> Result<Remote, ()> {
        let value = unsafe { BNCollaborationGroupGetRemote(self.as_raw()) };
        ptr::NonNull::new(value)
            .map(|handle| unsafe { Remote::from_raw(handle) })
            .ok_or(())
    }

    /// Web api endpoint url
    pub fn url(&self) -> BnString {
        let value = unsafe { BNCollaborationGroupGetUrl(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Unique id
    pub fn id(&self) -> u64 {
        unsafe { BNCollaborationGroupGetId(self.as_raw()) }
    }

    /// Group name
    pub fn name(&self) -> BnString {
        let value = unsafe { BNCollaborationGroupGetName(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Set group name
    /// You will need to push the group to update the Remote.
    pub fn set_name<U: BnStrCompatible>(&self, name: U) {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNCollaborationGroupSetName(self.as_raw(), name.as_ref().as_ptr() as *const ffi::c_char)
        }
    }

    /// Get list of users in the group
    pub fn users(&self) -> Result<(Array<BnString>, Array<BnString>), ()> {
        let mut usernames = ptr::null_mut();
        let mut user_ids = ptr::null_mut();
        let mut count = 0;
        let success = unsafe {
            BNCollaborationGroupGetUsers(self.as_raw(), &mut user_ids, &mut usernames, &mut count)
        };
        success
            .then(|| unsafe {
                let ids = Array::new(user_ids, count, ());
                let users = Array::new(usernames, count, ());
                (ids, users)
            })
            .ok_or(())
    }

    /// Set the list of users in a group by their usernames.
    /// You will need to push the group to update the Remote.
    pub fn set_user<I>(&self, usernames: I) -> Result<(), ()>
    where
        I: IntoIterator,
        I::Item: BnStrCompatible,
    {
        let usernames: Vec<_> = usernames
            .into_iter()
            .map(|u| u.into_bytes_with_nul())
            .collect();
        let mut usernames_raw: Vec<_> = usernames
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect();
        let success = unsafe {
            BNCollaborationGroupSetUsernames(
                self.as_raw(),
                usernames_raw.as_mut_ptr(),
                usernames_raw.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Test if a group has a user with the given username
    pub fn contains_user<U: BnStrCompatible>(&self, username: U) -> bool {
        let username = username.into_bytes_with_nul();
        unsafe {
            BNCollaborationGroupContainsUser(
                self.as_raw(),
                username.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }
}

impl CoreArrayProvider for Group {
    type Raw = *mut BNCollaborationGroup;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for Group {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationGroupList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

pub struct Id(pub u64);
impl Id {
    pub fn as_raw(&self) -> u64 {
        self.0
    }
}
impl CoreArrayProvider for Id {
    type Raw = u64;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for Id {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNCollaborationFreeIdList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Id(*raw)
    }
}
