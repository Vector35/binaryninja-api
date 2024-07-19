use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use super::Remote;

use crate::rc::{CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

/// Class representing a remote User
#[repr(transparent)]
pub struct User {
    handle: ptr::NonNull<BNCollaborationUser>,
}

impl Drop for User {
    fn drop(&mut self) {
        unsafe { BNFreeCollaborationUser(self.as_raw()) }
    }
}

impl PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for User {}

impl Clone for User {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(
                ptr::NonNull::new(BNNewCollaborationUserReference(self.as_raw())).unwrap(),
            )
        }
    }
}

impl User {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNCollaborationUser>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNCollaborationUser) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNCollaborationUser {
        &mut *self.handle.as_ptr()
    }

    /// Owning Remote
    pub fn remote(&self) -> Result<Remote, ()> {
        let value = unsafe { BNCollaborationUserGetRemote(self.as_raw()) };
        let handle = ptr::NonNull::new(value).ok_or(())?;
        Ok(unsafe { Remote::from_raw(handle) })
    }

    /// Web api endpoint url
    pub fn url(&self) -> BnString {
        let value = unsafe { BNCollaborationUserGetUrl(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Unique id
    pub fn id(&self) -> BnString {
        let value = unsafe { BNCollaborationUserGetId(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// User's login username
    pub fn username(&self) -> BnString {
        let value = unsafe { BNCollaborationUserGetUsername(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Set user's username. You will need to push the user to update the Remote
    pub fn set_username<U: BnStrCompatible>(&self, username: U) -> Result<(), ()> {
        let username = username.into_bytes_with_nul();
        let result = unsafe {
            BNCollaborationUserSetUsername(
                self.as_raw(),
                username.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        if result {
            Ok(())
        } else {
            Err(())
        }
    }

    /// User's email address
    pub fn email(&self) -> BnString {
        let value = unsafe { BNCollaborationUserGetEmail(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Set user's email. You will need to push the user to update the Remote
    pub fn set_email<U: BnStrCompatible>(&self, email: U) -> Result<(), ()> {
        let username = email.into_bytes_with_nul();
        let result = unsafe {
            BNCollaborationUserSetEmail(
                self.as_raw(),
                username.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        if result {
            Ok(())
        } else {
            Err(())
        }
    }

    /// String representing the last date the user logged in
    pub fn last_login(&self) -> BnString {
        let value = unsafe { BNCollaborationUserGetLastLogin(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// If the user account is active and can log in
    pub fn is_active(&self) -> bool {
        unsafe { BNCollaborationUserIsActive(self.as_raw()) }
    }

    /// Enable/disable a user account. You will need to push the user to update the Remote
    pub fn set_is_active(&self, value: bool) -> Result<(), ()> {
        if unsafe { BNCollaborationUserSetIsActive(self.as_raw(), value) } {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl CoreArrayProvider for User {
    type Raw = *mut BNCollaborationUser;
    type Context = ();
    type Wrapped<'a> = &'a User;
}

unsafe impl CoreArrayProviderInner for User {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationUserList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}
