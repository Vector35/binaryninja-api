use super::Remote;
use binaryninjacore_sys::*;
use std::ffi::c_char;
use std::ptr::NonNull;

use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};

#[repr(transparent)]
pub struct RemoteUser {
    pub(crate) handle: NonNull<BNCollaborationUser>,
}

impl RemoteUser {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNCollaborationUser>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNCollaborationUser>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Owning Remote
    pub fn remote(&self) -> Result<Ref<Remote>, ()> {
        let value = unsafe { BNCollaborationUserGetRemote(self.handle.as_ptr()) };
        let handle = NonNull::new(value).ok_or(())?;
        Ok(unsafe { Remote::ref_from_raw(handle) })
    }

    /// Web api endpoint url
    pub fn url(&self) -> BnString {
        let value = unsafe { BNCollaborationUserGetUrl(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Unique id
    pub fn id(&self) -> BnString {
        let value = unsafe { BNCollaborationUserGetId(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// User's login username
    pub fn username(&self) -> BnString {
        let value = unsafe { BNCollaborationUserGetUsername(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Set user's username. You will need to push the user to update the Remote
    pub fn set_username<U: BnStrCompatible>(&self, username: U) -> Result<(), ()> {
        let username = username.into_bytes_with_nul();
        let result = unsafe {
            BNCollaborationUserSetUsername(
                self.handle.as_ptr(),
                username.as_ref().as_ptr() as *const c_char,
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
        let value = unsafe { BNCollaborationUserGetEmail(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Set user's email. You will need to push the user to update the Remote
    pub fn set_email<U: BnStrCompatible>(&self, email: U) -> Result<(), ()> {
        let username = email.into_bytes_with_nul();
        let result = unsafe {
            BNCollaborationUserSetEmail(
                self.handle.as_ptr(),
                username.as_ref().as_ptr() as *const c_char,
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
        let value = unsafe { BNCollaborationUserGetLastLogin(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// If the user account is active and can log in
    pub fn is_active(&self) -> bool {
        unsafe { BNCollaborationUserIsActive(self.handle.as_ptr()) }
    }

    /// Enable/disable a user account. You will need to push the user to update the Remote
    pub fn set_is_active(&self, value: bool) -> Result<(), ()> {
        if unsafe { BNCollaborationUserSetIsActive(self.handle.as_ptr(), value) } {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl PartialEq for RemoteUser {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for RemoteUser {}

impl ToOwned for RemoteUser {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for RemoteUser {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewCollaborationUserReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeCollaborationUser(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for RemoteUser {
    type Raw = *mut BNCollaborationUser;
    type Context = ();
    type Wrapped<'a> = Guard<'a, RemoteUser>;
}

unsafe impl CoreArrayProviderInner for RemoteUser {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationUserList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}
