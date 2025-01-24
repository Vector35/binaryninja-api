use super::Remote;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};
use binaryninjacore_sys::*;
use std::ffi::c_char;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ptr::NonNull;

#[repr(transparent)]
pub struct RemoteGroup {
    pub(crate) handle: NonNull<BNCollaborationGroup>,
}

impl RemoteGroup {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNCollaborationGroup>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNCollaborationGroup>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Owning Remote
    pub fn remote(&self) -> Result<Ref<Remote>, ()> {
        let value = unsafe { BNCollaborationGroupGetRemote(self.handle.as_ptr()) };
        NonNull::new(value)
            .map(|handle| unsafe { Remote::ref_from_raw(handle) })
            .ok_or(())
    }

    /// Web api endpoint url
    pub fn url(&self) -> BnString {
        let value = unsafe { BNCollaborationGroupGetUrl(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Unique id
    pub fn id(&self) -> GroupId {
        GroupId(unsafe { BNCollaborationGroupGetId(self.handle.as_ptr()) })
    }

    /// Group name
    pub fn name(&self) -> BnString {
        let value = unsafe { BNCollaborationGroupGetName(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Set group name
    /// You will need to push the group to update the Remote.
    pub fn set_name<U: BnStrCompatible>(&self, name: U) {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNCollaborationGroupSetName(
                self.handle.as_ptr(),
                name.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Get list of users in the group
    pub fn users(&self) -> Result<(Array<BnString>, Array<BnString>), ()> {
        let mut usernames = std::ptr::null_mut();
        let mut user_ids = std::ptr::null_mut();
        let mut count = 0;
        // TODO: This should only fail if collaboration is not supported.
        // TODO: Because you should not have a RemoteGroup at that point we can ignore?
        let success = unsafe {
            BNCollaborationGroupGetUsers(
                self.handle.as_ptr(),
                &mut user_ids,
                &mut usernames,
                &mut count,
            )
        };
        success
            .then(|| unsafe {
                let ids = Array::new(user_ids, count, ());
                let users = Array::new(usernames, count, ());
                (ids, users)
            })
            .ok_or(())
    }

    // TODO: Are any permissions required to the set the remote group users?
    /// Set the list of users in a group by their usernames.
    /// You will need to push the group to update the Remote.
    pub fn set_users<I>(&self, usernames: I) -> Result<(), ()>
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
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect();
        // TODO: This should only fail if collaboration is not supported.
        // TODO: Because you should not have a RemoteGroup at that point we can ignore?
        // TODO: Do you need any permissions to do this?
        let success = unsafe {
            BNCollaborationGroupSetUsernames(
                self.handle.as_ptr(),
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
                self.handle.as_ptr(),
                username.as_ref().as_ptr() as *const c_char,
            )
        }
    }
}

impl PartialEq for RemoteGroup {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for RemoteGroup {}

impl ToOwned for RemoteGroup {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for RemoteGroup {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewCollaborationGroupReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeCollaborationGroup(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for RemoteGroup {
    type Raw = *mut BNCollaborationGroup;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for RemoteGroup {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationGroupList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(pub u64);

impl Display for GroupId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl CoreArrayProvider for GroupId {
    type Raw = u64;
    type Context = ();
    type Wrapped<'a> = GroupId;
}

unsafe impl CoreArrayProviderInner for GroupId {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNCollaborationFreeIdList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        GroupId(*raw)
    }
}
