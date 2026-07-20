use super::Remote;
use crate::collaboration::RemoteUser;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnString, IntoCStr};
use binaryninjacore_sys::*;
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
        unsafe { Ref::new(Self { handle }) }
    }

    /// Owning Remote
    pub fn remote(&self) -> Result<Ref<Remote>, ()> {
        let value = unsafe { BNCollaborationGroupGetRemote(self.handle.as_ptr()) };
        NonNull::new(value)
            .map(|handle| unsafe { Remote::ref_from_raw(handle) })
            .ok_or(())
    }

    /// Web api endpoint url
    pub fn url(&self) -> String {
        let value = unsafe { BNCollaborationGroupGetUrl(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::into_string(value) }
    }

    /// Unique id
    pub fn id(&self) -> GroupId {
        GroupId(unsafe { BNCollaborationGroupGetId(self.handle.as_ptr()) })
    }

    /// Group name
    pub fn name(&self) -> String {
        let value = unsafe { BNCollaborationGroupGetName(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::into_string(value) }
    }

    /// Set group name
    /// You will need to push the group to update the Remote.
    pub fn set_name(&self, name: &str) {
        let name = name.to_cstr();
        unsafe { BNCollaborationGroupSetName(self.handle.as_ptr(), name.as_ptr()) }
    }

    /// Get list of users in the group
    pub fn users(&self) -> Result<Array<RemoteUser>, ()> {
        let mut count = 0;
        // TODO: This should only fail if collaboration is not supported.
        // TODO: Because you should not have a RemoteGroup at that point we can ignore?
        let result = unsafe { BNCollaborationGroupGetUsers(self.handle.as_ptr(), &mut count) };
        (!result.is_null())
            .then(|| unsafe { Array::new(result, count, ()) })
            .ok_or(())
    }

    // TODO: Are any permissions required to the set the remote group users?
    /// Set the list of users in a group.
    /// You will need to push the group to update the Remote.
    pub fn set_users<I>(&self, users: I) -> Result<(), ()>
    where
        I: IntoIterator<Item = Ref<RemoteUser>>,
    {
        let mut users_raw: Vec<_> = users.into_iter().map(|s| s.handle.as_ptr()).collect();
        // TODO: This should only fail if collaboration is not supported.
        // TODO: Because you should not have a RemoteGroup at that point we can ignore?
        // TODO: Do you need any permissions to do this?
        let success = unsafe {
            BNCollaborationGroupSetUsers(
                self.handle.as_ptr(),
                users_raw.as_mut_ptr(),
                users_raw.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Test if a group contains a user
    pub fn contains_user(&self, user: Ref<RemoteUser>) -> bool {
        unsafe { BNCollaborationGroupContainsUser(self.handle.as_ptr(), user.handle.as_ptr()) }
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
        unsafe {
            Ref::new(Self {
                handle: NonNull::new(BNNewCollaborationGroupReference(handle.handle.as_ptr()))
                    .unwrap(),
            })
        }
    }

    unsafe fn dec_ref(handle: &Self) {
        unsafe {
            BNFreeCollaborationGroup(handle.handle.as_ptr());
        }
    }
}

impl CoreArrayProvider for RemoteGroup {
    type Raw = *mut BNCollaborationGroup;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for RemoteGroup {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        unsafe { BNFreeCollaborationGroupList(raw, count) }
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        unsafe {
            let raw_ptr = NonNull::new(*raw).unwrap();
            Guard::new(Self::from_raw(raw_ptr), context)
        }
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
        unsafe { BNCollaborationFreeIdList(raw, count) }
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        GroupId(*raw)
    }
}
