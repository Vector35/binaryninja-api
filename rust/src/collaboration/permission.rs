use super::{GroupId, Remote, RemoteProject};
use binaryninjacore_sys::*;
use std::ptr::NonNull;

use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::BnString;

pub type CollaborationPermissionLevel = BNCollaborationPermissionLevel;

/// Struct representing a permission grant for a user or group on a project.
#[repr(transparent)]
pub struct Permission {
    pub(crate) handle: NonNull<BNCollaborationPermission>,
}

impl Permission {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNCollaborationPermission>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNCollaborationPermission>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    pub fn remote(&self) -> Result<Ref<Remote>, ()> {
        let result = unsafe { BNCollaborationPermissionGetRemote(self.handle.as_ptr()) };
        NonNull::new(result)
            .map(|handle| unsafe { Remote::ref_from_raw(handle) })
            .ok_or(())
    }

    pub fn project(&self) -> Result<Ref<RemoteProject>, ()> {
        let result = unsafe { BNCollaborationPermissionGetProject(self.handle.as_ptr()) };
        NonNull::new(result)
            .map(|handle| unsafe { RemoteProject::ref_from_raw(handle) })
            .ok_or(())
    }

    /// Web api endpoint url
    pub fn url(&self) -> BnString {
        let value = unsafe { BNCollaborationPermissionGetUrl(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// unique id
    pub fn id(&self) -> BnString {
        let value = unsafe { BNCollaborationPermissionGetId(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Level of permission
    pub fn level(&self) -> CollaborationPermissionLevel {
        unsafe { BNCollaborationPermissionGetLevel(self.handle.as_ptr()) }
    }

    /// Change the level of the permission
    /// You will need to push the group to update the Remote.
    pub fn set_level(&self, level: CollaborationPermissionLevel) {
        unsafe { BNCollaborationPermissionSetLevel(self.handle.as_ptr(), level) }
    }

    /// Id of affected group
    pub fn group_id(&self) -> Option<GroupId> {
        let value = unsafe { BNCollaborationPermissionGetGroupId(self.handle.as_ptr()) };
        if value != 0 {
            Some(GroupId(value))
        } else {
            None
        }
    }

    /// Name of affected group
    pub fn group_name(&self) -> Option<BnString> {
        let value = unsafe { BNCollaborationPermissionGetGroupName(self.handle.as_ptr()) };
        assert!(!value.is_null());
        let result = unsafe { BnString::from_raw(value) };
        (!result.is_empty()).then_some(result)
    }

    /// Id of affected user
    pub fn user_id(&self) -> Option<BnString> {
        let value = unsafe { BNCollaborationPermissionGetUserId(self.handle.as_ptr()) };
        assert!(!value.is_null());
        let result = unsafe { BnString::from_raw(value) };
        (!result.is_empty()).then_some(result)
    }

    /// Name of affected user
    pub fn username(&self) -> Option<BnString> {
        let value = unsafe { BNCollaborationPermissionGetUsername(self.handle.as_ptr()) };
        assert!(!value.is_null());
        let result = unsafe { BnString::from_raw(value) };
        (!result.is_empty()).then_some(result)
    }

    /// If the permission grants the affect user/group the ability to read files in the project
    pub fn can_view(&self) -> bool {
        unsafe { BNCollaborationPermissionCanView(self.handle.as_ptr()) }
    }

    /// If the permission grants the affect user/group the ability to edit files in the project
    pub fn can_edit(&self) -> bool {
        unsafe { BNCollaborationPermissionCanEdit(self.handle.as_ptr()) }
    }

    /// If the permission grants the affect user/group the ability to administer the project
    pub fn can_admin(&self) -> bool {
        unsafe { BNCollaborationPermissionCanAdmin(self.handle.as_ptr()) }
    }
}

impl PartialEq for Permission {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for Permission {}

impl ToOwned for Permission {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Permission {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewCollaborationPermissionReference(
                handle.handle.as_ptr(),
            ))
            .unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeCollaborationPermission(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for Permission {
    type Raw = *mut BNCollaborationPermission;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for Permission {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationPermissionList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}
