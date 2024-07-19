use core::{mem, ptr};

use std::num::NonZeroU64;

use binaryninjacore_sys::*;

use super::{Remote, RemoteProject};

use crate::rc::{CoreArrayProvider, CoreArrayProviderInner};
use crate::string::BnString;

pub type CollaborationPermissionLevel = BNCollaborationPermissionLevel;

/// Struct representing a permission grant for a user or group on a project.
#[repr(transparent)]
pub struct Permission {
    handle: ptr::NonNull<BNCollaborationPermission>,
}

impl Drop for Permission {
    fn drop(&mut self) {
        unsafe { BNFreeCollaborationPermission(self.as_raw()) }
    }
}

impl PartialEq for Permission {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for Permission {}

impl Clone for Permission {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(
                ptr::NonNull::new(BNNewCollaborationPermissionReference(self.as_raw())).unwrap(),
            )
        }
    }
}

impl Permission {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNCollaborationPermission>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNCollaborationPermission) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNCollaborationPermission {
        &mut *self.handle.as_ptr()
    }

    pub fn remote(&self) -> Result<Remote, ()> {
        let result = unsafe { BNCollaborationPermissionGetRemote(self.as_raw()) };
        ptr::NonNull::new(result)
            .map(|handle| unsafe { Remote::from_raw(handle) })
            .ok_or(())
    }

    pub fn project(&self) -> Result<RemoteProject, ()> {
        let result = unsafe { BNCollaborationPermissionGetProject(self.as_raw()) };
        ptr::NonNull::new(result)
            .map(|handle| unsafe { RemoteProject::from_raw(handle) })
            .ok_or(())
    }

    /// Web api endpoint url
    pub fn url(&self) -> BnString {
        let value = unsafe { BNCollaborationPermissionGetUrl(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// unique id
    pub fn id(&self) -> BnString {
        let value = unsafe { BNCollaborationPermissionGetId(self.as_raw()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    /// Level of permission
    pub fn level(&self) -> CollaborationPermissionLevel {
        unsafe { BNCollaborationPermissionGetLevel(self.as_raw()) }
    }

    /// Change the level of the permission
    /// You will need to push the group to update the Remote.
    pub fn set_level(&self, level: CollaborationPermissionLevel) {
        unsafe { BNCollaborationPermissionSetLevel(self.as_raw(), level) }
    }

    /// Id of affected group
    pub fn group_id(&self) -> Option<NonZeroU64> {
        let value = unsafe { BNCollaborationPermissionGetGroupId(self.as_raw()) };
        NonZeroU64::new(value)
    }

    /// Name of affected group
    pub fn group_name(&self) -> Option<BnString> {
        let value = unsafe { BNCollaborationPermissionGetGroupName(self.as_raw()) };
        assert!(!value.is_null());
        let result = unsafe { BnString::from_raw(value) };
        (!result.is_empty()).then_some(result)
    }

    /// Id of affected user
    pub fn user_id(&self) -> Option<BnString> {
        let value = unsafe { BNCollaborationPermissionGetUserId(self.as_raw()) };
        assert!(!value.is_null());
        let result = unsafe { BnString::from_raw(value) };
        (!result.is_empty()).then_some(result)
    }

    /// Name of affected user
    pub fn username(&self) -> Option<BnString> {
        let value = unsafe { BNCollaborationPermissionGetUsername(self.as_raw()) };
        assert!(!value.is_null());
        let result = unsafe { BnString::from_raw(value) };
        (!result.is_empty()).then_some(result)
    }

    /// If the permission grants the affect user/group the ability to read files in the project
    pub fn can_view(&self) -> bool {
        unsafe { BNCollaborationPermissionCanView(self.as_raw()) }
    }

    /// If the permission grants the affect user/group the ability to edit files in the project
    pub fn can_edit(&self) -> bool {
        unsafe { BNCollaborationPermissionCanEdit(self.as_raw()) }
    }

    /// If the permission grants the affect user/group the ability to administer the project
    pub fn can_admin(&self) -> bool {
        unsafe { BNCollaborationPermissionCanAdmin(self.as_raw()) }
    }
}

impl CoreArrayProvider for Permission {
    type Raw = *mut BNCollaborationPermission;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for Permission {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCollaborationPermissionList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}
