use super::{Remote, RemoteProject};
use binaryninjacore_sys::*;
use std::ptr::NonNull;

use crate::project::folder::ProjectFolder;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnString, IntoCStr};

#[repr(transparent)]
pub struct RemoteFolder {
    pub(crate) handle: NonNull<BNRemoteFolder>,
}

impl RemoteFolder {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNRemoteFolder>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNRemoteFolder>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    // TODO: Rename to local folder?
    // TODO: Bump this to an option
    /// Get the core folder associated with this remote folder.
    pub fn core_folder(&self) -> Result<Ref<ProjectFolder>, ()> {
        let result = unsafe { BNRemoteFolderGetCoreFolder(self.handle.as_ptr()) };
        NonNull::new(result)
            .map(|handle| unsafe { ProjectFolder::ref_from_raw(handle) })
            .ok_or(())
    }

    // TODO: Bump this to an option
    /// Get the owning project of this folder.
    pub fn project(&self) -> Result<Ref<RemoteProject>, ()> {
        let result = unsafe { BNRemoteFolderGetProject(self.handle.as_ptr()) };
        NonNull::new(result)
            .map(|handle| unsafe { RemoteProject::ref_from_raw(handle) })
            .ok_or(())
    }

    // TODO: Bump this to an option
    /// Get the owning remote of this folder.
    pub fn remote(&self) -> Result<Ref<Remote>, ()> {
        let result = unsafe { BNRemoteFolderGetRemote(self.handle.as_ptr()) };
        NonNull::new(result)
            .map(|handle| unsafe { Remote::ref_from_raw(handle) })
            .ok_or(())
    }

    // TODO: Should this pull folders?
    // TODO: If it does we keep the result?
    /// Get the parent folder, if available.
    pub fn parent(&self) -> Result<Option<Ref<RemoteFolder>>, ()> {
        let project = self.project()?;
        // TODO: This sync should be removed?
        if !project.has_pulled_folders() {
            project.pull_folders()?;
        }
        let mut parent_handle = std::ptr::null_mut();
        let success = unsafe { BNRemoteFolderGetParent(self.handle.as_ptr(), &mut parent_handle) };
        success
            .then(|| {
                NonNull::new(parent_handle)
                    .map(|handle| unsafe { RemoteFolder::ref_from_raw(handle) })
            })
            .ok_or(())
    }

    /// Set the parent folder. You will need to push the folder to update the remote version.
    pub fn set_parent(&self, parent: Option<&RemoteFolder>) -> Result<(), ()> {
        let parent_handle = parent.map_or(std::ptr::null_mut(), |p| p.handle.as_ptr());
        let success = unsafe { BNRemoteFolderSetParent(self.handle.as_ptr(), parent_handle) };
        success.then_some(()).ok_or(())
    }

    /// Get web API endpoint URL.
    pub fn url(&self) -> String {
        let result = unsafe { BNRemoteFolderGetUrl(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Get unique ID.
    pub fn id(&self) -> String {
        let result = unsafe { BNRemoteFolderGetId(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Unique id of parent folder, if there is a parent. None, otherwise
    pub fn parent_id(&self) -> Option<BnString> {
        let mut parent_id = std::ptr::null_mut();
        let have = unsafe { BNRemoteFolderGetParentId(self.handle.as_ptr(), &mut parent_id) };
        have.then(|| unsafe { BnString::from_raw(parent_id) })
    }

    /// Displayed name of folder
    pub fn name(&self) -> String {
        let result = unsafe { BNRemoteFolderGetName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Set the display name of the folder. You will need to push the folder to update the remote version.
    pub fn set_name(&self, name: &str) -> Result<(), ()> {
        let name = name.to_cstr();
        let success = unsafe { BNRemoteFolderSetName(self.handle.as_ptr(), name.as_ptr()) };
        success.then_some(()).ok_or(())
    }

    /// Description of the folder
    pub fn description(&self) -> String {
        let result = unsafe { BNRemoteFolderGetDescription(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Set the description of the folder. You will need to push the folder to update the remote version.
    pub fn set_description(&self, description: &str) -> Result<(), ()> {
        let description = description.to_cstr();
        let success =
            unsafe { BNRemoteFolderSetDescription(self.handle.as_ptr(), description.as_ptr()) };
        success.then_some(()).ok_or(())
    }
}

impl PartialEq for RemoteFolder {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for RemoteFolder {}

impl ToOwned for RemoteFolder {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for RemoteFolder {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewRemoteFolderReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeRemoteFolder(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for RemoteFolder {
    type Raw = *mut BNRemoteFolder;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for RemoteFolder {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeRemoteFolderList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}
