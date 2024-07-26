use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use super::{Remote, RemoteProject};

use crate::ffi::ProgressCallbackNop;
use crate::project::ProjectFolder;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

/// Struct representing a remote folder in a project.
#[repr(transparent)]
pub struct RemoteFolder {
    handle: ptr::NonNull<BNRemoteFolder>,
}

impl Drop for RemoteFolder {
    fn drop(&mut self) {
        unsafe { BNFreeRemoteFolder(self.as_raw()) }
    }
}

impl PartialEq for RemoteFolder {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for RemoteFolder {}

impl Clone for RemoteFolder {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewRemoteFolderReference(self.as_raw())).unwrap())
        }
    }
}

impl RemoteFolder {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNRemoteFolder>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNRemoteFolder) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNRemoteFolder {
        &mut *self.handle.as_ptr()
    }

    /// Get the core folder associated with this remote folder.
    pub fn core_folder(&self) -> Result<ProjectFolder, ()> {
        let result = unsafe { BNRemoteFolderGetCoreFolder(self.as_raw()) };
        ptr::NonNull::new(result)
            .map(|handle| unsafe { ProjectFolder::from_raw(handle) })
            .ok_or(())
    }

    /// Get the owning project of this folder.
    pub fn project(&self) -> Result<RemoteProject, ()> {
        let result = unsafe { BNRemoteFolderGetProject(self.as_raw()) };
        ptr::NonNull::new(result)
            .map(|handle| unsafe { RemoteProject::from_raw(handle) })
            .ok_or(())
    }

    /// Get the owning remote of this folder.
    pub fn remote(&self) -> Result<Remote, ()> {
        let result = unsafe { BNRemoteFolderGetRemote(self.as_raw()) };
        ptr::NonNull::new(result)
            .map(|handle| unsafe { Remote::from_raw(handle) })
            .ok_or(())
    }

    /// Get the parent folder, if available.
    pub fn parent(&self) -> Result<Option<RemoteFolder>, ()> {
        let project = self.project()?;
        if !project.has_pulled_folders() {
            project.pull_folders(ProgressCallbackNop)?;
        }
        let mut parent_handle = ptr::null_mut();
        let success = unsafe { BNRemoteFolderGetParent(self.as_raw(), &mut parent_handle) };
        success
            .then(|| {
                ptr::NonNull::new(parent_handle)
                    .map(|handle| unsafe { RemoteFolder::from_raw(handle) })
            })
            .ok_or(())
    }

    /// Set the parent folder. You will need to push the folder to update the remote version.
    pub fn set_parent(&self, parent: Option<&RemoteFolder>) -> Result<(), ()> {
        let parent_handle = parent.map_or(ptr::null_mut(), |p| unsafe { p.as_raw() } as *mut _);
        let success = unsafe { BNRemoteFolderSetParent(self.as_raw(), parent_handle) };
        success.then_some(()).ok_or(())
    }

    /// Get web API endpoint URL.
    pub fn url(&self) -> BnString {
        let result = unsafe { BNRemoteFolderGetUrl(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Get unique ID.
    pub fn id(&self) -> BnString {
        let result = unsafe { BNRemoteFolderGetId(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Unique id of parent folder, if there is a parent. None, otherwise
    pub fn parent_id(&self) -> Option<BnString> {
        let mut parent_id = ptr::null_mut();
        let have = unsafe { BNRemoteFolderGetParentId(self.as_raw(), &mut parent_id) };
        have.then(|| unsafe { BnString::from_raw(parent_id) })
    }

    /// Displayed name of folder
    pub fn name(&self) -> BnString {
        let result = unsafe { BNRemoteFolderGetName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Set the display name of the folder. You will need to push the folder to update the remote version.
    pub fn set_name<S: BnStrCompatible>(&self, name: S) -> Result<(), ()> {
        let name = name.into_bytes_with_nul();
        let success = unsafe {
            BNRemoteFolderSetName(self.as_raw(), name.as_ref().as_ptr() as *const ffi::c_char)
        };
        success.then_some(()).ok_or(())
    }

    /// Description of the folder
    pub fn description(&self) -> BnString {
        let result = unsafe { BNRemoteFolderGetDescription(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Set the description of the folder. You will need to push the folder to update the remote version.
    pub fn set_description<S: BnStrCompatible>(&self, description: S) -> Result<(), ()> {
        let description = description.into_bytes_with_nul();
        let success = unsafe {
            BNRemoteFolderSetDescription(
                self.as_raw(),
                description.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        success.then_some(()).ok_or(())
    }
}

impl CoreArrayProvider for RemoteFolder {
    type Raw = *mut BNRemoteFolder;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for RemoteFolder {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeRemoteFolderList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}
