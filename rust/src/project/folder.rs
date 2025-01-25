use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::project::Project;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};
use binaryninjacore_sys::{
    BNFreeProjectFolder, BNFreeProjectFolderList, BNNewProjectFolderReference, BNProjectFolder,
    BNProjectFolderExport, BNProjectFolderGetDescription, BNProjectFolderGetId,
    BNProjectFolderGetName, BNProjectFolderGetParent, BNProjectFolderGetProject,
    BNProjectFolderSetDescription, BNProjectFolderSetName, BNProjectFolderSetParent,
};
use std::ffi::{c_char, c_void};
use std::fmt::Debug;
use std::ptr::{null_mut, NonNull};

#[repr(transparent)]
pub struct ProjectFolder {
    pub(crate) handle: NonNull<BNProjectFolder>,
}

impl ProjectFolder {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNProjectFolder>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNProjectFolder>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Get the project that owns this folder
    pub fn project(&self) -> Ref<Project> {
        unsafe {
            Project::ref_from_raw(
                NonNull::new(BNProjectFolderGetProject(self.handle.as_ptr())).unwrap(),
            )
        }
    }

    /// Get the unique id of this folder
    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectFolderGetId(self.handle.as_ptr())) }
    }

    /// Get the name of this folder
    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectFolderGetName(self.handle.as_ptr())) }
    }

    /// Set the name of this folder
    pub fn set_name<S: BnStrCompatible>(&self, value: S) -> bool {
        let value_raw = value.into_bytes_with_nul();
        unsafe {
            BNProjectFolderSetName(
                self.handle.as_ptr(),
                value_raw.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Get the description of this folder
    pub fn description(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectFolderGetDescription(self.handle.as_ptr())) }
    }

    /// Set the description of this folder
    pub fn set_description<S: BnStrCompatible>(&self, value: S) -> bool {
        let value_raw = value.into_bytes_with_nul();
        unsafe {
            BNProjectFolderSetDescription(
                self.handle.as_ptr(),
                value_raw.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Get the folder that contains this folder
    pub fn parent(&self) -> Option<Ref<ProjectFolder>> {
        let result = unsafe { BNProjectFolderGetParent(self.handle.as_ptr()) };
        NonNull::new(result).map(|handle| unsafe { ProjectFolder::ref_from_raw(handle) })
    }

    /// Set the folder that contains this folder
    pub fn set_folder(&self, folder: Option<&ProjectFolder>) -> bool {
        let folder_handle = folder.map(|x| x.handle.as_ptr()).unwrap_or(null_mut());
        unsafe { BNProjectFolderSetParent(self.handle.as_ptr(), folder_handle) }
    }

    // TODO: Take Path?
    /// Recursively export this folder to disk, returns `true' if the export succeeded
    ///
    /// * `dest` - Destination path for the exported contents
    pub fn export<S: BnStrCompatible>(&self, dest: S) -> bool {
        self.export_with_progress(dest, NoProgressCallback)
    }

    // TODO: Take Path?
    /// Recursively export this folder to disk, returns `true' if the export succeeded
    ///
    /// * `dest` - Destination path for the exported contents
    /// * `progress` - [`ProgressCallback`] that will be called as contents are exporting
    pub fn export_with_progress<S, P>(&self, dest: S, mut progress: P) -> bool
    where
        S: BnStrCompatible,
        P: ProgressCallback,
    {
        let dest_raw = dest.into_bytes_with_nul();

        let success = unsafe {
            BNProjectFolderExport(
                self.handle.as_ptr(),
                dest_raw.as_ref().as_ptr() as *const c_char,
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
            )
        };

        success
    }
}

impl Debug for ProjectFolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectFolder")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("description", &self.description())
            .finish()
    }
}

impl ToOwned for ProjectFolder {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for ProjectFolder {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewProjectFolderReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeProjectFolder(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for ProjectFolder {
    type Raw = *mut BNProjectFolder;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for ProjectFolder {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeProjectFolderList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}
