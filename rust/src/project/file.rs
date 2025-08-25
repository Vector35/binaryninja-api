use crate::project::{systime_from_bntime, Project, ProjectFolder};
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnString, IntoCStr};
use binaryninjacore_sys::{
    BNFreeProjectFile, BNFreeProjectFileList, BNNewProjectFileReference, BNProjectFile,
    BNProjectFileExistsOnDisk, BNProjectFileExport, BNProjectFileGetCreationTimestamp,
    BNProjectFileGetDescription, BNProjectFileGetFolder, BNProjectFileGetId, BNProjectFileGetName,
    BNProjectFileGetPathInProject, BNProjectFileGetPathOnDisk, BNProjectFileGetProject,
    BNProjectFileSetDescription, BNProjectFileSetFolder, BNProjectFileSetName,
};
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::ptr::{null_mut, NonNull};
use std::time::SystemTime;

#[repr(transparent)]
pub struct ProjectFile {
    pub(crate) handle: NonNull<BNProjectFile>,
}

impl ProjectFile {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNProjectFile>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNProjectFile>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Get the project that owns this file
    pub fn project(&self) -> Ref<Project> {
        unsafe {
            Project::ref_from_raw(
                NonNull::new(BNProjectFileGetProject(self.handle.as_ptr())).unwrap(),
            )
        }
    }

    /// Get the path on disk to this file's contents
    pub fn path_on_disk(&self) -> Option<PathBuf> {
        if !self.exists_on_disk() {
            return None;
        }
        let path_str =
            unsafe { BnString::into_string(BNProjectFileGetPathOnDisk(self.handle.as_ptr())) };
        Some(PathBuf::from(path_str))
    }

    /// Get the path in the project to this file's contents
    pub fn path_in_project(&self) -> PathBuf {
        let path_str =
            unsafe { BnString::into_string(BNProjectFileGetPathInProject(self.handle.as_ptr())) };
        PathBuf::from(path_str)
    }

    /// Check if this file's contents exist on disk
    pub fn exists_on_disk(&self) -> bool {
        unsafe { BNProjectFileExistsOnDisk(self.handle.as_ptr()) }
    }

    /// Get the unique id of this file
    pub fn id(&self) -> String {
        unsafe { BnString::into_string(BNProjectFileGetId(self.handle.as_ptr())) }
    }

    /// Get the name of this file
    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNProjectFileGetName(self.handle.as_ptr())) }
    }

    /// Set the name of this file
    pub fn set_name(&self, value: &str) -> bool {
        let value_raw = value.to_cstr();
        unsafe { BNProjectFileSetName(self.handle.as_ptr(), value_raw.as_ptr()) }
    }

    /// Get the description of this file
    pub fn description(&self) -> String {
        unsafe { BnString::into_string(BNProjectFileGetDescription(self.handle.as_ptr())) }
    }

    /// Set the description of this file
    pub fn set_description(&self, value: &str) -> bool {
        let value_raw = value.to_cstr();
        unsafe { BNProjectFileSetDescription(self.handle.as_ptr(), value_raw.as_ptr()) }
    }

    /// Get the file creation time
    pub fn creation_time(&self) -> SystemTime {
        systime_from_bntime(unsafe { BNProjectFileGetCreationTimestamp(self.handle.as_ptr()) })
            .unwrap()
    }

    /// Get the folder that contains this file
    pub fn folder(&self) -> Option<Ref<ProjectFolder>> {
        let result = unsafe { BNProjectFileGetFolder(self.handle.as_ptr()) };
        NonNull::new(result).map(|handle| unsafe { ProjectFolder::ref_from_raw(handle) })
    }

    /// Set the folder that contains this file
    pub fn set_folder(&self, folder: Option<&ProjectFolder>) -> bool {
        let folder_handle = folder.map(|x| x.handle.as_ptr()).unwrap_or(null_mut());
        unsafe { BNProjectFileSetFolder(self.handle.as_ptr(), folder_handle) }
    }

    /// Export this file to disk, `true' if the export succeeded
    ///
    /// * `dest` - Destination file path for the exported contents, passing a directory will append the file name.
    pub fn export(&self, dest: &Path) -> bool {
        let dest_raw = dest.to_cstr();
        unsafe { BNProjectFileExport(self.handle.as_ptr(), dest_raw.as_ptr()) }
    }
}

impl Debug for ProjectFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectFile")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("description", &self.description())
            .field("creation_time", &self.creation_time())
            .field("exists_on_disk", &self.exists_on_disk())
            .field("project", &self.project())
            .field("folder", &self.folder())
            .finish()
    }
}

unsafe impl Send for ProjectFile {}
unsafe impl Sync for ProjectFile {}

impl ToOwned for ProjectFile {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for ProjectFile {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewProjectFileReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeProjectFile(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for ProjectFile {
    type Raw = *mut BNProjectFile;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for ProjectFile {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeProjectFileList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}
