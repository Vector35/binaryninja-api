use std::ptr::{null_mut, NonNull};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{ffi, mem};

use binaryninjacore_sys::*;

use crate::metadata::Metadata;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{BnStrCompatible, BnString};

#[repr(C)]
pub struct Project {
    handle: NonNull<BNProject>,
}

impl Project {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNProject>) -> Self {
        Project { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNProject) -> &Self {
        debug_assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNProject {
        &mut *self.handle.as_ptr()
    }

    pub fn all_open() -> Array<Project> {
        let mut count = 0;
        let result = unsafe { BNGetOpenProjects(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Create a new project
    ///
    /// * `path` - Path to the project directory (.bnpr)
    /// * `name` - Name of the new project
    pub fn create<P: BnStrCompatible, S: BnStrCompatible>(path: P, name: S) -> Self {
        let path_raw = path.into_bytes_with_nul();
        let name_raw = name.into_bytes_with_nul();
        let handle = unsafe {
            BNCreateProject(
                path_raw.as_ref().as_ptr() as *const ffi::c_char,
                name_raw.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        unsafe { Self::from_raw(NonNull::new(handle).unwrap()) }
    }

    /// Open an existing project
    ///
    /// * `path` - Path to the project directory (.bnpr) or project metadata file (.bnpm)
    pub fn open_project<P: BnStrCompatible>(path: P) -> Self {
        let path_raw = path.into_bytes_with_nul();
        let handle = unsafe { BNOpenProject(path_raw.as_ref().as_ptr() as *const ffi::c_char) };
        unsafe { Self::from_raw(NonNull::new(handle).unwrap()) }
    }

    /// Check if the project is currently open
    pub fn is_open(&self) -> bool {
        unsafe { BNProjectIsOpen(self.as_raw()) }
    }

    /// Open a closed project
    pub fn open(&self) -> Result<(), ()> {
        if unsafe { BNProjectOpen(self.as_raw()) } {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Close a open project
    pub fn close(&self) -> Result<(), ()> {
        if unsafe { BNProjectClose(self.as_raw()) } {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Get the unique id of this project
    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectGetId(self.as_raw())) }
    }

    /// Get the path of the project
    pub fn path(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectGetPath(self.as_raw())) }
    }

    /// Get the name of the project
    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectGetName(self.as_raw())) }
    }

    /// Set the name of the project
    pub fn set_name<S: BnStrCompatible>(&self, value: S) {
        let value = value.into_bytes_with_nul();
        unsafe { BNProjectSetName(self.as_raw(), value.as_ref().as_ptr() as *const ffi::c_char) }
    }

    /// Get the description of the project
    pub fn description(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectGetDescription(self.as_raw())) }
    }

    /// Set the description of the project
    pub fn set_description<S: BnStrCompatible>(&self, value: S) {
        let value = value.into_bytes_with_nul();
        unsafe {
            BNProjectSetDescription(self.as_raw(), value.as_ref().as_ptr() as *const ffi::c_char)
        }
    }

    /// Retrieves metadata stored under a key from the project
    pub fn query_metadata<S: BnStrCompatible>(&self, key: S) -> Ref<Metadata> {
        let key = key.into_bytes_with_nul();
        let result = unsafe {
            BNProjectQueryMetadata(self.as_raw(), key.as_ref().as_ptr() as *const ffi::c_char)
        };
        unsafe { Metadata::ref_from_raw(result) }
    }

    /// Stores metadata within the project,
    ///
    /// * `key` - Key under which to store the Metadata object
    /// * `value` - Object to store
    pub fn store_metadata<S: BnStrCompatible>(&self, key: S, value: &Metadata) -> bool {
        let key_raw = key.into_bytes_with_nul();
        unsafe {
            BNProjectStoreMetadata(
                self.as_raw(),
                key_raw.as_ref().as_ptr() as *const ffi::c_char,
                value.handle,
            )
        }
    }

    /// Removes the metadata associated with this `key` from the project
    pub fn remove_metadata<S: BnStrCompatible>(&self, key: S) {
        let key_raw = key.into_bytes_with_nul();
        unsafe {
            BNProjectRemoveMetadata(
                self.as_raw(),
                key_raw.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn push_folder(&self, file: &ProjectFolder) {
        unsafe { BNProjectPushFolder(self.as_raw(), file.as_raw()) }
    }

    /// Recursively create files and folders in the project from a path on disk
    ///
    /// * `path` - Path to folder on disk
    /// * `parent` - Parent folder in the project that will contain the new contents
    /// * `description` - Description for created root folder
    pub fn create_folder_from_path<P, D>(
        &self,
        path: P,
        parent: Option<&ProjectFolder>,
        description: D,
    ) -> Result<ProjectFolder, ()>
    where
        P: BnStrCompatible,
        D: BnStrCompatible,
    {
        let path_raw = path.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let parent_ptr = parent
            .map(|p| unsafe { p.as_raw() as *mut _ })
            .unwrap_or(null_mut());

        unsafe {
            let result = BNProjectCreateFolderFromPath(
                self.as_raw(),
                path_raw.as_ref().as_ptr() as *const ffi::c_char,
                parent_ptr,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
                null_mut(),
                Some(cb_progress_func_nop),
            );
            Ok(ProjectFolder::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Recursively create files and folders in the project from a path on disk
    ///
    /// * `path` - Path to folder on disk
    /// * `parent` - Parent folder in the project that will contain the new contents
    /// * `description` - Description for created root folder
    /// * `progress_func` - Progress function that will be called
    pub fn create_folder_from_path_with_progress<P, D, F>(
        &self,
        path: P,
        parent: Option<&ProjectFolder>,
        description: D,
        mut progress_func: F,
    ) -> Result<ProjectFolder, ()>
    where
        P: BnStrCompatible,
        D: BnStrCompatible,
        F: FnMut(usize, usize) -> bool,
    {
        let path_raw = path.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let parent_ptr = parent
            .map(|p| unsafe { p.as_raw() as *mut _ })
            .unwrap_or(null_mut());

        let progress_ctx = &mut progress_func as *mut F as *mut ffi::c_void;
        unsafe {
            let result = BNProjectCreateFolderFromPath(
                self.as_raw(),
                path_raw.as_ref().as_ptr() as *const ffi::c_char,
                parent_ptr,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
                progress_ctx,
                Some(cb_progress_func::<F>),
            );
            Ok(ProjectFolder::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Recursively create files and folders in the project from a path on disk
    ///
    /// * `parent` - Parent folder in the project that will contain the new folder
    /// * `name` - Name for the created folder
    /// * `description` - Description for created folder
    pub fn create_folder<N, D>(
        &self,
        parent: Option<&ProjectFolder>,
        name: N,
        description: D,
    ) -> Result<ProjectFolder, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
    {
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let parent_ptr = parent
            .map(|p| unsafe { p.as_raw() as *mut _ })
            .unwrap_or(null_mut());
        unsafe {
            let result = BNProjectCreateFolder(
                self.as_raw(),
                parent_ptr,
                name_raw.as_ref().as_ptr() as *const ffi::c_char,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
            );
            Ok(ProjectFolder::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Recursively create files and folders in the project from a path on disk
    ///
    /// * `parent` - Parent folder in the project that will contain the new folder
    /// * `name` - Name for the created folder
    /// * `description` - Description for created folder
    /// * `id` - id unique ID
    pub unsafe fn create_folder_unsafe<N, D, I>(
        &self,
        parent: Option<&ProjectFolder>,
        name: N,
        description: D,
        id: I,
    ) -> Result<ProjectFolder, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
        I: BnStrCompatible,
    {
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let parent_ptr = parent
            .map(|p| unsafe { p.as_raw() as *mut _ })
            .unwrap_or(null_mut());
        let id_raw = id.into_bytes_with_nul();
        unsafe {
            let result = BNProjectCreateFolderUnsafe(
                self.as_raw(),
                parent_ptr,
                name_raw.as_ref().as_ptr() as *const ffi::c_char,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
                id_raw.as_ref().as_ptr() as *const ffi::c_char,
            );
            Ok(ProjectFolder::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Get a list of folders in the project
    pub fn folders(&self) -> Result<Array<ProjectFolder>, ()> {
        let mut count = 0;
        let result = unsafe { BNProjectGetFolders(self.as_raw(), &mut count) };
        if result.is_null() {
            return Err(());
        }

        Ok(unsafe { Array::new(result, count, ()) })
    }

    /// Retrieve a folder in the project by unique folder `id`
    pub fn folder_by_id<S: BnStrCompatible>(&self, id: S) -> Option<ProjectFolder> {
        let id_raw = id.into_bytes_with_nul();
        let id_ptr = id_raw.as_ref().as_ptr() as *const ffi::c_char;

        let result = unsafe { BNProjectGetFolderById(self.as_raw(), id_ptr) };
        let handle = NonNull::new(result)?;
        Some(unsafe { ProjectFolder::from_raw(handle) })
    }

    /// Recursively delete a folder from the project
    ///
    /// * `folder` - Folder to delete recursively
    pub fn delete_folder(&self, folder: &ProjectFolder) -> Result<(), ()> {
        let result = unsafe {
            BNProjectDeleteFolder(
                self.as_raw(),
                folder.as_raw(),
                null_mut(),
                Some(cb_progress_func_nop),
            )
        };
        if result {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Recursively delete a folder from the project
    ///
    /// * `folder` - Folder to delete recursively
    /// * `progress_func` - Progress function that will be called as objects get deleted
    pub fn delete_folder_with_progress<F>(
        &self,
        folder: &ProjectFolder,
        mut progress_func: F,
    ) -> Result<(), ()>
    where
        F: FnMut(usize, usize) -> bool,
    {
        let progress_ctx = &mut progress_func as *mut F as *mut ffi::c_void;
        let result = unsafe {
            BNProjectDeleteFolder(
                self.as_raw(),
                folder.as_raw(),
                progress_ctx,
                Some(cb_progress_func::<F>),
            )
        };
        if result {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn push_file(&self, file: &ProjectFile) {
        unsafe { BNProjectPushFile(self.as_raw(), file.as_raw()) }
    }

    /// Create a file in the project from a path on disk
    ///
    /// * `path` - Path on disk
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    pub fn create_file_from_path<P, N, D>(
        &self,
        path: P,
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
    ) -> Result<ProjectFile, ()>
    where
        P: BnStrCompatible,
        N: BnStrCompatible,
        D: BnStrCompatible,
    {
        let path_raw = path.into_bytes_with_nul();
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        unsafe {
            let result = BNProjectCreateFileFromPath(
                self.as_raw(),
                path_raw.as_ref().as_ptr() as *const ffi::c_char,
                folder.map(|x| x.as_raw() as *mut _).unwrap_or(null_mut()),
                name_raw.as_ref().as_ptr() as *const ffi::c_char,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
                null_mut(),
                Some(cb_progress_func_nop),
            );
            Ok(ProjectFile::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Create a file in the project from a path on disk
    ///
    /// * `path` - Path on disk
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    /// * `progress_func` - Progress function that will be called as the file is being added
    pub fn create_file_from_path_with_progress<P, N, D, F>(
        &self,
        path: P,
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        mut progress_func: F,
    ) -> Result<ProjectFile, ()>
    where
        P: BnStrCompatible,
        N: BnStrCompatible,
        D: BnStrCompatible,
        F: FnMut(usize, usize) -> bool,
    {
        let path_raw = path.into_bytes_with_nul();
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let progress_ctx = &mut progress_func as *mut F as *mut ffi::c_void;
        unsafe {
            let result = BNProjectCreateFileFromPath(
                self.as_raw(),
                path_raw.as_ref().as_ptr() as *const ffi::c_char,
                folder.map(|x| x.as_raw() as *mut _).unwrap_or(null_mut()),
                name_raw.as_ref().as_ptr() as *const ffi::c_char,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
                progress_ctx,
                Some(cb_progress_func::<F>),
            );
            Ok(ProjectFile::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Create a file in the project from a path on disk
    ///
    /// * `path` - Path on disk
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    /// * `id` - id unique ID
    /// * `creation_time` - Creation time of the file
    pub unsafe fn create_file_from_path_unsafe<P, N, D, I>(
        &self,
        path: P,
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        id: I,
        creation_time: SystemTime,
    ) -> Result<ProjectFile, ()>
    where
        P: BnStrCompatible,
        N: BnStrCompatible,
        D: BnStrCompatible,
        I: BnStrCompatible,
    {
        let path_raw = path.into_bytes_with_nul();
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let id_raw = id.into_bytes_with_nul();
        unsafe {
            let result = BNProjectCreateFileFromPathUnsafe(
                self.as_raw(),
                path_raw.as_ref().as_ptr() as *const ffi::c_char,
                folder.map(|x| x.as_raw() as *mut _).unwrap_or(null_mut()),
                name_raw.as_ref().as_ptr() as *const ffi::c_char,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
                id_raw.as_ref().as_ptr() as *const ffi::c_char,
                systime_to_bntime(creation_time).unwrap(),
                null_mut(),
                Some(cb_progress_func_nop),
            );
            Ok(ProjectFile::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Create a file in the project from a path on disk
    ///
    /// * `path` - Path on disk
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    /// * `id` - id unique ID
    /// * `creation_time` - Creation time of the file
    /// * `progress_func` - Progress function that will be called as the file is being added
    pub unsafe fn create_file_from_path_with_progress_unsafe<P, N, D, I, F>(
        &self,
        path: P,
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        id: I,
        creation_time: SystemTime,
        mut progress_func: F,
    ) -> Result<ProjectFile, ()>
    where
        P: BnStrCompatible,
        N: BnStrCompatible,
        D: BnStrCompatible,
        I: BnStrCompatible,
        F: FnMut(usize, usize) -> bool,
    {
        let path_raw = path.into_bytes_with_nul();
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let id_raw = id.into_bytes_with_nul();
        let progress_ctx = &mut progress_func as *mut F as *mut ffi::c_void;
        unsafe {
            let result = BNProjectCreateFileFromPathUnsafe(
                self.as_raw(),
                path_raw.as_ref().as_ptr() as *const ffi::c_char,
                folder.map(|x| x.as_raw() as *mut _).unwrap_or(null_mut()),
                name_raw.as_ref().as_ptr() as *const ffi::c_char,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
                id_raw.as_ref().as_ptr() as *const ffi::c_char,
                systime_to_bntime(creation_time).unwrap(),
                progress_ctx,
                Some(cb_progress_func::<F>),
            );
            Ok(ProjectFile::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Create a file in the project
    ///
    /// * `contents` - Bytes of the file that will be created
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    pub fn create_file<N, D>(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
    ) -> Result<ProjectFile, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
    {
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        unsafe {
            let result = BNProjectCreateFile(
                self.as_raw(),
                contents.as_ptr(),
                contents.len(),
                folder.map(|x| x.as_raw() as *mut _).unwrap_or(null_mut()),
                name_raw.as_ref().as_ptr() as *const ffi::c_char,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
                null_mut(),
                Some(cb_progress_func_nop),
            );
            Ok(ProjectFile::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Create a file in the project
    ///
    /// * `contents` - Bytes of the file that will be created
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    /// * `progress_func` - Progress function that will be called as the file is being added
    pub fn create_file_with_progress<N, D, F>(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        mut progress_func: F,
    ) -> Result<ProjectFile, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
        F: FnMut(usize, usize) -> bool,
    {
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let progress_ctx = &mut progress_func as *mut F as *mut ffi::c_void;
        unsafe {
            let result = BNProjectCreateFile(
                self.as_raw(),
                contents.as_ptr(),
                contents.len(),
                folder.map(|x| x.as_raw() as *mut _).unwrap_or(null_mut()),
                name_raw.as_ref().as_ptr() as *const ffi::c_char,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
                progress_ctx,
                Some(cb_progress_func::<F>),
            );
            Ok(ProjectFile::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Create a file in the project
    ///
    /// * `contents` - Bytes of the file that will be created
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    /// * `id` - id unique ID
    /// * `creation_time` - Creation time of the file
    pub unsafe fn create_file_unsafe<N, D, I>(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        id: I,
        creation_time: SystemTime,
    ) -> Result<ProjectFile, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
        I: BnStrCompatible,
    {
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let id_raw = id.into_bytes_with_nul();
        unsafe {
            let result = BNProjectCreateFileUnsafe(
                self.as_raw(),
                contents.as_ptr(),
                contents.len(),
                folder.map(|x| x.as_raw() as *mut _).unwrap_or(null_mut()),
                name_raw.as_ref().as_ptr() as *const ffi::c_char,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
                id_raw.as_ref().as_ptr() as *const ffi::c_char,
                systime_to_bntime(creation_time).unwrap(),
                null_mut(),
                Some(cb_progress_func_nop),
            );
            Ok(ProjectFile::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Create a file in the project
    ///
    /// * `contents` - Bytes of the file that will be created
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    /// * `id` - id unique ID
    /// * `creation_time` - Creation time of the file
    /// * `progress_func` - Progress function that will be called as the file is being added
    pub unsafe fn create_file_with_progress_unsafe<N, D, I, F>(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        id: I,
        creation_time: SystemTime,
        mut progress_func: F,
    ) -> Result<ProjectFile, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
        I: BnStrCompatible,
        F: FnMut(usize, usize) -> bool,
    {
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let id_raw = id.into_bytes_with_nul();
        let progress_ctx = &mut progress_func as *mut F as *mut ffi::c_void;
        unsafe {
            let result = BNProjectCreateFileUnsafe(
                self.as_raw(),
                contents.as_ptr(),
                contents.len(),
                folder.map(|x| x.as_raw() as *mut _).unwrap_or(null_mut()),
                name_raw.as_ref().as_ptr() as *const ffi::c_char,
                description_raw.as_ref().as_ptr() as *const ffi::c_char,
                id_raw.as_ref().as_ptr() as *const ffi::c_char,
                systime_to_bntime(creation_time).unwrap(),
                progress_ctx,
                Some(cb_progress_func::<F>),
            );
            Ok(ProjectFile::from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Get a list of files in the project
    pub fn files(&self) -> Result<Array<ProjectFile>, ()> {
        let mut count = 0;
        let result = unsafe { BNProjectGetFiles(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        Ok(unsafe { Array::new(result, count, ()) })
    }

    /// Retrieve a file in the project by unique `id`
    pub fn file_by_id<S: BnStrCompatible>(&self, id: S) -> Option<ProjectFile> {
        let id_raw = id.into_bytes_with_nul();
        let id_ptr = id_raw.as_ref().as_ptr() as *const ffi::c_char;

        let result = unsafe { BNProjectGetFileById(self.as_raw(), id_ptr) };
        let handle = NonNull::new(result)?;
        Some(unsafe { ProjectFile::from_raw(handle) })
    }

    /// Retrieve a file in the project by the `path` on disk
    pub fn file_by_path<S: BnStrCompatible>(&self, path: S) -> Option<ProjectFile> {
        let path_raw = path.into_bytes_with_nul();
        let path_ptr = path_raw.as_ref().as_ptr() as *const ffi::c_char;

        let result = unsafe { BNProjectGetFileByPathOnDisk(self.as_raw(), path_ptr) };
        let handle = NonNull::new(result)?;
        Some(unsafe { ProjectFile::from_raw(handle) })
    }

    /// Delete a file from the project
    pub fn delete_file(&self, file: &ProjectFile) -> bool {
        unsafe { BNProjectDeleteFile(self.as_raw(), file.as_raw()) }
    }

    /// A context manager to speed up bulk project operations.
    /// Project modifications are synced to disk in chunks,
    /// and the project on disk vs in memory may not agree on state
    /// if an exception occurs while a bulk operation is happening.
    ///
    /// ```no_run
    /// # use binaryninja::project::Project;
    /// # let project: Project = todo!();
    /// if let Ok(bulk) = project.bulk_operation() {
    ///     for file in std::fs::read_dir("/bin/").unwrap().into_iter() {
    ///         let file = file.unwrap();
    ///         let file_type = file.file_type().unwrap();
    ///         if file_type.is_file() && !file_type.is_symlink() {
    ///             bulk.create_file_from_path(
    ///                 "/bin/",
    ///                 None,
    ///                 &file.file_name().to_string_lossy(),
    ///                 "",
    ///             ).unwrap();
    ///         }
    ///     }
    /// }
    /// ```
    // NOTE mut is used here, so only one lock can be aquired at once
    pub fn bulk_operation(&mut self) -> Result<ProjectBultOperationLock, ()> {
        Ok(ProjectBultOperationLock::lock(self))
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        unsafe { BNFreeProject(self.as_raw()) }
    }
}

impl Clone for Project {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(NonNull::new(BNNewProjectReference(self.as_raw())).unwrap()) }
    }
}

impl CoreArrayProvider for Project {
    type Raw = *mut BNProject;
    type Context = ();
    type Wrapped<'a> = &'a Project;
}

unsafe impl CoreArrayProviderInner for Project {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeProjectList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

pub struct ProjectBultOperationLock<'a> {
    lock: &'a mut Project,
}

impl<'a> ProjectBultOperationLock<'a> {
    pub fn lock(project: &'a mut Project) -> Self {
        unsafe { BNProjectBeginBulkOperation(project.as_raw()) };
        Self { lock: project }
    }

    pub fn unlock(self) {
        // NOTE does nothing, just drop self
    }
}

impl std::ops::Deref for ProjectBultOperationLock<'_> {
    type Target = Project;
    fn deref(&self) -> &Self::Target {
        self.lock
    }
}

impl Drop for ProjectBultOperationLock<'_> {
    fn drop(&mut self) {
        unsafe { BNProjectEndBulkOperation(self.lock.as_raw()) };
    }
}

#[repr(transparent)]
pub struct ProjectFolder {
    handle: NonNull<BNProjectFolder>,
}

impl ProjectFolder {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNProjectFolder>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNProjectFolder) -> &Self {
        debug_assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNProjectFolder {
        &mut *self.handle.as_ptr()
    }

    /// Get the project that owns this folder
    pub fn project(&self) -> Project {
        unsafe {
            Project::from_raw(NonNull::new(BNProjectFolderGetProject(self.as_raw())).unwrap())
        }
    }

    /// Get the unique id of this folder
    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectFolderGetId(self.as_raw())) }
    }

    /// Get the name of this folder
    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectFolderGetName(self.as_raw())) }
    }

    /// Set the name of this folder
    pub fn set_name<S: BnStrCompatible>(&self, value: S) {
        let value_raw = value.into_bytes_with_nul();
        unsafe {
            BNProjectFolderSetName(
                self.as_raw(),
                value_raw.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Get the description of this folder
    pub fn description(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectFolderGetDescription(self.as_raw())) }
    }

    /// Set the description of this folder
    pub fn set_description<S: BnStrCompatible>(&self, value: S) {
        let value_raw = value.into_bytes_with_nul();
        unsafe {
            BNProjectFolderSetDescription(
                self.as_raw(),
                value_raw.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Get the folder that contains this folder
    pub fn parent(&self) -> Option<ProjectFolder> {
        let result = unsafe { BNProjectFolderGetParent(self.as_raw()) };
        NonNull::new(result).map(|handle| unsafe { ProjectFolder::from_raw(handle) })
    }

    /// Set the folder that contains this folder
    pub fn set_folder(&self, folder: Option<&ProjectFolder>) {
        let folder_handle = folder
            .map(|x| unsafe { x.as_raw() as *mut _ })
            .unwrap_or(null_mut());
        unsafe { BNProjectFolderSetParent(self.as_raw(), folder_handle) }
    }

    /// Recursively export this folder to disk, returns `true' if the export succeeded
    ///
    /// * `dest` - Destination path for the exported contents
    pub fn export<S: BnStrCompatible>(&self, dest: S) -> bool {
        let dest_raw = dest.into_bytes_with_nul();
        unsafe {
            BNProjectFolderExport(
                self.as_raw(),
                dest_raw.as_ref().as_ptr() as *const ffi::c_char,
                null_mut(),
                Some(cb_progress_func_nop),
            )
        }
    }

    /// Recursively export this folder to disk, returns `true' if the export succeeded
    ///
    /// * `dest` - Destination path for the exported contents
    /// * `progress_func` - Progress function that will be called as contents are exporting
    pub fn export_with_progress<S, F>(&self, dest: S, mut progress: F) -> bool
    where
        S: BnStrCompatible,
        F: FnMut(usize, usize) -> bool,
    {
        let dest_raw = dest.into_bytes_with_nul();
        unsafe {
            BNProjectFolderExport(
                self.as_raw(),
                dest_raw.as_ref().as_ptr() as *const ffi::c_char,
                &mut progress as *mut _ as *mut ffi::c_void,
                Some(cb_progress_func::<F>),
            )
        }
    }
}

impl Drop for ProjectFolder {
    fn drop(&mut self) {
        unsafe { BNFreeProjectFolder(self.as_raw()) }
    }
}

impl Clone for ProjectFolder {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(NonNull::new(BNNewProjectFolderReference(self.as_raw())).unwrap()) }
    }
}

impl CoreArrayProvider for ProjectFolder {
    type Raw = *mut BNProjectFolder;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for ProjectFolder {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeProjectFolderList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

#[repr(transparent)]
pub struct ProjectFile {
    handle: NonNull<BNProjectFile>,
}

impl ProjectFile {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNProjectFile>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNProjectFile) -> &Self {
        debug_assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNProjectFile {
        &mut *self.handle.as_ptr()
    }

    /// Get the project that owns this file
    pub fn project(&self) -> Project {
        unsafe { Project::from_raw(NonNull::new(BNProjectFileGetProject(self.as_raw())).unwrap()) }
    }

    /// Get the path on disk to this file's contents
    pub fn path_on_disk(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectFileGetPathOnDisk(self.as_raw())) }
    }

    /// Check if this file's contents exist on disk
    pub fn exists_on_disk(&self) -> bool {
        unsafe { BNProjectFileExistsOnDisk(self.as_raw()) }
    }

    /// Get the unique id of this file
    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectFileGetId(self.as_raw())) }
    }

    /// Get the name of this file
    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectFileGetName(self.as_raw())) }
    }

    /// Set the name of this file
    pub fn set_name<S: BnStrCompatible>(&self, value: S) {
        let value_raw = value.into_bytes_with_nul();
        unsafe {
            BNProjectFileSetName(
                self.as_raw(),
                value_raw.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Get the description of this file
    pub fn description(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectFileGetDescription(self.as_raw())) }
    }

    /// Set the description of this file
    pub fn set_description<S: BnStrCompatible>(&self, value: S) {
        let value_raw = value.into_bytes_with_nul();
        unsafe {
            BNProjectFileSetDescription(
                self.as_raw(),
                value_raw.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Get the file creation time
    pub fn creation_time(&self) -> SystemTime {
        systime_from_bntime(unsafe { BNProjectFileGetCreationTimestamp(self.as_raw()) }).unwrap()
    }

    /// Get the folder that contains this file
    pub fn folder(&self) -> Option<ProjectFolder> {
        let result = unsafe { BNProjectFileGetFolder(self.as_raw()) };
        NonNull::new(result).map(|handle| unsafe { ProjectFolder::from_raw(handle) })
    }

    /// Set the folder that contains this file
    pub fn set_folder(&self, folder: Option<&ProjectFolder>) {
        let folder_handle = folder
            .map(|x| unsafe { x.as_raw() as *mut _ })
            .unwrap_or(null_mut());
        unsafe { BNProjectFileSetFolder(self.as_raw(), folder_handle) }
    }

    /// Export this file to disk, `true' if the export succeeded
    ///
    /// * `dest` - Destination path for the exported contents
    pub fn export<S: BnStrCompatible>(&self, dest: S) -> bool {
        let dest_raw = dest.into_bytes_with_nul();
        unsafe {
            BNProjectFileExport(
                self.as_raw(),
                dest_raw.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }
}

impl Drop for ProjectFile {
    fn drop(&mut self) {
        unsafe { BNFreeProjectFile(self.as_raw()) }
    }
}

impl Clone for ProjectFile {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(NonNull::new(BNNewProjectFileReference(self.as_raw())).unwrap()) }
    }
}

impl CoreArrayProvider for ProjectFile {
    type Raw = *mut BNProjectFile;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for ProjectFile {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeProjectFileList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

fn systime_from_bntime(time: i64) -> Option<SystemTime> {
    let m = Duration::from_secs(time.try_into().ok()?);
    Some(UNIX_EPOCH + m)
}

fn systime_to_bntime(time: SystemTime) -> Option<i64> {
    time.duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs()
        .try_into()
        .ok()
}

unsafe extern "C" fn cb_progress_func<F: FnMut(usize, usize) -> bool>(
    ctxt: *mut ffi::c_void,
    progress: usize,
    total: usize,
) -> bool {
    if ctxt.is_null() {
        return true;
    }
    let closure: &mut F = mem::transmute(ctxt);
    closure(progress, total)
}

unsafe extern "C" fn cb_progress_func_nop(
    _ctxt: *mut ffi::c_void,
    _progress: usize,
    _total: usize,
) -> bool {
    true
}

#[cfg(test)]
mod test {
    use std::time::SystemTime;

    use crate::metadata::Metadata;
    use crate::rc::Ref;

    use super::Project;

    fn unique_project() -> (String, String) {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let tmp_dir = std::env::temp_dir();
        let project_path = format!("{}/tmp_project_{unique_id}", tmp_dir.to_str().unwrap());
        let project_name = format!("create_delete_empty_project_{unique_id}");
        (project_path, project_name)
    }

    #[test]
    fn create_delete_empty() {
        crate::headless::init();

        let (project_path, project_name) = unique_project();
        // create the project
        let project = Project::create(&project_path, &project_name);
        project.open().unwrap();
        assert!(project.is_open());

        // check project data
        let project_path_received = project.path();
        assert_eq!(&project_path, project_path_received.as_str());
        let project_name_received = project.name();
        assert_eq!(&project_name, project_name_received.as_str());

        // close the project
        project.close().unwrap();
        assert!(!project.is_open());
        drop(project);

        // delete the project
        std::fs::remove_dir_all(project_path).unwrap();

        crate::headless::shutdown();
    }

    #[test]
    fn create_close_open_close() {
        crate::headless::init();

        let (project_path, project_name) = unique_project();
        // create the project
        let project = Project::create(&project_path, &project_name);
        project.open().unwrap();

        // get the project id
        let id = project.id();

        // close the project
        project.close().unwrap();
        drop(project);

        let project = Project::open_project(&project_path);
        // assert same id
        let new_id = project.id();
        assert_eq!(id, new_id);

        // close the project
        project.close().unwrap();
        drop(project);

        // delete the project
        std::fs::remove_dir_all(project_path).unwrap();

        crate::headless::shutdown();
    }

    #[test]
    fn modify_project() {
        crate::headless::init();

        let (project_path, project_name) = unique_project();
        // create the project
        let project = Project::create(&project_path, project_name);
        project.open().unwrap();

        // get project id
        let id = project.id();

        // create data and verify that data was created
        let data_1: Ref<Metadata> = "data1".into();
        let data_2: Ref<Metadata> = "data2".into();
        assert!(project.store_metadata("key", data_1.as_ref()));
        assert_eq!(
            data_1.get_string().unwrap(),
            project.query_metadata("key").get_string().unwrap()
        );
        project.remove_metadata("key");
        assert!(project.store_metadata("key", data_2.as_ref()));
        assert_eq!(
            data_2.get_string().unwrap(),
            project.query_metadata("key").get_string().unwrap()
        );

        // create file that will be imported to the project
        let tmp_folder_1_name = format!(
            "tmp_folder_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        let tmp_folder_2_name = format!("{tmp_folder_1_name }_2");
        let tmp_folder_1 = format!(
            "{}/{tmp_folder_1_name}",
            std::env::temp_dir().to_str().unwrap()
        );
        let tmp_folder_2 = format!(
            "{}/{tmp_folder_2_name}",
            std::env::temp_dir().to_str().unwrap()
        );
        std::fs::create_dir(&tmp_folder_1).unwrap();
        std::fs::create_dir(&tmp_folder_2).unwrap();
        let input_file_1 = format!("{tmp_folder_2}/input_1");
        let input_file_2 = format!("{tmp_folder_2}/input_2");
        let input_file_1_data = b"input_1_data";
        let input_file_2_data = b"input_1_data";
        std::fs::write(&input_file_1, input_file_1_data).unwrap();
        std::fs::write(&input_file_2, input_file_2_data).unwrap();

        // create and delete folders
        let folder_1_desc = "desc_folder_1";
        let folder_1 = project
            .create_folder(None, "folder_1", folder_1_desc)
            .unwrap();
        let folder_2_desc = "AAAAA";
        let folder_2_id = "1717416787371";
        let folder_2 = unsafe {
            project
                .create_folder_unsafe(Some(&folder_1), "folder_2", folder_2_desc, folder_2_id)
                .unwrap()
        };
        let folder_3_desc = ""; // TODO "çàáÁÀ";
        let folder_3 = project
            .create_folder_from_path(&tmp_folder_1, None, folder_3_desc)
            .unwrap();
        let folder_4_desc = "";
        let _folder_4 = project
            .create_folder_from_path_with_progress(
                &tmp_folder_2,
                Some(&folder_3),
                folder_4_desc,
                |_, _| true,
            )
            .unwrap();
        let folder_5 = project
            .create_folder(None, "deleted_folder", folder_4_desc)
            .unwrap();

        assert_eq!(project.folders().unwrap().len(), 5);
        let last_folder = project.folder_by_id(folder_5.id()).unwrap();
        project.delete_folder(&last_folder).unwrap();
        assert_eq!(project.folders().unwrap().len(), 4);
        drop(folder_5);

        // create, import and delete file
        let file_1_data = b"data_1";
        let file_1_desc = "desc_file_1";
        let _file_1 = project
            .create_file(file_1_data, None, "file_1", file_1_desc)
            .unwrap();
        let file_2_data = b"data_2";
        let file_2_desc = "my desc";
        let file_2_id = "12334545";
        let _file_2 = unsafe {
            project.create_file_unsafe(
                file_2_data,
                Some(&folder_2),
                "file_2",
                file_2_desc,
                file_2_id,
                SystemTime::UNIX_EPOCH,
            )
        }
        .unwrap();
        let file_3_data = b"data\x023";
        let file_3_desc = "!";
        let _file_3 = project
            .create_file_with_progress(
                file_3_data,
                Some(&folder_1),
                "file_3",
                file_3_desc,
                |_, _| true,
            )
            .unwrap();
        let file_4_time = SystemTime::now();
        let file_4_data = b"data_4\x00_4";
        let file_4_desc = "";
        let file_4_id = "123123123";
        let _file_4 = unsafe {
            project.create_file_with_progress_unsafe(
                file_4_data,
                Some(&folder_3),
                "file_4",
                file_4_desc,
                file_4_id,
                file_4_time,
                |_, _| true,
            )
        }
        .unwrap();
        let file_5_desc = "desc";
        let _file_5 = project
            .create_file_from_path(&input_file_1, None, "file_5", file_5_desc)
            .unwrap();
        let file_6_time = SystemTime::now();
        let file_6_desc = "de";
        let file_6_id = "90218347";
        let _file_6 = unsafe {
            project.create_file_from_path_unsafe(
                &input_file_2,
                Some(&folder_3),
                "file_6",
                file_6_desc,
                file_6_id,
                file_6_time,
            )
        }
        .unwrap();
        let file_7 = project
            .create_file_from_path_with_progress(
                &input_file_2,
                Some(&folder_2),
                "file_7",
                "no",
                |_, _| true,
            )
            .unwrap();
        let file_8 = unsafe {
            project.create_file_from_path_with_progress_unsafe(
                &input_file_1,
                None,
                "file_7",
                "no",
                "92736528",
                SystemTime::now(),
                |_, _| true,
            )
        }
        .unwrap();

        assert_eq!(project.files().unwrap().len(), 10);
        let file_a = project.file_by_id(file_8.id()).unwrap();
        let file_b = project.file_by_path(file_7.path_on_disk()).unwrap();
        project.delete_file(&file_a);
        project.delete_file(&file_b);
        assert_eq!(project.files().unwrap().len(), 8);
        drop(file_8);
        drop(file_7);

        project.set_name("project_name");
        project.set_description("project_description");

        // close the project
        project.close().unwrap();
        drop(project);
        drop(folder_1);
        drop(folder_2);
        drop(folder_3);

        // reopen the project and verify the information store on it
        let project = Project::open_project(&project_path);

        // assert same id
        assert_eq!(id, project.id());

        // verify metadata
        assert_eq!(
            data_2.get_string().unwrap(),
            project.query_metadata("key").get_string().unwrap()
        );

        // check folders
        let folders = [
            ("folder_1", None, folder_1_desc),
            ("folder_2", Some(folder_2_id), folder_2_desc),
            (&tmp_folder_1_name, None, folder_3_desc),
            (&tmp_folder_2_name, None, folder_4_desc),
        ];
        for folder in project.folders().unwrap().iter() {
            let found = folders
                .iter()
                .find(|f| folder.name().as_str() == f.0)
                .unwrap();
            if let Some(id) = found.1 {
                assert_eq!(folder.id().as_str(), id);
            }
            assert_eq!(folder.description().as_str(), found.2);
        }

        // check files
        #[rustfmt::skip]
        let files = [
            ("file_1", &file_1_data[..], file_1_desc, None, None),
            ("file_2", &file_2_data[..], file_2_desc, Some(file_2_id), None),
            ("file_3", &file_3_data[..], file_3_desc, None, None),
            ("file_4", &file_4_data[..], file_4_desc, Some(file_4_id), Some(file_4_time)),
            ("file_5", &input_file_1_data[..], file_5_desc, None, None),
            ("file_6", &input_file_2_data[..], file_6_desc, Some(file_6_id), Some(file_6_time)),
            ("input_1", &input_file_1_data[..], "", None, None),
            ("input_2", &input_file_2_data[..], "", None, None),
        ];
        for file in project.files().unwrap().iter() {
            let found = files.iter().find(|f| file.name().as_str() == f.0).unwrap();
            if let Some(id) = found.3 {
                assert_eq!(file.id().as_str(), id);
            }
            if let Some(time) = found.4 {
                assert_eq!(
                    file.creation_time()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    time.duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                );
            }
            assert_eq!(file.description().as_str(), found.2);
            let content = std::fs::read(file.path_on_disk().as_str()).unwrap();
            assert_eq!(content, found.1);
        }

        assert_eq!(project.name().as_str(), "project_name");
        assert_eq!(project.description().as_str(), "project_description");

        // close the project
        project.close().unwrap();

        // delete the project
        std::fs::remove_dir_all(project_path).unwrap();
        std::fs::remove_dir_all(tmp_folder_1).unwrap();
        std::fs::remove_dir_all(tmp_folder_2).unwrap();

        crate::headless::shutdown();
    }
}
