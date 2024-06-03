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
