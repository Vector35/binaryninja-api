//! Represents a collection of files and folders within Binary Ninja.

use std::ffi::c_void;
use std::fmt::Debug;
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::ptr::{null_mut, NonNull};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use binaryninjacore_sys::*;

use crate::metadata::Metadata;
use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::project::file::ProjectFile;
use crate::project::folder::ProjectFolder;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnString, IntoCStr};

pub mod file;
pub mod folder;

pub struct Project {
    pub(crate) handle: NonNull<BNProject>,
}

impl Project {
    pub unsafe fn from_raw(handle: NonNull<BNProject>) -> Self {
        Project { handle }
    }

    pub unsafe fn ref_from_raw(handle: NonNull<BNProject>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// All of the open [`Project`]s
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
    pub fn create(path: impl AsRef<Path>, name: &str) -> Option<Ref<Self>> {
        let path_raw = path.as_ref().to_cstr();
        let name_raw = name.to_cstr();
        let handle = unsafe { BNCreateProject(path_raw.as_ptr(), name_raw.as_ptr()) };
        NonNull::new(handle).map(|h| unsafe { Self::ref_from_raw(h) })
    }

    /// Open an existing project
    ///
    /// * `path` - Path to the project directory (.bnpr) or project metadata file (.bnpm)
    pub fn open_project(path: impl AsRef<Path>) -> Option<Ref<Self>> {
        let path_raw = path.as_ref().to_cstr();
        let handle = unsafe { BNOpenProject(path_raw.as_ptr()) };
        NonNull::new(handle).map(|h| unsafe { Self::ref_from_raw(h) })
    }

    /// Check if the project is currently open
    pub fn is_open(&self) -> bool {
        unsafe { BNProjectIsOpen(self.handle.as_ptr()) }
    }

    /// Open a closed project
    pub fn open(&self) -> Result<(), ()> {
        if unsafe { BNProjectOpen(self.handle.as_ptr()) } {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Close an open project
    pub fn close(&self) -> Result<(), ()> {
        if unsafe { BNProjectClose(self.handle.as_ptr()) } {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Get the unique id of this project
    pub fn id(&self) -> String {
        unsafe { BnString::into_string(BNProjectGetId(self.handle.as_ptr())) }
    }

    /// Get the path on disk for the project
    pub fn path(&self) -> PathBuf {
        let path_str = unsafe { BnString::into_string(BNProjectGetPath(self.handle.as_ptr())) };
        PathBuf::from(path_str)
    }

    /// Get the name of the project
    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNProjectGetName(self.handle.as_ptr())) }
    }

    /// Set the name of the project
    pub fn set_name(&self, value: &str) -> bool {
        let value = value.to_cstr();
        unsafe { BNProjectSetName(self.handle.as_ptr(), value.as_ptr()) }
    }

    /// Get the description of the project
    pub fn description(&self) -> String {
        unsafe { BnString::into_string(BNProjectGetDescription(self.handle.as_ptr())) }
    }

    /// Set the description of the project
    pub fn set_description(&self, value: &str) -> bool {
        let value = value.to_cstr();
        unsafe { BNProjectSetDescription(self.handle.as_ptr(), value.as_ptr()) }
    }

    /// Retrieves metadata stored under a key from the project
    pub fn query_metadata(&self, key: &str) -> Ref<Metadata> {
        let key = key.to_cstr();
        let result = unsafe { BNProjectQueryMetadata(self.handle.as_ptr(), key.as_ptr()) };
        unsafe { Metadata::ref_from_raw(result) }
    }

    /// Stores metadata within the project,
    ///
    /// * `key` - Key under which to store the Metadata object
    /// * `value` - Object to store
    pub fn store_metadata(&self, key: &str, value: &Metadata) -> bool {
        let key_raw = key.to_cstr();
        unsafe { BNProjectStoreMetadata(self.handle.as_ptr(), key_raw.as_ptr(), value.handle) }
    }

    /// Removes the metadata associated with this `key` from the project
    pub fn remove_metadata(&self, key: &str) -> bool {
        let key_raw = key.to_cstr();
        unsafe { BNProjectRemoveMetadata(self.handle.as_ptr(), key_raw.as_ptr()) }
    }

    /// Call this after updating the [`ProjectFolder`] to have the changes reflected in the database.
    pub fn push_folder(&self, file: &ProjectFolder) -> bool {
        unsafe { BNProjectPushFolder(self.handle.as_ptr(), file.handle.as_ptr()) }
    }

    /// Recursively create files and folders in the project from a path on disk
    ///
    /// * `path` - Path to folder on disk
    /// * `parent` - Parent folder in the project that will contain the new contents
    /// * `description` - Description for created root folder
    pub fn create_folder_from_path(
        &self,
        path: impl AsRef<Path>,
        parent: Option<&ProjectFolder>,
        description: &str,
    ) -> Result<Ref<ProjectFolder>, ()> {
        self.create_folder_from_path_with_progress(path, parent, description, NoProgressCallback)
    }

    /// Recursively create files and folders in the project from a path on disk
    ///
    /// * `path` - Path to folder on disk
    /// * `parent` - Parent folder in the project that will contain the new contents
    /// * `description` - Description for created root folder
    /// * `progress` - [`ProgressCallback`] that will be called as the [`ProjectFolder`] is being created
    pub fn create_folder_from_path_with_progress<PC>(
        &self,
        path: impl AsRef<Path>,
        parent: Option<&ProjectFolder>,
        description: &str,
        mut progress: PC,
    ) -> Result<Ref<ProjectFolder>, ()>
    where
        PC: ProgressCallback,
    {
        let path_raw = path.as_ref().to_cstr();
        let description_raw = description.to_cstr();
        let parent_ptr = parent.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());

        unsafe {
            let result = BNProjectCreateFolderFromPath(
                self.handle.as_ptr(),
                path_raw.as_ptr(),
                parent_ptr,
                description_raw.as_ptr(),
                &mut progress as *mut PC as *mut c_void,
                Some(PC::cb_progress_callback),
            );
            Ok(ProjectFolder::ref_from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Recursively create files and folders in the project from a path on disk
    ///
    /// * `parent` - Parent folder in the project that will contain the new folder
    /// * `name` - Name for the created folder
    /// * `description` - Description for created folder
    pub fn create_folder(
        &self,
        parent: Option<&ProjectFolder>,
        name: &str,
        description: &str,
    ) -> Result<Ref<ProjectFolder>, ()> {
        let name_raw = name.to_cstr();
        let description_raw = description.to_cstr();
        let parent_ptr = parent.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());
        unsafe {
            let result = BNProjectCreateFolder(
                self.handle.as_ptr(),
                parent_ptr,
                name_raw.as_ptr(),
                description_raw.as_ptr(),
            );
            Ok(ProjectFolder::ref_from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    // TODO: Rename create_folder_with_id and comment about the id being unique
    /// Recursively create files and folders in the project from a path on disk
    ///
    /// * `parent` - Parent folder in the project that will contain the new folder
    /// * `name` - Name for the created folder
    /// * `description` - Description for created folder
    /// * `id` - id unique ID
    pub unsafe fn create_folder_unsafe(
        &self,
        parent: Option<&ProjectFolder>,
        name: &str,
        description: &str,
        id: &str,
    ) -> Result<Ref<ProjectFolder>, ()> {
        let name_raw = name.to_cstr();
        let description_raw = description.to_cstr();
        let parent_ptr = parent.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());
        let id_raw = id.to_cstr();
        unsafe {
            let result = BNProjectCreateFolderUnsafe(
                self.handle.as_ptr(),
                parent_ptr,
                name_raw.as_ptr(),
                description_raw.as_ptr(),
                id_raw.as_ptr(),
            );
            Ok(ProjectFolder::ref_from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Get a list of folders in the project
    pub fn folders(&self) -> Array<ProjectFolder> {
        let mut count = 0;
        let result = unsafe { BNProjectGetFolders(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Retrieve a folder in the project by unique folder `id`
    pub fn folder_by_id(&self, id: &str) -> Option<Ref<ProjectFolder>> {
        let raw_id = id.to_cstr();
        let result = unsafe { BNProjectGetFolderById(self.handle.as_ptr(), raw_id.as_ptr()) };
        let handle = NonNull::new(result)?;
        Some(unsafe { ProjectFolder::ref_from_raw(handle) })
    }

    /// Recursively delete a [`ProjectFolder`] from the [`Project`].
    ///
    /// * `folder` - [`ProjectFolder`] to delete recursively
    pub fn delete_folder(&self, folder: &ProjectFolder) -> Result<(), ()> {
        self.delete_folder_with_progress(folder, NoProgressCallback)
    }

    /// Recursively delete a [`ProjectFolder`] from the [`Project`].
    ///
    /// * `folder` - [`ProjectFolder`] to delete recursively
    /// * `progress` - [`ProgressCallback`] that will be called as objects get deleted
    pub fn delete_folder_with_progress<PC: ProgressCallback>(
        &self,
        folder: &ProjectFolder,
        mut progress: PC,
    ) -> Result<(), ()> {
        let result = unsafe {
            BNProjectDeleteFolder(
                self.handle.as_ptr(),
                folder.handle.as_ptr(),
                &mut progress as *mut PC as *mut c_void,
                Some(PC::cb_progress_callback),
            )
        };

        if result {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Call this after updating the [`ProjectFile`] to have the changes reflected in the database.
    pub fn push_file(&self, file: &ProjectFile) -> bool {
        unsafe { BNProjectPushFile(self.handle.as_ptr(), file.handle.as_ptr()) }
    }

    /// Create a file in the project from a path on disk
    ///
    /// * `path` - Path on disk
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    pub fn create_file_from_path(
        &self,
        path: impl AsRef<Path>,
        folder: Option<&ProjectFolder>,
        name: &str,
        description: &str,
    ) -> Result<Ref<ProjectFile>, ()> {
        self.create_file_from_path_with_progress(
            path,
            folder,
            name,
            description,
            NoProgressCallback,
        )
    }

    /// Create a file in the project from a path on disk
    ///
    /// * `path` - Path on disk
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    /// * `progress` - [`ProgressCallback`] that will be called as the [`ProjectFile`] is being added
    pub fn create_file_from_path_with_progress<PC>(
        &self,
        path: impl AsRef<Path>,
        folder: Option<&ProjectFolder>,
        name: &str,
        description: &str,
        mut progress: PC,
    ) -> Result<Ref<ProjectFile>, ()>
    where
        PC: ProgressCallback,
    {
        let path_raw = path.as_ref().to_cstr();
        let name_raw = name.to_cstr();
        let description_raw = description.to_cstr();
        let folder_ptr = folder.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());

        unsafe {
            let result = BNProjectCreateFileFromPath(
                self.handle.as_ptr(),
                path_raw.as_ptr(),
                folder_ptr,
                name_raw.as_ptr(),
                description_raw.as_ptr(),
                &mut progress as *mut PC as *mut c_void,
                Some(PC::cb_progress_callback),
            );
            Ok(ProjectFile::ref_from_raw(NonNull::new(result).ok_or(())?))
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
    pub unsafe fn create_file_from_path_unsafe(
        &self,
        path: impl AsRef<Path>,
        folder: Option<&ProjectFolder>,
        name: &str,
        description: &str,
        id: &str,
        creation_time: SystemTime,
    ) -> Result<Ref<ProjectFile>, ()> {
        self.create_file_from_path_unsafe_with_progress(
            path,
            folder,
            name,
            description,
            id,
            creation_time,
            NoProgressCallback,
        )
    }

    /// Create a file in the project from a path on disk
    ///
    /// * `path` - Path on disk
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    /// * `id` - id unique ID
    /// * `creation_time` - Creation time of the file
    /// * `progress` - [`ProgressCallback`] that will be called as the [`ProjectFile`] is being created
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn create_file_from_path_unsafe_with_progress<PC>(
        &self,
        path: impl AsRef<Path>,
        folder: Option<&ProjectFolder>,
        name: &str,
        description: &str,
        id: &str,
        creation_time: SystemTime,
        mut progress: PC,
    ) -> Result<Ref<ProjectFile>, ()>
    where
        PC: ProgressCallback,
    {
        let path_raw = path.as_ref().to_cstr();
        let name_raw = name.to_cstr();
        let description_raw = description.to_cstr();
        let id_raw = id.to_cstr();
        let folder_ptr = folder.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());

        unsafe {
            let result = BNProjectCreateFileFromPathUnsafe(
                self.handle.as_ptr(),
                path_raw.as_ptr(),
                folder_ptr,
                name_raw.as_ptr(),
                description_raw.as_ptr(),
                id_raw.as_ptr(),
                systime_to_bntime(creation_time).unwrap(),
                &mut progress as *mut PC as *mut c_void,
                Some(PC::cb_progress_callback),
            );
            Ok(ProjectFile::ref_from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Create a file in the project
    ///
    /// * `contents` - Bytes of the file that will be created
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    pub fn create_file(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: &str,
        description: &str,
    ) -> Result<Ref<ProjectFile>, ()> {
        self.create_file_with_progress(contents, folder, name, description, NoProgressCallback)
    }

    /// Create a file in the project
    ///
    /// * `contents` - Bytes of the file that will be created
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    /// * `progress` - [`ProgressCallback`] that will be called as the [`ProjectFile`] is being created
    pub fn create_file_with_progress<PC>(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: &str,
        description: &str,
        mut progress: PC,
    ) -> Result<Ref<ProjectFile>, ()>
    where
        PC: ProgressCallback,
    {
        let name_raw = name.to_cstr();
        let description_raw = description.to_cstr();
        let folder_ptr = folder.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());

        unsafe {
            let result = BNProjectCreateFile(
                self.handle.as_ptr(),
                contents.as_ptr(),
                contents.len(),
                folder_ptr,
                name_raw.as_ptr(),
                description_raw.as_ptr(),
                &mut progress as *mut PC as *mut c_void,
                Some(PC::cb_progress_callback),
            );
            Ok(ProjectFile::ref_from_raw(NonNull::new(result).ok_or(())?))
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
    pub unsafe fn create_file_unsafe(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: &str,
        description: &str,
        id: &str,
        creation_time: SystemTime,
    ) -> Result<Ref<ProjectFile>, ()> {
        self.create_file_unsafe_with_progress(
            contents,
            folder,
            name,
            description,
            id,
            creation_time,
            NoProgressCallback,
        )
    }

    /// Create a file in the project
    ///
    /// * `contents` - Bytes of the file that will be created
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    /// * `id` - id unique ID
    /// * `creation_time` - Creation time of the file
    /// * `progress` - [`ProgressCallback`] that will be called as the [`ProjectFile`] is being created
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn create_file_unsafe_with_progress<PC>(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: &str,
        description: &str,
        id: &str,
        creation_time: SystemTime,
        mut progress: PC,
    ) -> Result<Ref<ProjectFile>, ()>
    where
        PC: ProgressCallback,
    {
        let name_raw = name.to_cstr();
        let description_raw = description.to_cstr();
        let id_raw = id.to_cstr();
        let folder_ptr = folder.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());

        unsafe {
            let result = BNProjectCreateFileUnsafe(
                self.handle.as_ptr(),
                contents.as_ptr(),
                contents.len(),
                folder_ptr,
                name_raw.as_ptr(),
                description_raw.as_ptr(),
                id_raw.as_ptr(),
                systime_to_bntime(creation_time).unwrap(),
                &mut progress as *mut PC as *mut c_void,
                Some(PC::cb_progress_callback),
            );
            Ok(ProjectFile::ref_from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Get a list of files in the project
    pub fn files(&self) -> Array<ProjectFile> {
        let mut count = 0;
        let result = unsafe { BNProjectGetFiles(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Retrieve a file in the project by unique `id`
    pub fn file_by_id(&self, id: &str) -> Option<Ref<ProjectFile>> {
        let raw_id = id.to_cstr();
        let result = unsafe { BNProjectGetFileById(self.handle.as_ptr(), raw_id.as_ptr()) };
        let handle = NonNull::new(result)?;
        Some(unsafe { ProjectFile::ref_from_raw(handle) })
    }

    /// Retrieve a file in the project by the `path` on disk
    pub fn file_by_path(&self, path: &Path) -> Option<Ref<ProjectFile>> {
        let path_raw = path.to_cstr();
        let result =
            unsafe { BNProjectGetFileByPathOnDisk(self.handle.as_ptr(), path_raw.as_ptr()) };
        let handle = NonNull::new(result)?;
        Some(unsafe { ProjectFile::ref_from_raw(handle) })
    }

    /// Retrieve a list of files in the project by the `path` inside the project.
    ///
    /// Because a [`ProjectFile`] name is not unique, this returns a list instead of a single [`ProjectFile`].
    pub fn files_by_project_path(&self, path: &Path) -> Array<ProjectFile> {
        let path_raw = path.to_cstr();
        let mut count = 0;
        let result = unsafe {
            BNProjectGetFilesByPathInProject(self.handle.as_ptr(), path_raw.as_ptr(), &mut count)
        };
        unsafe { Array::new(result, count, ()) }
    }

    /// Retrieve a list of files in the project in a given folder.
    pub fn files_in_folder(&self, folder: Option<&ProjectFolder>) -> Array<ProjectFile> {
        let folder_ptr = folder.map(|f| f.handle.as_ptr()).unwrap_or(null_mut());
        let mut count = 0;
        let result =
            unsafe { BNProjectGetFilesInFolder(self.handle.as_ptr(), folder_ptr, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Delete a file from the project
    pub fn delete_file(&self, file: &ProjectFile) -> bool {
        unsafe { BNProjectDeleteFile(self.handle.as_ptr(), file.handle.as_ptr()) }
    }

    /// A context manager to speed up bulk project operations.
    /// Project modifications are synced to disk in chunks,
    /// and the project on disk vs in memory may not agree on state
    /// if an exception occurs while a bulk operation is happening.
    ///
    /// ```no_run
    /// # use binaryninja::project::Project;
    /// # let mut project: Project = todo!();
    /// if let Ok(bulk) = project.bulk_operation() {
    ///     for file in std::fs::read_dir("/bin/").unwrap().into_iter() {
    ///         let file = file.unwrap();
    ///         let file_type = file.file_type().unwrap();
    ///         if file_type.is_file() && !file_type.is_symlink() {
    ///             bulk.create_file_from_path("/bin/", None, &file.file_name().to_string_lossy(), "")
    ///                 .unwrap();
    ///         }
    ///     }
    /// }
    /// ```
    // NOTE mut is used here, so only one lock can be acquired at once
    pub fn bulk_operation(&mut self) -> Result<ProjectBulkOperationLock<'_>, ()> {
        Ok(ProjectBulkOperationLock::lock(self))
    }
}

impl Debug for Project {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Project")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("description", &self.description())
            .finish()
    }
}

impl PartialEq for Project {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for Project {}

impl Hash for Project {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}

impl ToOwned for Project {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Project {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewProjectReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeProject(handle.handle.as_ptr());
    }
}

unsafe impl Send for Project {}
unsafe impl Sync for Project {}

impl CoreArrayProvider for Project {
    type Raw = *mut BNProject;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Project>;
}

unsafe impl CoreArrayProviderInner for Project {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeProjectList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}

// TODO: Rename to bulk operation guard?
pub struct ProjectBulkOperationLock<'a> {
    lock: &'a mut Project,
}

impl<'a> ProjectBulkOperationLock<'a> {
    pub fn lock(project: &'a mut Project) -> Self {
        unsafe { BNProjectBeginBulkOperation(project.handle.as_ptr()) };
        Self { lock: project }
    }

    pub fn unlock(self) {
        // NOTE does nothing, just drop self
    }
}

impl std::ops::Deref for ProjectBulkOperationLock<'_> {
    type Target = Project;
    fn deref(&self) -> &Self::Target {
        self.lock
    }
}

impl Drop for ProjectBulkOperationLock<'_> {
    fn drop(&mut self) {
        unsafe { BNProjectEndBulkOperation(self.lock.handle.as_ptr()) };
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
