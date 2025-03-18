pub mod file;
pub mod folder;

use std::ffi::{c_char, c_void};
use std::fmt::Debug;
use std::ptr::{null_mut, NonNull};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use binaryninjacore_sys::*;

use crate::metadata::Metadata;
use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::project::file::ProjectFile;
use crate::project::folder::ProjectFolder;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};

pub struct Project {
    pub(crate) handle: NonNull<BNProject>,
}

impl Project {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNProject>) -> Self {
        Project { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNProject>) -> Ref<Self> {
        Ref::new(Self { handle })
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
    pub fn create<P: BnStrCompatible, S: BnStrCompatible>(path: P, name: S) -> Option<Ref<Self>> {
        let path_raw = path.into_bytes_with_nul();
        let name_raw = name.into_bytes_with_nul();
        let handle = unsafe {
            BNCreateProject(
                path_raw.as_ref().as_ptr() as *const c_char,
                name_raw.as_ref().as_ptr() as *const c_char,
            )
        };
        NonNull::new(handle).map(|h| unsafe { Self::ref_from_raw(h) })
    }

    /// Open an existing project
    ///
    /// * `path` - Path to the project directory (.bnpr) or project metadata file (.bnpm)
    pub fn open_project<P: BnStrCompatible>(path: P) -> Option<Ref<Self>> {
        let path_raw = path.into_bytes_with_nul();
        let handle = unsafe { BNOpenProject(path_raw.as_ref().as_ptr() as *const c_char) };
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

    /// Close a open project
    pub fn close(&self) -> Result<(), ()> {
        if unsafe { BNProjectClose(self.handle.as_ptr()) } {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Get the unique id of this project
    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectGetId(self.handle.as_ptr())) }
    }

    /// Get the path of the project
    pub fn path(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectGetPath(self.handle.as_ptr())) }
    }

    /// Get the name of the project
    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectGetName(self.handle.as_ptr())) }
    }

    /// Set the name of the project
    pub fn set_name<S: BnStrCompatible>(&self, value: S) {
        let value = value.into_bytes_with_nul();
        unsafe {
            BNProjectSetName(
                self.handle.as_ptr(),
                value.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Get the description of the project
    pub fn description(&self) -> BnString {
        unsafe { BnString::from_raw(BNProjectGetDescription(self.handle.as_ptr())) }
    }

    /// Set the description of the project
    pub fn set_description<S: BnStrCompatible>(&self, value: S) {
        let value = value.into_bytes_with_nul();
        unsafe {
            BNProjectSetDescription(
                self.handle.as_ptr(),
                value.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Retrieves metadata stored under a key from the project
    pub fn query_metadata<S: BnStrCompatible>(&self, key: S) -> Ref<Metadata> {
        let key = key.into_bytes_with_nul();
        let result = unsafe {
            BNProjectQueryMetadata(self.handle.as_ptr(), key.as_ref().as_ptr() as *const c_char)
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
                self.handle.as_ptr(),
                key_raw.as_ref().as_ptr() as *const c_char,
                value.handle,
            )
        }
    }

    /// Removes the metadata associated with this `key` from the project
    pub fn remove_metadata<S: BnStrCompatible>(&self, key: S) {
        let key_raw = key.into_bytes_with_nul();
        unsafe {
            BNProjectRemoveMetadata(
                self.handle.as_ptr(),
                key_raw.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    pub fn push_folder(&self, file: &ProjectFolder) {
        unsafe { BNProjectPushFolder(self.handle.as_ptr(), file.handle.as_ptr()) }
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
    ) -> Result<Ref<ProjectFolder>, ()>
    where
        P: BnStrCompatible,
        D: BnStrCompatible,
    {
        self.create_folder_from_path_with_progress(path, parent, description, NoProgressCallback)
    }

    /// Recursively create files and folders in the project from a path on disk
    ///
    /// * `path` - Path to folder on disk
    /// * `parent` - Parent folder in the project that will contain the new contents
    /// * `description` - Description for created root folder
    /// * `progress` - [`ProgressCallback`] that will be called as the [`ProjectFolder`] is being created
    pub fn create_folder_from_path_with_progress<P, D, PC>(
        &self,
        path: P,
        parent: Option<&ProjectFolder>,
        description: D,
        mut progress: PC,
    ) -> Result<Ref<ProjectFolder>, ()>
    where
        P: BnStrCompatible,
        D: BnStrCompatible,
        PC: ProgressCallback,
    {
        let path_raw = path.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let parent_ptr = parent.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());

        unsafe {
            let result = BNProjectCreateFolderFromPath(
                self.handle.as_ptr(),
                path_raw.as_ref().as_ptr() as *const c_char,
                parent_ptr,
                description_raw.as_ref().as_ptr() as *const c_char,
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
    pub fn create_folder<N, D>(
        &self,
        parent: Option<&ProjectFolder>,
        name: N,
        description: D,
    ) -> Result<Ref<ProjectFolder>, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
    {
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let parent_ptr = parent.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());
        unsafe {
            let result = BNProjectCreateFolder(
                self.handle.as_ptr(),
                parent_ptr,
                name_raw.as_ref().as_ptr() as *const c_char,
                description_raw.as_ref().as_ptr() as *const c_char,
            );
            Ok(ProjectFolder::ref_from_raw(NonNull::new(result).ok_or(())?))
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
    ) -> Result<Ref<ProjectFolder>, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
        I: BnStrCompatible,
    {
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let parent_ptr = parent.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());
        let id_raw = id.into_bytes_with_nul();
        unsafe {
            let result = BNProjectCreateFolderUnsafe(
                self.handle.as_ptr(),
                parent_ptr,
                name_raw.as_ref().as_ptr() as *const c_char,
                description_raw.as_ref().as_ptr() as *const c_char,
                id_raw.as_ref().as_ptr() as *const c_char,
            );
            Ok(ProjectFolder::ref_from_raw(NonNull::new(result).ok_or(())?))
        }
    }

    /// Get a list of folders in the project
    pub fn folders(&self) -> Result<Array<ProjectFolder>, ()> {
        let mut count = 0;
        let result = unsafe { BNProjectGetFolders(self.handle.as_ptr(), &mut count) };
        if result.is_null() {
            return Err(());
        }

        Ok(unsafe { Array::new(result, count, ()) })
    }

    /// Retrieve a folder in the project by unique folder `id`
    pub fn folder_by_id<S: BnStrCompatible>(&self, id: S) -> Option<Ref<ProjectFolder>> {
        let id_raw = id.into_bytes_with_nul();
        let id_ptr = id_raw.as_ref().as_ptr() as *const c_char;
        let result = unsafe { BNProjectGetFolderById(self.handle.as_ptr(), id_ptr) };
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
    pub fn delete_folder_with_progress<P: ProgressCallback>(
        &self,
        folder: &ProjectFolder,
        mut progress: P,
    ) -> Result<(), ()> {
        let result = unsafe {
            BNProjectDeleteFolder(
                self.handle.as_ptr(),
                folder.handle.as_ptr(),
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
            )
        };

        if result {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn push_file(&self, file: &ProjectFile) {
        unsafe { BNProjectPushFile(self.handle.as_ptr(), file.handle.as_ptr()) }
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
    ) -> Result<Ref<ProjectFile>, ()>
    where
        P: BnStrCompatible,
        N: BnStrCompatible,
        D: BnStrCompatible,
    {
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
    pub fn create_file_from_path_with_progress<P, N, D, PC>(
        &self,
        path: P,
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        mut progress: PC,
    ) -> Result<Ref<ProjectFile>, ()>
    where
        P: BnStrCompatible,
        N: BnStrCompatible,
        D: BnStrCompatible,
        PC: ProgressCallback,
    {
        let path_raw = path.into_bytes_with_nul();
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let folder_ptr = folder.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());

        unsafe {
            let result = BNProjectCreateFileFromPath(
                self.handle.as_ptr(),
                path_raw.as_ref().as_ptr() as *const c_char,
                folder_ptr,
                name_raw.as_ref().as_ptr() as *const c_char,
                description_raw.as_ref().as_ptr() as *const c_char,
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
    pub unsafe fn create_file_from_path_unsafe<P, N, D, I>(
        &self,
        path: P,
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        id: I,
        creation_time: SystemTime,
    ) -> Result<Ref<ProjectFile>, ()>
    where
        P: BnStrCompatible,
        N: BnStrCompatible,
        D: BnStrCompatible,
        I: BnStrCompatible,
    {
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
    pub unsafe fn create_file_from_path_unsafe_with_progress<P, N, D, I, PC>(
        &self,
        path: P,
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        id: I,
        creation_time: SystemTime,
        mut progress: PC,
    ) -> Result<Ref<ProjectFile>, ()>
    where
        P: BnStrCompatible,
        N: BnStrCompatible,
        D: BnStrCompatible,
        I: BnStrCompatible,
        PC: ProgressCallback,
    {
        let path_raw = path.into_bytes_with_nul();
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let id_raw = id.into_bytes_with_nul();
        let folder_ptr = folder.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());

        unsafe {
            let result = BNProjectCreateFileFromPathUnsafe(
                self.handle.as_ptr(),
                path_raw.as_ref().as_ptr() as *const c_char,
                folder_ptr,
                name_raw.as_ref().as_ptr() as *const c_char,
                description_raw.as_ref().as_ptr() as *const c_char,
                id_raw.as_ref().as_ptr() as *const c_char,
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
    pub fn create_file<N, D>(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
    ) -> Result<Ref<ProjectFile>, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
    {
        self.create_file_with_progress(contents, folder, name, description, NoProgressCallback)
    }

    /// Create a file in the project
    ///
    /// * `contents` - Bytes of the file that will be created
    /// * `folder` - Folder to place the created file in
    /// * `name` - Name to assign to the created file
    /// * `description` - Description to assign to the created file
    /// * `progress` - [`ProgressCallback`] that will be called as the [`ProjectFile`] is being created
    pub fn create_file_with_progress<N, D, P>(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        mut progress: P,
    ) -> Result<Ref<ProjectFile>, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
        P: ProgressCallback,
    {
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let folder_ptr = folder.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());

        unsafe {
            let result = BNProjectCreateFile(
                self.handle.as_ptr(),
                contents.as_ptr(),
                contents.len(),
                folder_ptr,
                name_raw.as_ref().as_ptr() as *const c_char,
                description_raw.as_ref().as_ptr() as *const c_char,
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
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
    pub unsafe fn create_file_unsafe<N, D, I>(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        id: I,
        creation_time: SystemTime,
    ) -> Result<Ref<ProjectFile>, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
        I: BnStrCompatible,
    {
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
    pub unsafe fn create_file_unsafe_with_progress<N, D, I, P>(
        &self,
        contents: &[u8],
        folder: Option<&ProjectFolder>,
        name: N,
        description: D,
        id: I,
        creation_time: SystemTime,
        mut progress: P,
    ) -> Result<Ref<ProjectFile>, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
        I: BnStrCompatible,
        P: ProgressCallback,
    {
        let name_raw = name.into_bytes_with_nul();
        let description_raw = description.into_bytes_with_nul();
        let id_raw = id.into_bytes_with_nul();
        let folder_ptr = folder.map(|p| p.handle.as_ptr()).unwrap_or(null_mut());

        unsafe {
            let result = BNProjectCreateFileUnsafe(
                self.handle.as_ptr(),
                contents.as_ptr(),
                contents.len(),
                folder_ptr,
                name_raw.as_ref().as_ptr() as *const c_char,
                description_raw.as_ref().as_ptr() as *const c_char,
                id_raw.as_ref().as_ptr() as *const c_char,
                systime_to_bntime(creation_time).unwrap(),
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
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
    pub fn file_by_id<S: BnStrCompatible>(&self, id: S) -> Option<Ref<ProjectFile>> {
        let id_raw = id.into_bytes_with_nul();
        let id_ptr = id_raw.as_ref().as_ptr() as *const c_char;

        let result = unsafe { BNProjectGetFileById(self.handle.as_ptr(), id_ptr) };
        let handle = NonNull::new(result)?;
        Some(unsafe { ProjectFile::ref_from_raw(handle) })
    }

    /// Retrieve a file in the project by the `path` on disk
    pub fn file_by_path<S: BnStrCompatible>(&self, path: S) -> Option<Ref<ProjectFile>> {
        let path_raw = path.into_bytes_with_nul();
        let path_ptr = path_raw.as_ref().as_ptr() as *const c_char;

        let result = unsafe { BNProjectGetFileByPathOnDisk(self.handle.as_ptr(), path_ptr) };
        let handle = NonNull::new(result)?;
        Some(unsafe { ProjectFile::ref_from_raw(handle) })
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
    pub fn bulk_operation(&mut self) -> Result<ProjectBulkOperationLock, ()> {
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
