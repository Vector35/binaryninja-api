use std::ffi::{c_char, c_void};
use std::ptr::NonNull;
use std::time::SystemTime;

use binaryninjacore_sys::*;

use super::{
    sync, CollaborationPermissionLevel, NameChangeset, Permission, Remote, RemoteFile,
    RemoteFileType, RemoteFolder,
};

use crate::binary_view::{BinaryView, BinaryViewExt};
use crate::database::Database;
use crate::file_metadata::FileMetadata;
use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::project::Project;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};

#[repr(transparent)]
pub struct RemoteProject {
    pub(crate) handle: NonNull<BNRemoteProject>,
}

impl RemoteProject {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNRemoteProject>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNRemoteProject>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Determine if the project is open (it needs to be opened before you can access its files)
    pub fn is_open(&self) -> bool {
        unsafe { BNRemoteProjectIsOpen(self.handle.as_ptr()) }
    }

    /// Open the project, allowing various file and folder based apis to work, as well as
    /// connecting a core Project
    pub fn open(&self) -> Result<(), ()> {
        self.open_with_progress(NoProgressCallback)
    }

    /// Open the project, allowing various file and folder based apis to work, as well as
    /// connecting a core Project
    pub fn open_with_progress<F: ProgressCallback>(&self, mut progress: F) -> Result<(), ()> {
        if self.is_open() {
            return Ok(());
        }
        let success = unsafe {
            BNRemoteProjectOpen(
                self.handle.as_ptr(),
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Close the project and stop all background operations (e.g. file uploads)
    pub fn close(&self) {
        unsafe { BNRemoteProjectClose(self.handle.as_ptr()) }
    }

    /// Get the Remote Project for a Database
    pub fn get_for_local_database(database: &Database) -> Result<Option<Ref<Self>>, ()> {
        // TODO: This sync should be removed?
        if sync::pull_projects(database)? {
            return Ok(None);
        }
        sync::get_remote_project_for_local_database(database)
    }

    /// Get the Remote Project for a BinaryView
    pub fn get_for_binaryview(bv: &BinaryView) -> Result<Option<Ref<Self>>, ()> {
        let file = bv.file();
        let Some(database) = file.database() else {
            return Ok(None);
        };
        Self::get_for_local_database(&database)
    }

    /// Get the core [`Project`] for the remote project.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    pub fn core_project(&self) -> Result<Ref<Project>, ()> {
        // TODO: This sync should be removed?
        self.open()?;

        let value = unsafe { BNRemoteProjectGetCoreProject(self.handle.as_ptr()) };
        NonNull::new(value)
            .map(|handle| unsafe { Project::ref_from_raw(handle) })
            .ok_or(())
    }

    /// Get the owning remote
    pub fn remote(&self) -> Result<Ref<Remote>, ()> {
        let value = unsafe { BNRemoteProjectGetRemote(self.handle.as_ptr()) };
        NonNull::new(value)
            .map(|handle| unsafe { Remote::ref_from_raw(handle) })
            .ok_or(())
    }

    /// Get the URL of the project
    pub fn url(&self) -> BnString {
        let result = unsafe { BNRemoteProjectGetUrl(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Get the unique ID of the project
    pub fn id(&self) -> BnString {
        let result = unsafe { BNRemoteProjectGetId(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Created date of the project
    pub fn created(&self) -> SystemTime {
        let result = unsafe { BNRemoteProjectGetCreated(self.handle.as_ptr()) };
        crate::ffi::time_from_bn(result.try_into().unwrap())
    }

    /// Last modification of the project
    pub fn last_modified(&self) -> SystemTime {
        let result = unsafe { BNRemoteProjectGetLastModified(self.handle.as_ptr()) };
        crate::ffi::time_from_bn(result.try_into().unwrap())
    }

    /// Displayed name of file
    pub fn name(&self) -> BnString {
        let result = unsafe { BNRemoteProjectGetName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Set the description of the file. You will need to push the file to update the remote version.
    pub fn set_name<S: BnStrCompatible>(&self, name: S) -> Result<(), ()> {
        let name = name.into_bytes_with_nul();
        let success = unsafe {
            BNRemoteProjectSetName(
                self.handle.as_ptr(),
                name.as_ref().as_ptr() as *const c_char,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Desciprtion of the file
    pub fn description(&self) -> BnString {
        let result = unsafe { BNRemoteProjectGetDescription(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Set the description of the file. You will need to push the file to update the remote version.
    pub fn set_description<S: BnStrCompatible>(&self, description: S) -> Result<(), ()> {
        let description = description.into_bytes_with_nul();
        let success = unsafe {
            BNRemoteProjectSetDescription(
                self.handle.as_ptr(),
                description.as_ref().as_ptr() as *const c_char,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Get the number of files in a project (without needing to pull them first)
    pub fn received_file_count(&self) -> u64 {
        unsafe { BNRemoteProjectGetReceivedFileCount(self.handle.as_ptr()) }
    }

    /// Get the number of folders in a project (without needing to pull them first)
    pub fn received_folder_count(&self) -> u64 {
        unsafe { BNRemoteProjectGetReceivedFolderCount(self.handle.as_ptr()) }
    }

    /// Get the default directory path for a remote Project. This is based off the Setting for
    /// collaboration.directory, the project's id, and the project's remote's id.
    pub fn default_path(&self) -> Result<BnString, ()> {
        sync::default_project_path(self)
    }

    /// If the project has pulled the folders yet
    pub fn has_pulled_files(&self) -> bool {
        unsafe { BNRemoteProjectHasPulledFiles(self.handle.as_ptr()) }
    }

    /// If the project has pulled the folders yet
    pub fn has_pulled_folders(&self) -> bool {
        unsafe { BNRemoteProjectHasPulledFolders(self.handle.as_ptr()) }
    }

    /// If the project has pulled the group permissions yet
    pub fn has_pulled_group_permissions(&self) -> bool {
        unsafe { BNRemoteProjectHasPulledGroupPermissions(self.handle.as_ptr()) }
    }

    /// If the project has pulled the user permissions yet
    pub fn has_pulled_user_permissions(&self) -> bool {
        unsafe { BNRemoteProjectHasPulledUserPermissions(self.handle.as_ptr()) }
    }

    /// If the currently logged in user is an administrator of the project (and can edit
    /// permissions and such for the project).
    pub fn is_admin(&self) -> bool {
        unsafe { BNRemoteProjectIsAdmin(self.handle.as_ptr()) }
    }

    /// Get the list of files in this project.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If folders have not been pulled, they will be pulled upon calling this.
    /// NOTE: If files have not been pulled, they will be pulled upon calling this.
    pub fn files(&self) -> Result<Array<RemoteFile>, ()> {
        // TODO: This sync should be removed?
        if !self.has_pulled_files() {
            self.pull_files()?;
        }

        let mut count = 0;
        let result = unsafe { BNRemoteProjectGetFiles(self.handle.as_ptr(), &mut count) };
        (!result.is_null())
            .then(|| unsafe { Array::new(result, count, ()) })
            .ok_or(())
    }

    /// Get a specific File in the Project by its id
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If files have not been pulled, they will be pulled upon calling this.
    pub fn get_file_by_id<S: BnStrCompatible>(&self, id: S) -> Result<Option<Ref<RemoteFile>>, ()> {
        // TODO: This sync should be removed?
        if !self.has_pulled_files() {
            self.pull_files()?;
        }
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNRemoteProjectGetFileById(self.handle.as_ptr(), id.as_ref().as_ptr() as *const c_char)
        };
        Ok(NonNull::new(result).map(|handle| unsafe { RemoteFile::ref_from_raw(handle) }))
    }

    /// Get a specific File in the Project by its name
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If files have not been pulled, they will be pulled upon calling this.
    pub fn get_file_by_name<S: BnStrCompatible>(
        &self,
        name: S,
    ) -> Result<Option<Ref<RemoteFile>>, ()> {
        // TODO: This sync should be removed?
        if !self.has_pulled_files() {
            self.pull_files()?;
        }
        let id = name.into_bytes_with_nul();
        let result = unsafe {
            BNRemoteProjectGetFileByName(
                self.handle.as_ptr(),
                id.as_ref().as_ptr() as *const c_char,
            )
        };
        Ok(NonNull::new(result).map(|handle| unsafe { RemoteFile::ref_from_raw(handle) }))
    }

    /// Pull the list of files from the Remote.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If folders have not been pulled, they will be pulled upon calling this.
    pub fn pull_files(&self) -> Result<(), ()> {
        self.pull_files_with_progress(NoProgressCallback)
    }

    /// Pull the list of files from the Remote.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If folders have not been pulled, they will be pulled upon calling this.
    pub fn pull_files_with_progress<P: ProgressCallback>(&self, mut progress: P) -> Result<(), ()> {
        // TODO: This sync should be removed?
        if !self.has_pulled_folders() {
            self.pull_folders()?;
        }
        let success = unsafe {
            BNRemoteProjectPullFiles(
                self.handle.as_ptr(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Create a new file on the remote and return a reference to the created file
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    ///
    /// * `filename` - File name
    /// * `contents` - File contents
    /// * `name` - Displayed file name
    /// * `description` - File description
    /// * `parent_folder` - Folder that will contain the file
    /// * `file_type` - Type of File to create
    pub fn create_file<F, N, D>(
        &self,
        filename: F,
        contents: &[u8],
        name: N,
        description: D,
        parent_folder: Option<&RemoteFolder>,
        file_type: RemoteFileType,
    ) -> Result<Ref<RemoteFile>, ()>
    where
        F: BnStrCompatible,
        N: BnStrCompatible,
        D: BnStrCompatible,
    {
        self.create_file_with_progress(
            filename,
            contents,
            name,
            description,
            parent_folder,
            file_type,
            NoProgressCallback,
        )
    }

    /// Create a new file on the remote and return a reference to the created file
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    ///
    /// * `filename` - File name
    /// * `contents` - File contents
    /// * `name` - Displayed file name
    /// * `description` - File description
    /// * `parent_folder` - Folder that will contain the file
    /// * `file_type` - Type of File to create
    /// * `progress` - Function to call on upload progress updates
    pub fn create_file_with_progress<F, N, D, P>(
        &self,
        filename: F,
        contents: &[u8],
        name: N,
        description: D,
        parent_folder: Option<&RemoteFolder>,
        file_type: RemoteFileType,
        mut progress: P,
    ) -> Result<Ref<RemoteFile>, ()>
    where
        F: BnStrCompatible,
        N: BnStrCompatible,
        D: BnStrCompatible,
        P: ProgressCallback,
    {
        // TODO: This sync should be removed?
        self.open()?;

        let filename = filename.into_bytes_with_nul();
        let name = name.into_bytes_with_nul();
        let description = description.into_bytes_with_nul();
        let folder_handle = parent_folder.map_or(std::ptr::null_mut(), |f| f.handle.as_ptr());
        let file_ptr = unsafe {
            BNRemoteProjectCreateFile(
                self.handle.as_ptr(),
                filename.as_ref().as_ptr() as *const c_char,
                contents.as_ptr() as *mut _,
                contents.len(),
                name.as_ref().as_ptr() as *const c_char,
                description.as_ref().as_ptr() as *const c_char,
                folder_handle,
                file_type,
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };

        NonNull::new(file_ptr)
            .map(|handle| unsafe { RemoteFile::ref_from_raw(handle) })
            .ok_or(())
    }

    /// Push an updated File object to the Remote
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    pub fn push_file<I, K, V>(&self, file: &RemoteFile, extra_fields: I) -> Result<(), ()>
    where
        I: Iterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
    {
        // TODO: This sync should be removed?
        self.open()?;

        let (keys, values): (Vec<_>, Vec<_>) = extra_fields
            .into_iter()
            .map(|(k, v)| (k.into_bytes_with_nul(), v.into_bytes_with_nul()))
            .unzip();
        let mut keys_raw = keys
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect::<Vec<_>>();
        let mut values_raw = values
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect::<Vec<_>>();
        let success = unsafe {
            BNRemoteProjectPushFile(
                self.handle.as_ptr(),
                file.handle.as_ptr(),
                keys_raw.as_mut_ptr(),
                values_raw.as_mut_ptr(),
                keys_raw.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    pub fn delete_file(&self, file: &RemoteFile) -> Result<(), ()> {
        // TODO: This sync should be removed?
        self.open()?;

        let success =
            unsafe { BNRemoteProjectDeleteFile(self.handle.as_ptr(), file.handle.as_ptr()) };
        success.then_some(()).ok_or(())
    }

    /// Get the list of folders in this project.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If folders have not been pulled, they will be pulled upon calling this.
    pub fn folders(&self) -> Result<Array<RemoteFolder>, ()> {
        // TODO: This sync should be removed?
        if !self.has_pulled_folders() {
            self.pull_folders()?;
        }
        let mut count = 0;
        let result = unsafe { BNRemoteProjectGetFolders(self.handle.as_ptr(), &mut count) };
        if result.is_null() {
            return Err(());
        }
        Ok(unsafe { Array::new(result, count, ()) })
    }

    /// Get a specific Folder in the Project by its id
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If folders have not been pulled, they will be pulled upon calling this.
    pub fn get_folder_by_id<S: BnStrCompatible>(
        &self,
        id: S,
    ) -> Result<Option<Ref<RemoteFolder>>, ()> {
        // TODO: This sync should be removed?
        if !self.has_pulled_folders() {
            self.pull_folders()?;
        }
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNRemoteProjectGetFolderById(
                self.handle.as_ptr(),
                id.as_ref().as_ptr() as *const c_char,
            )
        };
        Ok(NonNull::new(result).map(|handle| unsafe { RemoteFolder::ref_from_raw(handle) }))
    }

    /// Pull the list of folders from the Remote.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    pub fn pull_folders(&self) -> Result<(), ()> {
        self.pull_folders_with_progress(NoProgressCallback)
    }

    /// Pull the list of folders from the Remote.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    pub fn pull_folders_with_progress<P: ProgressCallback>(
        &self,
        mut progress: P,
    ) -> Result<(), ()> {
        // TODO: This sync should be removed?
        self.open()?;

        let success = unsafe {
            BNRemoteProjectPullFolders(
                self.handle.as_ptr(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Create a new folder on the remote (and pull it)
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    ///
    /// * `name` - Displayed folder name
    /// * `description` - Folder description
    /// * `parent` - Parent folder (optional)
    pub fn create_folder<N, D>(
        &self,
        name: N,
        description: D,
        parent_folder: Option<&RemoteFolder>,
    ) -> Result<Ref<RemoteFolder>, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
    {
        self.create_folder_with_progress(name, description, parent_folder, NoProgressCallback)
    }

    /// Create a new folder on the remote (and pull it)
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    ///
    /// * `name` - Displayed folder name
    /// * `description` - Folder description
    /// * `parent` - Parent folder (optional)
    /// * `progress` - Function to call on upload progress updates
    pub fn create_folder_with_progress<N, D, P>(
        &self,
        name: N,
        description: D,
        parent_folder: Option<&RemoteFolder>,
        mut progress: P,
    ) -> Result<Ref<RemoteFolder>, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
        P: ProgressCallback,
    {
        // TODO: This sync should be removed?
        self.open()?;

        let name = name.into_bytes_with_nul();
        let description = description.into_bytes_with_nul();
        let folder_handle = parent_folder.map_or(std::ptr::null_mut(), |f| f.handle.as_ptr());
        let file_ptr = unsafe {
            BNRemoteProjectCreateFolder(
                self.handle.as_ptr(),
                name.as_ref().as_ptr() as *const c_char,
                description.as_ref().as_ptr() as *const c_char,
                folder_handle,
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };

        NonNull::new(file_ptr)
            .map(|handle| unsafe { RemoteFolder::ref_from_raw(handle) })
            .ok_or(())
    }

    /// Push an updated Folder object to the Remote
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    ///
    /// * `folder` - Folder object which has been updated
    /// * `extra_fields` - Extra HTTP fields to send with the update
    pub fn push_folder<I, K, V>(&self, folder: &RemoteFolder, extra_fields: I) -> Result<(), ()>
    where
        I: Iterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
    {
        // TODO: This sync should be removed?
        self.open()?;

        let (keys, values): (Vec<_>, Vec<_>) = extra_fields
            .into_iter()
            .map(|(k, v)| (k.into_bytes_with_nul(), v.into_bytes_with_nul()))
            .unzip();
        let mut keys_raw = keys
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect::<Vec<_>>();
        let mut values_raw = values
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect::<Vec<_>>();
        let success = unsafe {
            BNRemoteProjectPushFolder(
                self.handle.as_ptr(),
                folder.handle.as_ptr(),
                keys_raw.as_mut_ptr(),
                values_raw.as_mut_ptr(),
                keys_raw.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Delete a folder from the remote
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    pub fn delete_folder(&self, folder: &RemoteFolder) -> Result<(), ()> {
        // TODO: This sync should be removed?
        self.open()?;

        let success =
            unsafe { BNRemoteProjectDeleteFolder(self.handle.as_ptr(), folder.handle.as_ptr()) };
        success.then_some(()).ok_or(())
    }

    /// Get the list of group permissions in this project.
    ///
    /// NOTE: If group permissions have not been pulled, they will be pulled upon calling this.
    pub fn group_permissions(&self) -> Result<Array<Permission>, ()> {
        // TODO: This sync should be removed?
        if !self.has_pulled_group_permissions() {
            self.pull_group_permissions()?;
        }

        let mut count: usize = 0;
        let value = unsafe { BNRemoteProjectGetGroupPermissions(self.handle.as_ptr(), &mut count) };
        assert!(!value.is_null());
        Ok(unsafe { Array::new(value, count, ()) })
    }

    /// Get the list of user permissions in this project.
    ///
    /// NOTE: If user permissions have not been pulled, they will be pulled upon calling this.
    pub fn user_permissions(&self) -> Result<Array<Permission>, ()> {
        // TODO: This sync should be removed?
        if !self.has_pulled_user_permissions() {
            self.pull_user_permissions()?;
        }

        let mut count: usize = 0;
        let value = unsafe { BNRemoteProjectGetUserPermissions(self.handle.as_ptr(), &mut count) };
        assert!(!value.is_null());
        Ok(unsafe { Array::new(value, count, ()) })
    }

    /// Get a specific permission in the Project by its id.
    ///
    /// NOTE: If group or user permissions have not been pulled, they will be pulled upon calling this.
    pub fn get_permission_by_id<S: BnStrCompatible>(
        &self,
        id: S,
    ) -> Result<Option<Ref<Permission>>, ()> {
        // TODO: This sync should be removed?
        if !self.has_pulled_user_permissions() {
            self.pull_user_permissions()?;
        }
        // TODO: This sync should be removed?
        if !self.has_pulled_group_permissions() {
            self.pull_group_permissions()?;
        }

        let id = id.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteProjectGetPermissionById(self.handle.as_ptr(), id.as_ref().as_ptr() as *const _)
        };
        Ok(NonNull::new(value).map(|v| unsafe { Permission::ref_from_raw(v) }))
    }

    /// Pull the list of group permissions from the Remote.
    pub fn pull_group_permissions(&self) -> Result<(), ()> {
        self.pull_group_permissions_with_progress(NoProgressCallback)
    }

    /// Pull the list of group permissions from the Remote.
    pub fn pull_group_permissions_with_progress<F: ProgressCallback>(
        &self,
        mut progress: F,
    ) -> Result<(), ()> {
        let success = unsafe {
            BNRemoteProjectPullGroupPermissions(
                self.handle.as_ptr(),
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Pull the list of user permissions from the Remote.
    pub fn pull_user_permissions(&self) -> Result<(), ()> {
        self.pull_user_permissions_with_progress(NoProgressCallback)
    }

    /// Pull the list of user permissions from the Remote.
    pub fn pull_user_permissions_with_progress<F: ProgressCallback>(
        &self,
        mut progress: F,
    ) -> Result<(), ()> {
        let success = unsafe {
            BNRemoteProjectPullUserPermissions(
                self.handle.as_ptr(),
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Create a new group permission on the remote (and pull it).
    ///
    /// # Arguments
    ///
    /// * `group_id` - Group id
    /// * `level` - Permission level
    pub fn create_group_permission(
        &self,
        group_id: i64,
        level: CollaborationPermissionLevel,
    ) -> Result<Ref<Permission>, ()> {
        self.create_group_permission_with_progress(group_id, level, NoProgressCallback)
    }

    /// Create a new group permission on the remote (and pull it).
    ///
    /// # Arguments
    ///
    /// * `group_id` - Group id
    /// * `level` - Permission level
    /// * `progress` - Function to call for upload progress updates
    pub fn create_group_permission_with_progress<F: ProgressCallback>(
        &self,
        group_id: i64,
        level: CollaborationPermissionLevel,
        mut progress: F,
    ) -> Result<Ref<Permission>, ()> {
        let value = unsafe {
            BNRemoteProjectCreateGroupPermission(
                self.handle.as_ptr(),
                group_id,
                level,
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut c_void,
            )
        };

        NonNull::new(value)
            .map(|v| unsafe { Permission::ref_from_raw(v) })
            .ok_or(())
    }

    /// Create a new user permission on the remote (and pull it).
    ///
    /// # Arguments
    ///
    /// * `user_id` - User id
    /// * `level` - Permission level
    pub fn create_user_permission<S: BnStrCompatible>(
        &self,
        user_id: S,
        level: CollaborationPermissionLevel,
    ) -> Result<Ref<Permission>, ()> {
        self.create_user_permission_with_progress(user_id, level, NoProgressCallback)
    }

    /// Create a new user permission on the remote (and pull it).
    ///
    /// # Arguments
    ///
    /// * `user_id` - User id
    /// * `level` - Permission level
    /// * `progress` - The progress callback to call
    pub fn create_user_permission_with_progress<S: BnStrCompatible, F: ProgressCallback>(
        &self,
        user_id: S,
        level: CollaborationPermissionLevel,
        mut progress: F,
    ) -> Result<Ref<Permission>, ()> {
        let user_id = user_id.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteProjectCreateUserPermission(
                self.handle.as_ptr(),
                user_id.as_ref().as_ptr() as *const c_char,
                level,
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut c_void,
            )
        };

        NonNull::new(value)
            .map(|v| unsafe { Permission::ref_from_raw(v) })
            .ok_or(())
    }

    /// Push project permissions to the remote.
    ///
    /// # Arguments
    ///
    /// * `permission` - Permission object which has been updated
    /// * `extra_fields` - Extra HTTP fields to send with the update
    pub fn push_permission<I, K, V>(
        &self,
        permission: &Permission,
        extra_fields: I,
    ) -> Result<(), ()>
    where
        I: Iterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
    {
        let (keys, values): (Vec<_>, Vec<_>) = extra_fields
            .into_iter()
            .map(|(k, v)| (k.into_bytes_with_nul(), v.into_bytes_with_nul()))
            .unzip();
        let mut keys_raw = keys
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect::<Vec<_>>();
        let mut values_raw = values
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect::<Vec<_>>();

        let success = unsafe {
            BNRemoteProjectPushPermission(
                self.handle.as_ptr(),
                permission.handle.as_ptr(),
                keys_raw.as_mut_ptr(),
                values_raw.as_mut_ptr(),
                keys_raw.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Delete a permission from the remote.
    pub fn delete_permission(&self, permission: &Permission) -> Result<(), ()> {
        let success = unsafe {
            BNRemoteProjectDeletePermission(self.handle.as_ptr(), permission.handle.as_ptr())
        };
        success.then_some(()).ok_or(())
    }

    /// Determine if a user is in any of the view/edit/admin groups.
    ///
    /// # Arguments
    ///
    /// * `username` - Username of user to check
    pub fn can_user_view<S: BnStrCompatible>(&self, username: S) -> bool {
        let username = username.into_bytes_with_nul();
        unsafe {
            BNRemoteProjectCanUserView(
                self.handle.as_ptr(),
                username.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Determine if a user is in any of the edit/admin groups.
    ///
    /// # Arguments
    ///
    /// * `username` - Username of user to check
    pub fn can_user_edit<S: BnStrCompatible>(&self, username: S) -> bool {
        let username = username.into_bytes_with_nul();
        unsafe {
            BNRemoteProjectCanUserEdit(
                self.handle.as_ptr(),
                username.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Determine if a user is in the admin group.
    ///
    /// # Arguments
    ///
    /// * `username` - Username of user to check
    pub fn can_user_admin<S: BnStrCompatible>(&self, username: S) -> bool {
        let username = username.into_bytes_with_nul();
        unsafe {
            BNRemoteProjectCanUserAdmin(
                self.handle.as_ptr(),
                username.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Get the default directory path for a remote Project. This is based off
    /// the Setting for collaboration.directory, the project's id, and the
    /// project's remote's id.
    pub fn default_project_path(&self) -> BnString {
        let result = unsafe { BNCollaborationDefaultProjectPath(self.handle.as_ptr()) };
        unsafe { BnString::from_raw(result) }
    }

    /// Upload a file, with database, to the remote under the given project
    ///
    /// * `metadata` - Local file with database
    /// * `parent_folder` - Optional parent folder in which to place this file
    /// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
    pub fn upload_database<C>(
        &self,
        metadata: &FileMetadata,
        parent_folder: Option<&RemoteFolder>,
        name_changeset: C,
    ) -> Result<Ref<RemoteFile>, ()>
    where
        C: NameChangeset,
    {
        // TODO: Do we want this?
        // TODO: If you have not yet pulled files you will have never filled the map you will be placing your
        // TODO: New file in.
        if !self.has_pulled_files() {
            self.pull_files()?;
        }
        sync::upload_database(self, parent_folder, metadata, name_changeset)
    }

    /// Upload a file, with database, to the remote under the given project
    ///
    /// * `metadata` - Local file with database
    /// * `parent_folder` - Optional parent folder in which to place this file
    /// * `progress` -: Function to call for progress updates
    /// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
    pub fn upload_database_with_progress<C>(
        &self,
        metadata: &FileMetadata,
        parent_folder: Option<&RemoteFolder>,
        name_changeset: C,
        progress_function: impl ProgressCallback,
    ) -> Result<Ref<RemoteFile>, ()>
    where
        C: NameChangeset,
    {
        sync::upload_database_with_progress(
            self,
            parent_folder,
            metadata,
            name_changeset,
            progress_function,
        )
    }

    // TODO: check remotebrowser.cpp for implementation
    ///// Upload a file to the project, creating a new File and pulling it
    /////
    ///// NOTE: If the project has not been opened, it will be opened upon calling this.
    /////
    ///// * `target` - Path to file on disk or BinaryView/FileMetadata object of
    /////                already-opened file
    ///// * `parent_folder` - Parent folder to place the uploaded file in
    ///// * `progress` - Function to call for progress updates
    //pub fn upload_new_file<S: BnStrCompatible, P: ProgressCallback>(
    //    &self,
    //    target: S,
    //    parent_folder: Option<&RemoteFolder>,
    //    progress: P,
    //    open_view_options: u32,
    //) -> Result<(), ()> {
    //    if !self.open(NoProgressCallback)? {
    //        return Err(());
    //    }
    //    let target = target.into_bytes_with_nul();
    //    todo!();
    //}
}

impl PartialEq for RemoteProject {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for RemoteProject {}

impl ToOwned for RemoteProject {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for RemoteProject {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewRemoteProjectReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeRemoteProject(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for RemoteProject {
    type Raw = *mut BNRemoteProject;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for RemoteProject {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeRemoteProjectList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}
