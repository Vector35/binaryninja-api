use core::{ffi, mem, ptr};

use std::time::SystemTime;

use binaryninjacore_sys::*;

use super::{
    databasesync, CollaborationPermissionLevel, NameChangeset, Permission, Remote, RemoteFile,
    RemoteFileType, RemoteFolder,
};

use crate::binaryview::{BinaryView, BinaryViewExt};
use crate::database::Database;
use crate::ffi::{ProgressCallback, ProgressCallbackNop};
use crate::filemetadata::FileMetadata;
use crate::project::Project;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

/// Struct representing a remote project
#[repr(transparent)]
pub struct RemoteProject {
    handle: ptr::NonNull<BNRemoteProject>,
}

impl Drop for RemoteProject {
    fn drop(&mut self) {
        unsafe { BNFreeRemoteProject(self.as_raw()) }
    }
}

impl PartialEq for RemoteProject {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for RemoteProject {}

impl Clone for RemoteProject {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewRemoteProjectReference(self.as_raw())).unwrap())
        }
    }
}

impl RemoteProject {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNRemoteProject>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNRemoteProject) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNRemoteProject {
        &mut *self.handle.as_ptr()
    }

    /// Determine if the project is open (it needs to be opened before you can access its files)
    pub fn is_open(&self) -> bool {
        unsafe { BNRemoteProjectIsOpen(self.as_raw()) }
    }

    /// Open the project, allowing various file and folder based apis to work, as well as
    /// connecting a core Project
    pub fn open<F: ProgressCallback>(&self, mut progress: F) -> Result<(), ()> {
        if self.is_open() {
            return Ok(());
        }
        let success = unsafe {
            BNRemoteProjectOpen(
                self.as_raw(),
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut ffi::c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Close the project and stop all background operations (e.g. file uploads)
    pub fn close(&self) {
        unsafe { BNRemoteProjectClose(self.as_raw()) }
    }

    /// Get the Remote Project for a Database
    pub fn get_for_local_database(database: &Database) -> Result<Option<Self>, ()> {
        if databasesync::pull_projects(database)? {
            return Ok(None);
        }
        databasesync::get_remote_project_for_local_database(database)
    }

    /// Get the Remote Project for a BinaryView
    pub fn get_for_binaryview(bv: &BinaryView) -> Result<Option<Self>, ()> {
        let file = bv.file();
        let Some(database) = file.database() else {
            return Ok(None);
        };
        Self::get_for_local_database(&database)
    }

    /// Get the core [Project] for the remote project.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    pub fn core_project(&self) -> Result<Project, ()> {
        self.open(ProgressCallbackNop)?;

        let value = unsafe { BNRemoteProjectGetCoreProject(self.as_raw()) };
        ptr::NonNull::new(value)
            .map(|handle| unsafe { Project::from_raw(handle) })
            .ok_or(())
    }

    /// Get the owning remote
    pub fn remote(&self) -> Result<Remote, ()> {
        let value = unsafe { BNRemoteProjectGetRemote(self.as_raw()) };
        ptr::NonNull::new(value)
            .map(|handle| unsafe { Remote::from_raw(handle) })
            .ok_or(())
    }

    /// Get the URL of the project
    pub fn url(&self) -> BnString {
        let result = unsafe { BNRemoteProjectGetUrl(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Get the unique ID of the project
    pub fn id(&self) -> BnString {
        let result = unsafe { BNRemoteProjectGetId(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Created date of the project
    pub fn created(&self) -> SystemTime {
        let result = unsafe { BNRemoteProjectGetCreated(self.as_raw()) };
        crate::ffi::time_from_bn(result.try_into().unwrap())
    }

    /// Last modification of the project
    pub fn last_modified(&self) -> SystemTime {
        let result = unsafe { BNRemoteProjectGetLastModified(self.as_raw()) };
        crate::ffi::time_from_bn(result.try_into().unwrap())
    }

    /// Displayed name of file
    pub fn name(&self) -> BnString {
        let result = unsafe { BNRemoteProjectGetName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Set the description of the file. You will need to push the file to update the remote version.
    pub fn set_name<S: BnStrCompatible>(&self, name: S) -> Result<(), ()> {
        let name = name.into_bytes_with_nul();
        let success = unsafe {
            BNRemoteProjectSetName(self.as_raw(), name.as_ref().as_ptr() as *const ffi::c_char)
        };
        success.then_some(()).ok_or(())
    }

    /// Desciprtion of the file
    pub fn description(&self) -> BnString {
        let result = unsafe { BNRemoteProjectGetDescription(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Set the description of the file. You will need to push the file to update the remote version.
    pub fn set_description<S: BnStrCompatible>(&self, description: S) -> Result<(), ()> {
        let description = description.into_bytes_with_nul();
        let success = unsafe {
            BNRemoteProjectSetDescription(
                self.as_raw(),
                description.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Get the number of files in a project (without needing to pull them first)
    pub fn received_file_count(&self) -> u64 {
        unsafe { BNRemoteProjectGetReceivedFileCount(self.as_raw()) }
    }

    /// Get the number of folders in a project (without needing to pull them first)
    pub fn received_folder_count(&self) -> u64 {
        unsafe { BNRemoteProjectGetReceivedFolderCount(self.as_raw()) }
    }

    /// Get the default directory path for a remote Project. This is based off the Setting for
    /// collaboration.directory, the project's id, and the project's remote's id.
    pub fn default_path(&self) -> Result<BnString, ()> {
        databasesync::default_project_path(self)
    }

    /// If the project has pulled the folders yet
    pub fn has_pulled_files(&self) -> bool {
        unsafe { BNRemoteProjectHasPulledFiles(self.as_raw()) }
    }

    /// If the project has pulled the folders yet
    pub fn has_pulled_folders(&self) -> bool {
        unsafe { BNRemoteProjectHasPulledFolders(self.as_raw()) }
    }

    /// If the project has pulled the group permissions yet
    pub fn has_pulled_group_permissions(&self) -> bool {
        unsafe { BNRemoteProjectHasPulledGroupPermissions(self.as_raw()) }
    }

    /// If the project has pulled the user permissions yet
    pub fn has_pulled_user_permissions(&self) -> bool {
        unsafe { BNRemoteProjectHasPulledUserPermissions(self.as_raw()) }
    }

    /// If the currently logged in user is an administrator of the project (and can edit
    /// permissions and such for the project).
    pub fn is_admin(&self) -> bool {
        unsafe { BNRemoteProjectIsAdmin(self.as_raw()) }
    }

    /// Get the list of files in this project.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If folders have not been pulled, they will be pulled upon calling this.
    /// NOTE: If files have not been pulled, they will be pulled upon calling this.
    pub fn files(&self) -> Result<Array<RemoteFile>, ()> {
        if !self.has_pulled_files() {
            self.pull_files(ProgressCallbackNop)?;
        }

        let mut count = 0;
        let result = unsafe { BNRemoteProjectGetFiles(self.as_raw(), &mut count) };
        (!result.is_null())
            .then(|| unsafe { Array::new(result, count, ()) })
            .ok_or(())
    }

    /// Get a specific File in the Project by its id
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If files have not been pulled, they will be pulled upon calling this.
    pub fn get_file_by_id<S: BnStrCompatible>(&self, id: S) -> Result<Option<RemoteFile>, ()> {
        if !self.has_pulled_files() {
            self.pull_files(ProgressCallbackNop)?;
        }
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNRemoteProjectGetFileById(self.as_raw(), id.as_ref().as_ptr() as *const ffi::c_char)
        };
        Ok(ptr::NonNull::new(result).map(|handle| unsafe { RemoteFile::from_raw(handle) }))
    }

    /// Get a specific File in the Project by its name
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If files have not been pulled, they will be pulled upon calling this.
    pub fn get_file_by_name<S: BnStrCompatible>(&self, name: S) -> Result<Option<RemoteFile>, ()> {
        if !self.has_pulled_files() {
            self.pull_files(ProgressCallbackNop)?;
        }
        let id = name.into_bytes_with_nul();
        let result = unsafe {
            BNRemoteProjectGetFileByName(self.as_raw(), id.as_ref().as_ptr() as *const ffi::c_char)
        };
        Ok(ptr::NonNull::new(result).map(|handle| unsafe { RemoteFile::from_raw(handle) }))
    }

    /// Pull the list of files from the Remote.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If folders have not been pulled, they will be pulled upon calling this.
    pub fn pull_files<P: ProgressCallback>(&self, mut progress: P) -> Result<(), ()> {
        if !self.has_pulled_folders() {
            self.pull_folders(ProgressCallbackNop)?;
        }
        let success = unsafe {
            BNRemoteProjectPullFiles(
                self.as_raw(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut ffi::c_void,
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
    /// * `progress` - Function to call on upload progress updates
    pub fn create_file<F, N, D, P>(
        &self,
        filename: F,
        contents: &[u8],
        name: N,
        description: D,
        parent_folder: Option<&RemoteFolder>,
        file_type: RemoteFileType,
        mut progress: P,
    ) -> Result<RemoteFile, ()>
    where
        F: BnStrCompatible,
        N: BnStrCompatible,
        D: BnStrCompatible,
        P: ProgressCallback,
    {
        self.open(ProgressCallbackNop)?;

        let filename = filename.into_bytes_with_nul();
        let name = name.into_bytes_with_nul();
        let description = description.into_bytes_with_nul();
        let folder_handle =
            parent_folder.map_or(ptr::null_mut(), |f| unsafe { f.as_raw() } as *mut _);
        let file_ptr = unsafe {
            BNRemoteProjectCreateFile(
                self.as_raw(),
                filename.as_ref().as_ptr() as *const ffi::c_char,
                contents.as_ptr() as *mut _,
                contents.len(),
                name.as_ref().as_ptr() as *const ffi::c_char,
                description.as_ref().as_ptr() as *const ffi::c_char,
                folder_handle,
                file_type,
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut ffi::c_void,
            )
        };

        ptr::NonNull::new(file_ptr)
            .map(|handle| unsafe { RemoteFile::from_raw(handle) })
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
        self.open(ProgressCallbackNop)?;

        let (keys, values): (Vec<_>, Vec<_>) = extra_fields
            .into_iter()
            .map(|(k, v)| (k.into_bytes_with_nul(), v.into_bytes_with_nul()))
            .unzip();
        let mut keys_raw = keys
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect::<Vec<_>>();
        let mut values_raw = values
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect::<Vec<_>>();
        let success = unsafe {
            BNRemoteProjectPushFile(
                self.as_raw(),
                file.as_raw(),
                keys_raw.as_mut_ptr(),
                values_raw.as_mut_ptr(),
                keys_raw.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    pub fn delete_file(&self, file: &RemoteFile) -> Result<(), ()> {
        self.open(ProgressCallbackNop)?;

        let success = unsafe { BNRemoteProjectDeleteFile(self.as_raw(), file.as_raw()) };
        success.then_some(()).ok_or(())
    }

    /// Get the list of folders in this project.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If folders have not been pulled, they will be pulled upon calling this.
    pub fn folders(&self) -> Result<Array<RemoteFolder>, ()> {
        if !self.has_pulled_folders() {
            self.pull_folders(ProgressCallbackNop)?;
        }
        let mut count = 0;
        let result = unsafe { BNRemoteProjectGetFolders(self.as_raw(), &mut count) };
        if result.is_null() {
            return Err(());
        }
        Ok(unsafe { Array::new(result, count, ()) })
    }

    /// Get a specific Folder in the Project by its id
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    /// NOTE: If folders have not been pulled, they will be pulled upon calling this.
    pub fn get_folder_by_id<S: BnStrCompatible>(&self, id: S) -> Result<Option<RemoteFolder>, ()> {
        if !self.has_pulled_folders() {
            self.pull_folders(ProgressCallbackNop)?;
        }
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNRemoteProjectGetFolderById(self.as_raw(), id.as_ref().as_ptr() as *const ffi::c_char)
        };
        Ok(ptr::NonNull::new(result).map(|handle| unsafe { RemoteFolder::from_raw(handle) }))
    }

    /// Pull the list of folders from the Remote.
    ///
    /// NOTE: If the project has not been opened, it will be opened upon calling this.
    pub fn pull_folders<P: ProgressCallback>(&self, mut progress: P) -> Result<(), ()> {
        self.open(ProgressCallbackNop)?;

        let success = unsafe {
            BNRemoteProjectPullFolders(
                self.as_raw(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut ffi::c_void,
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
    /// * `progress` - Function to call on upload progress updates
    pub fn create_folders<N, D, P>(
        &self,
        name: N,
        description: D,
        parent_folder: Option<&RemoteFolder>,
        mut progress: P,
    ) -> Result<RemoteFolder, ()>
    where
        N: BnStrCompatible,
        D: BnStrCompatible,
        P: ProgressCallback,
    {
        self.open(ProgressCallbackNop)?;

        let name = name.into_bytes_with_nul();
        let description = description.into_bytes_with_nul();
        let folder_handle =
            parent_folder.map_or(ptr::null_mut(), |f| unsafe { f.as_raw() } as *mut _);
        let file_ptr = unsafe {
            BNRemoteProjectCreateFolder(
                self.as_raw(),
                name.as_ref().as_ptr() as *const ffi::c_char,
                description.as_ref().as_ptr() as *const ffi::c_char,
                folder_handle,
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut ffi::c_void,
            )
        };

        ptr::NonNull::new(file_ptr)
            .map(|handle| unsafe { RemoteFolder::from_raw(handle) })
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
        self.open(ProgressCallbackNop)?;

        let (keys, values): (Vec<_>, Vec<_>) = extra_fields
            .into_iter()
            .map(|(k, v)| (k.into_bytes_with_nul(), v.into_bytes_with_nul()))
            .unzip();
        let mut keys_raw = keys
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect::<Vec<_>>();
        let mut values_raw = values
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect::<Vec<_>>();
        let success = unsafe {
            BNRemoteProjectPushFolder(
                self.as_raw(),
                folder.as_raw(),
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
    pub fn delete_folder(&self, file: &RemoteFolder) -> Result<(), ()> {
        self.open(ProgressCallbackNop)?;

        let success = unsafe { BNRemoteProjectDeleteFolder(self.as_raw(), file.as_raw()) };
        success.then_some(()).ok_or(())
    }

    /// Get the list of group permissions in this project.
    ///
    /// NOTE: If group permissions have not been pulled, they will be pulled upon calling this.
    pub fn group_permissions(&self) -> Result<Array<Permission>, ()> {
        if !self.has_pulled_group_permissions() {
            self.pull_group_permissions(ProgressCallbackNop)?;
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
        if !self.has_pulled_user_permissions() {
            self.pull_user_permissions(ProgressCallbackNop)?;
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
    ) -> Result<Option<Permission>, ()> {
        if !self.has_pulled_user_permissions() {
            self.pull_user_permissions(ProgressCallbackNop)?;
        }

        if !self.has_pulled_group_permissions() {
            self.pull_group_permissions(ProgressCallbackNop)?;
        }

        let id = id.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteProjectGetPermissionById(self.as_raw(), id.as_ref().as_ptr() as *const _)
        };
        Ok(ptr::NonNull::new(value).map(|v| unsafe { Permission::from_raw(v) }))
    }

    /// Pull the list of group permissions from the Remote.
    pub fn pull_group_permissions<F: ProgressCallback>(&self, mut progress: F) -> Result<(), ()> {
        let success = unsafe {
            BNRemoteProjectPullGroupPermissions(
                self.as_raw(),
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut ffi::c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Pull the list of user permissions from the Remote.
    pub fn pull_user_permissions<F: ProgressCallback>(&self, mut progress: F) -> Result<(), ()> {
        let success = unsafe {
            BNRemoteProjectPullUserPermissions(
                self.as_raw(),
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut ffi::c_void,
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
    /// * `progress` - Function to call for upload progress updates
    pub fn create_group_permission<F: ProgressCallback>(
        &self,
        group_id: i64,
        level: CollaborationPermissionLevel,
        mut progress: F,
    ) -> Result<Permission, ()> {
        let value = unsafe {
            BNRemoteProjectCreateGroupPermission(
                self.as_raw(),
                group_id,
                level,
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut ffi::c_void,
            )
        };

        ptr::NonNull::new(value)
            .map(|v| unsafe { Permission::from_raw(v) })
            .ok_or(())
    }

    /// Create a new user permission on the remote (and pull it).
    ///
    /// # Arguments
    ///
    /// * `user_id` - User id
    /// * `level` - Permission level
    pub fn create_user_permission<S: BnStrCompatible, F: ProgressCallback>(
        &self,
        user_id: S,
        level: CollaborationPermissionLevel,
        mut progress: F,
    ) -> Result<Permission, ()> {
        let user_id = user_id.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteProjectCreateUserPermission(
                self.as_raw(),
                user_id.as_ref().as_ptr() as *const ffi::c_char,
                level,
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut ffi::c_void,
            )
        };

        ptr::NonNull::new(value)
            .map(|v| unsafe { Permission::from_raw(v) })
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
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect::<Vec<_>>();
        let mut values_raw = values
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect::<Vec<_>>();

        let success = unsafe {
            BNRemoteProjectPushPermission(
                self.as_raw(),
                permission.as_raw(),
                keys_raw.as_mut_ptr(),
                values_raw.as_mut_ptr(),
                keys_raw.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Delete a permission from the remote.
    pub fn delete_permission(&self, permission: &Permission) -> Result<(), ()> {
        let success =
            unsafe { BNRemoteProjectDeletePermission(self.as_raw(), permission.as_raw()) };
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
                self.as_raw(),
                username.as_ref().as_ptr() as *const ffi::c_char,
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
                self.as_raw(),
                username.as_ref().as_ptr() as *const ffi::c_char,
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
                self.as_raw(),
                username.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Get the default directory path for a remote Project. This is based off
    /// the Setting for collaboration.directory, the project's id, and the
    /// project's remote's id.
    pub fn default_project_path(&self) -> BnString {
        let result = unsafe { BNCollaborationDefaultProjectPath(self.as_raw()) };
        unsafe { BnString::from_raw(result) }
    }

    /// Upload a file, with database, to the remote under the given project
    ///
    /// * `metadata` - Local file with database
    /// * `progress` -: Function to call for progress updates
    /// * `name_changeset` - Function to call for naming a pushed changeset, if necessary
    /// * `parent_folder` - Optional parent folder in which to place this file
    pub fn upload_database<S, P, C>(
        &self,
        metadata: &FileMetadata,
        parent_folder: Option<&RemoteFolder>,
        progress_function: P,
        name_changeset: C,
    ) -> Result<RemoteFile, ()>
    where
        S: BnStrCompatible,
        P: ProgressCallback,
        C: NameChangeset,
    {
        databasesync::upload_database(
            metadata,
            self,
            parent_folder,
            progress_function,
            name_changeset,
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
    //    if !self.open(ProgressCallbackNop)? {
    //        return Err(());
    //    }
    //    let target = target.into_bytes_with_nul();
    //    todo!();
    //}
}

impl CoreArrayProvider for RemoteProject {
    type Raw = *mut BNRemoteProject;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for RemoteProject {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeRemoteProjectList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}
