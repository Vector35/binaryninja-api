use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void};
use std::ptr::NonNull;

use super::{sync, GroupId, RemoteGroup, RemoteProject, RemoteUser};

use crate::binary_view::BinaryView;
use crate::database::Database;
use crate::enterprise;
use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::project::Project;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};

#[repr(transparent)]
pub struct Remote {
    pub(crate) handle: NonNull<BNRemote>,
}

impl Remote {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNRemote>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNRemote>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Create a Remote and add it to the list of known remotes (saved to Settings)
    pub fn new<N: BnStrCompatible, A: BnStrCompatible>(name: N, address: A) -> Ref<Self> {
        let name = name.into_bytes_with_nul();
        let address = address.into_bytes_with_nul();
        let result = unsafe {
            BNCollaborationCreateRemote(
                name.as_ref().as_ptr() as *const c_char,
                address.as_ref().as_ptr() as *const c_char,
            )
        };
        unsafe { Self::ref_from_raw(NonNull::new(result).unwrap()) }
    }

    /// Get the Remote for a Database
    pub fn get_for_local_database(database: &Database) -> Result<Option<Ref<Remote>>, ()> {
        sync::get_remote_for_local_database(database)
    }

    /// Get the Remote for a Binary View
    pub fn get_for_binary_view(bv: &BinaryView) -> Result<Option<Ref<Remote>>, ()> {
        sync::get_remote_for_binary_view(bv)
    }

    /// Checks if the remote has pulled metadata like its id, etc.
    pub fn has_loaded_metadata(&self) -> bool {
        unsafe { BNRemoteHasLoadedMetadata(self.handle.as_ptr()) }
    }

    /// Gets the unique id. If metadata has not been pulled, it will be pulled upon calling this.
    pub fn unique_id(&self) -> Result<BnString, ()> {
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }
        let result = unsafe { BNRemoteGetUniqueId(self.handle.as_ptr()) };
        assert!(!result.is_null());
        Ok(unsafe { BnString::from_raw(result) })
    }

    /// Gets the name of the remote.
    pub fn name(&self) -> BnString {
        let result = unsafe { BNRemoteGetName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Gets the address of the remote.
    pub fn address(&self) -> BnString {
        let result = unsafe { BNRemoteGetAddress(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Checks if the remote is connected.
    pub fn is_connected(&self) -> bool {
        unsafe { BNRemoteIsConnected(self.handle.as_ptr()) }
    }

    /// Gets the username used to connect to the remote.
    pub fn username(&self) -> BnString {
        let result = unsafe { BNRemoteGetUsername(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Gets the token used to connect to the remote.
    pub fn token(&self) -> BnString {
        let result = unsafe { BNRemoteGetToken(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Gets the server version. If metadata has not been pulled, it will be pulled upon calling this.
    pub fn server_version(&self) -> Result<i32, ()> {
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }
        Ok(unsafe { BNRemoteGetServerVersion(self.handle.as_ptr()) })
    }

    /// Gets the server build id. If metadata has not been pulled, it will be pulled upon calling this.
    pub fn server_build_id(&self) -> Result<BnString, ()> {
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }
        unsafe {
            Ok(BnString::from_raw(BNRemoteGetServerBuildId(
                self.handle.as_ptr(),
            )))
        }
    }

    /// Gets the list of supported authentication backends on the server.
    /// If metadata has not been pulled, it will be pulled upon calling this.
    pub fn auth_backends(&self) -> Result<(Array<BnString>, Array<BnString>), ()> {
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }

        let mut backend_ids = std::ptr::null_mut();
        let mut backend_names = std::ptr::null_mut();
        let mut count = 0;
        let success = unsafe {
            BNRemoteGetAuthBackends(
                self.handle.as_ptr(),
                &mut backend_ids,
                &mut backend_names,
                &mut count,
            )
        };
        success
            .then(|| unsafe {
                (
                    Array::new(backend_ids, count, ()),
                    Array::new(backend_names, count, ()),
                )
            })
            .ok_or(())
    }

    /// Checks if the current user is an administrator.
    pub fn is_admin(&self) -> Result<bool, ()> {
        if !self.has_pulled_users() {
            self.pull_users()?;
        }
        Ok(unsafe { BNRemoteIsAdmin(self.handle.as_ptr()) })
    }

    /// Checks if the remote is the same as the Enterprise License server.
    pub fn is_enterprise(&self) -> Result<bool, ()> {
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }
        Ok(unsafe { BNRemoteIsEnterprise(self.handle.as_ptr()) })
    }

    /// Loads metadata from the remote, including unique id and versions.
    pub fn load_metadata(&self) -> Result<(), ()> {
        let success = unsafe { BNRemoteLoadMetadata(self.handle.as_ptr()) };
        success.then_some(()).ok_or(())
    }

    /// Requests an authentication token using a username and password.
    pub fn request_authentication_token<U: BnStrCompatible, P: BnStrCompatible>(
        &self,
        username: U,
        password: P,
    ) -> Option<BnString> {
        let username = username.into_bytes_with_nul();
        let password = password.into_bytes_with_nul();
        let token = unsafe {
            BNRemoteRequestAuthenticationToken(
                self.handle.as_ptr(),
                username.as_ref().as_ptr() as *const c_char,
                password.as_ref().as_ptr() as *const c_char,
            )
        };
        if token.is_null() {
            None
        } else {
            Some(unsafe { BnString::from_raw(token) })
        }
    }

    /// Connects to the Remote, loading metadata and optionally acquiring a token.
    ///
    /// Use [Remote::connect_with_opts] if you cannot otherwise automatically connect using enterprise.
    ///
    /// WARNING: This is currently **not** thread safe, if you try and connect/disconnect to a remote on
    /// multiple threads you will be subject to race conditions. To avoid this wrap the [`Remote`] in
    /// a synchronization primitive, and pass that to your threads. Or don't try and connect on multiple threads.
    pub fn connect(&self) -> Result<(), ()> {
        // TODO: implement SecretsProvider
        if self.is_enterprise()? && enterprise::is_server_authenticated() {
            self.connect_with_opts(ConnectionOptions::from_enterprise()?)
        } else {
            // TODO: Make this error instead.
            let username =
                std::env::var("BN_ENTERPRISE_USERNAME").expect("No username for connection!");
            let password =
                std::env::var("BN_ENTERPRISE_PASSWORD").expect("No password for connection!");
            let connection_opts = ConnectionOptions::new_with_password(username, password);
            self.connect_with_opts(connection_opts)
        }
    }

    // TODO: This needs docs and proper error.
    pub fn connect_with_opts(&self, options: ConnectionOptions) -> Result<(), ()> {
        // TODO: Should we make used load metadata first?
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }
        let token = match options.token {
            Some(token) => token,
            None => {
                // TODO: If password not defined than error saying no token or password
                let password = options
                    .password
                    .expect("No password or token for connection!");
                let token = self.request_authentication_token(&options.username, password);
                // TODO: Error if None.
                token.unwrap().to_string()
            }
        };
        let username = options.username.into_bytes_with_nul();
        let username_ptr = username.as_ptr() as *const c_char;
        let token = token.into_bytes_with_nul();
        let token_ptr = token.as_ptr() as *const c_char;
        let success = unsafe { BNRemoteConnect(self.handle.as_ptr(), username_ptr, token_ptr) };
        success.then_some(()).ok_or(())
    }

    /// Disconnects from the remote.
    ///
    /// WARNING: This is currently **not** thread safe, if you try and connect/disconnect to a remote on
    /// multiple threads you will be subject to race conditions. To avoid this wrap the [`Remote`] in
    /// a synchronization primitive, and pass that to your threads. Or don't try and connect on multiple threads.
    pub fn disconnect(&self) -> Result<(), ()> {
        let success = unsafe { BNRemoteDisconnect(self.handle.as_ptr()) };
        success.then_some(()).ok_or(())
    }

    /// Checks if the project has pulled the projects yet.
    pub fn has_pulled_projects(&self) -> bool {
        unsafe { BNRemoteHasPulledProjects(self.handle.as_ptr()) }
    }

    /// Checks if the project has pulled the groups yet.
    pub fn has_pulled_groups(&self) -> bool {
        unsafe { BNRemoteHasPulledGroups(self.handle.as_ptr()) }
    }

    /// Checks if the project has pulled the users yet.
    pub fn has_pulled_users(&self) -> bool {
        unsafe { BNRemoteHasPulledUsers(self.handle.as_ptr()) }
    }

    /// Gets the list of projects in this project.
    ///
    /// NOTE: If projects have not been pulled, they will be pulled upon calling this.
    pub fn projects(&self) -> Result<Array<RemoteProject>, ()> {
        if !self.has_pulled_projects() {
            self.pull_projects()?;
        }

        let mut count = 0;
        let value = unsafe { BNRemoteGetProjects(self.handle.as_ptr(), &mut count) };
        if value.is_null() {
            return Err(());
        }
        Ok(unsafe { Array::new(value, count, ()) })
    }

    /// Gets a specific project in the Remote by its id.
    ///
    /// NOTE: If projects have not been pulled, they will be pulled upon calling this.
    pub fn get_project_by_id<S: BnStrCompatible>(
        &self,
        id: S,
    ) -> Result<Option<Ref<RemoteProject>>, ()> {
        if !self.has_pulled_projects() {
            self.pull_projects()?;
        }

        let id = id.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteGetProjectById(self.handle.as_ptr(), id.as_ref().as_ptr() as *const c_char)
        };
        Ok(NonNull::new(value).map(|handle| unsafe { RemoteProject::ref_from_raw(handle) }))
    }

    /// Gets a specific project in the Remote by its name.
    ///
    /// NOTE: If projects have not been pulled, they will be pulled upon calling this.
    pub fn get_project_by_name<S: BnStrCompatible>(
        &self,
        name: S,
    ) -> Result<Option<Ref<RemoteProject>>, ()> {
        if !self.has_pulled_projects() {
            self.pull_projects()?;
        }

        let name = name.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteGetProjectByName(
                self.handle.as_ptr(),
                name.as_ref().as_ptr() as *const c_char,
            )
        };
        Ok(NonNull::new(value).map(|handle| unsafe { RemoteProject::ref_from_raw(handle) }))
    }

    /// Pulls the list of projects from the Remote.
    pub fn pull_projects(&self) -> Result<(), ()> {
        self.pull_projects_with_progress(NoProgressCallback)
    }

    /// Pulls the list of projects from the Remote.
    ///
    /// # Arguments
    ///
    /// * `progress` - Function to call for progress updates
    pub fn pull_projects_with_progress<F: ProgressCallback>(
        &self,
        mut progress: F,
    ) -> Result<(), ()> {
        let success = unsafe {
            BNRemotePullProjects(
                self.handle.as_ptr(),
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Creates a new project on the remote (and pull it).
    ///
    /// # Arguments
    ///
    /// * `name` - Project name
    /// * `description` - Project description
    pub fn create_project<N: BnStrCompatible, D: BnStrCompatible>(
        &self,
        name: N,
        description: D,
    ) -> Result<Ref<RemoteProject>, ()> {
        // TODO: Do we want this?
        // TODO: If you have not yet pulled projects you will have never filled the map you will be placing your
        // TODO: New project in.
        if !self.has_pulled_projects() {
            self.pull_projects()?;
        }
        let name = name.into_bytes_with_nul();
        let description = description.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteCreateProject(
                self.handle.as_ptr(),
                name.as_ref().as_ptr() as *const c_char,
                description.as_ref().as_ptr() as *const c_char,
            )
        };
        NonNull::new(value)
            .map(|handle| unsafe { RemoteProject::ref_from_raw(handle) })
            .ok_or(())
    }

    /// Create a new project on the remote from a local project.
    pub fn import_local_project(&self, project: &Project) -> Option<Ref<RemoteProject>> {
        self.import_local_project_with_progress(project, NoProgressCallback)
    }

    /// Create a new project on the remote from a local project.
    pub fn import_local_project_with_progress<P: ProgressCallback>(
        &self,
        project: &Project,
        mut progress: P,
    ) -> Option<Ref<RemoteProject>> {
        let value = unsafe {
            BNRemoteImportLocalProject(
                self.handle.as_ptr(),
                project.handle.as_ptr(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };
        NonNull::new(value).map(|handle| unsafe { RemoteProject::ref_from_raw(handle) })
    }

    /// Pushes an updated Project object to the Remote.
    ///
    /// # Arguments
    ///
    /// * `project` - Project object which has been updated
    /// * `extra_fields` - Extra HTTP fields to send with the update
    pub fn push_project<I, K, V>(&self, project: &RemoteProject, extra_fields: I) -> Result<(), ()>
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
            BNRemotePushProject(
                self.handle.as_ptr(),
                project.handle.as_ptr(),
                keys_raw.as_mut_ptr(),
                values_raw.as_mut_ptr(),
                keys_raw.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Deletes a project from the remote.
    pub fn delete_project(&self, project: &RemoteProject) -> Result<(), ()> {
        let success =
            unsafe { BNRemoteDeleteProject(self.handle.as_ptr(), project.handle.as_ptr()) };
        success.then_some(()).ok_or(())
    }

    /// Gets the list of groups in this project.
    ///
    /// If groups have not been pulled, they will be pulled upon calling this.
    /// This function is only available to accounts with admin status on the Remote.
    pub fn groups(&self) -> Result<Array<RemoteGroup>, ()> {
        if !self.has_pulled_groups() {
            self.pull_groups()?;
        }

        let mut count = 0;
        let value = unsafe { BNRemoteGetGroups(self.handle.as_ptr(), &mut count) };
        if value.is_null() {
            return Err(());
        }
        Ok(unsafe { Array::new(value, count, ()) })
    }

    /// Gets a specific group in the Remote by its id.
    ///
    /// If groups have not been pulled, they will be pulled upon calling this.
    /// This function is only available to accounts with admin status on the Remote.
    pub fn get_group_by_id(&self, id: GroupId) -> Result<Option<Ref<RemoteGroup>>, ()> {
        if !self.has_pulled_groups() {
            self.pull_groups()?;
        }

        let value = unsafe { BNRemoteGetGroupById(self.handle.as_ptr(), id.0) };
        Ok(NonNull::new(value).map(|handle| unsafe { RemoteGroup::ref_from_raw(handle) }))
    }

    /// Gets a specific group in the Remote by its name.
    ///
    /// If groups have not been pulled, they will be pulled upon calling this.
    /// This function is only available to accounts with admin status on the Remote.
    pub fn get_group_by_name<S: BnStrCompatible>(
        &self,
        name: S,
    ) -> Result<Option<Ref<RemoteGroup>>, ()> {
        if !self.has_pulled_groups() {
            self.pull_groups()?;
        }

        let name = name.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteGetGroupByName(
                self.handle.as_ptr(),
                name.as_ref().as_ptr() as *const c_char,
            )
        };

        Ok(NonNull::new(value).map(|handle| unsafe { RemoteGroup::ref_from_raw(handle) }))
    }

    /// Searches for groups in the Remote with a given prefix.
    ///
    /// # Arguments
    ///
    /// * `prefix` - Prefix of name for groups
    pub fn search_groups<S: BnStrCompatible>(
        &self,
        prefix: S,
    ) -> Result<(Array<GroupId>, Array<BnString>), ()> {
        let prefix = prefix.into_bytes_with_nul();
        let mut count = 0;
        let mut group_ids = std::ptr::null_mut();
        let mut group_names = std::ptr::null_mut();

        let success = unsafe {
            BNRemoteSearchGroups(
                self.handle.as_ptr(),
                prefix.as_ref().as_ptr() as *const c_char,
                &mut group_ids,
                &mut group_names,
                &mut count,
            )
        };
        if !success {
            return Err(());
        }
        Ok(unsafe {
            (
                Array::new(group_ids, count, ()),
                Array::new(group_names, count, ()),
            )
        })
    }

    /// Pulls the list of groups from the Remote.
    /// This function is only available to accounts with admin status on the Remote.
    pub fn pull_groups(&self) -> Result<(), ()> {
        self.pull_groups_with_progress(NoProgressCallback)
    }

    /// Pulls the list of groups from the Remote.
    /// This function is only available to accounts with admin status on the Remote.
    ///
    /// # Arguments
    ///
    /// * `progress` - Function to call for progress updates
    pub fn pull_groups_with_progress<F: ProgressCallback>(
        &self,
        mut progress: F,
    ) -> Result<(), ()> {
        let success = unsafe {
            BNRemotePullGroups(
                self.handle.as_ptr(),
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Creates a new group on the remote (and pull it).
    /// This function is only available to accounts with admin status on the Remote.
    ///
    /// # Arguments
    ///
    /// * `name` - Group name
    /// * `usernames` - List of usernames of users in the group
    pub fn create_group<N, I>(&self, name: N, usernames: I) -> Result<Ref<RemoteGroup>, ()>
    where
        N: BnStrCompatible,
        I: IntoIterator,
        I::Item: BnStrCompatible,
    {
        let name = name.into_bytes_with_nul();
        let usernames: Vec<_> = usernames
            .into_iter()
            .map(|s| s.into_bytes_with_nul())
            .collect();
        let mut username_ptrs: Vec<_> = usernames
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect();

        let value = unsafe {
            BNRemoteCreateGroup(
                self.handle.as_ptr(),
                name.as_ref().as_ptr() as *const c_char,
                username_ptrs.as_mut_ptr(),
                username_ptrs.len(),
            )
        };
        NonNull::new(value)
            .map(|handle| unsafe { RemoteGroup::ref_from_raw(handle) })
            .ok_or(())
    }

    /// Pushes an updated Group object to the Remote.
    /// This function is only available to accounts with admin status on the Remote.
    ///
    /// # Arguments
    ///
    /// * `group` - Group object which has been updated
    /// * `extra_fields` - Extra HTTP fields to send with the update
    pub fn push_group<I, K, V>(&self, group: &RemoteGroup, extra_fields: I) -> Result<(), ()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
    {
        let (keys, values): (Vec<_>, Vec<_>) = extra_fields
            .into_iter()
            .map(|(k, v)| (k.into_bytes_with_nul(), v.into_bytes_with_nul()))
            .unzip();
        let mut keys_raw: Vec<_> = keys
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect();
        let mut values_raw: Vec<_> = values
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect();

        let success = unsafe {
            BNRemotePushGroup(
                self.handle.as_ptr(),
                group.handle.as_ptr(),
                keys_raw.as_mut_ptr(),
                values_raw.as_mut_ptr(),
                keys.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Deletes the specified group from the remote.
    ///
    /// NOTE: This function is only available to accounts with admin status on the Remote
    ///
    /// # Arguments
    ///
    /// * `group` - Reference to the group to delete.
    pub fn delete_group(&self, group: &RemoteGroup) -> Result<(), ()> {
        let success = unsafe { BNRemoteDeleteGroup(self.handle.as_ptr(), group.handle.as_ptr()) };
        success.then_some(()).ok_or(())
    }

    /// Retrieves the list of users in the project.
    ///
    /// NOTE: If users have not been pulled, they will be pulled upon calling this.
    ///
    /// NOTE: This function is only available to accounts with admin status on the Remote
    pub fn users(&self) -> Result<Array<RemoteUser>, ()> {
        if !self.has_pulled_users() {
            self.pull_users()?;
        }
        let mut count = 0;
        let value = unsafe { BNRemoteGetUsers(self.handle.as_ptr(), &mut count) };
        if value.is_null() {
            return Err(());
        }
        Ok(unsafe { Array::new(value, count, ()) })
    }

    /// Retrieves a specific user in the project by their ID.
    ///
    /// NOTE: If users have not been pulled, they will be pulled upon calling this.
    ///
    /// NOTE: This function is only available to accounts with admin status on the Remote
    ///
    /// # Arguments
    ///
    /// * `id` - The identifier of the user to retrieve.
    pub fn get_user_by_id<S: BnStrCompatible>(&self, id: S) -> Result<Option<Ref<RemoteUser>>, ()> {
        if !self.has_pulled_users() {
            self.pull_users()?;
        }
        let id = id.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteGetUserById(self.handle.as_ptr(), id.as_ref().as_ptr() as *const c_char)
        };
        Ok(NonNull::new(value).map(|handle| unsafe { RemoteUser::ref_from_raw(handle) }))
    }

    /// Retrieves a specific user in the project by their username.
    ///
    /// NOTE: If users have not been pulled, they will be pulled upon calling this.
    ///
    /// NOTE: This function is only available to accounts with admin status on the Remote
    ///
    /// # Arguments
    ///
    /// * `username` - The username of the user to retrieve.
    pub fn get_user_by_username<S: BnStrCompatible>(
        &self,
        username: S,
    ) -> Result<Option<Ref<RemoteUser>>, ()> {
        if !self.has_pulled_users() {
            self.pull_users()?;
        }
        let username = username.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteGetUserByUsername(
                self.handle.as_ptr(),
                username.as_ref().as_ptr() as *const c_char,
            )
        };
        Ok(NonNull::new(value).map(|handle| unsafe { RemoteUser::ref_from_raw(handle) }))
    }

    /// Retrieves the user object for the currently connected user.
    ///
    /// NOTE: If users have not been pulled, they will be pulled upon calling this.
    ///
    /// NOTE: This function is only available to accounts with admin status on the Remote
    pub fn current_user(&self) -> Result<Option<Ref<RemoteUser>>, ()> {
        if !self.has_pulled_users() {
            self.pull_users()?;
        }
        let value = unsafe { BNRemoteGetCurrentUser(self.handle.as_ptr()) };
        Ok(NonNull::new(value).map(|handle| unsafe { RemoteUser::ref_from_raw(handle) }))
    }

    /// Searches for users in the project with a given prefix.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The prefix to search for in usernames.
    pub fn search_users<S: BnStrCompatible>(
        &self,
        prefix: S,
    ) -> Result<(Array<BnString>, Array<BnString>), ()> {
        let prefix = prefix.into_bytes_with_nul();
        let mut count = 0;
        let mut user_ids = std::ptr::null_mut();
        let mut usernames = std::ptr::null_mut();
        let success = unsafe {
            BNRemoteSearchUsers(
                self.handle.as_ptr(),
                prefix.as_ref().as_ptr() as *const c_char,
                &mut user_ids,
                &mut usernames,
                &mut count,
            )
        };

        if !success {
            return Err(());
        }
        assert!(!user_ids.is_null());
        assert!(!usernames.is_null());
        Ok(unsafe {
            (
                Array::new(user_ids, count, ()),
                Array::new(usernames, count, ()),
            )
        })
    }

    /// Pulls the list of users from the remote.
    ///
    /// NOTE: This function is only available to accounts with admin status on the Remote.
    /// Non-admin accounts attempting to call this function will pull an empty list of users.
    pub fn pull_users(&self) -> Result<(), ()> {
        self.pull_users_with_progress(NoProgressCallback)
    }

    /// Pulls the list of users from the remote.
    ///
    /// NOTE: This function is only available to accounts with admin status on the Remote.
    /// Non-admin accounts attempting to call this function will pull an empty list of users.
    ///
    /// # Arguments
    ///
    /// * `progress` - Closure called to report progress. Takes current and total progress counts.
    pub fn pull_users_with_progress<P: ProgressCallback>(&self, mut progress: P) -> Result<(), ()> {
        let success = unsafe {
            BNRemotePullUsers(
                self.handle.as_ptr(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Creates a new user on the remote and returns a reference to the created user.
    ///
    /// NOTE: This function is only available to accounts with admin status on the Remote
    ///
    /// # Arguments
    ///
    /// * Various details about the new user to be created.
    pub fn create_user<U: BnStrCompatible, E: BnStrCompatible, P: BnStrCompatible>(
        &self,
        username: U,
        email: E,
        is_active: bool,
        password: P,
        group_ids: &[u64],
        user_permission_ids: &[u64],
    ) -> Result<Ref<RemoteUser>, ()> {
        let username = username.into_bytes_with_nul();
        let email = email.into_bytes_with_nul();
        let password = password.into_bytes_with_nul();

        let value = unsafe {
            BNRemoteCreateUser(
                self.handle.as_ptr(),
                username.as_ref().as_ptr() as *const c_char,
                email.as_ref().as_ptr() as *const c_char,
                is_active,
                password.as_ref().as_ptr() as *const c_char,
                group_ids.as_ptr(),
                group_ids.len(),
                user_permission_ids.as_ptr(),
                user_permission_ids.len(),
            )
        };
        NonNull::new(value)
            .map(|handle| unsafe { RemoteUser::ref_from_raw(handle) })
            .ok_or(())
    }

    /// Pushes updates to the specified user on the remote.
    ///
    /// NOTE: This function is only available to accounts with admin status on the Remote
    ///
    /// # Arguments
    ///
    /// * `user` - Reference to the `RemoteUser` object to push.
    /// * `extra_fields` - Optional extra fields to send with the update.
    pub fn push_user<I, K, V>(&self, user: &RemoteUser, extra_fields: I) -> Result<(), ()>
    where
        I: Iterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
    {
        let (keys, values): (Vec<_>, Vec<_>) = extra_fields
            .into_iter()
            .map(|(k, v)| (k.into_bytes_with_nul(), v.into_bytes_with_nul()))
            .unzip();
        let mut keys_raw: Vec<_> = keys
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect();
        let mut values_raw: Vec<_> = values
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect();
        let success = unsafe {
            BNRemotePushUser(
                self.handle.as_ptr(),
                user.handle.as_ptr(),
                keys_raw.as_mut_ptr(),
                values_raw.as_mut_ptr(),
                keys_raw.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    // TODO identify the request and ret type of this function, it seems to use a C++ implementation of
    // HTTP requests, composed mostly of `std:vector`.
    //pub fn request(&self) {
    //    unsafe { BNRemoteRequest(self.handle.as_ptr(), todo!(), todo!()) }
    //}
}

impl PartialEq for Remote {
    fn eq(&self, other: &Self) -> bool {
        // don't pull metadata if we hand't yet
        if !self.has_loaded_metadata() || other.has_loaded_metadata() {
            self.address() == other.address()
        } else if let Some((slf, oth)) = self.unique_id().ok().zip(other.unique_id().ok()) {
            slf == oth
        } else {
            // falback to comparing address
            self.address() == other.address()
        }
    }
}
impl Eq for Remote {}

impl ToOwned for Remote {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Remote {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewRemoteReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeRemote(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for Remote {
    type Raw = *mut BNRemote;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for Remote {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeRemoteList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionOptions {
    pub username: String,
    /// Provide this if you want to authenticate with a password.
    pub password: Option<String>,
    /// Provide this if you want to authenticate with a token.
    ///
    /// If you do not have a token you can use [ConnectionOptions::with_password].
    pub token: Option<String>,
}

impl ConnectionOptions {
    pub fn new_with_token(username: String, token: String) -> Self {
        Self {
            username,
            token: Some(token),
            password: None,
        }
    }

    pub fn new_with_password(username: String, password: String) -> Self {
        Self {
            username,
            token: None,
            password: Some(password),
        }
    }

    pub fn with_token(self, token: String) -> Self {
        Self {
            token: Some(token),
            ..self
        }
    }

    pub fn with_password(self, token: String) -> Self {
        Self {
            token: Some(token),
            ..self
        }
    }

    pub fn from_enterprise() -> Result<Self, ()> {
        // TODO: Check if enterprise is initialized and error if not.
        let username = enterprise::server_username();
        let token = enterprise::server_token();
        Ok(Self::new_with_token(
            username.to_string(),
            token.to_string(),
        ))
    }

    // TODO: from_secrets_provider
}
