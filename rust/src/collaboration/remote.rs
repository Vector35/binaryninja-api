use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use super::{databasesync, Group, Id, RemoteProject, User};

use crate::binaryview::BinaryView;
use crate::database::Database;
use crate::ffi::{ProgressCallback, ProgressCallbackNop};
use crate::project::Project;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

#[repr(transparent)]
pub struct Remote {
    handle: ptr::NonNull<BNRemote>,
}

impl Drop for Remote {
    fn drop(&mut self) {
        unsafe { BNFreeRemote(self.as_raw()) }
    }
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

impl Clone for Remote {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(ptr::NonNull::new(BNNewRemoteReference(self.as_raw())).unwrap()) }
    }
}

impl Remote {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNRemote>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNRemote) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNRemote {
        &mut *self.handle.as_ptr()
    }

    pub fn new<N: BnStrCompatible, A: BnStrCompatible>(name: N, address: A) -> Self {
        let name = name.into_bytes_with_nul();
        let address = address.into_bytes_with_nul();
        let result = unsafe {
            BNCollaborationCreateRemote(
                name.as_ref().as_ptr() as *const ffi::c_char,
                address.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        unsafe { Self::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    /// Get the Remote for a Database
    pub fn get_for_local_database(database: &Database) -> Result<Option<Remote>, ()> {
        databasesync::get_remote_for_local_database(database)
    }

    /// Get the Remote for a Binary View
    pub fn get_for_binary_view(bv: &BinaryView) -> Result<Option<Remote>, ()> {
        databasesync::get_remote_for_binary_view(bv)
    }

    /// Checks if the remote has pulled metadata like its id, etc.
    pub fn has_loaded_metadata(&self) -> bool {
        unsafe { BNRemoteHasLoadedMetadata(self.as_raw()) }
    }

    /// Gets the unique id. If metadata has not been pulled, it will be pulled upon calling this.
    pub fn unique_id(&self) -> Result<BnString, ()> {
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }
        let result = unsafe { BNRemoteGetUniqueId(self.as_raw()) };
        assert!(!result.is_null());
        Ok(unsafe { BnString::from_raw(result) })
    }

    /// Gets the name of the remote.
    pub fn name(&self) -> BnString {
        let result = unsafe { BNRemoteGetName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Gets the address of the remote.
    pub fn address(&self) -> BnString {
        let result = unsafe { BNRemoteGetAddress(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Checks if the remote is connected.
    pub fn is_connected(&self) -> bool {
        unsafe { BNRemoteIsConnected(self.as_raw()) }
    }

    /// Gets the username used to connect to the remote.
    pub fn username(&self) -> BnString {
        let result = unsafe { BNRemoteGetUsername(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Gets the token used to connect to the remote.
    pub fn token(&self) -> BnString {
        let result = unsafe { BNRemoteGetToken(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Gets the server version. If metadata has not been pulled, it will be pulled upon calling this.
    pub fn server_version(&self) -> Result<i32, ()> {
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }
        Ok(unsafe { BNRemoteGetServerVersion(self.as_raw()) })
    }

    /// Gets the server build id. If metadata has not been pulled, it will be pulled upon calling this.
    pub fn server_build_id(&self) -> Result<BnString, ()> {
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }
        unsafe { Ok(BnString::from_raw(BNRemoteGetServerBuildId(self.as_raw()))) }
    }

    /// Gets the list of supported authentication backends on the server.
    /// If metadata has not been pulled, it will be pulled upon calling this.
    pub fn auth_backends(&self) -> Result<(Array<BnString>, Array<BnString>), ()> {
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }

        let mut backend_ids = ptr::null_mut();
        let mut backend_names = ptr::null_mut();
        let mut count = 0;
        let success = unsafe {
            BNRemoteGetAuthBackends(
                self.as_raw(),
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
            self.pull_users(ProgressCallbackNop)?;
        }
        Ok(unsafe { BNRemoteIsAdmin(self.as_raw()) })
    }

    /// Checks if the remote is the same as the Enterprise License server.
    pub fn is_enterprise(&self) -> Result<bool, ()> {
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }
        Ok(unsafe { BNRemoteIsEnterprise(self.as_raw()) })
    }

    /// Loads metadata from the remote, including unique id and versions.
    pub fn load_metadata(&self) -> Result<(), ()> {
        let success = unsafe { BNRemoteLoadMetadata(self.as_raw()) };
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
                self.as_raw(),
                username.as_ref().as_ptr() as *const ffi::c_char,
                password.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        if token.is_null() {
            None
        } else {
            Some(unsafe { BnString::from_raw(token) })
        }
    }

    // TODO: implement enterprise and SecretsProvider
    /// Connects to the Remote, loading metadata and optionally acquiring a token.
    ///
    /// NOTE: If no username or token are provided, they will be looked up from the keychain, \
    /// 	likely saved there by Enterprise authentication.
    pub fn connect<U: BnStrCompatible, T: BnStrCompatible>(
        &self,
        username_and_token: Option<(U, T)>,
    ) -> Result<(), ()> {
        if !self.has_loaded_metadata() {
            self.load_metadata()?;
        }

        let success = if let Some((username, token)) = username_and_token {
            return self.connect_with_username_and_token(username, token);
        // TODO: implement enterprise
        //} else if self.is_enterprise()? && enterprise::is_authenticated() {
        //    // try with the enterprise
        //    let username = enterprise::username();
        //    let token = enterprise::token();

        //    unsafe { BNRemoteConnect(self.as_raw(), username.as_ptr(), token.as_ptr()) }
        } else {
            // TODO: implement SecretsProvider
            //let secrets_prov_name = crate::settings::Settings::new(c"default").get_string(
            //    c"enterprise.secretsProvider",
            //    None,
            //    None,
            //);
            //let secrets_prov = secrets::SecretsProvider::by_name(secrets_prov_name);
            //let secrets_proc_creds = secrets_prov.get_data(self.address());
            let secrets_proc_creds: Option<BnString> = None;
            if let Some(_creds_json) = secrets_proc_creds {
                // TODO: implement/use a json_decode
                // try loggin from the secrets provider
                //let crefs = json_decode::decode(creds_json.as_str());
                //let username = creds.get("username");
                //let token = creds.get("token");
                //unsafe { BNRemoteConnect(self.as_raw(), username.as_ptr(), token.as_ptr()) }
                unreachable!();
            } else {
                // try loggin in with creds in the env
                let username = std::env::var("BN_ENTERPRISE_USERNAME").ok();
                let password = std::env::var("BN_ENTERPRISE_PASSWORD").ok();
                let token = username.as_ref().zip(password).map(|(username, password)| {
                    self.request_authentication_token(username, password)
                });

                if let Some(Some(token)) = token {
                    let username_ptr = username.as_ref().unwrap().as_ptr() as *const ffi::c_char;

                    unsafe { BNRemoteConnect(self.as_raw(), username_ptr, token.as_ptr()) }
                } else {
                    // unable to find valid creds
                    return Err(());
                }
            }
        };
        success.then_some(()).ok_or(())
    }

    pub fn connect_with_username_and_token<U: BnStrCompatible, T: BnStrCompatible>(
        &self,
        username: U,
        token: T,
    ) -> Result<(), ()> {
        let username = username.into_bytes_with_nul();
        let token = token.into_bytes_with_nul();
        let username_ptr = username.as_ref().as_ptr() as *const ffi::c_char;
        let token_ptr = token.as_ref().as_ptr() as *const ffi::c_char;

        let success = unsafe { BNRemoteConnect(self.as_raw(), username_ptr, token_ptr) };
        success.then_some(()).ok_or(())
    }

    /// Disconnects from the remote.
    pub fn disconnect(&self) -> Result<(), ()> {
        let success = unsafe { BNRemoteDisconnect(self.as_raw()) };
        success.then_some(()).ok_or(())
    }

    /// Checks if the project has pulled the projects yet.
    pub fn has_pulled_projects(&self) -> bool {
        unsafe { BNRemoteHasPulledProjects(self.as_raw()) }
    }

    /// Checks if the project has pulled the groups yet.
    pub fn has_pulled_groups(&self) -> bool {
        unsafe { BNRemoteHasPulledGroups(self.as_raw()) }
    }

    /// Checks if the project has pulled the users yet.
    pub fn has_pulled_users(&self) -> bool {
        unsafe { BNRemoteHasPulledUsers(self.as_raw()) }
    }

    /// Gets the list of projects in this project.
    ///
    /// NOTE: If projects have not been pulled, they will be pulled upon calling this.
    pub fn projects(&self) -> Result<Array<RemoteProject>, ()> {
        if !self.has_pulled_projects() {
            self.pull_projects(ProgressCallbackNop)?;
        }

        let mut count = 0;
        let value = unsafe { BNRemoteGetProjects(self.as_raw(), &mut count) };
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
    ) -> Result<Option<RemoteProject>, ()> {
        if !self.has_pulled_projects() {
            self.pull_projects(ProgressCallbackNop)?;
        }

        let id = id.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteGetProjectById(self.as_raw(), id.as_ref().as_ptr() as *const ffi::c_char)
        };
        Ok(ptr::NonNull::new(value).map(|handle| unsafe { RemoteProject::from_raw(handle) }))
    }

    /// Gets a specific project in the Remote by its name.
    ///
    /// NOTE: If projects have not been pulled, they will be pulled upon calling this.
    pub fn get_project_by_name<S: BnStrCompatible>(
        &self,
        name: S,
    ) -> Result<Option<RemoteProject>, ()> {
        if !self.has_pulled_projects() {
            self.pull_projects(ProgressCallbackNop)?;
        }

        let name = name.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteGetProjectByName(self.as_raw(), name.as_ref().as_ptr() as *const ffi::c_char)
        };
        Ok(ptr::NonNull::new(value).map(|handle| unsafe { RemoteProject::from_raw(handle) }))
    }

    /// Pulls the list of projects from the Remote.
    ///
    /// # Arguments
    ///
    /// * `progress` - Function to call for progress updates
    pub fn pull_projects<F: ProgressCallback>(&self, mut progress: F) -> Result<(), ()> {
        let success = unsafe {
            BNRemotePullProjects(
                self.as_raw(),
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut ffi::c_void,
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
    ) -> Result<RemoteProject, ()> {
        let name = name.into_bytes_with_nul();
        let description = description.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteCreateProject(
                self.as_raw(),
                name.as_ref().as_ptr() as *const ffi::c_char,
                description.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        ptr::NonNull::new(value)
            .map(|handle| unsafe { RemoteProject::from_raw(handle) })
            .ok_or(())
    }

    /// Create a new project on the remote from a local project.
    pub fn import_local_project<P: ProgressCallback>(
        &self,
        project: &Project,
        mut progress: P,
    ) -> Option<RemoteProject> {
        let value = unsafe {
            BNRemoteImportLocalProject(
                self.as_raw(),
                project.as_raw(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut ffi::c_void,
            )
        };
        ptr::NonNull::new(value).map(|handle| unsafe { RemoteProject::from_raw(handle) })
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
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect::<Vec<_>>();
        let mut values_raw = values
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect::<Vec<_>>();

        let success = unsafe {
            BNRemotePushProject(
                self.as_raw(),
                project.as_raw(),
                keys_raw.as_mut_ptr(),
                values_raw.as_mut_ptr(),
                keys_raw.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Deletes a project from the remote.
    pub fn delete_project(&self, project: &RemoteProject) -> Result<(), ()> {
        let success = unsafe { BNRemoteDeleteProject(self.as_raw(), project.as_raw()) };
        success.then_some(()).ok_or(())
    }

    /// Gets the list of groups in this project.
    ///
    /// If groups have not been pulled, they will be pulled upon calling this.
    /// This function is only available to accounts with admin status on the Remote.
    pub fn groups(&self) -> Result<Array<Group>, ()> {
        if !self.has_pulled_groups() {
            self.pull_groups(ProgressCallbackNop)?;
        }

        let mut count = 0;
        let value = unsafe { BNRemoteGetGroups(self.as_raw(), &mut count) };
        if value.is_null() {
            return Err(());
        }
        Ok(unsafe { Array::new(value, count, ()) })
    }

    /// Gets a specific group in the Remote by its id.
    ///
    /// If groups have not been pulled, they will be pulled upon calling this.
    /// This function is only available to accounts with admin status on the Remote.
    pub fn get_group_by_id(&self, id: u64) -> Result<Option<Group>, ()> {
        if !self.has_pulled_groups() {
            self.pull_groups(ProgressCallbackNop)?;
        }

        let value = unsafe { BNRemoteGetGroupById(self.as_raw(), id) };
        Ok(ptr::NonNull::new(value).map(|handle| unsafe { Group::from_raw(handle) }))
    }

    /// Gets a specific group in the Remote by its name.
    ///
    /// If groups have not been pulled, they will be pulled upon calling this.
    /// This function is only available to accounts with admin status on the Remote.
    pub fn get_group_by_name<S: BnStrCompatible>(&self, name: S) -> Result<Option<Group>, ()> {
        if !self.has_pulled_groups() {
            self.pull_groups(ProgressCallbackNop)?;
        }

        let name = name.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteGetGroupByName(self.as_raw(), name.as_ref().as_ptr() as *const ffi::c_char)
        };

        Ok(ptr::NonNull::new(value).map(|handle| unsafe { Group::from_raw(handle) }))
    }

    /// Searches for groups in the Remote with a given prefix.
    ///
    /// # Arguments
    ///
    /// * `prefix` - Prefix of name for groups
    pub fn search_groups<S: BnStrCompatible>(
        &self,
        prefix: S,
    ) -> Result<(Array<Id>, Array<BnString>), ()> {
        let prefix = prefix.into_bytes_with_nul();
        let mut count = 0;
        let mut group_ids = ptr::null_mut();
        let mut group_names = ptr::null_mut();

        let success = unsafe {
            BNRemoteSearchGroups(
                self.as_raw(),
                prefix.as_ref().as_ptr() as *const ffi::c_char,
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
    ///
    /// # Arguments
    ///
    /// * `progress` - Function to call for progress updates
    pub fn pull_groups<F: ProgressCallback>(&self, mut progress: F) -> Result<(), ()> {
        let success = unsafe {
            BNRemotePullGroups(
                self.as_raw(),
                Some(F::cb_progress_callback),
                &mut progress as *mut F as *mut ffi::c_void,
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
    pub fn create_group<N, I>(&self, name: N, usernames: I) -> Result<Group, ()>
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
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect();

        let value = unsafe {
            BNRemoteCreateGroup(
                self.as_raw(),
                name.as_ref().as_ptr() as *const ffi::c_char,
                username_ptrs.as_mut_ptr(),
                username_ptrs.len(),
            )
        };
        ptr::NonNull::new(value)
            .map(|handle| unsafe { Group::from_raw(handle) })
            .ok_or(())
    }

    /// Pushes an updated Group object to the Remote.
    /// This function is only available to accounts with admin status on the Remote.
    ///
    /// # Arguments
    ///
    /// * `group` - Group object which has been updated
    /// * `extra_fields` - Extra HTTP fields to send with the update
    pub fn push_group<I, K, V>(&self, group: &Group, extra_fields: I) -> Result<(), ()>
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
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect();
        let mut values_raw: Vec<_> = values
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect();

        let success = unsafe {
            BNRemotePushGroup(
                self.as_raw(),
                group.as_raw(),
                keys_raw.as_mut_ptr(),
                values_raw.as_mut_ptr(),
                keys.len(),
            )
        };
        success.then_some(()).ok_or(())
    }

    /// Deletes the specified group from the remote.

    /// NOTE: This function is only available to accounts with admin status on the Remote
    ///
    /// # Arguments
    ///
    /// * `group` - Reference to the group to delete.
    pub fn delete_group(&self, group: &Group) -> Result<(), ()> {
        let success = unsafe { BNRemoteDeleteGroup(self.as_raw(), group.as_raw()) };
        success.then_some(()).ok_or(())
    }

    /// Retrieves the list of users in the project.
    ///
    /// NOTE: If users have not been pulled, they will be pulled upon calling this.
    ///
    /// NOTE: This function is only available to accounts with admin status on the Remote
    pub fn users(&self) -> Result<Array<User>, ()> {
        if !self.has_pulled_users() {
            self.pull_users(ProgressCallbackNop)?;
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
    pub fn get_user_by_id<S: BnStrCompatible>(&self, id: S) -> Result<Option<User>, ()> {
        if !self.has_pulled_users() {
            self.pull_users(ProgressCallbackNop)?;
        }
        let id = id.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteGetUserById(self.as_raw(), id.as_ref().as_ptr() as *const ffi::c_char)
        };
        Ok(ptr::NonNull::new(value).map(|handle| unsafe { User::from_raw(handle) }))
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
    ) -> Result<Option<User>, ()> {
        if !self.has_pulled_users() {
            self.pull_users(ProgressCallbackNop)?;
        }
        let username = username.into_bytes_with_nul();
        let value = unsafe {
            BNRemoteGetUserByUsername(
                self.as_raw(),
                username.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        Ok(ptr::NonNull::new(value).map(|handle| unsafe { User::from_raw(handle) }))
    }

    /// Retrieves the user object for the currently connected user.
    ///
    /// NOTE: If users have not been pulled, they will be pulled upon calling this.
    ///
    /// NOTE: This function is only available to accounts with admin status on the Remote
    pub fn current_user(&self) -> Result<Option<User>, ()> {
        if !self.has_pulled_users() {
            self.pull_users(ProgressCallbackNop)?;
        }
        let value = unsafe { BNRemoteGetCurrentUser(self.handle.as_ptr()) };
        Ok(ptr::NonNull::new(value).map(|handle| unsafe { User::from_raw(handle) }))
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
        let mut user_ids = ptr::null_mut();
        let mut usernames = ptr::null_mut();
        let success = unsafe {
            BNRemoteSearchUsers(
                self.as_raw(),
                prefix.as_ref().as_ptr() as *const ffi::c_char,
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
    ///
    /// # Arguments
    ///
    /// * `progress` - Closure called to report progress. Takes current and total progress counts.
    pub fn pull_users<P: ProgressCallback>(&self, mut progress: P) -> Result<(), ()> {
        let success = unsafe {
            BNRemotePullUsers(
                self.as_raw(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut ffi::c_void,
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
    ) -> Result<User, ()> {
        let username = username.into_bytes_with_nul();
        let email = email.into_bytes_with_nul();
        let password = password.into_bytes_with_nul();

        let value = unsafe {
            BNRemoteCreateUser(
                self.as_raw(),
                username.as_ref().as_ptr() as *const ffi::c_char,
                email.as_ref().as_ptr() as *const ffi::c_char,
                is_active,
                password.as_ref().as_ptr() as *const ffi::c_char,
                group_ids.as_ptr(),
                group_ids.len(),
                user_permission_ids.as_ptr(),
                user_permission_ids.len(),
            )
        };
        ptr::NonNull::new(value)
            .map(|handle| unsafe { User::from_raw(handle) })
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
    pub fn push_user<I, K, V>(&self, user: &User, extra_fields: I) -> Result<(), ()>
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
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect();
        let mut values_raw: Vec<_> = values
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const ffi::c_char)
            .collect();
        let success = unsafe {
            BNRemotePushUser(
                self.as_raw(),
                user.as_raw(),
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
    //    unsafe { BNRemoteRequest(self.as_raw(), todo!(), todo!()) }
    //}
}

impl CoreArrayProvider for Remote {
    type Raw = *mut BNRemote;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for Remote {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeRemoteList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}
