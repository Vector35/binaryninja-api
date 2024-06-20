use core::{cmp, ffi, mem, ptr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use binaryninjacore_sys::*;

use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

pub type PluginType = BNPluginType;
pub type PluginStatus = BNPluginStatus;

/// Keeps track of all the repositories and keeps the `enabled_plugins.json`
/// file coherent with the plugins that are installed/uninstalled enabled/disabled
#[repr(transparent)]
pub struct RepositoryManager {
    handle: ptr::NonNull<BNRepositoryManager>,
}

impl Drop for RepositoryManager {
    fn drop(&mut self) {
        unsafe { BNFreeRepositoryManager(self.as_raw()) }
    }
}

impl Clone for RepositoryManager {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(
                ptr::NonNull::new(BNNewRepositoryManagerReference(self.as_raw())).unwrap(),
            )
        }
    }
}

impl Default for RepositoryManager {
    fn default() -> Self {
        let result = unsafe { BNGetRepositoryManager() };
        unsafe { Self::from_raw(ptr::NonNull::new(result).unwrap()) }
    }
}

impl RepositoryManager {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNRepositoryManager>) -> Self {
        Self { handle }
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNRepositoryManager {
        &mut *self.handle.as_ptr()
    }

    pub fn new<S: BnStrCompatible>(plugins_path: S) -> Self {
        let plugins_path = plugins_path.into_bytes_with_nul();
        let result = unsafe {
            BNCreateRepositoryManager(plugins_path.as_ref().as_ptr() as *const ffi::c_char)
        };
        unsafe { Self::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    /// Check for updates for all managed Repository objects
    pub fn check_for_updates(&self) -> bool {
        unsafe { BNRepositoryManagerCheckForUpdates(self.as_raw()) }
    }

    /// List of Repository objects being managed
    pub fn repositories(&self) -> Array<Repository> {
        let mut count = 0;
        let result = unsafe { BNRepositoryManagerGetRepositories(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Adds a new plugin repository for the manager to track.
    ///
    /// To remove a repository, restart Binary Ninja (and don't re-add the repository!).
    /// File artifacts will remain on disk under repositories/ file in the User Folder.
    ///
    /// Before you can query plugin metadata from a repository, you need to call [RepositoryManager::check_for_updates].
    ///
    /// * `url` - URL to the plugins.json containing the records for this repository
    /// * `repopath` - path to where the repository will be stored on disk locally
    ///
    /// Returns true if the repository was successfully added, false otherwise.
    pub fn add_repository<U: BnStrCompatible, P: BnStrCompatible>(
        &self,
        url: U,
        repository_path: P,
    ) -> bool {
        let url = url.into_bytes_with_nul();
        let repo_path = repository_path.into_bytes_with_nul();
        unsafe {
            BNRepositoryManagerAddRepository(
                self.as_raw(),
                url.as_ref().as_ptr() as *const ffi::c_char,
                repo_path.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn repository_by_path<P: BnStrCompatible>(&self, path: P) -> Repository {
        let path = path.into_bytes_with_nul();
        let result = unsafe {
            BNRepositoryGetRepositoryByPath(
                self.as_raw(),
                path.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        unsafe { Repository::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    /// Gets the default Repository
    pub fn default_repository(&self) -> Repository {
        let result = unsafe { BNRepositoryManagerGetDefaultRepository(self.as_raw()) };
        assert!(!result.is_null());
        // NOTE result is not onwed, we need to clone it
        let default = unsafe { Repository::ref_from_raw(&result) };
        default.clone()
    }
}

#[repr(transparent)]
pub struct Repository {
    handle: ptr::NonNull<BNRepository>,
}

impl Drop for Repository {
    fn drop(&mut self) {
        unsafe { BNFreeRepository(self.as_raw()) }
    }
}

impl Clone for Repository {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewRepositoryReference(self.as_raw())).unwrap())
        }
    }
}

impl Repository {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNRepository>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNRepository) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNRepository {
        &mut *self.handle.as_ptr()
    }

    /// String URL of the git repository where the plugin repository's are stored
    pub fn url(&self) -> BnString {
        let result = unsafe { BNRepositoryGetUrl(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }

    /// String local path to store the given plugin repository
    pub fn path(&self) -> BnString {
        let result = unsafe { BNRepositoryGetRepoPath(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }

    /// List of RepoPlugin objects contained within this repository
    pub fn plugins(&self) -> Array<RepoPlugin> {
        let mut count = 0;
        let result = unsafe { BNRepositoryGetPlugins(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn plugin_by_path<S: BnStrCompatible>(&self, path: S) -> Option<RepoPlugin> {
        let path = path.into_bytes_with_nul();
        let result = unsafe {
            BNRepositoryGetPluginByPath(self.as_raw(), path.as_ref().as_ptr() as *const ffi::c_char)
        };
        ptr::NonNull::new(result).map(|h| unsafe { RepoPlugin::from_raw(h) })
    }

    /// String full path the repository
    pub fn full_path(&self) -> BnString {
        let result = unsafe { BNRepositoryGetPluginsPath(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }
}

impl CoreArrayProvider for Repository {
    type Raw = *mut BNRepository;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for Repository {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeRepositoryManagerRepositoriesList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

#[repr(transparent)]
pub struct RepoPlugin {
    handle: ptr::NonNull<BNRepoPlugin>,
}

impl Drop for RepoPlugin {
    fn drop(&mut self) {
        unsafe { BNFreePlugin(self.as_raw()) }
    }
}

impl Clone for RepoPlugin {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(ptr::NonNull::new(BNNewPluginReference(self.as_raw())).unwrap()) }
    }
}

impl RepoPlugin {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNRepoPlugin>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNRepoPlugin) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNRepoPlugin {
        &mut *self.handle.as_ptr()
    }

    /// String indicating the API used by the plugin
    pub fn apis(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNPluginGetApis(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// String of the plugin author
    pub fn author(&self) -> BnString {
        let result = unsafe { BNPluginGetAuthor(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }

    /// String short description of the plugin
    pub fn description(&self) -> BnString {
        let result = unsafe { BNPluginGetDescription(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }

    /// String complete license text for the given plugin
    pub fn license_text(&self) -> BnString {
        let result = unsafe { BNPluginGetLicenseText(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }

    /// String long description of the plugin
    pub fn long_description(&self) -> BnString {
        let result = unsafe { BNPluginGetLongdescription(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }

    /// Minimum version info the plugin was tested on
    pub fn minimum_version_info(&self) -> VersionInfo {
        let result = unsafe { BNPluginGetMinimumVersionInfo(self.as_raw()) };
        unsafe { VersionInfo::from_raw(result) }
    }

    /// Maximum version info the plugin will support
    pub fn maximum_version_info(&self) -> VersionInfo {
        let result = unsafe { BNPluginGetMaximumVersionInfo(self.as_raw()) };
        unsafe { VersionInfo::from_raw(result) }
    }

    /// String plugin name
    pub fn name(&self) -> BnString {
        let result = unsafe { BNPluginGetName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }

    /// String URL of the plugin's git repository
    pub fn project_url(&self) -> BnString {
        let result = unsafe { BNPluginGetProjectUrl(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }

    /// String URL of the plugin's git repository
    pub fn package_url(&self) -> BnString {
        let result = unsafe { BNPluginGetPackageUrl(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }

    /// String URL of the plugin author's url
    pub fn author_url(&self) -> BnString {
        let result = unsafe { BNPluginGetAuthorUrl(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }
    /// String version of the plugin
    pub fn version(&self) -> BnString {
        let result = unsafe { BNPluginGetVersion(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut i8) }
    }

    /// String of the commit of this plugin git repository
    pub fn commit(&self) -> BnString {
        let result = unsafe { BNPluginGetCommit(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut i8) }
    }

    /// Relative path from the base of the repository to the actual plugin
    pub fn path(&self) -> BnString {
        let result = unsafe { BNPluginGetPath(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut i8) }
    }

    /// Optional sub-directory the plugin code lives in as a relative path from the plugin root
    pub fn subdir(&self) -> BnString {
        let result = unsafe { BNPluginGetSubdir(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut i8) }
    }

    /// Dependencies required for installing this plugin
    pub fn dependencies(&self) -> BnString {
        let result = unsafe { BNPluginGetDependencies(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut i8) }
    }

    /// true if the plugin is installed, false otherwise
    pub fn is_installed(&self) -> bool {
        unsafe { BNPluginIsInstalled(self.as_raw()) }
    }

    /// true if the plugin is enabled, false otherwise
    pub fn is_enabled(&self) -> bool {
        unsafe { BNPluginIsEnabled(self.as_raw()) }
    }

    pub fn status(&self) -> PluginStatus {
        unsafe { BNPluginGetPluginStatus(self.as_raw()) }
    }

    /// List of PluginType enumeration objects indicating the plugin type(s)
    pub fn types(&self) -> Array<PluginType> {
        let mut count = 0;
        let result = unsafe { BNPluginGetPluginTypes(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Enable this plugin, optionally trying to force it.
    /// Force loading a plugin with ignore platform and api constraints.
    pub fn enable(&self, force: bool) -> bool {
        unsafe { BNPluginEnable(self.as_raw(), force) }
    }

    pub fn disable(&self) -> bool {
        unsafe { BNPluginDisable(self.as_raw()) }
    }

    /// Attempt to install the given plugin
    pub fn install(&self) -> bool {
        unsafe { BNPluginInstall(self.as_raw()) }
    }

    pub fn install_dependencies(&self) -> bool {
        unsafe { BNPluginInstallDependencies(self.as_raw()) }
    }

    /// Attempt to uninstall the given plugin
    pub fn uninstall(&self) -> bool {
        unsafe { BNPluginUninstall(self.as_raw()) }
    }

    pub fn updated(&self) -> bool {
        unsafe { BNPluginUpdate(self.as_raw()) }
    }

    /// List of platforms this plugin can execute on
    pub fn platforms(&self) -> Array<PluginPlatforms> {
        let mut count = 0;
        let result = unsafe { BNPluginGetPlatforms(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn repository(&self) -> BnString {
        let result = unsafe { BNPluginGetRepository(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut i8) }
    }

    /// Boolean status indicating that the plugin is being deleted
    pub fn is_being_deleted(&self) -> bool {
        unsafe { BNPluginIsBeingDeleted(self.as_raw()) }
    }

    /// Boolean status indicating that the plugin is being updated
    pub fn is_being_updated(&self) -> bool {
        unsafe { BNPluginIsBeingUpdated(self.as_raw()) }
    }

    /// Boolean status indicating that the plugin is currently running
    pub fn is_running(&self) -> bool {
        unsafe { BNPluginIsRunning(self.as_raw()) }
    }

    /// Boolean status indicating that the plugin has updates will be installed after the next restart
    pub fn is_update_pending(&self) -> bool {
        unsafe { BNPluginIsUpdatePending(self.as_raw()) }
    }

    /// Boolean status indicating that the plugin will be disabled after the next restart
    pub fn is_disable_pending(&self) -> bool {
        unsafe { BNPluginIsDisablePending(self.as_raw()) }
    }

    /// Boolean status indicating that the plugin will be deleted after the next restart
    pub fn is_delete_pending(&self) -> bool {
        unsafe { BNPluginIsDeletePending(self.as_raw()) }
    }

    /// Boolean status indicating that the plugin has updates available
    pub fn is_updated_available(&self) -> bool {
        unsafe { BNPluginIsUpdateAvailable(self.as_raw()) }
    }

    /// Boolean status indicating that the plugin's dependencies are currently being installed
    pub fn are_dependencies_being_installed(&self) -> bool {
        unsafe { BNPluginAreDependenciesBeingInstalled(self.as_raw()) }
    }

    /// Gets a json object of the project data field
    pub fn project_data(&self) -> BnString {
        let result = unsafe { BNPluginGetProjectData(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Returns a datetime object representing the plugins last update
    pub fn last_update(&self) -> SystemTime {
        let result = unsafe { BNPluginGetLastUpdate(self.as_raw()) };
        UNIX_EPOCH + Duration::from_secs(result)
    }
}

impl CoreArrayProvider for RepoPlugin {
    type Raw = *mut BNRepoPlugin;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for RepoPlugin {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeRepositoryPluginList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct VersionInfo {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub channel: BnString,
}

impl cmp::PartialOrd for VersionInfo {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for VersionInfo {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        if self == other {
            return cmp::Ordering::Equal;
        }
        if unsafe { BNVersionLessThan(*self.as_raw(), *other.as_raw()) } {
            cmp::Ordering::Less
        } else {
            cmp::Ordering::Greater
        }
    }
}

impl VersionInfo {
    pub(crate) unsafe fn from_raw(value: BNVersionInfo) -> Self {
        assert!(!value.channel.is_null());
        Self {
            major: value.major,
            minor: value.minor,
            build: value.build,
            channel: BnString::from_raw(value.channel),
        }
    }

    pub(crate) unsafe fn as_raw(&self) -> &BNVersionInfo {
        mem::transmute(self)
    }

    pub fn parser_version_string<S: BnStrCompatible>(string: S) -> Self {
        let string = string.into_bytes_with_nul();
        let result =
            unsafe { BNParseVersionString(string.as_ref().as_ptr() as *const ffi::c_char) };
        unsafe { Self::from_raw(result) }
    }
}

impl CoreArrayProvider for PluginType {
    type Raw = BNPluginType;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for PluginType {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreePluginTypes(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        *raw
    }
}

pub struct PluginPlatforms;
impl CoreArrayProvider for PluginPlatforms {
    type Raw = *mut ffi::c_char;
    type Context = ();
    type Wrapped<'a> = &'a ffi::CStr;
}

unsafe impl CoreArrayProviderInner for PluginPlatforms {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreePluginPlatforms(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        ffi::CStr::from_ptr(*raw)
    }
}

pub struct PluginDirectorys;
impl CoreArrayProvider for PluginDirectorys {
    type Raw = *mut ffi::c_char;
    type Context = ();
    type Wrapped<'a> = &'a ffi::CStr;
}

unsafe impl CoreArrayProviderInner for PluginDirectorys {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNRepositoryFreePluginDirectoryList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        ffi::CStr::from_ptr(*raw)
    }
}
