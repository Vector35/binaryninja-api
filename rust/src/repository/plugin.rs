use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::repository::{PluginStatus, PluginType};
use crate::string::BnString;
use crate::VersionInfo;
use binaryninjacore_sys::*;
use std::ffi::c_char;
use std::fmt::Debug;
use std::ptr::NonNull;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[repr(transparent)]
pub struct RepositoryPlugin {
    handle: NonNull<BNRepoPlugin>,
}

impl RepositoryPlugin {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNRepoPlugin>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNRepoPlugin>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// String indicating the API used by the plugin
    pub fn apis(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNPluginGetApis(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// String of the plugin author
    pub fn author(&self) -> BnString {
        let result = unsafe { BNPluginGetAuthor(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// String short description of the plugin
    pub fn description(&self) -> BnString {
        let result = unsafe { BNPluginGetDescription(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// String complete license text for the given plugin
    pub fn license_text(&self) -> BnString {
        let result = unsafe { BNPluginGetLicenseText(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// String long description of the plugin
    pub fn long_description(&self) -> BnString {
        let result = unsafe { BNPluginGetLongdescription(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// Minimum version info the plugin was tested on
    pub fn minimum_version_info(&self) -> VersionInfo {
        let result = unsafe { BNPluginGetMinimumVersionInfo(self.handle.as_ptr()) };
        VersionInfo::from_owned_raw(result)
    }

    /// Maximum version info the plugin will support
    pub fn maximum_version_info(&self) -> VersionInfo {
        let result = unsafe { BNPluginGetMaximumVersionInfo(self.handle.as_ptr()) };
        VersionInfo::from_owned_raw(result)
    }

    /// String plugin name
    pub fn name(&self) -> BnString {
        let result = unsafe { BNPluginGetName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// String URL of the plugin's git repository
    pub fn project_url(&self) -> BnString {
        let result = unsafe { BNPluginGetProjectUrl(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// String URL of the plugin's git repository
    pub fn package_url(&self) -> BnString {
        let result = unsafe { BNPluginGetPackageUrl(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// String URL of the plugin author's url
    pub fn author_url(&self) -> BnString {
        let result = unsafe { BNPluginGetAuthorUrl(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }
    /// String version of the plugin
    pub fn version(&self) -> BnString {
        let result = unsafe { BNPluginGetVersion(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// String of the commit of this plugin git repository
    pub fn commit(&self) -> BnString {
        let result = unsafe { BNPluginGetCommit(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// Relative path from the base of the repository to the actual plugin
    pub fn path(&self) -> BnString {
        let result = unsafe { BNPluginGetPath(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// Optional sub-directory the plugin code lives in as a relative path from the plugin root
    pub fn subdir(&self) -> BnString {
        let result = unsafe { BNPluginGetSubdir(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// Dependencies required for installing this plugin
    pub fn dependencies(&self) -> BnString {
        let result = unsafe { BNPluginGetDependencies(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// true if the plugin is installed, false otherwise
    pub fn is_installed(&self) -> bool {
        unsafe { BNPluginIsInstalled(self.handle.as_ptr()) }
    }

    /// true if the plugin is enabled, false otherwise
    pub fn is_enabled(&self) -> bool {
        unsafe { BNPluginIsEnabled(self.handle.as_ptr()) }
    }

    pub fn status(&self) -> PluginStatus {
        unsafe { BNPluginGetPluginStatus(self.handle.as_ptr()) }
    }

    /// List of PluginType enumeration objects indicating the plugin type(s)
    pub fn types(&self) -> Array<PluginType> {
        let mut count = 0;
        let result = unsafe { BNPluginGetPluginTypes(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Enable this plugin, optionally trying to force it.
    /// Force loading a plugin with ignore platform and api constraints.
    pub fn enable(&self, force: bool) -> bool {
        unsafe { BNPluginEnable(self.handle.as_ptr(), force) }
    }

    pub fn disable(&self) -> bool {
        unsafe { BNPluginDisable(self.handle.as_ptr()) }
    }

    /// Attempt to install the given plugin
    pub fn install(&self) -> bool {
        unsafe { BNPluginInstall(self.handle.as_ptr()) }
    }

    pub fn install_dependencies(&self) -> bool {
        unsafe { BNPluginInstallDependencies(self.handle.as_ptr()) }
    }

    /// Attempt to uninstall the given plugin
    pub fn uninstall(&self) -> bool {
        unsafe { BNPluginUninstall(self.handle.as_ptr()) }
    }

    pub fn updated(&self) -> bool {
        unsafe { BNPluginUpdate(self.handle.as_ptr()) }
    }

    /// List of platforms this plugin can execute on
    pub fn platforms(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNPluginGetPlatforms(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn repository(&self) -> BnString {
        let result = unsafe { BNPluginGetRepository(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// Boolean status indicating that the plugin is being deleted
    pub fn is_being_deleted(&self) -> bool {
        unsafe { BNPluginIsBeingDeleted(self.handle.as_ptr()) }
    }

    /// Boolean status indicating that the plugin is being updated
    pub fn is_being_updated(&self) -> bool {
        unsafe { BNPluginIsBeingUpdated(self.handle.as_ptr()) }
    }

    /// Boolean status indicating that the plugin is currently running
    pub fn is_running(&self) -> bool {
        unsafe { BNPluginIsRunning(self.handle.as_ptr()) }
    }

    /// Boolean status indicating that the plugin has updates will be installed after the next restart
    pub fn is_update_pending(&self) -> bool {
        unsafe { BNPluginIsUpdatePending(self.handle.as_ptr()) }
    }

    /// Boolean status indicating that the plugin will be disabled after the next restart
    pub fn is_disable_pending(&self) -> bool {
        unsafe { BNPluginIsDisablePending(self.handle.as_ptr()) }
    }

    /// Boolean status indicating that the plugin will be deleted after the next restart
    pub fn is_delete_pending(&self) -> bool {
        unsafe { BNPluginIsDeletePending(self.handle.as_ptr()) }
    }

    /// Boolean status indicating that the plugin has updates available
    pub fn is_updated_available(&self) -> bool {
        unsafe { BNPluginIsUpdateAvailable(self.handle.as_ptr()) }
    }

    /// Boolean status indicating that the plugin's dependencies are currently being installed
    pub fn are_dependencies_being_installed(&self) -> bool {
        unsafe { BNPluginAreDependenciesBeingInstalled(self.handle.as_ptr()) }
    }

    /// Gets a json object of the project data field
    pub fn project_data(&self) -> BnString {
        let result = unsafe { BNPluginGetProjectData(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Returns a datetime object representing the plugins last update
    pub fn last_update(&self) -> SystemTime {
        let result = unsafe { BNPluginGetLastUpdate(self.handle.as_ptr()) };
        UNIX_EPOCH + Duration::from_secs(result)
    }
}

impl Debug for RepositoryPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryPlugin")
            .field("name", &self.name())
            .field("version", &self.version())
            .field("author", &self.author())
            .field("description", &self.description())
            .field("minimum_version_info", &self.minimum_version_info())
            .field("maximum_version_info", &self.maximum_version_info())
            .field("last_update", &self.last_update())
            .field("status", &self.status())
            .finish()
    }
}

impl ToOwned for RepositoryPlugin {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for RepositoryPlugin {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(NonNull::new(BNNewPluginReference(handle.handle.as_ptr())).unwrap())
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreePlugin(handle.handle.as_ptr())
    }
}

impl CoreArrayProvider for RepositoryPlugin {
    type Raw = *mut BNRepoPlugin;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for RepositoryPlugin {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeRepositoryPluginList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(NonNull::new(*raw).unwrap()), context)
    }
}
