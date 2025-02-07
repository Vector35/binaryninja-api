use crate::rc::{Array, Ref, RefCountable};
use crate::repository::Repository;
use crate::string::BnStrCompatible;
use binaryninjacore_sys::{
    BNCreateRepositoryManager, BNFreeRepositoryManager, BNGetRepositoryManager,
    BNNewRepositoryManagerReference, BNRepositoryGetRepositoryByPath, BNRepositoryManager,
    BNRepositoryManagerAddRepository, BNRepositoryManagerCheckForUpdates,
    BNRepositoryManagerGetDefaultRepository, BNRepositoryManagerGetRepositories,
};
use std::ffi::c_char;
use std::fmt::Debug;
use std::ptr::NonNull;

/// Keeps track of all the repositories and keeps the `enabled_plugins.json`
/// file coherent with the plugins that are installed/uninstalled enabled/disabled
#[repr(transparent)]
pub struct RepositoryManager {
    handle: NonNull<BNRepositoryManager>,
}

impl RepositoryManager {
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Ref<Self> {
        let result = unsafe { BNGetRepositoryManager() };
        unsafe { Self::ref_from_raw(NonNull::new(result).unwrap()) }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNRepositoryManager>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    pub fn new<S: BnStrCompatible>(plugins_path: S) -> Ref<Self> {
        let plugins_path = plugins_path.into_bytes_with_nul();
        let result =
            unsafe { BNCreateRepositoryManager(plugins_path.as_ref().as_ptr() as *const c_char) };
        unsafe { Self::ref_from_raw(NonNull::new(result).unwrap()) }
    }

    /// Check for updates for all managed [`Repository`] objects
    pub fn check_for_updates(&self) -> bool {
        unsafe { BNRepositoryManagerCheckForUpdates(self.handle.as_ptr()) }
    }

    /// List of [`Repository`] objects being managed
    pub fn repositories(&self) -> Array<Repository> {
        let mut count = 0;
        let result =
            unsafe { BNRepositoryManagerGetRepositories(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Adds a new plugin repository for the manager to track.
    ///
    /// To remove a repository, restart Binary Ninja (and don't re-add the repository!).
    /// File artifacts will remain on disk under repositories/ file in the User Folder.
    ///
    /// Before you can query plugin metadata from a repository, you need to call [`RepositoryManager::check_for_updates`].
    ///
    /// * `url` - URL to the plugins.json containing the records for this repository
    /// * `repository_path` - path to where the repository will be stored on disk locally
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
                self.handle.as_ptr(),
                url.as_ref().as_ptr() as *const c_char,
                repo_path.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    pub fn repository_by_path<P: BnStrCompatible>(&self, path: P) -> Option<Repository> {
        let path = path.into_bytes_with_nul();
        let result = unsafe {
            BNRepositoryGetRepositoryByPath(
                self.handle.as_ptr(),
                path.as_ref().as_ptr() as *const c_char,
            )
        };
        NonNull::new(result).map(|raw| unsafe { Repository::from_raw(raw) })
    }

    /// Gets the default [`Repository`]
    pub fn default_repository(&self) -> Ref<Repository> {
        let result = unsafe { BNRepositoryManagerGetDefaultRepository(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { Repository::ref_from_raw(NonNull::new(result).unwrap()) }
    }
}

impl Debug for RepositoryManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryManager")
            .field("repositories", &self.repositories().to_vec())
            .finish()
    }
}

impl ToOwned for RepositoryManager {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for RepositoryManager {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(
            NonNull::new(BNNewRepositoryManagerReference(handle.handle.as_ptr())).unwrap(),
        )
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeRepositoryManager(handle.handle.as_ptr())
    }
}
