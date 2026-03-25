use crate::rc::{Array, Ref};
use crate::repository::Repository;
use crate::string::IntoCStr;
use binaryninjacore_sys::{
    BNRepositoryGetRepositoryByPath, BNRepositoryManagerAddRepository,
    BNRepositoryManagerCheckForUpdates, BNRepositoryManagerGetDefaultRepository,
    BNRepositoryManagerGetRepositories,
};
use std::fmt::Debug;
use std::path::Path;
use std::ptr::NonNull;

/// Keeps track of all the repositories and keeps the `enabled_plugins.json`
/// file coherent with the plugins that are installed/uninstalled enabled/disabled
pub struct RepositoryManager;

impl RepositoryManager {
    /// Check for updates for all managed [`Repository`] objects
    pub fn check_for_updates() -> bool {
        unsafe { BNRepositoryManagerCheckForUpdates() }
    }

    /// List of [`Repository`] objects being managed
    pub fn repositories() -> Array<Repository> {
        let mut count = 0;
        let result = unsafe { BNRepositoryManagerGetRepositories(&mut count) };
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
    pub fn add_repository(url: &str, repository_path: &Path) -> bool {
        let url = url.to_cstr();
        let repo_path = repository_path.to_cstr();
        unsafe { BNRepositoryManagerAddRepository(url.as_ptr(), repo_path.as_ptr()) }
    }

    pub fn repository_by_path(path: &Path) -> Option<Repository> {
        let path = path.to_cstr();
        let result = unsafe { BNRepositoryGetRepositoryByPath(path.as_ptr()) };
        NonNull::new(result).map(|raw| unsafe { Repository::from_raw(raw) })
    }

    /// Gets the default [`Repository`]
    pub fn default_repository() -> Ref<Repository> {
        let result = unsafe { BNRepositoryManagerGetDefaultRepository() };
        assert!(!result.is_null());
        unsafe { Repository::ref_from_raw(NonNull::new(result).unwrap()) }
    }
}

impl Debug for RepositoryManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryManager")
            .field("repositories", &RepositoryManager::repositories().to_vec())
            .finish()
    }
}
