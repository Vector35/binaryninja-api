mod manager;
mod plugin;

use std::ffi::c_char;
use std::fmt::Debug;
use std::ptr::NonNull;

use binaryninjacore_sys::*;

use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::repository::plugin::RepositoryPlugin;
use crate::string::{BnStrCompatible, BnString};

pub use manager::RepositoryManager;

pub type PluginType = BNPluginType;
pub type PluginStatus = BNPluginStatus;

#[repr(transparent)]
pub struct Repository {
    handle: NonNull<BNRepository>,
}

impl Repository {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNRepository>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNRepository>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// String URL of the git repository where the plugin repository's are stored
    pub fn url(&self) -> BnString {
        let result = unsafe { BNRepositoryGetUrl(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// String local path to store the given plugin repository
    pub fn path(&self) -> BnString {
        let result = unsafe { BNRepositoryGetRepoPath(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }

    /// List of RepoPlugin objects contained within this repository
    pub fn plugins(&self) -> Array<RepositoryPlugin> {
        let mut count = 0;
        let result = unsafe { BNRepositoryGetPlugins(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn plugin_by_path<S: BnStrCompatible>(&self, path: S) -> Option<Ref<RepositoryPlugin>> {
        let path = path.into_bytes_with_nul();
        let result = unsafe {
            BNRepositoryGetPluginByPath(
                self.handle.as_ptr(),
                path.as_ref().as_ptr() as *const c_char,
            )
        };
        NonNull::new(result).map(|h| unsafe { RepositoryPlugin::ref_from_raw(h) })
    }

    // TODO: Make this a PathBuf?
    /// String full path the repository
    pub fn full_path(&self) -> BnString {
        let result = unsafe { BNRepositoryGetPluginsPath(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut c_char) }
    }
}

impl Debug for Repository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repository")
            .field("url", &self.url())
            .field("path", &self.path())
            .field("full_path", &self.full_path())
            .field("plugins", &self.plugins().to_vec())
            .finish()
    }
}

impl ToOwned for Repository {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { <Self as RefCountable>::inc_ref(self) }
    }
}

unsafe impl RefCountable for Repository {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(NonNull::new(BNNewRepositoryReference(handle.handle.as_ptr())).unwrap())
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeRepository(handle.handle.as_ptr())
    }
}

impl CoreArrayProvider for Repository {
    type Raw = *mut BNRepository;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for Repository {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeRepositoryManagerRepositoriesList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(NonNull::new(*raw).unwrap()), context)
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
