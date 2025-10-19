use crate::download::{CustomDownloadInstance, DownloadInstance};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref};
use crate::settings::Settings;
use crate::string::{BnString, IntoCStr};
use binaryninjacore_sys::*;
use std::ffi::c_void;
use std::fmt::Debug;
use std::mem::MaybeUninit;

/// Register a new download provider type, which is used by the core (and other plugins) to make HTTP requests.
pub fn register_download_provider<C>(name: &str) -> &'static mut C
where
    C: CustomDownloadProvider,
{
    let name = name.to_cstr();
    let provider_uninit = MaybeUninit::uninit();
    // SAFETY: Download provider is never freed
    let leaked_provider = Box::leak(Box::new(provider_uninit));
    let result = unsafe {
        BNRegisterDownloadProvider(
            name.as_ptr(),
            &mut BNDownloadProviderCallbacks {
                context: leaked_provider as *mut _ as *mut c_void,
                createInstance: Some(cb_create_instance::<C>),
            },
        )
    };

    let provider_core = DownloadProvider::from_raw(result);
    // We now have the core provider so we can actually construct the object.
    leaked_provider.write(C::from_core(provider_core));
    unsafe { leaked_provider.assume_init_mut() }
}

pub trait CustomDownloadProvider: 'static + Sync {
    type Instance: CustomDownloadInstance;

    fn handle(&self) -> DownloadProvider;

    /// Called to construct this provider object with the given core object.
    fn from_core(core: DownloadProvider) -> Self;

    fn create_instance(&self) -> Result<Ref<DownloadInstance>, ()> {
        Self::Instance::new_with_provider(self.handle())
    }
}

#[derive(Copy, Clone)]
pub struct DownloadProvider {
    pub(crate) handle: *mut BNDownloadProvider,
}

impl DownloadProvider {
    pub(crate) fn from_raw(handle: *mut BNDownloadProvider) -> DownloadProvider {
        Self { handle }
    }

    pub fn get(name: &str) -> Option<DownloadProvider> {
        let name = name.to_cstr();
        let result = unsafe { BNGetDownloadProviderByName(name.as_ptr()) };
        if result.is_null() {
            return None;
        }
        Some(DownloadProvider { handle: result })
    }

    pub fn list() -> Result<Array<DownloadProvider>, ()> {
        let mut count = 0;
        let list: *mut *mut BNDownloadProvider = unsafe { BNGetDownloadProviderList(&mut count) };

        if list.is_null() {
            return Err(());
        }

        Ok(unsafe { Array::new(list, count, ()) })
    }

    /// TODO: We may want to `impl Default`, error checking might be preventing us from doing so
    pub fn try_default() -> Result<DownloadProvider, ()> {
        let s = Settings::new();
        let dp_name = s.get_string("network.downloadProviderName");
        Self::get(&dp_name).ok_or(())
    }

    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNGetDownloadProviderName(self.handle)) }
    }

    pub fn create_instance(&self) -> Result<Ref<DownloadInstance>, ()> {
        let result: *mut BNDownloadInstance =
            unsafe { BNCreateDownloadProviderInstance(self.handle) };
        if result.is_null() {
            return Err(());
        }

        Ok(unsafe { DownloadInstance::ref_from_raw(result) })
    }
}

impl Debug for DownloadProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownloadProvider")
            .field("name", &self.name())
            .finish()
    }
}

impl CoreArrayProvider for DownloadProvider {
    type Raw = *mut BNDownloadProvider;
    type Context = ();
    type Wrapped<'a> = Guard<'a, DownloadProvider>;
}

unsafe impl CoreArrayProviderInner for DownloadProvider {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeDownloadProviderList(raw);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(DownloadProvider::from_raw(*raw), &())
    }
}

unsafe impl Send for DownloadProvider {}
unsafe impl Sync for DownloadProvider {}

unsafe extern "C" fn cb_create_instance<C: CustomDownloadProvider>(
    ctxt: *mut c_void,
) -> *mut BNDownloadInstance {
    ffi_wrap!("CustomDownloadProvider::cb_create_instance", unsafe {
        let provider = &*(ctxt as *const C);
        match provider.create_instance() {
            Ok(instance) => Ref::into_raw(instance).handle,
            Err(_) => std::ptr::null_mut(),
        }
    })
}
