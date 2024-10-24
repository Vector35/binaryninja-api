use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

/// Struct for storing secrets (e.g. tokens) in a system-specific manner
#[repr(transparent)]
pub struct SecretsProvider {
    handle: ptr::NonNull<BNSecretsProvider>,
}

impl SecretsProvider {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNSecretsProvider>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNSecretsProvider) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNSecretsProvider {
        &mut *self.handle.as_ptr()
    }

    /// Register a new provider
    pub fn new<N: IntoSecretsProviderName, C: SecretsProviderCallback>(
        name: N,
        callback: C,
    ) -> Self {
        // SAFETY: once create SecretsProvider is never dropped
        let name = name.secrets_provider_name();
        let callback = Box::leak(Box::new(callback));
        let mut callbacks = BNSecretsProviderCallbacks {
            context: callback as *mut C as *mut ffi::c_void,
            hasData: Some(cb_has_data::<C>),
            getData: Some(cb_get_data::<C>),
            storeData: Some(cb_store_data::<C>),
            deleteData: Some(cb_delete_data::<C>),
        };
        let result = unsafe { BNRegisterSecretsProvider(name.as_ptr(), &mut callbacks) };
        unsafe { Self::from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    /// Retrieve the list of providers
    pub fn all() -> Array<SecretsProvider> {
        let mut count = 0;
        let result = unsafe { BNGetSecretsProviderList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Retrieve a provider by name
    pub fn by_name<S: BnStrCompatible>(name: S) -> Option<SecretsProvider> {
        let name = name.into_bytes_with_nul();
        let result =
            unsafe { BNGetSecretsProviderByName(name.as_ref().as_ptr() as *const ffi::c_char) };
        ptr::NonNull::new(result).map(|h| unsafe { Self::from_raw(h) })
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNGetSecretsProviderName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Check if data for a specific key exists, but do not retrieve it
    pub fn has_data<S: BnStrCompatible>(&self, key: S) -> bool {
        let key = key.into_bytes_with_nul();
        unsafe {
            BNSecretsProviderHasData(self.as_raw(), key.as_ref().as_ptr() as *const ffi::c_char)
        }
    }

    /// Retrieve data for the given key, if it exists
    pub fn get_data<S: BnStrCompatible>(&self, key: S) -> Option<BnString> {
        let key = key.into_bytes_with_nul();
        let result = unsafe {
            BNGetSecretsProviderData(self.as_raw(), key.as_ref().as_ptr() as *const ffi::c_char)
        };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Store data with the given key
    pub fn store_data<K: BnStrCompatible, V: BnStrCompatible>(&self, key: K, value: V) -> bool {
        let key = key.into_bytes_with_nul();
        let value = value.into_bytes_with_nul();
        unsafe {
            BNStoreSecretsProviderData(
                self.as_raw(),
                key.as_ref().as_ptr() as *const ffi::c_char,
                value.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Delete stored data with the given key
    pub fn delete_data<S: BnStrCompatible>(&self, key: S) -> bool {
        let key = key.into_bytes_with_nul();
        unsafe {
            BNDeleteSecretsProviderData(self.as_raw(), key.as_ref().as_ptr() as *const ffi::c_char)
        }
    }
}

impl CoreArrayProvider for SecretsProvider {
    type Raw = *mut BNSecretsProvider;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for SecretsProvider {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeSecretsProviderList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

pub trait IntoSecretsProviderName {
    fn secrets_provider_name(self) -> BnString;
}

impl<S: BnStrCompatible> IntoSecretsProviderName for S {
    fn secrets_provider_name(self) -> BnString {
        BnString::new(self)
    }
}

impl IntoSecretsProviderName for &SecretsProvider {
    fn secrets_provider_name(self) -> BnString {
        self.name()
    }
}

pub trait SecretsProviderCallback {
    fn has_data(&mut self, key: &str) -> bool;
    fn get_data(&mut self, key: &str) -> String;
    fn store_data(&mut self, key: &str, data: &str) -> bool;
    fn delete_data(&mut self, key: &str) -> bool;
}

unsafe extern "C" fn cb_has_data<C: SecretsProviderCallback>(
    ctxt: *mut ffi::c_void,
    key: *const ffi::c_char,
) -> bool {
    let ctxt: &mut C = &mut *(ctxt as *mut C);
    ctxt.has_data(&ffi::CStr::from_ptr(key).to_string_lossy())
}

unsafe extern "C" fn cb_get_data<C: SecretsProviderCallback>(
    ctxt: *mut ffi::c_void,
    key: *const ffi::c_char,
) -> *mut ffi::c_char {
    let ctxt: &mut C = &mut *(ctxt as *mut C);
    let result = ctxt.get_data(&ffi::CStr::from_ptr(key).to_string_lossy());
    BnString::new(result).into_raw()
}

unsafe extern "C" fn cb_store_data<C: SecretsProviderCallback>(
    ctxt: *mut ffi::c_void,
    key: *const ffi::c_char,
    data: *const ffi::c_char,
) -> bool {
    let ctxt: &mut C = &mut *(ctxt as *mut C);
    let key = ffi::CStr::from_ptr(key).to_string_lossy();
    let data = ffi::CStr::from_ptr(data).to_string_lossy();
    ctxt.store_data(&key, &data)
}

unsafe extern "C" fn cb_delete_data<C: SecretsProviderCallback>(
    ctxt: *mut ffi::c_void,
    key: *const ffi::c_char,
) -> bool {
    let ctxt: &mut C = &mut *(ctxt as *mut C);
    ctxt.delete_data(&ffi::CStr::from_ptr(key).to_string_lossy())
}
