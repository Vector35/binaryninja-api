use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void, CStr};
use std::fmt::Debug;
use std::ptr::NonNull;

use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

pub trait SecretsProvider {
    fn has_data(&mut self, key: &str) -> bool;
    fn get_data(&mut self, key: &str) -> String;
    fn store_data(&mut self, key: &str, data: &str) -> bool;
    fn delete_data(&mut self, key: &str) -> bool;
}

/// Struct for storing secrets (e.g. tokens) in a system-specific manner
#[repr(transparent)]
pub struct CoreSecretsProvider {
    handle: NonNull<BNSecretsProvider>,
}

impl CoreSecretsProvider {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNSecretsProvider>) -> Self {
        Self { handle }
    }

    /// Register a new provider
    pub fn new<C: SecretsProvider>(name: &str, callback: C) -> Self {
        // SAFETY: once create SecretsProvider is never dropped
        let name = name.into_bytes_with_nul();
        let callback = Box::leak(Box::new(callback));
        let mut callbacks = BNSecretsProviderCallbacks {
            context: callback as *mut C as *mut c_void,
            hasData: Some(cb_has_data::<C>),
            getData: Some(cb_get_data::<C>),
            storeData: Some(cb_store_data::<C>),
            deleteData: Some(cb_delete_data::<C>),
        };
        let result =
            unsafe { BNRegisterSecretsProvider(name.as_ptr() as *const c_char, &mut callbacks) };
        unsafe { Self::from_raw(NonNull::new(result).unwrap()) }
    }

    /// Retrieve the list of providers
    pub fn all() -> Array<CoreSecretsProvider> {
        let mut count = 0;
        let result = unsafe { BNGetSecretsProviderList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Retrieve a provider by name
    pub fn by_name<S: BnStrCompatible>(name: S) -> Option<CoreSecretsProvider> {
        let name = name.into_bytes_with_nul();
        let result = unsafe { BNGetSecretsProviderByName(name.as_ref().as_ptr() as *const c_char) };
        NonNull::new(result).map(|h| unsafe { Self::from_raw(h) })
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNGetSecretsProviderName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Check if data for a specific key exists, but do not retrieve it
    pub fn has_data<S: BnStrCompatible>(&self, key: S) -> bool {
        let key = key.into_bytes_with_nul();
        unsafe {
            BNSecretsProviderHasData(self.handle.as_ptr(), key.as_ref().as_ptr() as *const c_char)
        }
    }

    /// Retrieve data for the given key, if it exists
    pub fn get_data<S: BnStrCompatible>(&self, key: S) -> BnString {
        let key = key.into_bytes_with_nul();
        let result = unsafe {
            BNGetSecretsProviderData(self.handle.as_ptr(), key.as_ref().as_ptr() as *const c_char)
        };
        unsafe { BnString::from_raw(result) }
    }

    /// Store data with the given key
    pub fn store_data<K: BnStrCompatible, V: BnStrCompatible>(&self, key: K, value: V) -> bool {
        let key = key.into_bytes_with_nul();
        let value = value.into_bytes_with_nul();
        unsafe {
            BNStoreSecretsProviderData(
                self.handle.as_ptr(),
                key.as_ref().as_ptr() as *const c_char,
                value.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Delete stored data with the given key
    pub fn delete_data<S: BnStrCompatible>(&self, key: S) -> bool {
        let key = key.into_bytes_with_nul();
        unsafe {
            BNDeleteSecretsProviderData(
                self.handle.as_ptr(),
                key.as_ref().as_ptr() as *const c_char,
            )
        }
    }
}

impl Debug for CoreSecretsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreSecretsProvider")
            .field("name", &self.name())
            .finish()
    }
}

impl CoreArrayProvider for CoreSecretsProvider {
    type Raw = *mut BNSecretsProvider;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CoreSecretsProvider {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeSecretsProviderList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Self::from_raw(raw_ptr)
    }
}

unsafe extern "C" fn cb_has_data<C: SecretsProvider>(
    ctxt: *mut c_void,
    key: *const c_char,
) -> bool {
    let ctxt: &mut C = &mut *(ctxt as *mut C);
    ctxt.has_data(&CStr::from_ptr(key).to_string_lossy())
}

unsafe extern "C" fn cb_get_data<C: SecretsProvider>(
    ctxt: *mut c_void,
    key: *const c_char,
) -> *mut c_char {
    let ctxt: &mut C = &mut *(ctxt as *mut C);
    let result = ctxt.get_data(&CStr::from_ptr(key).to_string_lossy());
    BnString::into_raw(BnString::new(result))
}

unsafe extern "C" fn cb_store_data<C: SecretsProvider>(
    ctxt: *mut c_void,
    key: *const c_char,
    data: *const c_char,
) -> bool {
    let ctxt: &mut C = &mut *(ctxt as *mut C);
    let key = CStr::from_ptr(key).to_string_lossy();
    let data = CStr::from_ptr(data).to_string_lossy();
    ctxt.store_data(&key, &data)
}

unsafe extern "C" fn cb_delete_data<C: SecretsProvider>(
    ctxt: *mut c_void,
    key: *const c_char,
) -> bool {
    let ctxt: &mut C = &mut *(ctxt as *mut C);
    ctxt.delete_data(&CStr::from_ptr(key).to_string_lossy())
}
