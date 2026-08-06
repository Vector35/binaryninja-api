//! APIs for resolving argument types described by format strings.

use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void};
use std::fmt::Debug;
use std::ptr::NonNull;

use crate::confidence::Conf;
use crate::platform::Platform;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{raw_to_string, BnString, IntoCStr};
use crate::types::Type;

/// A custom provider that validates format strings and resolves their argument types.
///
/// Providers are registered for the lifetime of the process and may be invoked from multiple
/// analysis threads.
pub trait CustomFormatStringResolutionProvider: Send + Sync + 'static {
    /// Resolve the argument types described by `format` for `platform`.
    ///
    /// Return `None` when the string is not valid for this provider. A valid string with no
    /// arguments is represented by `Some(Vec::new())`. Each returned type retains its individual
    /// confidence value.
    fn is_valid(&self, format: &str, platform: Option<&Platform>) -> Option<Vec<Conf<Ref<Type>>>>;
}

/// A registered format string resolution provider.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct FormatStringResolutionProvider {
    handle: NonNull<BNFormatStringResolutionProvider>,
}

impl FormatStringResolutionProvider {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNFormatStringResolutionProvider>) -> Self {
        Self { handle }
    }

    /// Register a custom format string resolution provider.
    ///
    /// The provider is retained for the lifetime of the process.
    pub fn register<P>(name: &str, provider: P) -> Self
    where
        P: CustomFormatStringResolutionProvider,
    {
        let name = name.to_cstr();
        // The core registry has no unregister operation, so the callback context must remain valid
        // for the lifetime of the process.
        let provider = Box::leak(Box::new(provider));
        let mut callbacks = BNFormatStringResolutionProviderCallbacks {
            context: provider as *mut P as *mut c_void,
            isValid: Some(cb_is_valid::<P>),
            freeTypeList: Some(cb_free_type_list),
        };
        let result =
            unsafe { BNRegisterFormatStringResolutionProvider(name.as_ptr(), &mut callbacks) };
        let handle =
            NonNull::new(result).expect("failed to register format string resolution provider");
        unsafe { Self::from_raw(handle) }
    }

    /// Retrieve all registered format string resolution providers.
    pub fn all() -> Array<Self> {
        let mut count = 0;
        let result = unsafe { BNGetFormatStringResolutionProviderList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Retrieve a registered format string resolution provider by name.
    pub fn by_name(name: &str) -> Option<Self> {
        let name = name.to_cstr();
        let result = unsafe { BNGetFormatStringResolutionProviderByName(name.as_ptr()) };
        NonNull::new(result).map(|handle| unsafe { Self::from_raw(handle) })
    }

    /// Return the provider's registration name.
    pub fn name(&self) -> String {
        let result = unsafe { BNGetFormatStringResolutionProviderName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Resolve the argument types described by `format` for `platform`.
    ///
    /// Return `None` when the string is not valid for this provider. A valid string with no
    /// arguments is represented by `Some(Vec::new())`.
    pub fn is_valid(
        &self,
        format: &str,
        platform: Option<&Platform>,
    ) -> Option<Vec<Conf<Ref<Type>>>> {
        let format = format.to_cstr();
        let mut types = std::ptr::null_mut();
        let mut count = 0;
        let valid = unsafe {
            BNFormatStringResolutionProviderIsValid(
                self.handle.as_ptr(),
                format.as_ptr(),
                platform.map_or(std::ptr::null_mut(), |platform| platform.handle),
                &mut types,
                &mut count,
            )
        };

        if !valid {
            if !types.is_null() {
                unsafe { BNFreeTypeWithConfidenceList(types, count) };
            }
            return None;
        }

        if count == 0 {
            if !types.is_null() {
                unsafe { BNFreeTypeWithConfidenceList(types, count) };
            }
            return Some(Vec::new());
        }

        if types.is_null() {
            return None;
        }

        let result = unsafe { std::slice::from_raw_parts(types, count) }
            .iter()
            .map(Conf::<Ref<Type>>::from_raw)
            .collect();
        unsafe { BNFreeTypeWithConfidenceList(types, count) };
        Some(result)
    }
}

impl Debug for FormatStringResolutionProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FormatStringResolutionProvider")
            .field("name", &self.name())
            .finish()
    }
}

unsafe impl Send for FormatStringResolutionProvider {}
unsafe impl Sync for FormatStringResolutionProvider {}

impl CoreArrayProvider for FormatStringResolutionProvider {
    type Raw = *mut BNFormatStringResolutionProvider;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for FormatStringResolutionProvider {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeFormatStringResolutionProviderList(raw);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        let handle =
            NonNull::new(*raw).expect("format string resolution provider list contained null");
        Self::from_raw(handle)
    }
}

unsafe extern "C" fn cb_is_valid<P>(
    ctxt: *mut c_void,
    format: *const c_char,
    platform: *mut BNPlatform,
    types: *mut *mut BNTypeWithConfidence,
    count: *mut usize,
) -> bool
where
    P: CustomFormatStringResolutionProvider,
{
    ffi_wrap!("CustomFormatStringResolutionProvider::is_valid", unsafe {
        if types.is_null() || count.is_null() {
            return false;
        }
        *types = std::ptr::null_mut();
        *count = 0;

        let Some(format) = raw_to_string(format) else {
            return false;
        };
        let provider = &*(ctxt as *const P);
        let platform = NonNull::new(platform).map(|handle| Platform::from_raw(handle.as_ptr()));
        let Some(result) = provider.is_valid(&format, platform.as_ref()) else {
            return false;
        };

        let raw_types: Box<[BNTypeWithConfidence]> = result
            .into_iter()
            .map(Conf::<Ref<Type>>::into_raw)
            .collect();
        *count = raw_types.len();
        if raw_types.is_empty() {
            true
        } else {
            *types = Box::leak(raw_types).as_mut_ptr();
            true
        }
    })
}

unsafe extern "C" fn cb_free_type_list(
    _ctxt: *mut c_void,
    types: *mut BNTypeWithConfidence,
    count: usize,
) {
    ffi_wrap!(
        "CustomFormatStringResolutionProvider::free_type_list",
        unsafe {
            if types.is_null() {
                return;
            }
            let types = Box::from_raw(std::ptr::slice_from_raw_parts_mut(types, count));
            for ty in types {
                Conf::<Ref<Type>>::free_raw(ty);
            }
        }
    )
}
