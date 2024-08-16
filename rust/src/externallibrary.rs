use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use crate::project::ProjectFile;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};
use crate::symbol::Symbol;

/// An ExternalLibrary is an abstraction for a library that is optionally backed
/// by a [ProjectFile].
#[repr(transparent)]
pub struct ExternalLibrary {
    handle: ptr::NonNull<BNExternalLibrary>,
}

impl Drop for ExternalLibrary {
    fn drop(&mut self) {
        unsafe { BNFreeExternalLibrary(self.as_raw()) }
    }
}

impl Clone for ExternalLibrary {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewExternalLibraryReference(self.as_raw())).unwrap())
        }
    }
}

impl ExternalLibrary {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNExternalLibrary>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNExternalLibrary) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNExternalLibrary {
        &mut *self.handle.as_ptr()
    }

    /// Get the name of this external library
    pub fn name(&self) -> BnString {
        let result = unsafe { BNExternalLibraryGetName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Get the file backing this external library
    pub fn backing_file(&self) -> Option<ProjectFile> {
        let result = unsafe { BNExternalLibraryGetBackingFile(self.as_raw()) };
        let handle = ptr::NonNull::new(result)?;
        Some(unsafe { ProjectFile::from_raw(handle) })
    }

    /// Set the file backing this external library
    pub fn set_backing_file(&self, file: Option<&ProjectFile>) {
        let file_handle = file
            .map(|x| unsafe {x.as_raw() as *mut _})
            .unwrap_or(ptr::null_mut());
        unsafe { BNExternalLibrarySetBackingFile(self.as_raw(), file_handle) }
    }
}

impl CoreArrayProvider for ExternalLibrary {
    type Raw = *mut BNExternalLibrary;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for ExternalLibrary {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeExternalLibraryList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

/// An ExternalLocation is an association from a source symbol in a binary view
/// to a target symbol and/or address in an [ExternalLibrary].
#[repr(transparent)]
pub struct ExternalLocation {
    handle: ptr::NonNull<BNExternalLocation>,
}

impl Drop for ExternalLocation {
    fn drop(&mut self) {
        unsafe { BNFreeExternalLocation(self.as_raw()) }
    }
}

impl Clone for ExternalLocation {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(
                ptr::NonNull::new(BNNewExternalLocationReference(self.as_raw())).unwrap(),
            )
        }
    }
}

impl ExternalLocation {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNExternalLocation>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNExternalLocation) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNExternalLocation {
        &mut *self.handle.as_ptr()
    }

    /// Get the source symbol for this ExternalLocation
    pub fn source_symbol(&self) -> Symbol {
        let result = unsafe { BNExternalLocationGetSourceSymbol(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { Symbol::from_raw(result) }
    }

    /// Get the ExternalLibrary that this ExternalLocation targets
    pub fn library(&self) -> Option<ExternalLibrary> {
        let result = unsafe { BNExternalLocationGetExternalLibrary(self.as_raw()) };
        let handle = ptr::NonNull::new(result)?;
        Some(unsafe { ExternalLibrary::from_raw(handle) })
    }

    /// Set the ExternalLibrary that this ExternalLocation targets
    pub fn set_external_library(&self, lib: Option<&ExternalLibrary>) {
        let lib_handle = lib
            .map(|x| unsafe {x.as_raw() as *mut _})
            .unwrap_or(ptr::null_mut());
        unsafe { BNExternalLocationSetExternalLibrary(self.as_raw(), lib_handle) }
    }

    /// Check if this ExternalLocation has a target address
    pub fn has_target_address(&self) -> bool {
        unsafe { BNExternalLocationHasTargetAddress(self.as_raw()) }
    }

    /// Check if this ExternalLocation has a target symbol
    pub fn has_target_symbol(&self) -> bool {
        unsafe { BNExternalLocationHasTargetSymbol(self.as_raw()) }
    }

    /// Get the address pointed to by this ExternalLocation, if any
    pub fn target_address(&self) -> Option<u64> {
        self.has_target_address()
            .then(|| unsafe { BNExternalLocationGetTargetAddress(self.as_raw()) })
    }

    /// Set the address pointed to by this ExternalLocation.
    /// ExternalLocations must have a valid target address and/or symbol set.
    pub fn set_target_address(&self, mut address: Option<u64>) -> bool {
        let address_ptr = address
            .as_mut()
            .map(|x| x as *mut u64)
            .unwrap_or(ptr::null_mut());
        unsafe { BNExternalLocationSetTargetAddress(self.as_raw(), address_ptr) }
    }

    /// Get the symbol pointed to by this ExternalLocation, if any
    pub fn target_symbol(&self) -> Option<BnString> {
        self.has_target_symbol().then(|| unsafe {
            let result = BNExternalLocationGetTargetSymbol(self.as_raw());
            assert!(!result.is_null());
            BnString::from_raw(result)
        })
    }

    /// Set the symbol pointed to by this ExternalLocation.
    /// ExternalLocations must have a valid target address and/or symbol set.
    pub fn set_target_symbol<S: BnStrCompatible>(&self, symbol: Option<S>) -> bool {
        let symbol = symbol
            .map(|x| x.into_bytes_with_nul().as_ref().as_ptr() as *const ffi::c_char)
            .unwrap_or(ptr::null_mut());
        unsafe {
            BNExternalLocationSetTargetSymbol(
                self.as_raw(),
                symbol,
            )
        }
    }
}

impl CoreArrayProvider for ExternalLocation {
    type Raw = *mut BNExternalLocation;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for ExternalLocation {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeExternalLocationList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}
