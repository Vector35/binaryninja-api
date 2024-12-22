use crate::project::file::ProjectFile;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};
use crate::symbol::Symbol;
use binaryninjacore_sys::*;
use std::ffi::c_char;
use std::fmt::Debug;
use std::ptr::NonNull;

/// An ExternalLibrary is an abstraction for a library that is optionally backed
/// by a [ProjectFile].
#[repr(transparent)]
pub struct ExternalLibrary {
    pub(crate) handle: NonNull<BNExternalLibrary>,
}

impl ExternalLibrary {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNExternalLibrary>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNExternalLibrary>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Get the name of this external library
    pub fn name(&self) -> BnString {
        let result = unsafe { BNExternalLibraryGetName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Get the file backing this external library
    pub fn backing_file(&self) -> Option<Ref<ProjectFile>> {
        let result = unsafe { BNExternalLibraryGetBackingFile(self.handle.as_ptr()) };
        let handle = NonNull::new(result)?;
        Some(unsafe { ProjectFile::ref_from_raw(handle) })
    }

    /// Set the file backing this external library
    pub fn set_backing_file(&self, file: Option<&ProjectFile>) {
        let file_handle = file
            .map(|x| x.handle.as_ptr())
            .unwrap_or(std::ptr::null_mut());
        unsafe { BNExternalLibrarySetBackingFile(self.handle.as_ptr(), file_handle) }
    }
}

impl ToOwned for ExternalLibrary {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for ExternalLibrary {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewExternalLibraryReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeExternalLibrary(handle.handle.as_ptr());
    }
}

impl Debug for ExternalLibrary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalLibrary")
            .field("name", &self.name())
            .field("backing_file", &self.backing_file())
            .finish()
    }
}

impl CoreArrayProvider for ExternalLibrary {
    type Raw = *mut BNExternalLibrary;
    type Context = ();
    type Wrapped<'a> = Guard<'a, ExternalLibrary>;
}

unsafe impl CoreArrayProviderInner for ExternalLibrary {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeExternalLibraryList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}

/// An [`ExternalLocation`] is an association from a source symbol in a binary view
/// to a target symbol and/or address in an [`ExternalLibrary`].
#[repr(transparent)]
pub struct ExternalLocation {
    handle: NonNull<BNExternalLocation>,
}

impl ExternalLocation {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNExternalLocation>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNExternalLocation>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Get the source symbol for this ExternalLocation
    pub fn source_symbol(&self) -> Ref<Symbol> {
        let result = unsafe { BNExternalLocationGetSourceSymbol(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { Symbol::ref_from_raw(result) }
    }

    /// Get the ExternalLibrary that this ExternalLocation targets
    pub fn library(&self) -> Option<Ref<ExternalLibrary>> {
        let result = unsafe { BNExternalLocationGetExternalLibrary(self.handle.as_ptr()) };
        let handle = NonNull::new(result)?;
        Some(unsafe { ExternalLibrary::ref_from_raw(handle) })
    }

    /// Set the ExternalLibrary that this ExternalLocation targets
    pub fn set_external_library(&self, lib: Option<&ExternalLibrary>) {
        let lib_handle = lib
            .map(|x| x.handle.as_ptr())
            .unwrap_or(std::ptr::null_mut());
        unsafe { BNExternalLocationSetExternalLibrary(self.handle.as_ptr(), lib_handle) }
    }

    /// Check if this ExternalLocation has a target address
    pub fn has_target_address(&self) -> bool {
        unsafe { BNExternalLocationHasTargetAddress(self.handle.as_ptr()) }
    }

    /// Check if this ExternalLocation has a target symbol
    pub fn has_target_symbol(&self) -> bool {
        unsafe { BNExternalLocationHasTargetSymbol(self.handle.as_ptr()) }
    }

    /// Get the address pointed to by this ExternalLocation, if any
    pub fn target_address(&self) -> Option<u64> {
        self.has_target_address()
            .then(|| unsafe { BNExternalLocationGetTargetAddress(self.handle.as_ptr()) })
    }

    /// Set the address pointed to by this ExternalLocation.
    /// ExternalLocations must have a valid target address and/or symbol set.
    pub fn set_target_address(&self, address: Option<u64>) -> bool {
        match address {
            Some(mut addr) => unsafe {
                BNExternalLocationSetTargetAddress(self.handle.as_ptr(), &mut addr)
            },
            None => unsafe {
                BNExternalLocationSetTargetAddress(self.handle.as_ptr(), std::ptr::null_mut())
            },
        }
    }

    /// Get the symbol pointed to by this ExternalLocation, if any
    pub fn target_symbol(&self) -> Option<BnString> {
        let result = unsafe { BNExternalLocationGetTargetSymbol(self.handle.as_ptr()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Set the symbol pointed to by this ExternalLocation.
    /// ExternalLocations must have a valid target address and/or symbol set.
    pub fn set_target_symbol<S: BnStrCompatible>(&self, symbol: Option<S>) -> bool {
        let symbol = symbol
            .map(|x| x.into_bytes_with_nul().as_ref().as_ptr() as *const c_char)
            .unwrap_or(std::ptr::null_mut());
        unsafe { BNExternalLocationSetTargetSymbol(self.handle.as_ptr(), symbol) }
    }
}

impl Debug for ExternalLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalLocation")
            .field("source_symbol", &self.source_symbol())
            .field("library", &self.library())
            .field("target_address", &self.target_address())
            .field("target_symbol", &self.target_symbol())
            .finish()
    }
}

impl ToOwned for ExternalLocation {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for ExternalLocation {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewExternalLocationReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeExternalLocation(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for ExternalLocation {
    type Raw = *mut BNExternalLocation;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for ExternalLocation {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeExternalLocationList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}
