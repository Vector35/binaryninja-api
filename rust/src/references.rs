#![allow(dead_code)]
use crate::architecture::CoreArchitecture;
use crate::function::Function;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Ref};
use binaryninjacore_sys::{BNFreeCodeReferences, BNFreeDataReferences, BNReferenceSource};

/// A struct representing a single code cross-reference.
#[derive(Debug)]
pub struct CodeReference {
    pub arch: Option<CoreArchitecture>,
    pub func: Option<Ref<Function>>,
    pub address: u64,
}

impl CodeReference {
    pub(crate) fn from_raw(value: &BNReferenceSource) -> Self {
        Self {
            func: match value.func.is_null() {
                false => Some(unsafe { Function::from_raw(value.func) }.to_owned()),
                true => None,
            },
            arch: match value.func.is_null() {
                false => Some(unsafe { CoreArchitecture::from_raw(value.arch) }),
                true => None,
            },
            address: value.addr,
        }
    }

    pub(crate) fn from_owned_raw(value: BNReferenceSource) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNReferenceSource {
        BNReferenceSource {
            func: match value.func {
                Some(func) => unsafe { Ref::into_raw(func) }.handle,
                None => std::ptr::null_mut(),
            },
            arch: value.arch.map(|a| a.handle).unwrap_or(std::ptr::null_mut()),
            addr: value.address,
        }
    }

    pub(crate) fn into_owned_raw(value: &Self) -> BNReferenceSource {
        BNReferenceSource {
            func: match &value.func {
                Some(func) => func.handle,
                None => std::ptr::null_mut(),
            },
            arch: value.arch.map(|a| a.handle).unwrap_or(std::ptr::null_mut()),
            addr: value.address,
        }
    }

    pub(crate) fn free_raw(value: BNReferenceSource) {
        let _ = unsafe { Function::ref_from_raw(value.func) };
    }

    pub fn new(address: u64, func: Option<Ref<Function>>, arch: Option<CoreArchitecture>) -> Self {
        Self {
            func,
            arch,
            address,
        }
    }
}

// Code Reference Array<T> boilerplate

impl CoreArrayProvider for CodeReference {
    type Raw = BNReferenceSource;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CodeReference {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCodeReferences(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        CodeReference::from_raw(raw)
    }
}

// TODO: This only exists so that Array can free.
// TODO: Is there any way we can have this instead be Array<Location> of some sort?
/// A struct representing a single data cross-reference.
/// Data references have no associated metadata, so this object has only
/// a single [`DataReference::address`] attribute.
pub struct DataReference {
    pub address: u64,
}

impl CoreArrayProvider for DataReference {
    type Raw = u64;
    type Context = ();
    type Wrapped<'a> = DataReference;
}

unsafe impl CoreArrayProviderInner for DataReference {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeDataReferences(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        DataReference { address: *raw }
    }
}
