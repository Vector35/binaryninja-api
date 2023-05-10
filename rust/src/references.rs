use crate::architecture::CoreArchitecture;
use crate::function::Function;
use crate::rc::{CoreArrayProvider, CoreArrayWrapper, CoreOwnedArrayProvider, Ref};
use binaryninjacore_sys::{BNFreeCodeReferences, BNFreeDataReferences, BNReferenceSource};
use std::mem::ManuallyDrop;

/// A struct representing a single code cross-reference.
/// Taking a cue from [LinearDisassemblyLine], this struct uses [ManuallyDrop] to
/// prevent destructors from being run on the [Function] object allocated by
/// the core in [BNGetCodeReferences] (et al). The reference is cleaned up on [Drop] of
/// the enclosing array object.
#[derive(Debug)]
pub struct CodeReference {
    arch: CoreArchitecture,
    func: ManuallyDrop<Ref<Function>>,
    pub address: u64,
}

/// A struct representing a single data cross-reference.
/// Data references have no associated metadata, so this object has only
/// a single [address] attribute.
pub struct DataReference {
    pub address: u64,
}

impl CodeReference {
    pub(crate) unsafe fn new(handle: &BNReferenceSource) -> Self {
        let func = ManuallyDrop::new(Function::from_raw(handle.func));
        let arch = CoreArchitecture::from_raw(handle.arch);
        let address = handle.addr;
        Self {
            func,
            arch,
            address,
        }
    }
}

impl<'a> CodeReference {
    /// A handle to the referenced function bound by the [CodeReference] object's lifetime.
    /// A user can call `.to_owned()` to promote this into its own ref-counted struct
    /// and use it after the lifetime of the [CodeReference].
    pub fn function(&'a self) -> &'a Function {
        self.func.as_ref()
    }

    /// A handle to the [CodeReference]'s [CoreArchitecture]. This type is [Copy] so reference
    /// shenanigans are not needed here.
    pub fn architecture(&self) -> CoreArchitecture {
        self.arch
    }
}

// Code Reference Array<T> boilerplate

impl CoreArrayProvider for CodeReference {
    type Raw = BNReferenceSource;
    type Context = ();
}

unsafe impl CoreOwnedArrayProvider for CodeReference {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeCodeReferences(raw, count)
    }
}

unsafe impl<'a> CoreArrayWrapper<'a> for CodeReference {
    type Wrapped = CodeReference;

    unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
        CodeReference::new(raw)
    }
}

// Data Reference Array<T> boilerplate

impl CoreArrayProvider for DataReference {
    type Raw = u64;
    type Context = ();
}

unsafe impl CoreOwnedArrayProvider for DataReference {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeDataReferences(raw)
    }
}

unsafe impl<'a> CoreArrayWrapper<'a> for DataReference {
    type Wrapped = DataReference;

    unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
        DataReference { address: *raw }
    }
}
