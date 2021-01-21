use std::mem;
use std::slice;
use binaryninjacore_sys::*;

use crate::rc::*;

#[derive(PartialEq, Eq, Hash)]
pub struct Type {
    pub(crate) handle: *mut BNType,
}

unsafe impl Send for Type {}
unsafe impl Sync for Type {}

impl Type {
    pub(crate) unsafe fn from_raw(handle: *mut BNType) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }
}

impl ToOwned for Type {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Type {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewTypeReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeType(handle.handle);
    }
}

#[repr(C)]
pub struct QualifiedName {
    object: BNQualifiedName,
}

impl QualifiedName {
    pub fn string(&self) -> String {
        use std::ffi::CStr;

        unsafe {
            slice::from_raw_parts(self.object.name, self.object.nameCount)
                .iter()
                .map(|c| CStr::from_ptr(*c).to_string_lossy())
                .collect::<Vec<_>>()
                .join("::")
        }
    }
}

impl Drop for QualifiedName {
    fn drop(&mut self) {
        unsafe { BNFreeQualifiedName(&mut self.object); }
    }
}

#[repr(C)]
pub struct QualifiedNameAndType {
    object: BNQualifiedNameAndType,
}

impl QualifiedNameAndType {
    pub fn name(&self) -> &QualifiedName {
        unsafe {
            mem::transmute(&self.object.name)
        }
    }

    pub fn type_object(&self) -> Guard<Type> {
        unsafe {
            Guard::new(Type::from_raw(self.object.type_), self)
        }
    }
}

impl Drop for QualifiedNameAndType {
    fn drop(&mut self) {
        unsafe { BNFreeQualifiedNameAndType(&mut self.object); }
    }
}

unsafe impl CoreOwnedArrayProvider for QualifiedNameAndType {
    type Raw = BNQualifiedNameAndType;
    type Context = ();

    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeList(raw, count);
    }
}

unsafe impl<'a> CoreOwnedArrayWrapper<'a> for QualifiedNameAndType {
    type Wrapped = &'a QualifiedNameAndType;

    unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
        mem::transmute(raw)
    }
}

