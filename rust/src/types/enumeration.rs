use crate::rc::{Ref, RefCountable};
use crate::string::{raw_to_string, BnString, IntoCStr};
use binaryninjacore_sys::*;
use std::fmt::{Debug, Formatter};

#[derive(PartialEq, Eq, Hash)]
pub struct EnumerationBuilder {
    pub(crate) handle: *mut BNEnumerationBuilder,
}

impl EnumerationBuilder {
    pub fn new() -> Self {
        Self {
            handle: unsafe { BNCreateEnumerationBuilder() },
        }
    }

    pub(crate) unsafe fn from_raw(handle: *mut BNEnumerationBuilder) -> Self {
        Self { handle }
    }

    pub fn finalize(&self) -> Ref<Enumeration> {
        unsafe { Enumeration::ref_from_raw(BNFinalizeEnumerationBuilder(self.handle)) }
    }

    pub fn append(&mut self, name: &str) -> &mut Self {
        let name = name.to_cstr();
        unsafe {
            BNAddEnumerationBuilderMember(self.handle, name.as_ref().as_ptr() as _);
        }
        self
    }

    pub fn insert(&mut self, name: &str, value: u64) -> &mut Self {
        let name = name.to_cstr();
        unsafe {
            BNAddEnumerationBuilderMemberWithValue(self.handle, name.as_ref().as_ptr() as _, value);
        }
        self
    }

    pub fn replace(&mut self, id: usize, name: &str, value: u64) -> &mut Self {
        let name = name.to_cstr();
        unsafe {
            BNReplaceEnumerationBuilderMember(self.handle, id, name.as_ref().as_ptr() as _, value);
        }
        self
    }

    pub fn remove(&mut self, id: usize) -> &mut Self {
        unsafe {
            BNRemoveEnumerationBuilderMember(self.handle, id);
        }

        self
    }

    pub fn members(&self) -> Vec<EnumerationMember> {
        unsafe {
            let mut count = 0;
            let members_raw_ptr = BNGetEnumerationBuilderMembers(self.handle, &mut count);
            let members_raw: &[BNEnumerationMember] =
                std::slice::from_raw_parts(members_raw_ptr, count);
            let members = members_raw
                .iter()
                .map(EnumerationMember::from_raw)
                .collect();
            BNFreeEnumerationMemberList(members_raw_ptr, count);
            members
        }
    }
}

impl Default for EnumerationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&Enumeration> for EnumerationBuilder {
    fn from(enumeration: &Enumeration) -> Self {
        unsafe {
            Self::from_raw(BNCreateEnumerationBuilderFromEnumeration(
                enumeration.handle,
            ))
        }
    }
}

impl Drop for EnumerationBuilder {
    fn drop(&mut self) {
        unsafe { BNFreeEnumerationBuilder(self.handle) };
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct Enumeration {
    pub(crate) handle: *mut BNEnumeration,
}

impl Enumeration {
    pub(crate) unsafe fn ref_from_raw(handle: *mut BNEnumeration) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn builder() -> EnumerationBuilder {
        EnumerationBuilder::new()
    }

    pub fn members(&self) -> Vec<EnumerationMember> {
        unsafe {
            let mut count = 0;
            let members_raw_ptr = BNGetEnumerationMembers(self.handle, &mut count);
            debug_assert!(!members_raw_ptr.is_null());
            let members_raw: &[BNEnumerationMember] =
                std::slice::from_raw_parts(members_raw_ptr, count);
            let members = members_raw
                .iter()
                .map(EnumerationMember::from_raw)
                .collect();
            BNFreeEnumerationMemberList(members_raw_ptr, count);
            members
        }
    }
}

impl Debug for Enumeration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enumeration")
            .field("members", &self.members())
            .finish()
    }
}

unsafe impl RefCountable for Enumeration {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(BNNewEnumerationReference(handle.handle))
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeEnumeration(handle.handle);
    }
}

impl ToOwned for Enumeration {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EnumerationMember {
    pub name: String,
    /// The associated constant value for the member.
    pub value: u64,
    /// Whether this is the default member for the associated [`Enumeration`].
    pub default: bool,
}

impl EnumerationMember {
    pub(crate) fn from_raw(value: &BNEnumerationMember) -> Self {
        Self {
            name: raw_to_string(value.name).unwrap(),
            value: value.value,
            default: value.isDefault,
        }
    }

    #[allow(unused)]
    pub(crate) fn from_owned_raw(value: BNEnumerationMember) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    #[allow(unused)]
    pub(crate) fn into_raw(value: Self) -> BNEnumerationMember {
        let bn_name = BnString::new(value.name);
        BNEnumerationMember {
            name: BnString::into_raw(bn_name),
            value: value.value,
            isDefault: value.default,
        }
    }

    #[allow(unused)]
    pub(crate) fn free_raw(value: BNEnumerationMember) {
        unsafe { BnString::free_raw(value.name) };
    }

    pub fn new(name: String, value: u64, default: bool) -> Self {
        Self {
            name,
            value,
            default,
        }
    }
}
