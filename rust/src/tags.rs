// Copyright 2022-2024 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Interfaces for creating and modifying tags in a BinaryView.

use binaryninjacore_sys::*;

use crate::architecture::CoreArchitecture;
use crate::binaryview::BinaryView;

use crate::function::Function;
use crate::rc::*;
use crate::string::*;

#[repr(transparent)]
pub struct Tag {
    pub(crate) handle: *mut BNTag,
}

impl Tag {
    pub(crate) unsafe fn from_raw(handle: *mut BNTag) -> Ref<Self> {
        debug_assert!(!handle.is_null());

        Ref::new(Self { handle })
    }

    pub fn new(t: &TagType, data: impl AsCStr) -> Ref<Self> {
        unsafe { Self::from_raw(BNCreateTag(t.handle, data.as_cstr().as_ptr())) }
    }

    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagGetId(self.handle)) }
    }

    pub fn data(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagGetData(self.handle)) }
    }

    pub fn t(&self) -> Ref<TagType> {
        unsafe { TagType::from_raw(BNTagGetType(self.handle)) }
    }

    pub fn set_data(&self, data: impl AsCStr) {
        unsafe { BNTagSetData(self.handle, data.as_cstr().as_ptr()) }
    }
}

unsafe impl RefCountable for Tag {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewTagReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeTag(handle.handle);
    }
}

impl ToOwned for Tag {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

impl CoreArrayProvider for Tag {
    type Raw = *mut BNTag;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for Tag {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTagList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        debug_assert!(!raw.is_null());
        // SAFETY: `Tag` is repr(transparent)
        unsafe { &*(raw as *const _ as *const Self) }
    }
}

unsafe impl Send for Tag {}
unsafe impl Sync for Tag {}

pub type TagTypeType = BNTagTypeType;

pub struct TagType {
    pub(crate) handle: *mut BNTagType,
}

impl TagType {
    pub(crate) unsafe fn from_raw(handle: *mut BNTagType) -> Ref<Self> {
        debug_assert!(!handle.is_null());

        Ref::new(Self { handle })
    }

    pub fn create(view: &BinaryView, name: impl AsCStr, icon: impl AsCStr) -> Ref<Self> {
        let tag_type = unsafe { Self::from_raw(BNCreateTagType(view.handle)) };
        tag_type.set_name(name);
        tag_type.set_icon(icon);
        tag_type
    }

    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagTypeGetId(self.handle)) }
    }

    pub fn icon(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagTypeGetIcon(self.handle)) }
    }

    pub fn set_icon(&self, icon: impl AsCStr) {
        unsafe { BNTagTypeSetIcon(self.handle, icon.as_cstr().as_ptr()) }
    }

    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagTypeGetName(self.handle)) }
    }

    pub fn set_name(&self, name: impl AsCStr) {
        unsafe { BNTagTypeSetName(self.handle, name.as_cstr().as_ptr()) }
    }

    pub fn visible(&self) -> bool {
        unsafe { BNTagTypeGetVisible(self.handle) }
    }

    pub fn set_visible(&self, visible: bool) {
        unsafe { BNTagTypeSetVisible(self.handle, visible) }
    }

    pub fn t(&self) -> TagTypeType {
        unsafe { BNTagTypeGetType(self.handle) }
    }

    pub fn set_type(&self, t: impl AsCStr) {
        unsafe { BNTagTypeSetName(self.handle, t.as_cstr().as_ptr()) }
    }

    pub fn view(&self) -> Ref<BinaryView> {
        unsafe { BinaryView::from_raw(BNTagTypeGetView(self.handle)) }
    }
}

unsafe impl RefCountable for TagType {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewTagTypeReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeTagType(handle.handle);
    }
}

impl ToOwned for TagType {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl Send for TagType {}
unsafe impl Sync for TagType {}

pub type TagReferenceType = BNTagReferenceType;

pub struct TagReference {
    ref_type: TagReferenceType,
    auto_defined: bool,
    tag: Ref<Tag>,
    arch: CoreArchitecture,
    func: Ref<Function>,
    addr: u64,
}

impl TagReference {
    unsafe fn from_borrowed_raw(value: &BNTagReference) -> Self {
        Self {
            ref_type: value.refType,
            auto_defined: value.autoDefined,
            tag: Tag { handle: value.tag }.to_owned(),
            arch: CoreArchitecture::from_raw(value.arch),
            func: Function { handle: value.func }.to_owned(),
            addr: value.addr,
        }
    }
    pub fn ref_type(&self) -> TagReferenceType {
        self.ref_type
    }
    pub fn auto(&self) -> bool {
        self.auto_defined
    }
    pub fn tag(&self) -> &Tag {
        &self.tag
    }
    pub fn arch(&self) -> CoreArchitecture {
        self.arch
    }
    pub fn functions(&self) -> &Function {
        &self.func
    }
    pub fn address(&self) -> u64 {
        self.addr
    }
}

impl CoreArrayProvider for TagReference {
    type Raw = BNTagReference;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for TagReference {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTagReferences(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_borrowed_raw(raw)
    }
}
