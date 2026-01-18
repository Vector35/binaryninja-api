// Copyright 2022-2026 Vector 35 Inc.
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
use std::fmt::{Debug, Formatter};
use std::ptr::NonNull;

use crate::architecture::CoreArchitecture;
use crate::binary_view::BinaryView;

use crate::function::Function;
use crate::rc::*;
use crate::string::*;

pub type TagTypeType = BNTagTypeType;
pub type TagReferenceType = BNTagReferenceType;

pub struct Tag {
    pub(crate) handle: *mut BNTag,
}

impl Tag {
    pub(crate) unsafe fn from_raw(handle: *mut BNTag) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNTag) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn new(t: &TagType, data: &str) -> Ref<Self> {
        let data = data.to_cstr();
        unsafe { Self::ref_from_raw(BNCreateTag(t.handle, data.as_ptr())) }
    }

    pub fn id(&self) -> String {
        unsafe { BnString::into_string(BNTagGetId(self.handle)) }
    }

    pub fn data(&self) -> String {
        unsafe { BnString::into_string(BNTagGetData(self.handle)) }
    }

    pub fn ty(&self) -> Ref<TagType> {
        unsafe { TagType::ref_from_raw(BNTagGetType(self.handle)) }
    }

    pub fn set_data(&self, data: &str) {
        let data = data.to_cstr();
        unsafe {
            BNTagSetData(self.handle, data.as_ptr());
        }
    }
}

impl Debug for Tag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tag")
            .field("id", &self.id())
            .field("data", &self.data())
            .field("type", &self.ty())
            .finish()
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for Tag {}

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
    type Wrapped<'a> = Guard<'a, Tag>;
}

unsafe impl CoreArrayProviderInner for Tag {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTagList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self { handle: *raw }, &context)
    }
}

unsafe impl Send for Tag {}
unsafe impl Sync for Tag {}

pub struct TagType {
    pub(crate) handle: *mut BNTagType,
}

impl CoreArrayProvider for TagType {
    type Raw = *mut BNTagType;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for TagType {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTagTypeList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(*raw), context)
    }
}

impl TagType {
    pub(crate) unsafe fn from_raw(handle: *mut BNTagType) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNTagType) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn create(view: &BinaryView, name: &str, icon: &str) -> Ref<Self> {
        let tag_type = unsafe { Self::ref_from_raw(BNCreateTagType(view.handle)) };
        tag_type.set_name(name);
        tag_type.set_icon(icon);
        tag_type.set_type(TagTypeType::UserTagType);
        tag_type
    }

    pub fn id(&self) -> String {
        unsafe { BnString::into_string(BNTagTypeGetId(self.handle)) }
    }

    pub fn icon(&self) -> String {
        unsafe { BnString::into_string(BNTagTypeGetIcon(self.handle)) }
    }

    pub fn set_icon(&self, icon: &str) {
        let icon = icon.to_cstr();
        unsafe {
            BNTagTypeSetIcon(self.handle, icon.as_ptr());
        }
    }

    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNTagTypeGetName(self.handle)) }
    }

    pub fn set_name(&self, name: &str) {
        let name = name.to_cstr();
        unsafe {
            BNTagTypeSetName(self.handle, name.as_ptr());
        }
    }

    pub fn visible(&self) -> bool {
        unsafe { BNTagTypeGetVisible(self.handle) }
    }

    pub fn set_visible(&self, visible: bool) {
        unsafe { BNTagTypeSetVisible(self.handle, visible) }
    }

    pub fn ty(&self) -> TagTypeType {
        unsafe { BNTagTypeGetType(self.handle) }
    }

    pub fn set_type(&self, ty: TagTypeType) {
        unsafe {
            BNTagTypeSetType(self.handle, ty);
        }
    }

    pub fn view(&self) -> Ref<BinaryView> {
        unsafe { BinaryView::ref_from_raw(BNTagTypeGetView(self.handle)) }
    }
}

impl Debug for TagType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TagType")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("icon", &self.icon())
            .field("visible", &self.visible())
            .field("type", &self.ty())
            .finish()
    }
}

impl PartialEq for TagType {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for TagType {}

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

#[derive(Clone, PartialEq)]
pub struct TagReference {
    pub arch: Option<CoreArchitecture>,
    pub func: Option<Ref<Function>>,
    pub addr: u64,
    pub auto_defined: bool,
    pub reference_type: TagReferenceType,
    pub tag: Ref<Tag>,
}

impl From<&BNTagReference> for TagReference {
    fn from(value: &BNTagReference) -> Self {
        Self {
            reference_type: value.refType,
            auto_defined: value.autoDefined,
            tag: unsafe { Tag::from_raw(value.tag).to_owned() },
            arch: NonNull::new(value.arch)
                .map(|arch| unsafe { CoreArchitecture::from_raw(arch.as_ptr()) }),
            func: NonNull::new(value.func)
                .map(|func| unsafe { Function::from_raw(func.as_ptr()).to_owned() }),
            addr: value.addr,
        }
    }
}

impl Debug for TagReference {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TagReference")
            .field("addr", &self.addr)
            .field("auto_defined", &self.auto_defined)
            .field("reference_type", &self.reference_type)
            .field("tag", &self.tag)
            .finish()
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
        raw.into()
    }
}
