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
use std::fmt::{Debug, Formatter};

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

    pub fn new<S: BnStrCompatible>(t: &TagType, data: S) -> Ref<Self> {
        let data = data.into_bytes_with_nul();
        unsafe { Self::ref_from_raw(BNCreateTag(t.handle, data.as_ref().as_ptr() as *mut _)) }
    }

    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagGetId(self.handle)) }
    }

    pub fn data(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagGetData(self.handle)) }
    }

    pub fn ty(&self) -> Ref<TagType> {
        unsafe { TagType::ref_from_raw(BNTagGetType(self.handle)) }
    }

    pub fn set_data<S: BnStrCompatible>(&self, data: S) {
        let data = data.into_bytes_with_nul();
        unsafe {
            BNTagSetData(self.handle, data.as_ref().as_ptr() as *mut _);
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

impl TagType {
    pub(crate) unsafe fn ref_from_raw(handle: *mut BNTagType) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn create<N: BnStrCompatible, I: BnStrCompatible>(
        view: &BinaryView,
        name: N,
        icon: I,
    ) -> Ref<Self> {
        let tag_type = unsafe { Self::ref_from_raw(BNCreateTagType(view.handle)) };
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

    pub fn set_icon<S: BnStrCompatible>(&self, icon: S) {
        let icon = icon.into_bytes_with_nul();
        unsafe {
            BNTagTypeSetIcon(self.handle, icon.as_ref().as_ptr() as *mut _);
        }
    }

    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagTypeGetName(self.handle)) }
    }

    pub fn set_name<S: BnStrCompatible>(&self, name: S) {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNTagTypeSetName(self.handle, name.as_ref().as_ptr() as *mut _);
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

    pub fn set_type<S: BnStrCompatible>(&self, t: S) {
        let t = t.into_bytes_with_nul();
        unsafe {
            BNTagTypeSetName(self.handle, t.as_ref().as_ptr() as *mut _);
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
    pub arch: CoreArchitecture,
    pub func: Ref<Function>,
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
            tag: unsafe { Tag::ref_from_raw(value.tag).to_owned() },
            arch: unsafe { CoreArchitecture::from_raw(value.arch) },
            func: unsafe { Function::from_raw(value.func).to_owned() },
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
