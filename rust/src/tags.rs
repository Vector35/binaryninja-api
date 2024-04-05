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

use crate::binaryview::BinaryView;

use crate::string::*;

pub struct Tag {
    pub(crate) handle: *mut BNTag,
}

impl Tag {
    pub(crate) unsafe fn from_raw(handle: *mut BNTag) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    pub fn new<S: BnStrCompatible>(t: &TagType, data: S) -> Self {
        let data = data.into_bytes_with_nul();
        unsafe { Self::from_raw(BNCreateTag(t.handle, data.as_ref().as_ptr() as *mut _)) }
    }

    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagGetId(self.handle)) }
    }

    pub fn data(&self) -> BnString {
        unsafe { BnString::from_raw(BNTagGetData(self.handle)) }
    }

    pub fn t(&self) -> TagType {
        unsafe { TagType::from_raw(BNTagGetType(self.handle)) }
    }

    pub fn set_data<S: BnStrCompatible>(&self, data: S) {
        let data = data.into_bytes_with_nul();
        unsafe {
            BNTagSetData(self.handle, data.as_ref().as_ptr() as *mut _);
        }
    }
}

impl Clone for Tag {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(BNNewTagReference(self.handle)) }
    }
}

impl Drop for Tag {
    fn drop(&mut self) {
        unsafe { BNFreeTag(self.handle) }
    }
}

unsafe impl Send for Tag {}
unsafe impl Sync for Tag {}

pub type TagTypeType = BNTagTypeType;

pub struct TagType {
    pub(crate) handle: *mut BNTagType,
}

impl TagType {
    pub(crate) unsafe fn from_raw(handle: *mut BNTagType) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    pub fn create<N: BnStrCompatible, I: BnStrCompatible>(
        view: &BinaryView,
        name: N,
        icon: I,
    ) -> Self {
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

    pub fn set_icon<S: BnStrCompatible>(&self, icon: S) {
        let icon = icon.into_bytes_with_nul();
        unsafe {
            BNTagTypeSetName(self.handle, icon.as_ref().as_ptr() as *mut _);
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

    pub fn t(&self) -> TagTypeType {
        unsafe { BNTagTypeGetType(self.handle) }
    }

    pub fn set_type<S: BnStrCompatible>(&self, t: S) {
        let t = t.into_bytes_with_nul();
        unsafe {
            BNTagTypeSetName(self.handle, t.as_ref().as_ptr() as *mut _);
        }
    }

    pub fn view(&self) -> BinaryView {
        unsafe { BinaryView::from_raw(BNTagTypeGetView(self.handle)) }
    }
}

impl Clone for TagType {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(BNNewTagTypeReference(self.handle)) }
    }
}

impl Drop for TagType {
    fn drop(&mut self) {
        unsafe { BNFreeTagType(self.handle) }
    }
}

unsafe impl Send for TagType {}
unsafe impl Sync for TagType {}
