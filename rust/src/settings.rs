// Copyright 2021-2024 Vector 35 Inc.
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

//! An interface for reading, writing, and creating new settings

pub use binaryninjacore_sys::BNSettingsScope as SettingsScope;
use binaryninjacore_sys::*;

use crate::binaryview::BinaryView;
use crate::rc::*;
use crate::string::{AsCStr, BnString};

use std::ptr;

#[derive(PartialEq, Eq, Hash)]
pub struct Settings {
    pub(crate) handle: *mut BNSettings,
}

unsafe impl Send for Settings {}
unsafe impl Sync for Settings {}

impl Settings {
    pub(crate) unsafe fn from_raw(handle: *mut BNSettings) -> Ref<Self> {
        debug_assert!(!handle.is_null());

        Ref::new(Self { handle })
    }

    pub fn new(instance_id: impl AsCStr) -> Ref<Self> {
        unsafe {
            let handle = BNCreateSettings(instance_id.as_cstr().as_ptr());

            debug_assert!(!handle.is_null());

            Ref::new(Self { handle })
        }
    }

    pub fn set_resource_id(&self, resource_id: impl AsCStr) {
        unsafe { BNSettingsSetResourceId(self.handle, resource_id.as_cstr().as_ptr()) };
    }

    pub fn serialize_schema(&self) -> BnString {
        unsafe { BnString::from_raw(BNSettingsSerializeSchema(self.handle)) }
    }

    pub fn deserialize_schema(&self, schema: impl AsCStr) -> bool {
        unsafe {
            BNSettingsDeserializeSchema(
                self.handle,
                schema.as_cstr().as_ptr(),
                BNSettingsScope::SettingsAutoScope,
                true,
            )
        }
    }

    pub fn contains(&self, key: impl AsCStr) -> bool {
        unsafe { BNSettingsContains(self.handle, key.as_cstr().as_ptr()) }
    }

    // TODO Update the settings API to take an optional BinaryView or Function. Separate functions or...?

    pub fn get_bool(
        &self,
        key: impl AsCStr,
        view: Option<&BinaryView>,
        scope: Option<Box<SettingsScope>>,
    ) -> bool {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope_ptr = scope.map_or(ptr::null_mut(), |mut scope| scope.as_mut());
        unsafe {
            BNSettingsGetBool(
                self.handle,
                key.as_cstr().as_ptr(),
                view_handle,
                ptr::null_mut(),
                scope_ptr,
            )
        }
    }

    pub fn get_double(
        &self,
        key: impl AsCStr,
        view: Option<&BinaryView>,
        scope: Option<Box<SettingsScope>>,
    ) -> f64 {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope_ptr = scope.map_or(ptr::null_mut(), |mut scope| scope.as_mut());
        unsafe {
            BNSettingsGetDouble(
                self.handle,
                key.as_cstr().as_ptr(),
                view_handle,
                ptr::null_mut(),
                scope_ptr,
            )
        }
    }

    pub fn get_integer(
        &self,
        key: impl AsCStr,
        view: Option<&BinaryView>,
        scope: Option<Box<SettingsScope>>,
    ) -> u64 {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope_ptr = scope.map_or(ptr::null_mut(), |mut scope| scope.as_mut());
        unsafe {
            BNSettingsGetUInt64(
                self.handle,
                key.as_cstr().as_ptr(),
                view_handle,
                ptr::null_mut(),
                scope_ptr,
            )
        }
    }

    pub fn get_string(
        &self,
        key: impl AsCStr,
        view: Option<&BinaryView>,
        scope: Option<Box<SettingsScope>>,
    ) -> BnString {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope_ptr = scope.map_or(ptr::null_mut(), |mut scope| scope.as_mut());
        unsafe {
            BnString::from_raw(BNSettingsGetString(
                self.handle,
                key.as_cstr().as_ptr(),
                view_handle,
                ptr::null_mut(),
                scope_ptr,
            ))
        }
    }

    pub fn get_string_list(
        &self,
        key: impl AsCStr,
        view: Option<&BinaryView>,
        scope: Option<Box<SettingsScope>>,
    ) -> Array<BnString> {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope_ptr = scope.map_or(ptr::null_mut(), |mut scope| scope.as_mut());
        let mut size: usize = 0;
        unsafe {
            let string_list = BNSettingsGetStringList(
                self.handle,
                key.as_cstr().as_ptr(),
                view_handle,
                ptr::null_mut(),
                scope_ptr,
                &mut size,
            ) as *mut *mut _;
            Array::new(string_list, size, ())
        }
    }

    pub fn get_json(
        &self,
        key: impl AsCStr,
        view: Option<&BinaryView>,
        scope: Option<Box<SettingsScope>>,
    ) -> BnString {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope_ptr = scope.map_or(ptr::null_mut(), |mut scope| scope.as_mut());
        unsafe {
            BnString::from_raw(BNSettingsGetJson(
                self.handle,
                key.as_cstr().as_ptr(),
                view_handle,
                ptr::null_mut(),
                scope_ptr,
            ))
        }
    }

    pub fn set_bool(
        &self,
        key: impl AsCStr,
        value: bool,
        view: Option<&BinaryView>,
        scope: Option<SettingsScope>,
    ) {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope = scope.unwrap_or(SettingsScope::SettingsAutoScope);
        unsafe {
            BNSettingsSetBool(
                self.handle,
                view_handle,
                ptr::null_mut(),
                scope,
                key.as_cstr().as_ptr(),
                value,
            );
        }
    }

    pub fn set_double(
        &self,
        key: impl AsCStr,
        value: f64,
        view: Option<&BinaryView>,
        scope: Option<SettingsScope>,
    ) {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope = scope.unwrap_or(SettingsScope::SettingsAutoScope);
        unsafe {
            BNSettingsSetDouble(
                self.handle,
                view_handle,
                ptr::null_mut(),
                scope,
                key.as_cstr().as_ptr(),
                value,
            );
        }
    }

    pub fn set_integer(
        &self,
        key: impl AsCStr,
        value: u64,
        view: Option<&BinaryView>,
        scope: Option<SettingsScope>,
    ) {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope = scope.unwrap_or(SettingsScope::SettingsAutoScope);
        unsafe {
            BNSettingsSetUInt64(
                self.handle,
                view_handle,
                ptr::null_mut(),
                scope,
                key.as_cstr().as_ptr(),
                value,
            );
        }
    }

    pub fn set_string(
        &self,
        key: impl AsCStr,
        value: impl AsCStr,
        view: Option<&BinaryView>,
        scope: Option<SettingsScope>,
    ) {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope = scope.unwrap_or(SettingsScope::SettingsAutoScope);
        unsafe {
            BNSettingsSetString(
                self.handle,
                view_handle,
                ptr::null_mut(),
                scope,
                key.as_cstr().as_ptr(),
                value.as_cstr().as_ptr(),
            );
        }
    }

    pub fn set_string_list(
        &self,
        key: impl AsCStr,
        value: impl IntoIterator<Item = impl AsCStr>,
        view: Option<&BinaryView>,
        scope: Option<SettingsScope>,
    ) -> bool {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope = scope.unwrap_or(SettingsScope::SettingsAutoScope);
        let value = value.into_iter().map(BnString::new).collect::<Vec<_>>();
        let mut value = value
            .into_iter()
            .map(|item| item.as_raw() as *const _)
            .collect::<Vec<_>>();

        unsafe {
            BNSettingsSetStringList(
                self.handle,
                view_handle,
                ptr::null_mut(),
                scope,
                key.as_cstr().as_ptr(),
                value.as_mut_ptr(),
                value.len(),
            )
        }
    }

    pub fn set_json(
        &self,
        key: impl AsCStr,
        value: impl AsCStr,
        view: Option<&BinaryView>,
        scope: Option<SettingsScope>,
    ) -> bool {
        let view_handle = view.map_or(ptr::null_mut(), |view| view.handle);
        let scope = scope.unwrap_or(SettingsScope::SettingsAutoScope);

        unsafe {
            BNSettingsSetJson(
                self.handle,
                view_handle,
                ptr::null_mut(),
                scope,
                key.as_cstr().as_ptr(),
                value.as_cstr().as_ptr(),
            )
        }
    }

    pub fn update_bool_property(&self, key: impl AsCStr, property: impl AsCStr, value: bool) {
        unsafe {
            BNSettingsUpdateBoolProperty(
                self.handle,
                key.as_cstr().as_ptr(),
                property.as_cstr().as_ptr(),
                value,
            );
        }
    }

    pub fn update_integer_property(&self, key: impl AsCStr, property: impl AsCStr, value: u64) {
        unsafe {
            BNSettingsUpdateUInt64Property(
                self.handle,
                key.as_cstr().as_ptr(),
                property.as_cstr().as_ptr(),
                value,
            );
        }
    }

    pub fn update_double_property(&self, key: impl AsCStr, property: impl AsCStr, value: f64) {
        unsafe {
            BNSettingsUpdateDoubleProperty(
                self.handle,
                key.as_cstr().as_ptr(),
                property.as_cstr().as_ptr(),
                value,
            );
        }
    }

    pub fn update_string_property(
        &self,
        key: impl AsCStr,
        property: impl AsCStr,
        value: impl AsCStr,
    ) {
        unsafe {
            BNSettingsUpdateStringProperty(
                self.handle,
                key.as_cstr().as_ptr(),
                property.as_cstr().as_ptr(),
                value.as_cstr().as_ptr(),
            );
        }
    }

    pub fn update_string_list_property(
        &self,
        key: impl AsCStr,
        property: impl AsCStr,
        value: impl IntoIterator<Item = impl AsCStr>,
    ) {
        let value = value.into_iter().map(BnString::new).collect::<Vec<_>>();
        let mut value = value
            .iter()
            .map(|s| s.as_raw() as *const _)
            .collect::<Vec<_>>();

        unsafe {
            BNSettingsUpdateStringListProperty(
                self.handle,
                key.as_cstr().as_ptr(),
                property.as_cstr().as_ptr(),
                value.as_mut_ptr(),
                value.len(),
            );
        }
    }

    pub fn register_group(&self, group: impl AsCStr, title: impl AsCStr) -> bool {
        unsafe {
            BNSettingsRegisterGroup(
                self.handle,
                group.as_cstr().as_ptr(),
                title.as_cstr().as_ptr(),
            )
        }
    }

    pub fn register_setting_json(&self, group: impl AsCStr, properties: impl AsCStr) -> bool {
        unsafe {
            BNSettingsRegisterSetting(
                self.handle,
                group.as_cstr().as_ptr(),
                properties.as_cstr().as_ptr(),
            )
        }
    }

    // TODO: register_setting but type-safely turn it into json
}

impl ToOwned for Settings {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Settings {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSettingsReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSettings(handle.handle);
    }
}
