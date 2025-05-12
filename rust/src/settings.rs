// Copyright 2021-2025 Vector 35 Inc.
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

use binaryninjacore_sys::*;
use std::ffi::c_char;
use std::fmt::Debug;

use crate::binary_view::BinaryView;
use crate::rc::*;
use crate::string::{BnString, IntoCStr};

use crate::function::Function;

pub type SettingsScope = BNSettingsScope;

pub const DEFAULT_INSTANCE_ID: &str = "default";
pub const GLOBAL_INSTANCE_ID: &str = "";

#[derive(PartialEq, Eq, Hash)]
pub struct Settings {
    pub(crate) handle: *mut BNSettings,
}

impl Settings {
    pub(crate) unsafe fn ref_from_raw(handle: *mut BNSettings) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn new() -> Ref<Self> {
        Self::new_with_id(GLOBAL_INSTANCE_ID)
    }

    pub fn new_with_id(instance_id: &str) -> Ref<Self> {
        let instance_id = instance_id.to_cstr();
        unsafe { Self::ref_from_raw(BNCreateSettings(instance_id.as_ptr())) }
    }

    pub fn set_resource_id(&self, resource_id: &str) {
        let resource_id = resource_id.to_cstr();
        unsafe { BNSettingsSetResourceId(self.handle, resource_id.as_ptr()) };
    }

    pub fn serialize_schema(&self) -> String {
        unsafe { BnString::into_string(BNSettingsSerializeSchema(self.handle)) }
    }

    pub fn deserialize_schema(&self, schema: &str) -> bool {
        self.deserialize_schema_with_scope(schema, SettingsScope::SettingsAutoScope)
    }

    pub fn deserialize_schema_with_scope(&self, schema: &str, scope: SettingsScope) -> bool {
        let schema = schema.to_cstr();
        unsafe { BNSettingsDeserializeSchema(self.handle, schema.as_ptr(), scope, true) }
    }

    pub fn contains(&self, key: &str) -> bool {
        let key = key.to_cstr();

        unsafe { BNSettingsContains(self.handle, key.as_ptr()) }
    }

    pub fn keys(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNSettingsKeysList(self.handle, &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result as *mut *mut c_char, count, ()) }
    }

    pub fn get_bool(&self, key: &str) -> bool {
        self.get_bool_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_bool_with_opts(&self, key: &str, options: &mut QueryOptions) -> bool {
        let key = key.to_cstr();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BNSettingsGetBool(
                self.handle,
                key.as_ptr(),
                view_ptr,
                func_ptr,
                &mut options.scope,
            )
        }
    }

    pub fn get_double(&self, key: &str) -> f64 {
        self.get_double_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_double_with_opts(&self, key: &str, options: &mut QueryOptions) -> f64 {
        let key = key.to_cstr();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BNSettingsGetDouble(
                self.handle,
                key.as_ptr(),
                view_ptr,
                func_ptr,
                &mut options.scope,
            )
        }
    }

    pub fn get_integer(&self, key: &str) -> u64 {
        self.get_integer_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_integer_with_opts(&self, key: &str, options: &mut QueryOptions) -> u64 {
        let key = key.to_cstr();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BNSettingsGetUInt64(
                self.handle,
                key.as_ptr(),
                view_ptr,
                func_ptr,
                &mut options.scope,
            )
        }
    }

    pub fn get_string(&self, key: &str) -> String {
        self.get_string_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_string_with_opts(&self, key: &str, options: &mut QueryOptions) -> String {
        let key = key.to_cstr();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BnString::into_string(BNSettingsGetString(
                self.handle,
                key.as_ptr(),
                view_ptr,
                func_ptr,
                &mut options.scope,
            ))
        }
    }

    pub fn get_string_list(&self, key: &str) -> Array<BnString> {
        self.get_string_list_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_string_list_with_opts(
        &self,
        key: &str,
        options: &mut QueryOptions,
    ) -> Array<BnString> {
        let key = key.to_cstr();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        let mut size: usize = 0;
        unsafe {
            Array::new(
                BNSettingsGetStringList(
                    self.handle,
                    key.as_ptr(),
                    view_ptr,
                    func_ptr,
                    &mut options.scope,
                    &mut size,
                ) as *mut *mut c_char,
                size,
                (),
            )
        }
    }

    pub fn get_json(&self, key: &str) -> String {
        self.get_json_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_json_with_opts(&self, key: &str, options: &mut QueryOptions) -> String {
        let key = key.to_cstr();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BnString::into_string(BNSettingsGetJson(
                self.handle,
                key.as_ptr(),
                view_ptr,
                func_ptr,
                &mut options.scope,
            ))
        }
    }

    pub fn set_bool(&self, key: &str, value: bool) {
        self.set_bool_with_opts(key, value, &QueryOptions::default())
    }

    pub fn set_bool_with_opts(&self, key: &str, value: bool, options: &QueryOptions) {
        let key = key.to_cstr();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BNSettingsSetBool(
                self.handle,
                view_ptr,
                func_ptr,
                options.scope,
                key.as_ptr(),
                value,
            );
        }
    }

    pub fn set_double(&self, key: &str, value: f64) {
        self.set_double_with_opts(key, value, &QueryOptions::default())
    }
    pub fn set_double_with_opts(&self, key: &str, value: f64, options: &QueryOptions) {
        let key = key.to_cstr();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BNSettingsSetDouble(
                self.handle,
                view_ptr,
                func_ptr,
                options.scope,
                key.as_ptr(),
                value,
            );
        }
    }

    pub fn set_integer(&self, key: &str, value: u64) {
        self.set_integer_with_opts(key, value, &QueryOptions::default())
    }

    pub fn set_integer_with_opts(&self, key: &str, value: u64, options: &QueryOptions) {
        let key = key.to_cstr();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BNSettingsSetUInt64(
                self.handle,
                view_ptr,
                func_ptr,
                options.scope,
                key.as_ptr(),
                value,
            );
        }
    }

    pub fn set_string(&self, key: &str, value: &str) {
        self.set_string_with_opts(key, value, &QueryOptions::default())
    }

    pub fn set_string_with_opts(&self, key: &str, value: &str, options: &QueryOptions) {
        let key = key.to_cstr();
        let value = value.to_cstr();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BNSettingsSetString(
                self.handle,
                view_ptr,
                func_ptr,
                options.scope,
                key.as_ptr(),
                value.as_ptr(),
            );
        }
    }

    pub fn set_string_list<I: IntoIterator<Item = String>>(&self, key: &str, value: I) -> bool {
        self.set_string_list_with_opts(key, value, &QueryOptions::default())
    }

    pub fn set_string_list_with_opts<I: IntoIterator<Item = String>>(
        &self,
        key: &str,
        value: I,
        options: &QueryOptions,
    ) -> bool {
        let key = key.to_cstr();
        let raw_list: Vec<_> = value.into_iter().map(|s| s.to_cstr()).collect();
        let mut raw_list_ptr: Vec<_> = raw_list.iter().map(|s| s.as_ptr()).collect();

        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BNSettingsSetStringList(
                self.handle,
                view_ptr,
                func_ptr,
                options.scope,
                key.as_ptr(),
                raw_list_ptr.as_mut_ptr(),
                raw_list_ptr.len(),
            )
        }
    }

    pub fn set_json(&self, key: &str, value: &str) -> bool {
        self.set_json_with_opts(key, value, &QueryOptions::default())
    }

    pub fn set_json_with_opts(&self, key: &str, value: &str, options: &QueryOptions) -> bool {
        let key = key.to_cstr();
        let value = value.to_cstr();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BNSettingsSetJson(
                self.handle,
                view_ptr,
                func_ptr,
                options.scope,
                key.as_ptr(),
                value.as_ptr(),
            )
        }
    }

    pub fn get_property_string(&self, key: &str, property: &str) -> String {
        let key = key.to_cstr();
        let property = property.to_cstr();
        unsafe {
            BnString::into_string(BNSettingsQueryPropertyString(
                self.handle,
                key.as_ptr(),
                property.as_ptr(),
            ))
        }
    }

    pub fn get_property_string_list(&self, key: &str, property: &str) -> Array<BnString> {
        let key = key.to_cstr();
        let property = property.to_cstr();
        let mut size: usize = 0;
        unsafe {
            Array::new(
                BNSettingsQueryPropertyStringList(
                    self.handle,
                    key.as_ptr(),
                    property.as_ptr(),
                    &mut size,
                ) as *mut *mut c_char,
                size,
                (),
            )
        }
    }

    pub fn update_bool_property(&self, key: &str, property: &str, value: bool) {
        let key = key.to_cstr();
        let property = property.to_cstr();
        unsafe {
            BNSettingsUpdateBoolProperty(self.handle, key.as_ptr(), property.as_ptr(), value);
        }
    }

    pub fn update_integer_property(&self, key: &str, property: &str, value: u64) {
        let key = key.to_cstr();
        let property = property.to_cstr();
        unsafe {
            BNSettingsUpdateUInt64Property(self.handle, key.as_ptr(), property.as_ptr(), value);
        }
    }

    pub fn update_double_property(&self, key: &str, property: &str, value: f64) {
        let key = key.to_cstr();
        let property = property.to_cstr();
        unsafe {
            BNSettingsUpdateDoubleProperty(self.handle, key.as_ptr(), property.as_ptr(), value);
        }
    }

    pub fn update_string_property(&self, key: &str, property: &str, value: &str) {
        let key = key.to_cstr();
        let property = property.to_cstr();
        let value = value.to_cstr();
        unsafe {
            BNSettingsUpdateStringProperty(
                self.handle,
                key.as_ptr(),
                property.as_ptr(),
                value.as_ptr(),
            );
        }
    }

    pub fn update_string_list_property<I: IntoIterator<Item = String>>(
        &self,
        key: &str,
        property: &str,
        value: I,
    ) {
        let key = key.to_cstr();
        let property = property.to_cstr();
        let raw_list: Vec<_> = value.into_iter().map(|s| s.to_cstr()).collect();
        let mut raw_list_ptr: Vec<_> = raw_list.iter().map(|s| s.as_ptr()).collect();

        unsafe {
            BNSettingsUpdateStringListProperty(
                self.handle,
                key.as_ptr(),
                property.as_ptr(),
                raw_list_ptr.as_mut_ptr(),
                raw_list_ptr.len(),
            );
        }
    }

    pub fn register_group(&self, group: &str, title: &str) -> bool {
        let group = group.to_cstr();
        let title = title.to_cstr();

        unsafe { BNSettingsRegisterGroup(self.handle, group.as_ptr(), title.as_ptr()) }
    }

    pub fn register_setting_json(&self, group: &str, properties: &str) -> bool {
        let group = group.to_cstr();
        let properties = properties.to_cstr();

        unsafe { BNSettingsRegisterSetting(self.handle, group.as_ptr(), properties.as_ptr()) }
    }

    // TODO: register_setting but type-safely turn it into json
}

impl Default for Ref<Settings> {
    fn default() -> Self {
        Settings::new_with_id(DEFAULT_INSTANCE_ID)
    }
}

unsafe impl Send for Settings {}
unsafe impl Sync for Settings {}

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

#[derive(Debug, Clone)]
pub struct QueryOptions<'a> {
    pub scope: SettingsScope,
    pub view: Option<&'a BinaryView>,
    pub function: Option<Ref<Function>>,
}

impl<'a> QueryOptions<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_view(view: &'a BinaryView) -> Self {
        Self {
            view: Some(view),
            ..Default::default()
        }
    }

    pub fn new_with_func(func: Ref<Function>) -> Self {
        Self {
            function: Some(func),
            ..Default::default()
        }
    }

    /// Set the query to target a specific view, this will be overridden if a function is targeted.
    pub fn with_view(mut self, view: &'a BinaryView) -> Self {
        self.view = Some(view);
        self
    }

    pub fn with_scope(mut self, scope: SettingsScope) -> Self {
        self.scope = scope;
        self
    }

    /// Set the query to target a specific function, this will override the target view.
    pub fn with_function(mut self, function: Ref<Function>) -> Self {
        self.function = Some(function);
        self
    }
}

impl Default for QueryOptions<'_> {
    fn default() -> Self {
        Self {
            view: None,
            scope: SettingsScope::SettingsAutoScope,
            function: None,
        }
    }
}
