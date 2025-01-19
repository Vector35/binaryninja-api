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

use binaryninjacore_sys::*;
use std::ffi::c_char;
use std::fmt::Debug;

use crate::binary_view::BinaryView;
use crate::rc::*;
use crate::string::{BnStrCompatible, BnString};

use crate::function::Function;

pub type SettingsScope = BNSettingsScope;

pub const DEFAULT_INSTANCE_ID: &str = "default";
pub const GLOBAL_INSTANCE_ID: &str = "";

#[derive(PartialEq, Eq, Hash)]
pub struct Settings {
    pub(crate) handle: *mut BNSettings,
}

impl Settings {
    pub(crate) unsafe fn from_raw(handle: *mut BNSettings) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn new() -> Ref<Self> {
        Self::new_with_id(GLOBAL_INSTANCE_ID)
    }

    pub fn new_with_id<S: BnStrCompatible>(instance_id: S) -> Ref<Self> {
        let instance_id = instance_id.into_bytes_with_nul();
        unsafe {
            let handle = BNCreateSettings(instance_id.as_ref().as_ptr() as *mut _);
            debug_assert!(!handle.is_null());
            Ref::new(Self { handle })
        }
    }

    pub fn set_resource_id<S: BnStrCompatible>(&self, resource_id: S) {
        let resource_id = resource_id.into_bytes_with_nul();
        unsafe { BNSettingsSetResourceId(self.handle, resource_id.as_ref().as_ptr() as *mut _) };
    }

    pub fn serialize_schema(&self) -> BnString {
        unsafe { BnString::from_raw(BNSettingsSerializeSchema(self.handle)) }
    }

    pub fn deserialize_schema<S: BnStrCompatible>(&self, schema: S) -> bool {
        self.deserialize_schema_with_scope(schema, SettingsScope::SettingsAutoScope)
    }

    pub fn deserialize_schema_with_scope<S: BnStrCompatible>(
        &self,
        schema: S,
        scope: SettingsScope,
    ) -> bool {
        let schema = schema.into_bytes_with_nul();
        unsafe {
            BNSettingsDeserializeSchema(
                self.handle,
                schema.as_ref().as_ptr() as *mut _,
                scope,
                true,
            )
        }
    }

    pub fn contains<S: BnStrCompatible>(&self, key: S) -> bool {
        let key = key.into_bytes_with_nul();

        unsafe { BNSettingsContains(self.handle, key.as_ref().as_ptr() as *mut _) }
    }

    pub fn keys(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNSettingsKeysList(self.handle, &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result as *mut *mut c_char, count, ()) }
    }

    // TODO Update the settings API to take an optional BinaryView or Function. Separate functions or...?

    pub fn get_bool<S: BnStrCompatible>(&self, key: S) -> bool {
        self.get_bool_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_bool_with_opts<S: BnStrCompatible>(
        &self,
        key: S,
        options: &mut QueryOptions,
    ) -> bool {
        let key = key.into_bytes_with_nul();
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
                key.as_ref().as_ptr() as *mut _,
                view_ptr,
                func_ptr,
                &mut options.scope,
            )
        }
    }

    pub fn get_double<S: BnStrCompatible>(&self, key: S) -> f64 {
        self.get_double_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_double_with_opts<S: BnStrCompatible>(
        &self,
        key: S,
        options: &mut QueryOptions,
    ) -> f64 {
        let key = key.into_bytes_with_nul();
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
                key.as_ref().as_ptr() as *mut _,
                view_ptr,
                func_ptr,
                &mut options.scope,
            )
        }
    }

    pub fn get_integer<S: BnStrCompatible>(&self, key: S) -> u64 {
        self.get_integer_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_integer_with_opts<S: BnStrCompatible>(
        &self,
        key: S,
        options: &mut QueryOptions,
    ) -> u64 {
        let key = key.into_bytes_with_nul();
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
                key.as_ref().as_ptr() as *mut _,
                view_ptr,
                func_ptr,
                &mut options.scope,
            )
        }
    }

    pub fn get_string<S: BnStrCompatible>(&self, key: S) -> BnString {
        self.get_string_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_string_with_opts<S: BnStrCompatible>(
        &self,
        key: S,
        options: &mut QueryOptions,
    ) -> BnString {
        let key = key.into_bytes_with_nul();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BnString::from_raw(BNSettingsGetString(
                self.handle,
                key.as_ref().as_ptr() as *mut _,
                view_ptr,
                func_ptr,
                &mut options.scope,
            ))
        }
    }

    pub fn get_string_list<S: BnStrCompatible>(&self, key: S) -> Array<BnString> {
        self.get_string_list_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_string_list_with_opts<S: BnStrCompatible>(
        &self,
        key: S,
        options: &mut QueryOptions,
    ) -> Array<BnString> {
        let key = key.into_bytes_with_nul();
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
                    key.as_ref().as_ptr() as *mut _,
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

    pub fn get_json<S: BnStrCompatible>(&self, key: S) -> BnString {
        self.get_json_with_opts(key, &mut QueryOptions::default())
    }

    pub fn get_json_with_opts<S: BnStrCompatible>(
        &self,
        key: S,
        options: &mut QueryOptions,
    ) -> BnString {
        let key = key.into_bytes_with_nul();
        let view_ptr = match options.view.as_ref() {
            Some(view) => view.handle,
            _ => std::ptr::null_mut(),
        };
        let func_ptr = match options.function.as_ref() {
            Some(func) => func.handle,
            _ => std::ptr::null_mut(),
        };
        unsafe {
            BnString::from_raw(BNSettingsGetJson(
                self.handle,
                key.as_ref().as_ptr() as *mut _,
                view_ptr,
                func_ptr,
                &mut options.scope,
            ))
        }
    }

    pub fn set_bool<S: BnStrCompatible>(&self, key: S, value: bool) {
        self.set_bool_with_opts(key, value, &QueryOptions::default())
    }

    pub fn set_bool_with_opts<S: BnStrCompatible>(
        &self,
        key: S,
        value: bool,
        options: &QueryOptions,
    ) {
        let key = key.into_bytes_with_nul();
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
                key.as_ref().as_ptr() as *mut _,
                value,
            );
        }
    }

    pub fn set_double<S: BnStrCompatible>(&self, key: S, value: f64) {
        self.set_double_with_opts(key, value, &QueryOptions::default())
    }
    pub fn set_double_with_opts<S: BnStrCompatible>(
        &self,
        key: S,
        value: f64,
        options: &QueryOptions,
    ) {
        let key = key.into_bytes_with_nul();
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
                key.as_ref().as_ptr() as *mut _,
                value,
            );
        }
    }

    pub fn set_integer<S: BnStrCompatible>(&self, key: S, value: u64) {
        self.set_integer_with_opts(key, value, &QueryOptions::default())
    }

    pub fn set_integer_with_opts<S: BnStrCompatible>(
        &self,
        key: S,
        value: u64,
        options: &QueryOptions,
    ) {
        let key = key.into_bytes_with_nul();
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
                key.as_ref().as_ptr() as *mut _,
                value,
            );
        }
    }

    pub fn set_string<S1: BnStrCompatible, S2: BnStrCompatible>(&self, key: S1, value: S2) {
        self.set_string_with_opts(key, value, &QueryOptions::default())
    }

    pub fn set_string_with_opts<S1: BnStrCompatible, S2: BnStrCompatible>(
        &self,
        key: S1,
        value: S2,
        options: &QueryOptions,
    ) {
        let key = key.into_bytes_with_nul();
        let value = value.into_bytes_with_nul();
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
                key.as_ref().as_ptr() as *mut _,
                value.as_ref().as_ptr() as *mut _,
            );
        }
    }

    pub fn set_string_list<S1: BnStrCompatible, S2: BnStrCompatible, I: Iterator<Item = S2>>(
        &self,
        key: S1,
        value: I,
    ) -> bool {
        self.set_string_list_with_opts(key, value, &QueryOptions::default())
    }

    pub fn set_string_list_with_opts<
        S1: BnStrCompatible,
        S2: BnStrCompatible,
        I: Iterator<Item = S2>,
    >(
        &self,
        key: S1,
        value: I,
        options: &QueryOptions,
    ) -> bool {
        let key = key.into_bytes_with_nul();
        let raw_list: Vec<_> = value.map(|s| s.into_bytes_with_nul()).collect();
        let mut raw_list_ptr: Vec<_> = raw_list
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect();

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
                key.as_ref().as_ptr() as *mut _,
                raw_list_ptr.as_mut_ptr(),
                raw_list_ptr.len(),
            )
        }
    }

    pub fn set_json<S1: BnStrCompatible, S2: BnStrCompatible>(&self, key: S1, value: S2) -> bool {
        self.set_json_with_opts(key, value, &QueryOptions::default())
    }

    pub fn set_json_with_opts<S1: BnStrCompatible, S2: BnStrCompatible>(
        &self,
        key: S1,
        value: S2,
        options: &QueryOptions,
    ) -> bool {
        let key = key.into_bytes_with_nul();
        let value = value.into_bytes_with_nul();
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
                key.as_ref().as_ptr() as *mut _,
                value.as_ref().as_ptr() as *mut _,
            )
        }
    }

    pub fn get_property_string<S: BnStrCompatible>(&self, key: S, property: S) -> BnString {
        let key = key.into_bytes_with_nul();
        let property = property.into_bytes_with_nul();
        unsafe {
            BnString::from_raw(BNSettingsQueryPropertyString(
                self.handle,
                key.as_ref().as_ptr() as *mut _,
                property.as_ref().as_ptr() as *mut _,
            ))
        }
    }

    pub fn get_property_string_list<S: BnStrCompatible>(
        &self,
        key: S,
        property: S,
    ) -> Array<BnString> {
        let key = key.into_bytes_with_nul();
        let property = property.into_bytes_with_nul();
        let mut size: usize = 0;
        unsafe {
            Array::new(
                BNSettingsQueryPropertyStringList(
                    self.handle,
                    key.as_ref().as_ptr() as *mut _,
                    property.as_ref().as_ptr() as *mut _,
                    &mut size,
                ) as *mut *mut c_char,
                size,
                (),
            )
        }
    }

    pub fn update_bool_property<S: BnStrCompatible>(&self, key: S, property: S, value: bool) {
        let key = key.into_bytes_with_nul();
        let property = property.into_bytes_with_nul();
        unsafe {
            BNSettingsUpdateBoolProperty(
                self.handle,
                key.as_ref().as_ptr() as *mut _,
                property.as_ref().as_ptr() as *mut _,
                value,
            );
        }
    }

    pub fn update_integer_property<S: BnStrCompatible>(&self, key: S, property: S, value: u64) {
        let key = key.into_bytes_with_nul();
        let property = property.into_bytes_with_nul();
        unsafe {
            BNSettingsUpdateUInt64Property(
                self.handle,
                key.as_ref().as_ptr() as *mut _,
                property.as_ref().as_ptr() as *mut _,
                value,
            );
        }
    }

    pub fn update_double_property<S: BnStrCompatible>(&self, key: S, property: S, value: f64) {
        let key = key.into_bytes_with_nul();
        let property = property.into_bytes_with_nul();
        unsafe {
            BNSettingsUpdateDoubleProperty(
                self.handle,
                key.as_ref().as_ptr() as *mut _,
                property.as_ref().as_ptr() as *mut _,
                value,
            );
        }
    }

    pub fn update_string_property<S: BnStrCompatible>(&self, key: S, property: S, value: S) {
        let key = key.into_bytes_with_nul();
        let property = property.into_bytes_with_nul();
        let value = value.into_bytes_with_nul();
        unsafe {
            BNSettingsUpdateStringProperty(
                self.handle,
                key.as_ref().as_ptr() as *mut _,
                property.as_ref().as_ptr() as *mut _,
                value.as_ref().as_ptr() as *mut _,
            );
        }
    }

    pub fn update_string_list_property<S: BnStrCompatible, I: Iterator<Item = S>>(
        &self,
        key: S,
        property: S,
        value: I,
    ) {
        let key = key.into_bytes_with_nul();
        let property = property.into_bytes_with_nul();
        let raw_list: Vec<_> = value.map(|s| s.into_bytes_with_nul()).collect();
        let mut raw_list_ptr: Vec<_> = raw_list
            .iter()
            .map(|s| s.as_ref().as_ptr() as *const c_char)
            .collect();

        unsafe {
            BNSettingsUpdateStringListProperty(
                self.handle,
                key.as_ref().as_ptr() as *mut _,
                property.as_ref().as_ptr() as *mut _,
                raw_list_ptr.as_mut_ptr(),
                raw_list_ptr.len(),
            );
        }
    }

    pub fn register_group<S1: BnStrCompatible, S2: BnStrCompatible>(
        &self,
        group: S1,
        title: S2,
    ) -> bool {
        let group = group.into_bytes_with_nul();
        let title = title.into_bytes_with_nul();

        unsafe {
            BNSettingsRegisterGroup(
                self.handle,
                group.as_ref().as_ptr() as *mut _,
                title.as_ref().as_ptr() as *mut _,
            )
        }
    }

    pub fn register_setting_json<S1: BnStrCompatible, S2: BnStrCompatible>(
        &self,
        group: S1,
        properties: S2,
    ) -> bool {
        let group = group.into_bytes_with_nul();
        let properties = properties.into_bytes_with_nul();

        unsafe {
            BNSettingsRegisterSetting(
                self.handle,
                group.as_ref().as_ptr() as *mut _,
                properties.as_ref().as_ptr() as *mut _,
            )
        }
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
            scope: SettingsScope::SettingsDefaultScope,
            function: None,
        }
    }
}
