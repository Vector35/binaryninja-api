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

// TODO: These clippy-allow are bad and needs to be removed
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::result_unit_err)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_doctest_main)]
#![doc(html_root_url = "https://dev-rust.binary.ninja/")]
#![doc(html_favicon_url = "https://binary.ninja/icons/favicon-32x32.png")]
#![doc(html_logo_url = "https://binary.ninja/icons/android-chrome-512x512.png")]
#![doc(issue_tracker_base_url = "https://github.com/Vector35/binaryninja-api/issues/")]
#![doc = include_str!("../README.md")]

#[macro_use]
mod ffi;
mod operand_iter;

pub mod architecture;
pub mod background_task;
pub mod basic_block;
pub mod binary_reader;
pub mod binary_view;
pub mod binary_writer;
pub mod calling_convention;
pub mod collaboration;
pub mod command;
pub mod component;
pub mod confidence;
pub mod custom_binary_view;
pub mod data_buffer;
pub mod database;
pub mod debuginfo;
pub mod demangle;
pub mod disassembly;
pub mod download_provider;
pub mod enterprise;
pub mod external_library;
pub mod file_accessor;
pub mod file_metadata;
pub mod flowgraph;
pub mod function;
pub mod function_recognizer;
pub mod headless;
pub mod high_level_il;
pub mod interaction;
pub mod linear_view;
pub mod logger;
pub mod low_level_il;
pub mod main_thread;
pub mod medium_level_il;
pub mod metadata;
pub mod platform;
pub mod progress;
pub mod project;
pub mod rc;
pub mod references;
pub mod relocation;
pub mod render_layer;
pub mod repository;
pub mod secrets_provider;
pub mod section;
pub mod segment;
pub mod settings;
pub mod string;
pub mod symbol;
pub mod tags;
pub mod template_simplifier;
pub mod type_archive;
pub mod type_container;
pub mod type_library;
pub mod type_parser;
pub mod type_printer;
pub mod types;
pub mod update;
pub mod variable;
pub mod worker_thread;
pub mod workflow;

use crate::file_metadata::FileMetadata;
use crate::function::Function;
use binary_view::BinaryView;
use binaryninjacore_sys::*;
use metadata::Metadata;
use metadata::MetadataType;
use rc::Ref;
use std::cmp;
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::path::{Path, PathBuf};
use string::BnStrCompatible;
use string::BnString;
use string::IntoJson;

use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::string::raw_to_string;
pub use binaryninjacore_sys::BNBranchType as BranchType;
pub use binaryninjacore_sys::BNDataFlowQueryOption as DataFlowQueryOption;
pub use binaryninjacore_sys::BNEndianness as Endianness;
pub use binaryninjacore_sys::BNILBranchDependence as ILBranchDependence;

pub const BN_FULL_CONFIDENCE: u8 = u8::MAX;
pub const BN_INVALID_EXPR: usize = usize::MAX;

/// The main way to open and load files into Binary Ninja. Make sure you've properly initialized the core before calling this function. See [`crate::headless::init()`]
pub fn load(file_path: impl AsRef<Path>) -> Option<Ref<BinaryView>> {
    load_with_progress(file_path, NoProgressCallback)
}

/// Equivalent to [`load`] but with a progress callback.
///
/// NOTE: The progress callback will _only_ be called when loading BNDBs.
pub fn load_with_progress<P: ProgressCallback>(
    file_path: impl AsRef<Path>,
    mut progress: P,
) -> Option<Ref<BinaryView>> {
    let file_path = file_path.as_ref().into_bytes_with_nul();
    let options = c"";
    let handle = unsafe {
        BNLoadFilename(
            file_path.as_ptr() as *mut _,
            true,
            options.as_ptr() as *mut c_char,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
        )
    };

    if handle.is_null() {
        None
    } else {
        Some(unsafe { BinaryView::ref_from_raw(handle) })
    }
}

/// The main way to open and load files (with options) into Binary Ninja. Make sure you've properly initialized the core before calling this function. See [`crate::headless::init()`]
///
/// <div class="warning">Strict JSON doesn't support single quotes for strings, so you'll need to either use a raw strings (<code>f#"{"setting": "value"}"#</code>) or escape double quotes (<code>"{\"setting\": \"value\"}"</code>). Or use <code>serde_json::json</code>.</div>
///
/// ```no_run
/// # // Mock implementation of json! macro for documentation purposes
/// # macro_rules! json {
/// #   ($($arg:tt)*) => {
/// #     stringify!($($arg)*)
/// #   };
/// # }
/// use binaryninja::{metadata::Metadata, rc::Ref};
/// use std::collections::HashMap;
///
/// let bv = binaryninja::load_with_options("/bin/cat", true, Some(json!("analysis.linearSweep.autorun": false).to_string()))
///     .expect("Couldn't open `/bin/cat`");
/// ```
pub fn load_with_options<O>(
    file_path: impl AsRef<Path>,
    update_analysis_and_wait: bool,
    options: Option<O>,
) -> Option<Ref<BinaryView>>
where
    O: IntoJson,
{
    load_with_options_and_progress(
        file_path,
        update_analysis_and_wait,
        options,
        NoProgressCallback,
    )
}

/// Equivalent to [`load_with_options`] but with a progress callback.
///
/// NOTE: The progress callback will _only_ be called when loading BNDBs.
pub fn load_with_options_and_progress<O, P>(
    file_path: impl AsRef<Path>,
    update_analysis_and_wait: bool,
    options: Option<O>,
    mut progress: P,
) -> Option<Ref<BinaryView>>
where
    O: IntoJson,
    P: ProgressCallback,
{
    let file_path = file_path.as_ref().into_bytes_with_nul();
    let options_or_default = if let Some(opt) = options {
        opt.get_json_string()
            .ok()?
            .into_bytes_with_nul()
            .as_ref()
            .to_vec()
    } else {
        Metadata::new_of_type(MetadataType::KeyValueDataType)
            .get_json_string()
            .ok()?
            .as_ref()
            .to_vec()
    };
    let handle = unsafe {
        BNLoadFilename(
            file_path.as_ptr() as *mut _,
            update_analysis_and_wait,
            options_or_default.as_ptr() as *mut c_char,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
        )
    };

    if handle.is_null() {
        None
    } else {
        Some(unsafe { BinaryView::ref_from_raw(handle) })
    }
}

pub fn load_view<O>(
    bv: &BinaryView,
    update_analysis_and_wait: bool,
    options: Option<O>,
) -> Option<Ref<BinaryView>>
where
    O: IntoJson,
{
    load_view_with_progress(bv, update_analysis_and_wait, options, NoProgressCallback)
}

/// Equivalent to [`load_view`] but with a progress callback.
pub fn load_view_with_progress<O, P>(
    bv: &BinaryView,
    update_analysis_and_wait: bool,
    options: Option<O>,
    mut progress: P,
) -> Option<Ref<BinaryView>>
where
    O: IntoJson,
    P: ProgressCallback,
{
    let options_or_default = if let Some(opt) = options {
        opt.get_json_string()
            .ok()?
            .into_bytes_with_nul()
            .as_ref()
            .to_vec()
    } else {
        Metadata::new_of_type(MetadataType::KeyValueDataType)
            .get_json_string()
            .ok()?
            .as_ref()
            .to_vec()
    };
    let handle = unsafe {
        BNLoadBinaryView(
            bv.handle as *mut _,
            update_analysis_and_wait,
            options_or_default.as_ptr() as *mut c_char,
            Some(P::cb_progress_callback),
            &mut progress as *mut P as *mut c_void,
        )
    };

    if handle.is_null() {
        None
    } else {
        Some(unsafe { BinaryView::ref_from_raw(handle) })
    }
}

pub fn install_directory() -> PathBuf {
    let install_dir_ptr: *mut c_char = unsafe { BNGetInstallDirectory() };
    assert!(!install_dir_ptr.is_null());
    let bn_install_dir = unsafe { BnString::from_raw(install_dir_ptr) };
    PathBuf::from(bn_install_dir.to_string())
}

pub fn bundled_plugin_directory() -> Result<PathBuf, ()> {
    let s: *mut c_char = unsafe { BNGetBundledPluginDirectory() };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(unsafe { BnString::from_raw(s) }.to_string()))
}

pub fn set_bundled_plugin_directory(new_dir: impl AsRef<Path>) {
    let new_dir = new_dir.as_ref().into_bytes_with_nul();
    unsafe { BNSetBundledPluginDirectory(new_dir.as_ptr() as *const c_char) };
}

pub fn user_directory() -> PathBuf {
    let user_dir_ptr: *mut c_char = unsafe { BNGetUserDirectory() };
    assert!(!user_dir_ptr.is_null());
    let bn_user_dir = unsafe { BnString::from_raw(user_dir_ptr) };
    PathBuf::from(bn_user_dir.to_string())
}

pub fn user_plugin_directory() -> Result<PathBuf, ()> {
    let s: *mut c_char = unsafe { BNGetUserPluginDirectory() };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(unsafe { BnString::from_raw(s) }.to_string()))
}

pub fn repositories_directory() -> Result<PathBuf, ()> {
    let s: *mut c_char = unsafe { BNGetRepositoriesDirectory() };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(unsafe { BnString::from_raw(s) }.to_string()))
}

pub fn settings_file_name() -> PathBuf {
    let settings_file_name_ptr: *mut c_char = unsafe { BNGetSettingsFileName() };
    assert!(!settings_file_name_ptr.is_null());
    let bn_settings_file_name = unsafe { BnString::from_raw(settings_file_name_ptr) };
    PathBuf::from(bn_settings_file_name.to_string())
}

/// Write the installation directory of the currently running core instance to disk.
///
/// This is used to select the most recent installation for running scripts.
pub fn save_last_run() {
    unsafe { BNSaveLastRun() };
}

pub fn path_relative_to_bundled_plugin_directory(path: impl AsRef<Path>) -> Result<PathBuf, ()> {
    let path_raw = path.as_ref().into_bytes_with_nul();
    let s: *mut c_char =
        unsafe { BNGetPathRelativeToBundledPluginDirectory(path_raw.as_ptr() as *const c_char) };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(unsafe { BnString::from_raw(s) }.to_string()))
}

pub fn path_relative_to_user_plugin_directory(path: impl AsRef<Path>) -> Result<PathBuf, ()> {
    let path_raw = path.as_ref().into_bytes_with_nul();
    let s: *mut c_char =
        unsafe { BNGetPathRelativeToUserPluginDirectory(path_raw.as_ptr() as *const c_char) };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(unsafe { BnString::from_raw(s) }.to_string()))
}

pub fn path_relative_to_user_directory(path: impl AsRef<Path>) -> Result<PathBuf, ()> {
    let path_raw = path.as_ref().into_bytes_with_nul();
    let s: *mut c_char =
        unsafe { BNGetPathRelativeToUserDirectory(path_raw.as_ptr() as *const c_char) };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(unsafe { BnString::from_raw(s) }.to_string()))
}

/// Returns if the running thread is the "main thread"
///
/// If there is no registered main thread than this will always return true.
pub fn is_main_thread() -> bool {
    unsafe { BNIsMainThread() }
}

pub fn memory_info() -> HashMap<String, u64> {
    let mut count = 0;
    let mut usage = HashMap::new();
    unsafe {
        let info_ptr = BNGetMemoryUsageInfo(&mut count);
        let info_list = std::slice::from_raw_parts(info_ptr, count);
        for info in info_list {
            let info_name = CStr::from_ptr(info.name).to_str().unwrap().to_string();
            usage.insert(info_name, info.value);
        }
        BNFreeMemoryUsageInfo(info_ptr, count);
    }
    usage
}

/// The trait required for receiving core object destruction callbacks.
pub trait ObjectDestructor: 'static + Sync + Sized {
    fn destruct_view(&self, _view: &BinaryView) {}
    fn destruct_file_metadata(&self, _metadata: &FileMetadata) {}
    fn destruct_function(&self, _func: &Function) {}

    unsafe extern "C" fn cb_destruct_binary_view(ctxt: *mut c_void, view: *mut BNBinaryView) {
        ffi_wrap!("ObjectDestructor::destruct_view", {
            let view_type = &*(ctxt as *mut Self);
            let view = BinaryView { handle: view };
            view_type.destruct_view(&view);
        })
    }

    unsafe extern "C" fn cb_destruct_file_metadata(ctxt: *mut c_void, file: *mut BNFileMetadata) {
        ffi_wrap!("ObjectDestructor::destruct_file_metadata", {
            let view_type = &*(ctxt as *mut Self);
            let file = FileMetadata::from_raw(file);
            view_type.destruct_file_metadata(&file);
        })
    }

    unsafe extern "C" fn cb_destruct_function(ctxt: *mut c_void, func: *mut BNFunction) {
        ffi_wrap!("ObjectDestructor::destruct_function", {
            let view_type = &*(ctxt as *mut Self);
            let func = Function { handle: func };
            view_type.destruct_function(&func);
        })
    }

    unsafe fn as_callbacks(&'static mut self) -> BNObjectDestructionCallbacks {
        BNObjectDestructionCallbacks {
            context: std::mem::transmute(&self),
            destructBinaryView: Some(Self::cb_destruct_binary_view),
            destructFileMetadata: Some(Self::cb_destruct_file_metadata),
            destructFunction: Some(Self::cb_destruct_function),
        }
    }

    fn register(&'static mut self) {
        unsafe { BNRegisterObjectDestructionCallbacks(&mut self.as_callbacks()) };
    }

    fn unregister(&'static mut self) {
        unsafe { BNUnregisterObjectDestructionCallbacks(&mut self.as_callbacks()) };
    }
}

pub fn version() -> BnString {
    unsafe { BnString::from_raw(BNGetVersionString()) }
}

pub fn build_id() -> u32 {
    unsafe { BNGetBuildId() }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct VersionInfo {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub channel: String,
}

impl VersionInfo {
    pub(crate) fn from_raw(value: &BNVersionInfo) -> Self {
        Self {
            major: value.major,
            minor: value.minor,
            build: value.build,
            // NOTE: Because of plugin manager the channel might not be filled.
            channel: raw_to_string(value.channel).unwrap_or_default(),
        }
    }

    pub(crate) fn from_owned_raw(value: BNVersionInfo) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_owned_raw(value: &Self) -> BNVersionInfo {
        BNVersionInfo {
            major: value.major,
            minor: value.minor,
            build: value.build,
            channel: value.channel.as_ptr() as *mut c_char,
        }
    }

    pub(crate) fn free_raw(value: BNVersionInfo) {
        let _ = unsafe { BnString::from_raw(value.channel) };
    }

    pub fn from_string<S: BnStrCompatible>(string: S) -> Self {
        let string = string.into_bytes_with_nul();
        let result = unsafe { BNParseVersionString(string.as_ref().as_ptr() as *const c_char) };
        Self::from_owned_raw(result)
    }
}

impl PartialOrd for VersionInfo {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VersionInfo {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        if self == other {
            return cmp::Ordering::Equal;
        }
        let bn_version_0 = VersionInfo::into_owned_raw(self);
        let bn_version_1 = VersionInfo::into_owned_raw(other);
        if unsafe { BNVersionLessThan(bn_version_0, bn_version_1) } {
            cmp::Ordering::Less
        } else {
            cmp::Ordering::Greater
        }
    }
}

pub fn version_info() -> VersionInfo {
    let info_raw = unsafe { BNGetVersionInfo() };
    VersionInfo::from_owned_raw(info_raw)
}

pub fn serial_number() -> BnString {
    unsafe { BnString::from_raw(BNGetSerialNumber()) }
}

pub fn is_license_validated() -> bool {
    unsafe { BNIsLicenseValidated() }
}

pub fn licensed_user_email() -> BnString {
    unsafe { BnString::from_raw(BNGetLicensedUserEmail()) }
}

pub fn license_path() -> PathBuf {
    user_directory().join("license.dat")
}

pub fn license_count() -> i32 {
    unsafe { BNGetLicenseCount() }
}

/// Set the license that will be used once the core initializes. You can reset the license by passing `None`.
///
/// If not set the normal license retrieval will occur:
/// 1. Check the BN_LICENSE environment variable
/// 2. Check the Binary Ninja user directory for license.dat
#[cfg(not(feature = "demo"))]
pub fn set_license<S: BnStrCompatible + Default>(license: Option<S>) {
    let license = license.unwrap_or_default().into_bytes_with_nul();
    let license_slice = license.as_ref();
    unsafe { BNSetLicense(license_slice.as_ptr() as *const c_char) }
}

#[cfg(feature = "demo")]
pub fn set_license<S: BnStrCompatible + Default>(_license: Option<S>) {}

pub fn product() -> BnString {
    unsafe { BnString::from_raw(BNGetProduct()) }
}

pub fn product_type() -> BnString {
    unsafe { BnString::from_raw(BNGetProductType()) }
}

pub fn license_expiration_time() -> std::time::SystemTime {
    let m = std::time::Duration::from_secs(unsafe { BNGetLicenseExpirationTime() });
    std::time::UNIX_EPOCH + m
}

pub fn is_ui_enabled() -> bool {
    unsafe { BNIsUIEnabled() }
}

pub fn is_database<S: BnStrCompatible>(filename: S) -> bool {
    let filename = filename.into_bytes_with_nul();
    let filename_slice = filename.as_ref();
    unsafe { BNIsDatabase(filename_slice.as_ptr() as *const c_char) }
}

pub fn plugin_abi_version() -> u32 {
    BN_CURRENT_CORE_ABI_VERSION
}

pub fn plugin_abi_minimum_version() -> u32 {
    BN_MINIMUM_CORE_ABI_VERSION
}

pub fn core_abi_version() -> u32 {
    unsafe { BNGetCurrentCoreABIVersion() }
}

pub fn core_abi_minimum_version() -> u32 {
    unsafe { BNGetMinimumCoreABIVersion() }
}

pub fn plugin_ui_abi_version() -> u32 {
    BN_CURRENT_UI_ABI_VERSION
}

pub fn plugin_ui_abi_minimum_version() -> u32 {
    BN_MINIMUM_UI_ABI_VERSION
}

pub fn add_required_plugin_dependency<S: BnStrCompatible>(name: S) {
    unsafe {
        BNAddRequiredPluginDependency(name.into_bytes_with_nul().as_ref().as_ptr() as *const c_char)
    };
}

pub fn add_optional_plugin_dependency<S: BnStrCompatible>(name: S) {
    unsafe {
        BNAddOptionalPluginDependency(name.into_bytes_with_nul().as_ref().as_ptr() as *const c_char)
    };
}

// Provide ABI version automatically so that the core can verify binary compatibility
#[cfg(not(feature = "no_exports"))]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginABIVersion() -> u32 {
    plugin_abi_version()
}

#[cfg(not(feature = "no_exports"))]
#[no_mangle]
pub extern "C" fn UIPluginABIVersion() -> u32 {
    plugin_ui_abi_version()
}
