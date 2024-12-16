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

// TODO : These clippy-allow are bad and needs to be removed
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::result_unit_err)]
#![allow(clippy::type_complexity)]
#![doc(html_root_url = "https://dev-rust.binary.ninja/binaryninja/")]
#![doc(html_favicon_url = "/favicon.ico")]
#![doc(html_logo_url = "/logo.png")]
#![doc(issue_tracker_base_url = "https://github.com/Vector35/binaryninja-api/issues/")]

//! This crate is the official [Binary Ninja] API wrapper for Rust.
//!
//! [Binary Ninja] is an interactive disassembler, decompiler, and binary analysis platform for reverse engineers, malware analysts, vulnerability researchers, and software developers that runs on Windows, macOS, and Linux. Our extensive API can be used to create and customize loaders, add or augment architectures, customize the UI, or automate any workflow (types, patches, decompilation...anything!).
//!
//! If you're just getting started with [Binary Ninja], you may wish to check out the [Getting Started Guide]
//!
//! If you have questions, we'd love to answer them in [our public Slack], and if you find any issues, please [file an issue] or [submit a PR].
//!
//! ---
//!  # Warning
//! <img align="right" src="../under_construction.png" width="175" height="175">
//!
//! > ⚠️ **These bindings are in a very early beta, only have partial support for the core APIs and are still actively under development. Compatibility _will_ break and conventions _will_ change! They are being used for core Binary Ninja features however, so we expect much of what is already there to be reliable enough to build on, just don't be surprised if your plugins/scripts need to hit a moving target.**
//!
//! > ⚠️ This project runs on Rust version `1.83.0`
//!
//! ---
//!
//! # Examples
//!
//! There are two distinct ways to use this crate:
//!  1. [Writing a Plugin](#writing-a-plugin)
//!  2. [Writing a Script](#writing-a-script)
//!
//! ## Writing a Plugin
//!
//! Create a new library (`cargo new --lib <plugin-name>`) and include the following in your `Cargo.toml`:
//!
//! ```toml
//! [lib]
//! crate-type = ["cdylib"]
//!
//! [dependencies]
//! binaryninja = {git = "https://github.com/Vector35/binaryninja-api.git", branch = "dev"}
//! ```
//!
//! In `lib.rs` you'll need to provide a `CorePluginInit` or `UIPluginInit` function for Binary Ninja to call.
//!
//! See [`command`] for the different actions you can provide and how to register your plugin with [Binary Ninja].
//!
//! ## Writing a Script:
//!
//! "Scripts" are binaries (`cargo new --bin <script-name>`), and have some specific requirements:
//!
//! ### build.rs
//!
//! Because [the only official method of providing linker arguments to a crate is through that crate's `build.rs`], all scripts need to provide their own `build.rs` so they can probably link with Binary Ninja.
//!
//! The most up-to-date version of the suggested [`build.rs` is here].
//!
//! ### `main.rs`
//! Standalone binaries need to initialize Binary Ninja before they can work. You can do this through [`headless::Session`], [`headless::script_helper`], or [`headless::init()`] at start and [`headless::shutdown()`] at shutdown.
//! ```no_run
//! // This loads all the core architecture, platform, etc plugins
//! // Standalone executables need to call this, but plugins do not
//! let headless_session = binaryninja::headless::Session::new();
//!
//! println!("Loading binary...");
//! let bv = headless_session.load("/bin/cat").expect("Couldn't open `/bin/cat`");
//!
//! // Your code here...
//! ```
//!
//! ### `Cargo.toml`
//! ```toml
//! [dependencies]
//! binaryninja = { git = "https://github.com/Vector35/binaryninja-api.git", branch = "dev"}
//! ```
//!
//! See the [examples] on GitHub for more comprehensive examples.
//!
//! [Binary Ninja]: https://binary.ninja/
//! [Getting Started Guide]: https://docs.binary.ninja/
//! [our public Slack]: https://join.slack.com/t/binaryninja/shared_invite/zt-3u4vu3ja-IGUF4ZWNlD7ER2ulvICvuQ
//! [file an issue]: https://github.com/Vector35/binaryninja-api/issues
//! [submit a PR]: https://github.com/Vector35/binaryninja-api/pulls
//! [the only official method of providing linker arguments to a crate is through that crate's `build.rs`]: https://github.com/rust-lang/cargo/issues/9554
//! [`build.rs` is here]: https://github.com/Vector35/binaryninja-api/blob/dev/rust/examples/template/build.rs
//! [examples]: https://github.com/Vector35/binaryninja-api/tree/dev/rust/examples
//!

#[macro_use]
extern crate log;
#[doc(hidden)]
pub extern crate binaryninjacore_sys;
#[cfg(feature = "rayon")]
extern crate rayon;

// TODO
// move some options to results
// replace `fn handle` with `AsRef` bounds
// possible values
// arch rework
// cc possible values
// bv reorg
// core fileaccessor (for bv saving)
// platform cc

#[macro_use]
mod ffi;
mod operand_iter;

pub mod architecture;
pub mod backgroundtask;
pub mod basicblock;
pub mod binaryreader;
pub mod binaryview;
pub mod binarywriter;
pub mod callingconvention;
pub mod command;
pub mod custombinaryview;
pub mod database;
pub mod databuffer;
pub mod debuginfo;
pub mod demangle;
pub mod disassembly;
pub mod enterprise;
pub mod component;
pub mod downloadprovider;
pub mod externallibrary;
pub mod fileaccessor;
pub mod filemetadata;
pub mod flowgraph;
pub mod function;
pub mod functionrecognizer;
pub mod headless;
pub mod hlil;
pub mod interaction;
pub mod linearview;
pub mod llil;
pub mod logger;
pub mod metadata;
pub mod mlil;
pub mod platform;
pub mod project;
pub mod rc;
pub mod references;
pub mod relocation;
pub mod section;
pub mod segment;
pub mod settings;
pub mod string;
pub mod symbol;
pub mod tags;
pub mod templatesimplifier;
pub mod typelibrary;
pub mod typearchive;
pub mod types;
pub mod update;
pub mod workflow;

use std::collections::HashMap;
use std::ffi::{c_void, CStr};
use std::path::PathBuf;
use std::ptr;
use binaryninjacore_sys::{BNBinaryView, BNFileMetadata, BNFunction, BNObjectDestructionCallbacks, BNRegisterObjectDestructionCallbacks, BNUnregisterObjectDestructionCallbacks};
pub use binaryninjacore_sys::BNBranchType as BranchType;
pub use binaryninjacore_sys::BNEndianness as Endianness;
use binaryview::BinaryView;
use metadata::Metadata;
use metadata::MetadataType;
use string::BnStrCompatible;
use string::IntoJson;
use crate::filemetadata::FileMetadata;
use crate::function::Function;
// Commented out to suppress unused warnings
// const BN_MAX_INSTRUCTION_LENGTH: u64 = 256;
// const BN_DEFAULT_INSTRUCTION_LENGTH: u64 = 16;
// const BN_DEFAULT_OPCODE_DISPLAY: u64 = 8;
// const BN_MAX_INSTRUCTION_BRANCHES: u64 = 3;
// const BN_MAX_STORED_DATA_LENGTH: u64 = 0x3fffffff;
// const BN_NULL_ID: i64 = -1;
// const BN_INVALID_REGISTER: usize = 0xffffffff;
// const BN_AUTOCOERCE_EXTERN_PTR: u64 = 0xfffffffd;
// const BN_NOCOERCE_EXTERN_PTR: u64 = 0xfffffffe;
// const BN_INVALID_OPERAND: u64 = 0xffffffff;
// const BN_MAX_STRING_LENGTH: u64 = 128;
// const BN_MAX_VARIABLE_OFFSET: u64 = 0x7fffffffff;
// const BN_MAX_VARIABLE_INDEX: u64 = 0xfffff;
// const BN_MINIMUM_CONFIDENCE: u8 = 1;
// const BN_HEURISTIC_CONFIDENCE: u8 = 192;

const BN_FULL_CONFIDENCE: u8 = 255;
const BN_INVALID_EXPR: usize = usize::MAX;

unsafe extern "C" fn cb_progress_func<F: FnMut(usize, usize) -> bool>(
    ctxt: *mut std::ffi::c_void,
    progress: usize,
    total: usize,
) -> bool {
    if ctxt.is_null() {
        return true;
    }
    let closure: &mut F = std::mem::transmute(ctxt);
    closure(progress, total)
}


unsafe extern "C" fn cb_progress_nop(
    _ctxt: *mut std::ffi::c_void,
    _arg1: usize,
    _arg2: usize
) -> bool {
    true
}


/// The main way to open and load files into Binary Ninja. Make sure you've properly initialized the core before calling this function. See [`crate::headless::init()`]
pub fn load<S>(
    filename: S,
) -> Option<rc::Ref<binaryview::BinaryView>>
where
    S: BnStrCompatible,
{
    let filename = filename.into_bytes_with_nul();
    let options = "\x00";


    let handle = unsafe {
        binaryninjacore_sys::BNLoadFilename(
            filename.as_ref().as_ptr() as *mut _,
            true,
            options.as_ptr() as *mut core::ffi::c_char,
            Some(cb_progress_nop),
            ptr::null_mut(),
        )
    };

    if handle.is_null() {
        None
    } else {
        Some(unsafe { BinaryView::from_raw(handle) })
    }
}

pub fn load_with_progress<S, F>(
    filename: S,
    mut progress: F,
) -> Option<rc::Ref<binaryview::BinaryView>>
where
    S: BnStrCompatible,
    F: FnMut(usize, usize) -> bool,
{
    let filename = filename.into_bytes_with_nul();
    let options = "\x00";

    let progress_ctx = &mut progress as *mut F as *mut std::ffi::c_void;

    let handle = unsafe {
        binaryninjacore_sys::BNLoadFilename(
            filename.as_ref().as_ptr() as *mut _,
            true,
            options.as_ptr() as *mut core::ffi::c_char,
            Some(cb_progress_func::<F>),
            progress_ctx,
        )
    };

    if handle.is_null() {
        None
    } else {
        Some(unsafe { BinaryView::from_raw(handle) })
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
pub fn load_with_options<S, O>(
    filename: S,
    update_analysis_and_wait: bool,
    options: Option<O>,
) -> Option<rc::Ref<binaryview::BinaryView>>
where
    S: BnStrCompatible,
    O: IntoJson,
{
    let filename = filename.into_bytes_with_nul();

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
        binaryninjacore_sys::BNLoadFilename(
            filename.as_ref().as_ptr() as *mut _,
            update_analysis_and_wait,
            options_or_default.as_ptr() as *mut core::ffi::c_char,
            Some(cb_progress_nop),
            core::ptr::null_mut(),
        )
    };

    if handle.is_null() {
        None
    } else {
        Some(unsafe { BinaryView::from_raw(handle) })
    }
}

pub fn load_with_options_and_progress<S, O, F>(
    filename: S,
    update_analysis_and_wait: bool,
    options: Option<O>,
    progress: Option<F>,
) -> Option<rc::Ref<binaryview::BinaryView>>
where
    S: BnStrCompatible,
    O: IntoJson,
    F: FnMut(usize, usize) -> bool,
{
    let filename = filename.into_bytes_with_nul();

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

    let progress_ctx = match progress {
        Some(mut x) => &mut x as *mut F as *mut std::ffi::c_void,
        None => core::ptr::null_mut()
    };

    let handle = unsafe {
        binaryninjacore_sys::BNLoadFilename(
            filename.as_ref().as_ptr() as *mut _,
            update_analysis_and_wait,
            options_or_default.as_ptr() as *mut core::ffi::c_char,
            Some(cb_progress_func::<F>),
            progress_ctx,
        )
    };

    if handle.is_null() {
        None
    } else {
        Some(unsafe { BinaryView::from_raw(handle) })
    }
}

pub fn load_view<O>(
    bv: &BinaryView,
    update_analysis_and_wait: bool,
    options: Option<O>,
) -> Option<rc::Ref<binaryview::BinaryView>>
where
    O: IntoJson,
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
        binaryninjacore_sys::BNLoadBinaryView(
            bv.handle as *mut _,
            update_analysis_and_wait,
            options_or_default.as_ptr() as *mut core::ffi::c_char,
            Some(cb_progress_nop),
            core::ptr::null_mut(),
        )
    };

    if handle.is_null() {
        None
    } else {
        Some(unsafe { BinaryView::from_raw(handle) })
    }
}

pub fn load_view_with_progress<O, F>(
    bv: &BinaryView,
    update_analysis_and_wait: bool,
    options: Option<O>,
    progress: Option<F>,
) -> Option<rc::Ref<binaryview::BinaryView>>
where
    O: IntoJson,
    F: FnMut(usize, usize) -> bool,
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

    let progress_ctx = match progress {
        Some(mut x) => &mut x as *mut F as *mut std::ffi::c_void,
        None => core::ptr::null_mut()
    };

    let handle = unsafe {
        binaryninjacore_sys::BNLoadBinaryView(
            bv.handle as *mut _,
            update_analysis_and_wait,
            options_or_default.as_ptr() as *mut core::ffi::c_char,
            Some(cb_progress_func::<F>),
            progress_ctx,
        )
    };

    if handle.is_null() {
        None
    } else {
        Some(unsafe { BinaryView::from_raw(handle) })
    }
}

pub fn install_directory() -> Result<PathBuf, ()> {
    let s: *mut std::os::raw::c_char = unsafe { binaryninjacore_sys::BNGetInstallDirectory() };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(
        unsafe { string::BnString::from_raw(s) }.to_string(),
    ))
}

pub fn bundled_plugin_directory() -> Result<PathBuf, ()> {
    let s: *mut std::os::raw::c_char =
        unsafe { binaryninjacore_sys::BNGetBundledPluginDirectory() };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(
        unsafe { string::BnString::from_raw(s) }.to_string(),
    ))
}

pub fn set_bundled_plugin_directory<S: string::BnStrCompatible>(new_dir: S) {
    unsafe {
        binaryninjacore_sys::BNSetBundledPluginDirectory(
            new_dir.into_bytes_with_nul().as_ref().as_ptr() as *const std::os::raw::c_char,
        )
    };
}

pub fn user_directory() -> Result<PathBuf, ()> {
    let s: *mut std::os::raw::c_char = unsafe { binaryninjacore_sys::BNGetUserDirectory() };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(
        unsafe { string::BnString::from_raw(s) }.to_string(),
    ))
}

pub fn user_plugin_directory() -> Result<PathBuf, ()> {
    let s: *mut std::os::raw::c_char = unsafe { binaryninjacore_sys::BNGetUserPluginDirectory() };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(
        unsafe { string::BnString::from_raw(s) }.to_string(),
    ))
}

pub fn repositories_directory() -> Result<PathBuf, ()> {
    let s: *mut std::os::raw::c_char = unsafe { binaryninjacore_sys::BNGetRepositoriesDirectory() };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(
        unsafe { string::BnString::from_raw(s) }.to_string(),
    ))
}

pub fn settings_file_name() -> Result<PathBuf, ()> {
    let s: *mut std::os::raw::c_char = unsafe { binaryninjacore_sys::BNGetSettingsFileName() };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(
        unsafe { string::BnString::from_raw(s) }.to_string(),
    ))
}

pub fn save_last_run() {
    unsafe { binaryninjacore_sys::BNSaveLastRun() };
}

pub fn path_relative_to_bundled_plugin_directory<S: string::BnStrCompatible>(
    path: S,
) -> Result<PathBuf, ()> {
    let s: *mut std::os::raw::c_char = unsafe {
        binaryninjacore_sys::BNGetPathRelativeToBundledPluginDirectory(
            path.into_bytes_with_nul().as_ref().as_ptr() as *const std::os::raw::c_char,
        )
    };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(
        unsafe { string::BnString::from_raw(s) }.to_string(),
    ))
}

pub fn path_relative_to_user_plugin_directory<S: string::BnStrCompatible>(
    path: S,
) -> Result<PathBuf, ()> {
    let s: *mut std::os::raw::c_char = unsafe {
        binaryninjacore_sys::BNGetPathRelativeToUserPluginDirectory(
            path.into_bytes_with_nul().as_ref().as_ptr() as *const std::os::raw::c_char,
        )
    };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(
        unsafe { string::BnString::from_raw(s) }.to_string(),
    ))
}

pub fn path_relative_to_user_directory<S: string::BnStrCompatible>(path: S) -> Result<PathBuf, ()> {
    let s: *mut std::os::raw::c_char = unsafe {
        binaryninjacore_sys::BNGetPathRelativeToUserDirectory(
            path.into_bytes_with_nul().as_ref().as_ptr() as *const std::os::raw::c_char,
        )
    };
    if s.is_null() {
        return Err(());
    }
    Ok(PathBuf::from(
        unsafe { string::BnString::from_raw(s) }.to_string(),
    ))
}

pub fn memory_info() -> HashMap<String, u64> {
    let mut count = 0;
    let mut usage = HashMap::new();
    unsafe {
        let info_ptr = binaryninjacore_sys::BNGetMemoryUsageInfo(&mut count);
        let info_list = std::slice::from_raw_parts(info_ptr, count);
        for info in info_list {
            let info_name = CStr::from_ptr(info.name).to_str().unwrap().to_string();
            usage.insert(info_name, info.value);
        }
        binaryninjacore_sys::BNFreeMemoryUsageInfo(info_ptr, count);
    }
    usage
}

/// The trait required for receiving core object destruction callbacks.
pub trait ObjectDestructor: 'static + Sync + Sized {
    fn destruct_view(&self, _view: &BinaryView) {}
    fn destruct_file_metadata(&self, _metadata: &FileMetadata) {}
    fn destruct_function(&self, _func: &Function) {}

    unsafe extern "C" fn cb_destruct_binary_view(ctxt: *mut c_void, view: *mut BNBinaryView)
    {
        ffi_wrap!("ObjectDestructor::destruct_view", {
            let view_type = &*(ctxt as *mut Self);
            let view = BinaryView { handle: view };
            view_type.destruct_view(&view);
        })
    }

    unsafe extern "C" fn cb_destruct_file_metadata(ctxt: *mut c_void, file: *mut BNFileMetadata)
    {
        ffi_wrap!("ObjectDestructor::destruct_file_metadata", {
            let view_type = &*(ctxt as *mut Self);
            let file = FileMetadata::from_raw(file);
            view_type.destruct_file_metadata(&file);
        })
    }

    unsafe extern "C" fn cb_destruct_function(ctxt: *mut c_void, func: *mut BNFunction)
    {
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

pub fn version() -> string::BnString {
    unsafe { string::BnString::from_raw(binaryninjacore_sys::BNGetVersionString()) }
}

pub fn build_id() -> u32 {
    unsafe { binaryninjacore_sys::BNGetBuildId() }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VersionInfo {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub channel: string::BnString,
}

pub fn version_info() -> VersionInfo {
    let info_raw = unsafe { binaryninjacore_sys::BNGetVersionInfo() };
    VersionInfo {
        major: info_raw.major,
        minor: info_raw.minor,
        build: info_raw.build,
        channel: unsafe { string::BnString::from_raw(info_raw.channel) },
    }
}

pub fn serial_number() -> string::BnString {
    unsafe { string::BnString::from_raw(binaryninjacore_sys::BNGetSerialNumber()) }
}

pub fn is_license_validated() -> bool {
    unsafe { binaryninjacore_sys::BNIsLicenseValidated() }
}

pub fn licensed_user_email() -> string::BnString {
    unsafe { string::BnString::from_raw(binaryninjacore_sys::BNGetLicensedUserEmail()) }
}

pub fn license_count() -> i32 {
    unsafe { binaryninjacore_sys::BNGetLicenseCount() }
}

pub fn set_license<S: string::BnStrCompatible>(license: S) {
    let license = license.into_bytes_with_nul();
    let license_slice = license.as_ref();
    unsafe { binaryninjacore_sys::BNSetLicense(license_slice.as_ptr() as *const std::os::raw::c_char) }
}

pub fn product() -> string::BnString {
    unsafe { string::BnString::from_raw(binaryninjacore_sys::BNGetProduct()) }
}

pub fn product_type() -> string::BnString {
    unsafe { string::BnString::from_raw(binaryninjacore_sys::BNGetProductType()) }
}

pub fn license_expiration_time() -> std::time::SystemTime {
    let m = std::time::Duration::from_secs(unsafe {
        binaryninjacore_sys::BNGetLicenseExpirationTime()
    });
    std::time::UNIX_EPOCH + m
}

pub fn is_ui_enabled() -> bool {
    unsafe { binaryninjacore_sys::BNIsUIEnabled() }
}

pub fn is_database<S: string::BnStrCompatible>(filename: S) -> bool {
    let filename = filename.into_bytes_with_nul();
    let filename_slice = filename.as_ref();
    unsafe { binaryninjacore_sys::BNIsDatabase(filename_slice.as_ptr() as *const std::os::raw::c_char) }
}

pub fn plugin_abi_version() -> u32 {
    binaryninjacore_sys::BN_CURRENT_CORE_ABI_VERSION
}

pub fn plugin_abi_minimum_version() -> u32 {
    binaryninjacore_sys::BN_MINIMUM_CORE_ABI_VERSION
}

pub fn core_abi_version() -> u32 {
    unsafe { binaryninjacore_sys::BNGetCurrentCoreABIVersion() }
}

pub fn core_abi_minimum_version() -> u32 {
    unsafe { binaryninjacore_sys::BNGetMinimumCoreABIVersion() }
}

pub fn plugin_ui_abi_version() -> u32 {
    binaryninjacore_sys::BN_CURRENT_UI_ABI_VERSION
}

pub fn plugin_ui_abi_minimum_version() -> u32 {
    binaryninjacore_sys::BN_MINIMUM_UI_ABI_VERSION
}

pub fn add_required_plugin_dependency<S: string::BnStrCompatible>(name: S) {
    unsafe {
        binaryninjacore_sys::BNAddRequiredPluginDependency(
            name.into_bytes_with_nul().as_ref().as_ptr() as *const std::os::raw::c_char,
        )
    };
}

pub fn add_optional_plugin_dependency<S: string::BnStrCompatible>(name: S) {
    unsafe {
        binaryninjacore_sys::BNAddOptionalPluginDependency(
            name.into_bytes_with_nul().as_ref().as_ptr() as *const std::os::raw::c_char,
        )
    };
}

// Provide ABI version automatically so that the core can verify binary compatibility
#[cfg(not(feature = "noexports"))]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginABIVersion() -> u32 {
    plugin_abi_version()
}

#[cfg(not(feature = "noexports"))]
#[no_mangle]
pub extern "C" fn UIPluginABIVersion() -> u32 {
    plugin_ui_abi_version()
}
