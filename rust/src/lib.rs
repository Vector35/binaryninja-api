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
//! > ⚠️ This project runs on Rust version `stable-2022-12-15`
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
//! ```
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
//! ```rust
//! fn main() {
//!     // This loads all the core architecture, platform, etc plugins
//!     // Standalone executables need to call this, but plugins do not
//!     let headless_session = binaryninja::headless::Session::new();
//!
//!     println!("Loading binary...");
//!     let bv = headless_session.load("/bin/cat").expect("Couldn't open `/bin/cat`");
//!
//!     // Your code here...
//! }
//! ```
//!
//! ### `Cargo.toml`
//! ```
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
extern crate libc;
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

pub mod architecture;
pub mod backgroundtask;
pub mod basicblock;
pub mod binaryreader;
pub mod binaryview;
pub mod binarywriter;
pub mod callingconvention;
pub mod command;
pub mod custombinaryview;
pub mod databuffer;
pub mod debuginfo;
pub mod demangle;
pub mod disassembly;
pub mod downloadprovider;
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
pub mod types;

use std::path::PathBuf;

pub use binaryninjacore_sys::BNBranchType as BranchType;
pub use binaryninjacore_sys::BNEndianness as Endianness;
use binaryview::BinaryView;
use metadata::Metadata;
use metadata::MetadataType;
use rc::Ref;
use string::BnStrCompatible;

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

/// The main way to open and load files into Binary Ninja. Make sure you've properly initialized the core before calling this function. See [`crate::headless::init()`]
pub fn load<S: BnStrCompatible>(filename: S) -> Option<rc::Ref<binaryview::BinaryView>> {
    let filename = filename.into_bytes_with_nul();
    let metadata = Metadata::new_of_type(MetadataType::KeyValueDataType);

    let handle = unsafe {
        binaryninjacore_sys::BNLoadFilename(
            filename.as_ref().as_ptr() as *mut _,
            true,
            None,
            metadata.handle,
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
/// ```rust
/// let settings = [("analysis.linearSweep.autorun", false)].into();
///
/// let bv = binaryninja::load_with_options("/bin/cat", true, Some(settings))
///     .expect("Couldn't open `/bin/cat`");
/// ```
pub fn load_with_options<S: BnStrCompatible>(
    filename: S,
    update_analysis_and_wait: bool,
    options: Option<Ref<Metadata>>,
) -> Option<rc::Ref<binaryview::BinaryView>> {
    let filename = filename.into_bytes_with_nul();

    let handle = unsafe {
        binaryninjacore_sys::BNLoadFilename(
            filename.as_ref().as_ptr() as *mut _,
            update_analysis_and_wait,
            None,
            if let Some(options) = options {
                options.as_ref().handle
            } else {
                Metadata::new_of_type(MetadataType::KeyValueDataType).handle
            },
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

pub fn version() -> string::BnString {
    unsafe { string::BnString::from_raw(binaryninjacore_sys::BNGetVersionString()) }
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
