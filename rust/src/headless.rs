// Copyright 2021-2023 Vector 35 Inc.
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

use crate::string::BnStrCompatible;

use std::env;
use std::path::PathBuf;

#[cfg(not(target_os = "windows"))]
fn binja_path() -> PathBuf {
    use std::ffi::{CStr, OsStr};
    use std::mem;
    use std::os::raw;
    use std::os::unix::ffi::OsStrExt;

    #[repr(C)]
    struct DlInfo {
        dli_fname: *const raw::c_char,
        dli_fbase: *mut raw::c_void,
        dli_sname: *const raw::c_char,
        dli_saddr: *mut raw::c_void,
    }

    if let Ok(p) = env::var("BINJA_DIR") {
        return PathBuf::from(p);
    }

    extern "C" {
        fn dladdr(addr: *mut raw::c_void, info: *mut DlInfo) -> raw::c_int;
    }

    unsafe {
        let mut info: DlInfo = mem::zeroed();

        if dladdr(BNSetBundledPluginDirectory as *mut _, &mut info) == 0 {
            panic!("Failed to find libbinaryninjacore path!");
        }

        if info.dli_fname.is_null() {
            panic!("Failed to find libbinaryninjacore path!");
        }

        let path = CStr::from_ptr(info.dli_fname);
        let path = OsStr::from_bytes(path.to_bytes());
        let mut path = PathBuf::from(path);

        path.pop();
        path
    }
}

#[cfg(target_os = "windows")]
fn binja_path() -> PathBuf {
    PathBuf::from(env::var("PROGRAMFILES").unwrap()).join("Vector35\\BinaryNinja\\")
}

use binaryninjacore_sys::{BNInitPlugins, BNInitRepoPlugins, BNSetBundledPluginDirectory};

/// Loads plugins, core architecture, platform, etc.
///
/// ⚠️ Important! Must be called at the beginning of scripts.  Plugins do not need to call this. ⚠️
pub fn init() {
    unsafe {
        let path = binja_path().join("plugins").into_os_string();
        let path = path.into_string().unwrap();

        BNSetBundledPluginDirectory(path.as_str().into_bytes_with_nul().as_ptr() as *mut _);
        BNInitPlugins(true);
        BNInitRepoPlugins();
    }
}

/// Unloads plugins, stops all worker threads, and closes open logs
///
/// ⚠️ Important! Must be called at the end of scripts. ⚠️
pub fn shutdown() {
    unsafe { binaryninjacore_sys::BNShutdown() };
}

/// Prelued-postlued helper function (calls [`init`] and [`shutdown`] for you)
/// ```rust
/// binaryninja::headless::script_helper(|| {
///     binaryninja::load("/bin/cat")
///         .expect("Couldn't open `/bin/cat`")
///         .iter()
///         .for_each(|func| println!("  `{}`", func.symbol().full_name()));
/// });
/// ```
pub fn script_helper(func: fn()) {
    init();
    func();
    shutdown();
}
