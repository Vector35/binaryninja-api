// Copyright 2021 Vector 35 Inc.
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

//! # Warning
//! > ⚠️ **These bindings are in a very early beta, only have partial support for the core APIs and are still actively under development. Compatibility _will_ break and conventions _will_ change! They are being used for core Binary Ninja features however, so we expect much of what is already there to be reliable enough to build on, just don't be surprised if your plugins/scripts need to hit a moving target.**

#[macro_use]
extern crate log;
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
// headless wrapper for shutdown
// platform cc

#[macro_use]
mod ffi;

pub mod architecture;
pub mod backgroundtask;
pub mod basicblock;
pub mod binaryview;
pub mod callingconvention;
pub mod command;
pub mod custombinaryview;
pub mod databuffer;
pub mod debuginfo;
pub mod disassembly;
pub mod fileaccessor;
pub mod filemetadata;
pub mod flowgraph;
pub mod function;
pub mod headless;
pub mod llil;
pub mod platform;
pub mod rc;
pub mod section;
pub mod segment;
pub mod settings;
pub mod string;
pub mod symbol;
pub mod types;

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub use binaryninjacore_sys::BNBranchType as BranchType;
pub use binaryninjacore_sys::BNEndianness as Endianness;

// Commented out to suppress unused warnings
// const BN_MAX_INSTRUCTION_LENGTH: u64 = 256;
// const BN_DEFAULT_NSTRUCTION_LENGTH: u64 = 16;
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

pub mod logger {
    use std::os::raw::{c_char, c_void};

    use log;

    use crate::string::BnStr;

    pub use binaryninjacore_sys::BNLogLevel as Level;
    use binaryninjacore_sys::{BNLogListener, BNUpdateLogListeners};

    struct Logger;
    static LOGGER: Logger = Logger;

    impl log::Log for Logger {
        fn enabled(&self, _metadata: &log::Metadata) -> bool {
            true
        }

        fn log(&self, record: &log::Record) {
            use self::Level::*;
            use binaryninjacore_sys::BNLog;
            use log::Level;
            use std::ffi::CString;

            let level = match record.level() {
                Level::Error => ErrorLog,
                Level::Warn => WarningLog,
                Level::Info => InfoLog,
                Level::Debug | Level::Trace => DebugLog,
            };

            if let Ok(msg) = CString::new(format!("{}", record.args())) {
                unsafe {
                    BNLog(level, msg.as_ptr());
                }
            };
        }

        fn flush(&self) {}
    }

    /// Uses BinaryNinja's logging functionality as the sink for
    /// Rust's `log` crate.
    pub fn init(filter: log::LevelFilter) -> Result<(), log::SetLoggerError> {
        log::set_max_level(filter);
        log::set_logger(&LOGGER)
    }

    pub trait LogListener: 'static + Sync {
        fn log(&self, level: Level, msg: &BnStr);
        fn level(&self) -> Level;
        fn close(&self) {}
    }

    pub struct LogGuard<L: LogListener> {
        ctxt: *mut L,
    }

    impl<L: LogListener> Drop for LogGuard<L> {
        fn drop(&mut self) {
            use binaryninjacore_sys::BNUnregisterLogListener;

            let mut bn_obj = BNLogListener {
                context: self.ctxt as *mut _,
                log: Some(cb_log::<L>),
                close: Some(cb_close::<L>),
                getLogLevel: Some(cb_level::<L>),
            };

            unsafe {
                BNUnregisterLogListener(&mut bn_obj);
                BNUpdateLogListeners();

                let _listener = Box::from_raw(self.ctxt);
            }
        }
    }

    pub fn register_listener<L: LogListener>(listener: L) -> LogGuard<L> {
        use binaryninjacore_sys::BNRegisterLogListener;

        let raw = Box::into_raw(Box::new(listener));
        let mut bn_obj = BNLogListener {
            context: raw as *mut _,
            log: Some(cb_log::<L>),
            close: Some(cb_close::<L>),
            getLogLevel: Some(cb_level::<L>),
        };

        unsafe {
            BNRegisterLogListener(&mut bn_obj);
            BNUpdateLogListeners();
        }

        LogGuard { ctxt: raw }
    }

    extern "C" fn cb_log<L>(ctxt: *mut c_void, level: Level, msg: *const c_char)
    where
        L: LogListener,
    {
        ffi_wrap!("LogListener::log", unsafe {
            let listener = &*(ctxt as *const L);
            listener.log(level, BnStr::from_raw(msg));
        })
    }

    extern "C" fn cb_close<L>(ctxt: *mut c_void)
    where
        L: LogListener,
    {
        ffi_wrap!("LogListener::close", unsafe {
            let listener = &*(ctxt as *const L);
            listener.close();
        })
    }

    extern "C" fn cb_level<L>(ctxt: *mut c_void) -> Level
    where
        L: LogListener,
    {
        ffi_wrap!("LogListener::log", unsafe {
            let listener = &*(ctxt as *const L);
            listener.level()
        })
    }
}

pub fn open_view<F: AsRef<Path>>(filename: F) -> Result<rc::Ref<binaryview::BinaryView>, String> {
    use crate::binaryview::BinaryViewExt;
    use crate::custombinaryview::BinaryViewTypeExt;

    let filename = filename.as_ref();

    let mut metadata = filemetadata::FileMetadata::with_filename(filename.to_str().unwrap());

    let mut is_bndb = false;
    let view = match match filename.ends_with(".bndb") {
        true => {
            match File::open(filename) {
                Ok(mut file) => {
                    let mut buf = [0; 15];
                    match file.read_exact(&mut buf) {
                        Ok(_) => {
                            let sqlite_string = "SQLite format 3";
                            if buf != sqlite_string.as_bytes() {
                                return Err("Not a valid BNDB (invalid magic)".to_string());
                            }
                        }
                        _ => return Err("Not a valid BNDB (too small)".to_string()),
                    }
                }
                _ => return Err("Could not open file".to_string()),
            }
            is_bndb = true;
            metadata.open_database(filename.to_str().unwrap())
        }
        false => binaryview::BinaryView::from_filename(&mut metadata, filename.to_str().unwrap()),
    } {
        Ok(view) => view,
        _ => return Err("Unable to open file".to_string()),
    };

    let mut bv = None;
    for available_view in custombinaryview::BinaryViewType::list_valid_types_for(&view).iter() {
        // TODO : These weird comparison arguments is probably symptomatic of something we should fix (fix other instance too)
        if bv.is_none() && **available_view.name() != *"Raw" {
            if is_bndb {
                bv = Some(
                    view.metadata()
                        .get_view_of_type(available_view.name())
                        .unwrap(),
                );
            } else {
                // TODO : add log prints
                // println!("Opening view of type: `{}`", available_view.name());
                bv = Some(available_view.open(&view).unwrap());
            }
            break;
        }
    }

    let bv = match bv {
        None => {
            if is_bndb {
                match view.metadata().get_view_of_type("Raw") {
                    Ok(view) => view,
                    _ => return Err("Could not get raw view from bndb".to_string()),
                }
            } else {
                match custombinaryview::BinaryViewType::by_name("Raw")
                    .unwrap()
                    .open(&view)
                {
                    Ok(view) => view,
                    _ => return Err("Could not open raw view".to_string()),
                }
            }
        }
        Some(bv) => bv,
    };

    bv.update_analysis_and_wait();
    Ok(bv)
}

pub fn open_view_with_options<F: AsRef<Path>>(
    filename: F,
    update_analysis_and_wait: bool,
    options: Option<HashMap<&str, &str>>,
) -> Result<rc::Ref<binaryview::BinaryView>, String> {
    //! This is incomplete, but should work in most cases:
    //! ```
    //! let settings = [("analysis.linearSweep.autorun", "false")]
    //!     .iter()
    //!     .cloned()
    //!     .collect();
    //!
    //! let bv = binaryninja::open_view_with_options("/bin/cat", true, Some(settings))
    //!     .expect("Couldn't open `/bin/cat`");
    //! ```

    use crate::binaryview::BinaryViewExt;
    use crate::custombinaryview::{BinaryViewTypeBase, BinaryViewTypeExt};

    let filename = filename.as_ref();

    let mut metadata = filemetadata::FileMetadata::with_filename(filename.to_str().unwrap());

    let mut is_bndb = false;
    let view = match match filename.ends_with(".bndb") {
        true => {
            match File::open(filename) {
                Ok(mut file) => {
                    let mut buf = [0; 15];
                    match file.read_exact(&mut buf) {
                        Ok(_) => {
                            let sqlite_string = "SQLite format 3";
                            if buf != sqlite_string.as_bytes() {
                                return Err("Not a valid BNDB (invalid magic)".to_string());
                            }
                        }
                        _ => return Err("Not a valid BNDB (too small)".to_string()),
                    }
                }
                _ => return Err("Could not open file".to_string()),
            }
            is_bndb = true;
            metadata.open_database_for_configuration(filename.to_str().unwrap())
        }
        false => binaryview::BinaryView::from_filename(&mut metadata, filename.to_str().unwrap()),
    } {
        Ok(view) => view,
        _ => return Err("Unable to open file".to_string()),
    };

    let mut universal_view_type = None;
    let mut view_type = None;
    for available_view in custombinaryview::BinaryViewType::list_valid_types_for(&view).iter() {
        if available_view.name().as_ref() == "Universal".as_bytes() {
            universal_view_type = Some(available_view);
        } else if view_type.is_none() && **available_view.name() != *"Raw" {
            view_type = Some(available_view);
        }
    }

    let view_type = match view_type {
        None => custombinaryview::BinaryViewType::by_name("Mapped").unwrap(),
        Some(view_type) => view_type,
    };

    let setting_id = format!("{}{}", view_type.name(), "_settings");
    let default_settings = settings::Settings::new(setting_id);
    default_settings.deserialize_schema(settings::Settings::new("").serialize_schema());
    default_settings.set_resource_id(view_type.name());

    let mut load_settings = match (is_bndb, view.load_settings(view_type.name())) {
        (true, Ok(settings)) => Some(settings),
        _ => None,
    };

    if load_settings.is_none() {
        // TODO : The Python version has a "fixme" here but I have no idea why
        if universal_view_type.is_some()
            && options.is_some()
            && options
                .as_ref()
                .unwrap()
                .contains_key("files.universal.architecturePreference")
        {
            load_settings = match universal_view_type
                .unwrap()
                .load_settings_for_data(view.as_ref())
            {
                Ok(settings) => Some(settings),
                _ => return Err("Could not load settings for universal view data".to_string()),
            };

            // let arch_list = load_settings.as_ref().unwrap().get_string(
            //     "loader.universal.architectures",
            //     None,
            //     None,
            // );

            // TODO : Need json support
            // let arch_list = arch_list.as_str();
            // let arch_list = arch_list[1..arch_list.len()].split("'");
            // arch_entry = [entry for entry in arch_list if entry['architecture'] == options['files.universal.architecturePreference'][0]]
            // if not arch_entry:
            //     log.log_error(f"Could not load {options['files.universal.architecturePreference'][0]} from Universal image. Entry not found!")
            //     return None

            // let tmp_load_settings = settings::Settings::new(BNGetUniqueIdentifierString());
            // tmp_load_settings.deserialize_schema(arch_entry[0]['loadSchema']);
            // load_settings = Some(tmp_load_settings);
        } else {
            load_settings = match view_type.load_settings_for_data(view.as_ref()) {
                Ok(settings) => Some(settings),
                _ => None,
            };
        }
    }
    if load_settings.is_none() {
        // log.log_error(f"Could not get load settings for binary view of type `{bvt.name}`")
        return Ok(view);
    }
    let load_settings = load_settings.unwrap();
    load_settings.set_resource_id(view_type.name());
    view.set_load_settings(view_type.name(), load_settings.as_ref());

    match options {
        Some(options) => {
            for (setting, value) in options {
                if load_settings.contains(setting) {
                    if !load_settings.set_json(setting, value, Some(view.as_ref()), None) {
                        return Err(format!("Setting: {} set operation failed!", setting));
                    }
                } else if default_settings.contains(setting) {
                    if !default_settings.set_json(setting, value, Some(view.as_ref()), None) {
                        return Err(format!("Setting: {} set operation failed!", setting));
                    }
                } else {
                    return Err(format!("Setting: {} not available!", setting));
                }
            }
        }
        None => (),
    }

    if is_bndb {
        let view = view
            .metadata()
            .open_database(filename.to_str().unwrap())
            .expect("Couldn't open database");
        let view_type_name = view_type.name();

        let bv = match view.metadata().get_view_of_type(view_type_name) {
            Ok(bv) => bv,
            _ => view,
        };

        if update_analysis_and_wait {
            bv.update_analysis_and_wait();
        }
        Ok(bv)
    } else {
        match view_type.open(&view) {
            Ok(bv) => {
                if update_analysis_and_wait {
                    bv.update_analysis_and_wait();
                }
                Ok(bv)
            }
            _ => Ok(view),
        }
    }
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

// Provide ABI version automatically so that the core can verify binary compatibility
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginABIVersion() -> u32 {
    plugin_abi_version()
}

#[no_mangle]
pub extern "C" fn UIPluginABIVersion() -> u32 {
    plugin_ui_abi_version()
}
