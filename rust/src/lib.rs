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
pub extern crate binaryninjacore_sys; // For testing functions and stuff
#[cfg(feature = "ui")]
pub extern crate binaryninjaui_sys; // For testing functions and stuff
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

pub fn version() -> string::BnString {
    unsafe { string::BnString::from_raw(binaryninjacore_sys::BNGetVersionString()) }
}

// TODO : We need to get this from uitypes.h::BN_CURRENT_UI_ABI_VERSION
pub fn plugin_abi_version() -> u32 {
    2
}

// TODO : We need to get this from uitypes.h::BN_MINIMUM_UI_ABI_VERSION
pub fn plugin_abi_minimum_version() -> u32 {
    2
}

pub fn core_abi_version() -> u32 {
    unsafe { binaryninjacore_sys::BNGetCurrentCoreABIVersion() }
}

pub fn core_abi_minimum_version() -> u32 {
    unsafe { binaryninjacore_sys::BNGetMinimumCoreABIVersion() }
}

// Provide ABI version automatically so that the core can verify binary compatibility
#[cfg(any(windows, not(feature = "headless")))]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginABIVersion() -> u32 {
    core_abi_version()
}

// TODO : We need to get this from uitypes.h
#[cfg(any(windows, not(feature = "headless")))]
#[no_mangle]
pub extern "C" fn UIPluginABIVersion() -> u32 {
    plugin_abi_version()
}
