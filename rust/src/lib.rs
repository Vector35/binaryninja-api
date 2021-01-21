#[macro_use]
extern crate log;
#[cfg(feature = "rayon")]
extern crate rayon;
extern crate libc;
extern crate binaryninjacore_sys;

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
pub mod basicblock;
pub mod binaryview;
pub mod segment;
pub mod section;
pub mod symbol;
pub mod callingconvention;
pub mod command;
pub mod fileaccessor;
pub mod filemetadata;
pub mod function;
pub mod platform;
pub mod llil;
pub mod types;
pub mod rc;
pub mod headless;
pub mod string;
pub mod settings;

pub use binaryninjacore_sys::BNEndianness as Endianness;
pub use binaryninjacore_sys::BNBranchType as BranchType;

pub mod logger {
    use std::os::raw::{c_void, c_char};

    use log;

    use crate::string::BnStr;

    use binaryninjacore_sys::{BNLogListener, BNUpdateLogListeners};
    pub use binaryninjacore_sys::BNLogLevel as Level;

    struct Logger;
    static LOGGER: Logger = Logger;

    impl log::Log for Logger {
        fn enabled(&self, _metadata: &log::Metadata) -> bool {
            true
        }

        fn log(&self, record: &log::Record) {
            use binaryninjacore_sys::BNLog;
            use std::ffi::CString;
            use self::Level::*;
            use log::Level;

            let level = match record.level() {
                Level::Error => ErrorLog,
                Level::Warn => WarningLog,
                Level::Info => InfoLog,
                Level::Debug |
                Level::Trace => DebugLog,
            };

            if let Ok(msg) = CString::new(format!("{}", record.args())) {
                unsafe { BNLog(level, msg.as_ptr()); }
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

        LogGuard {
            ctxt: raw,
        }
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
