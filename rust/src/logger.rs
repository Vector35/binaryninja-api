#![allow(clippy::needless_doctest_main)]

//! To use logging in your script, do something like:
//!
//! ```no-test
//! use binaryninja::logger;
//! use log::{info, LevelFilter};
//!
//! fn main() {
//!     logger::init(LevelFilter::Warn).expect("Unable to initialize logger");
//!     info!("The logger has been initialized!");
//!     // Your code here...
//! }
//! ```
//!
//! or
//!
//!```no-test
//! use binaryninja::logger;
//! use log::{info, LevelFilter};
//!
//! #[no_mangle]
//! pub extern "C" fn CorePluginInit() -> bool {
//!     logger::init(LevelFilter::Warn).expect("Unable to initialize logger");
//!     info!("The logger has been initialized!");
//!     // Your code here...
//!     true
//! }
//! ```
//!

pub use binaryninjacore_sys::BNLogLevel as Level;
use binaryninjacore_sys::{BNLogListener, BNUpdateLogListeners};

use log;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

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
            let percent_s = CString::new("%s").expect("'%s' has no null bytes");
            unsafe {
                BNLog(
                    0,
                    level,
                    std::ptr::null(),
                    0,
                    percent_s.as_ptr(),
                    msg.as_ptr(),
                );
            }
        };
    }

    fn flush(&self) {}
}

/// Uses BinaryNinja's logging functionality as the sink for Rust's `log` crate.
/// 
/// NOTE: There is no guarantee that logs will be sent to BinaryNinja as another log sink
/// may have already been initialized beforehand.
pub fn init(filter: log::LevelFilter) {
    log::set_max_level(filter);
    let _ = log::set_logger(&LOGGER);
}

pub trait LogListener: 'static + Sync {
    fn log(&self, session: usize, level: Level, msg: &CStr, logger_name: &CStr, tid: usize);
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

extern "C" fn cb_log<L>(
    ctxt: *mut c_void,
    session: usize,
    level: Level,
    msg: *const c_char,
    logger_name: *const c_char,
    tid: usize,
) where
    L: LogListener,
{
    ffi_wrap!("LogListener::log", unsafe {
        let listener = &*(ctxt as *const L);
        listener.log(
            session,
            level,
            CStr::from_ptr(msg),
            CStr::from_ptr(logger_name),
            tid,
        );
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
