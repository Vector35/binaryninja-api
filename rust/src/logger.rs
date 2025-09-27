#![allow(clippy::needless_doctest_main)]

//! To use logging in your script, do something like:
//!
//! ```no-test
//! use binaryninja::logger::Logger;
//! use log::{info, LevelFilter};
//!
//! fn main() {
//!     Logger::default().init();
//!     info!("The logger has been initialized!");
//!     // Your code here...
//! }
//! ```
//!
//! or
//!
//!```no-test
//! use binaryninja::logger::Logger;
//! use log::{info, LevelFilter};
//!
//! #[no_mangle]
//! pub extern "C" fn CorePluginInit() -> bool {
//!     Logger::new("My Plugin").with_level(LevelFilter::Warn).init();
//!     info!("The logger has been initialized!");
//!     // Your code here...
//!     true
//! }
//! ```

pub use binaryninjacore_sys::BNLogLevel as Level;
use binaryninjacore_sys::{
    BNFreeLogger, BNLogCreateLogger, BNLogListener, BNLogger, BNLoggerGetName,
    BNLoggerGetSessionId, BNNewLoggerReference, BNUpdateLogListeners,
};

use crate::rc::{Ref, RefCountable};
use crate::string::{raw_to_string, BnString, IntoCStr};
use log;
use log::LevelFilter;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::ptr::NonNull;

const LOGGER_DEFAULT_SESSION_ID: usize = 0;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Logger {
    handle: NonNull<BNLogger>,
    level: LevelFilter,
}

impl Logger {
    pub fn new(name: &str) -> Ref<Logger> {
        Self::new_with_session(name, LOGGER_DEFAULT_SESSION_ID)
    }

    pub fn new_with_session(name: &str, session_id: usize) -> Ref<Logger> {
        let name_raw = CString::new(name).unwrap();
        let handle = unsafe { BNLogCreateLogger(name_raw.as_ptr(), session_id) };
        unsafe {
            Ref::new(Logger {
                handle: NonNull::new(handle).unwrap(),
                level: LevelFilter::Debug,
            })
        }
    }

    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNLoggerGetName(self.handle.as_ptr())) }
    }

    pub fn session_id(&self) -> usize {
        unsafe { BNLoggerGetSessionId(self.handle.as_ptr()) }
    }
}

// NOTE: Due to the ref counted core object, we must impl on the ref counted object.
// NOTE: If we wanted to be less specific than we would need Ref to impl Copy
impl Ref<Logger> {
    pub fn with_level(mut self, level: LevelFilter) -> Ref<Logger> {
        self.level = level;
        self
    }

    /// Calling this will set the global logger to `self`.
    ///
    /// NOTE: There is no guarantee that logs will be sent to BinaryNinja as another log sink
    /// may have already been initialized beforehand.
    pub fn init(self) {
        log::set_max_level(self.level);
        let _ = log::set_boxed_logger(Box::new(self));
    }

    /// Send a log to the logger instance, if you instead want to use the `log` crate and its facilities,
    /// you should use [`Ref<Logger>::init`] to initialize the `log` compatible logger.
    pub fn send_log(&self, level: Level, msg: &str) {
        use binaryninjacore_sys::BNLog;
        if let Ok(msg) = CString::new(format!("{}", msg)) {
            let logger_name = self.name().to_cstr();
            unsafe {
                BNLog(
                    self.session_id(),
                    level,
                    logger_name.as_ptr(),
                    0,
                    c"%s".as_ptr(),
                    msg.as_ptr(),
                )
            }
        }
    }
}

impl Default for Ref<Logger> {
    fn default() -> Self {
        Logger::new("Default")
    }
}

impl ToOwned for Logger {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Logger {
    unsafe fn inc_ref(logger: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewLoggerReference(logger.handle.as_ptr())).unwrap(),
            level: logger.level,
        })
    }

    unsafe fn dec_ref(logger: &Self) {
        BNFreeLogger(logger.handle.as_ptr());
    }
}

impl log::Log for Ref<Logger> {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        use self::Level::*;
        let level = match record.level() {
            log::Level::Error => ErrorLog,
            log::Level::Warn => WarningLog,
            log::Level::Info => InfoLog,
            log::Level::Debug | log::Level::Trace => DebugLog,
        };
        self.send_log(level, &format!("{}", record.args()));
    }

    fn flush(&self) {}
}

unsafe impl Send for Logger {}
unsafe impl Sync for Logger {}

pub trait LogListener: 'static + Sync {
    fn log(&self, session: usize, level: Level, msg: &str, logger_name: &str, tid: usize);
    fn level(&self) -> Level;
    fn close(&self) {}

    fn log_with_stack_trace(
        &self,
        session: usize,
        level: Level,
        _stack_trace: &str,
        msg: &str,
        logger_name: &str,
        tid: usize,
    ) {
        self.log(session, level, msg, logger_name, tid);
    }
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
            logWithStackTrace: Some(cb_log_with_stack_trace::<L>),
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
        logWithStackTrace: Some(cb_log_with_stack_trace::<L>),
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
        let msg_str = raw_to_string(msg).unwrap();
        let logger_name_str = raw_to_string(logger_name).unwrap();
        listener.log(session, level, &msg_str, &logger_name_str, tid);
    })
}

extern "C" fn cb_log_with_stack_trace<L>(
    ctxt: *mut c_void,
    session: usize,
    level: Level,
    stack_trace: *const c_char,
    msg: *const c_char,
    logger_name: *const c_char,
    tid: usize,
) where
    L: LogListener,
{
    ffi_wrap!("LogListener::log_with_stack_trace", unsafe {
        let listener = &*(ctxt as *const L);
        let stack_trace_str = raw_to_string(stack_trace).unwrap();
        let msg_str = raw_to_string(msg).unwrap();
        let logger_name_str = raw_to_string(logger_name).unwrap();
        listener.log_with_stack_trace(
            session,
            level,
            &stack_trace_str,
            &msg_str,
            &logger_name_str,
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
