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
                BNLog(0, level, std::ptr::null(), 0, msg.as_ptr());
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
    fn log(&self, session: usize, level: Level, msg: &BnStr, logger_name: &BnStr, tid: usize);
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
            BnStr::from_raw(msg),
            BnStr::from_raw(logger_name),
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
