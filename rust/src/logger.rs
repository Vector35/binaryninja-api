//! Core [`Logger`] implementation, see [`crate::tracing`] for typical plugin and headless usage.
//!
//! This module defines the core logger model, which is typically not used directly and instead is used
//! via the [`crate::tracing`] implementations. If you require a custom [`LogListener`] or need to log
//! directly to the core instead of through `tracing` macros, that is what this module is useful for.
use crate::file_metadata::SessionId;
use crate::rc::{Ref, RefCountable};
use crate::string::{raw_to_string, BnString, IntoCStr};
use binaryninjacore_sys::*;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::ptr::NonNull;

// Used for documentation purposes.
#[allow(unused_imports)]
use crate::binary_view::BinaryView;

pub use binaryninjacore_sys::BNLogLevel as BnLogLevel;

pub const LOGGER_DEFAULT_SESSION_ID: SessionId = SessionId(0);

/// Send a global log message **to the core**.
///
/// Prefer [`bn_log_with_session`] when a [`SessionId`] is available, via binary views file metadata.
pub fn bn_log(logger: &str, level: BnLogLevel, msg: &str) {
    bn_log_with_session(LOGGER_DEFAULT_SESSION_ID, logger, level, msg);
}

/// Send a session-scoped log message **to the core**.
///
/// The [`SessionId`] is how you attribute the log to a specific [`BinaryView`]. Without passing
/// a session, logs will be shown in the UI globally, which you should not do if you can avoid it.
pub fn bn_log_with_session(session_id: SessionId, logger: &str, level: BnLogLevel, msg: &str) {
    if let Ok(msg) = CString::new(msg) {
        let logger_name = logger.to_cstr();
        unsafe {
            BNLog(
                session_id.0,
                level,
                logger_name.as_ptr(),
                0,
                c"%s".as_ptr(),
                msg.as_ptr(),
            )
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Logger {
    handle: NonNull<BNLogger>,
}

impl Logger {
    /// Create a logger with the given name.
    pub fn new(name: &str) -> Ref<Logger> {
        Self::new_with_session(name, LOGGER_DEFAULT_SESSION_ID)
    }

    /// Create a logger scoped with the specific [`SessionId`], hiding the logs when the session
    /// is not active in the UI.
    ///
    /// # Example
    ///
    /// Typically, you will want to retrieve the [`SessionId`] from the [`BinaryView`] file metadata
    ///
    /// ```no_run
    /// # use binaryninja::binary_view::BinaryView;
    /// # use binaryninja::logger::Logger;
    /// # let bv: BinaryView = todo!();
    /// Logger::new_with_session("MyLogger", bv.file().session_id());
    /// ```
    pub fn new_with_session(name: &str, session_id: SessionId) -> Ref<Logger> {
        let name_raw = CString::new(name).unwrap();
        let handle = unsafe { BNLogCreateLogger(name_raw.as_ptr(), session_id.0) };
        unsafe {
            Ref::new(Logger {
                handle: NonNull::new(handle).unwrap(),
            })
        }
    }

    /// Name of the logger instance.
    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNLoggerGetName(self.handle.as_ptr())) }
    }

    /// The [`SessionId`] associated with the logger instance.
    ///
    /// The [`SessionId`] is how the core knows to associate logs with a specific opened binary,
    /// hiding other sessions (binaries) logs when not active in the UI.
    pub fn session_id(&self) -> Option<SessionId> {
        let raw = unsafe { BNLoggerGetSessionId(self.handle.as_ptr()) };
        match raw {
            0 => None,
            _ => Some(SessionId(raw)),
        }
    }

    /// Send a log to the logger instance.
    ///
    /// If you do not have a [`Logger`] you may call [`bn_log`] or [`bn_log_with_session`].
    pub fn log(&self, level: BnLogLevel, msg: &str) {
        let session = self.session_id().unwrap_or(LOGGER_DEFAULT_SESSION_ID);
        bn_log_with_session(session, &self.name(), level, msg);
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
        })
    }

    unsafe fn dec_ref(logger: &Self) {
        BNFreeLogger(logger.handle.as_ptr());
    }
}

unsafe impl Send for Logger {}
unsafe impl Sync for Logger {}

/// Register a [`LogListener`] that will receive log messages **from the core**.
///
/// This is typically used in headless usage. It can also be used to temporarily log core
/// messages to something like a file while some analysis is occurring, once the [`LogGuard`] is
/// dropped, the listener will be unregistered.
#[must_use]
pub fn register_log_listener<L: LogListener>(listener: L) -> LogGuard<L> {
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

/// The context associated with a log message received from the core as part of a [`LogListener`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogContext<'a> {
    /// The optional [`SessionId`] associated with the log message.
    ///
    /// This will correspond with a [`BinaryView`] file's [`SessionId`].
    pub session_id: Option<SessionId>,
    /// The thread ID associated with the log message.
    pub thread_id: usize,
    /// The optional stack trace associated with the log message.
    pub stack_trace: Option<&'a str>,
    /// The target [`Logger`] for the log message.
    pub logger_name: &'a str,
}

/// The trait implemented by objects that wish to receive log messages from the core.
///
/// Currently, we supply one implementation of this trait called [`crate::tracing::TracingLogListener`]
/// which will send the core logs to the registered tracing subscriber.
pub trait LogListener: 'static + Sync {
    /// Called when a log message is received from the core.
    ///
    /// Logs will only be sent that are above the desired [`LogListener::level`].
    fn log(&self, ctx: &LogContext, lvl: BnLogLevel, msg: &str);

    /// The desired minimum log level, any logs below this level will be ignored.
    ///
    /// For example, returning [`BnLogLevel::InfoLog`] will result in [`BnLogLevel::DebugLog`] logs
    /// being ignored by this listener.
    fn level(&self) -> BnLogLevel;

    /// Called when the listener is unregistered.
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

extern "C" fn cb_log<L>(
    ctxt: *mut c_void,
    session: usize,
    level: BnLogLevel,
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
        let session_id = match session {
            0 => None,
            _ => Some(SessionId(session)),
        };
        let ctx = LogContext {
            session_id,
            thread_id: tid,
            stack_trace: None,
            logger_name: &logger_name_str,
        };
        listener.log(&ctx, level, &msg_str);
    })
}

extern "C" fn cb_log_with_stack_trace<L>(
    ctxt: *mut c_void,
    session: usize,
    level: BnLogLevel,
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
        let session_id = match session {
            0 => None,
            _ => Some(SessionId(session)),
        };
        let ctx = LogContext {
            session_id,
            thread_id: tid,
            stack_trace: Some(&stack_trace_str),
            logger_name: &logger_name_str,
        };
        listener.log(&ctx, level, &msg_str);
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

extern "C" fn cb_level<L>(ctxt: *mut c_void) -> BnLogLevel
where
    L: LogListener,
{
    ffi_wrap!("LogListener::log", unsafe {
        let listener = &*(ctxt as *const L);
        listener.level()
    })
}
