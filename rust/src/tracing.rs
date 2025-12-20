//! Integration with the [`tracing`](https://docs.rs/tracing) ecosystem. Send logs to and from Binary Ninja.
//!
//! This module allows you to use standard Rust `tracing` macros (like `info!`, `warn!`, `error!`)
//! and have them get sent to Binary Ninja, as well as the other way around with [`TracingLogListener`].
//!
//! ## For Plugins
//!
//! When writing a plugin, and you want your Rust logs to appear in the Binary Ninja UI, use the
//! [`crate::tracing_init`] macro at the start of your plugin's init function.
//!
//! ## For Headless
//!
//! When running headless (standalone executables), and you want internal Binary Ninja logs to appear
//! in your terminal's standard output, register the [`TracingLogListener`] after initializing your
//! tracing subscriber.
//!
//! ## Never use both [`BinaryNinjaLayer`] and [`TracingLogListener`] simultaneously
//!
//! Enabling both creates an infinite feedback loop where a log triggers a log, deadlocking the application.

use crate::file_metadata::SessionId;
use crate::logger::{
    bn_log_with_session, BnLogLevel, LogContext, LogGuard, LogListener, LOGGER_DEFAULT_SESSION_ID,
};
use tracing::{Event, Id, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// Helper macro to initialize the [`BinaryNinjaLayer`] tracing layer for plugins.
///
/// Maps the current crate name to the provided display name and enables target formatting.
/// Use [`init_with_layer`] if you intend on registering a [`BinaryNinjaLayer`] with non-default values.
///
/// ## Note for Plugins
///
/// This should **only** be called once, at the start of plugins.
///
/// ```no_run
/// #[unsafe(no_mangle)]
/// pub unsafe extern "C" fn CorePluginInit() -> bool {
///     binaryninja::tracing_init!("MyPlugin");
///     tracing::info!("Core plugin initialized");
///     true
/// }
/// ```
///
/// ## Note for Headless
///
/// This should **never** be called if you are running headlessly and as you will likely be
/// registering a [`LogListener`], which will possibly round-trip back to tracing logs and deadlock
/// the program.
#[macro_export]
macro_rules! tracing_init {
    () => {
        let layer = $crate::tracing::BinaryNinjaLayer::default();
        $crate::tracing::init_with_layer(layer);
    };
    ($name:expr) => {
        let layer = $crate::tracing::BinaryNinjaLayer::default()
            .with_target_mapping(env!("CARGO_CRATE_NAME"), $name);
        $crate::tracing::init_with_layer(layer);
    };
}

/// Initialize the core tracing subscriber with the given [`BinaryNinjaLayer`]. Collects and sends logs
/// to the core.
pub fn init_with_layer(layer: BinaryNinjaLayer) {
    let subscriber = tracing_subscriber::registry().with(layer);
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Subscribes to all spans and events emitted by `tracing` and forwards them to the core logging API.
#[derive(Clone)]
pub struct BinaryNinjaLayer {
    /// Rewrite mappings for the default target.
    ///
    /// # Example
    ///
    /// Given the target "my_crate::commands::analyze" and the mapping ("my_crate", "MyPlugin") the
    /// target will be rewritten to "MyPlugin::commands::analyze", assuming no other rewrites occur.
    pub target_mappings: Vec<(String, String)>,
    /// Whether the default target should be formatted to be displayed in the "common" logger name
    /// format for Binary Ninja.
    ///
    /// This formatting will only be applied when the target name is implicit. Explicitly provided
    /// target names will be preserved as-is.
    ///
    /// # Example
    ///
    /// Given the target "my_crate::commands::analyze" the target will be rewritten to "MyCrate.Commands.Analyze".
    pub format_target: bool,
}

impl BinaryNinjaLayer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a target mapping which will rewrite the `old` in the default target to `new`.
    ///
    /// This is typically done when you have a plugin name that is verbose, and you wish to display
    /// it in the logs as something else.
    pub fn with_target_mapping(mut self, old: &str, new: &str) -> Self {
        self.target_mappings
            .push((old.to_string(), new.to_string()));
        self
    }

    /// Whether formatting of the default target should be applied when sending logs to the core.
    pub fn with_format_target(mut self, formatted: bool) -> Self {
        self.format_target = formatted;
        self
    }
}

impl BinaryNinjaLayer {
    /// Rewrite the target so that the logger name will be displayed in the common Binary Ninja format.
    pub fn rewrite_target(&self, mut target: String) -> String {
        // Formats the target such that "my_crate::commands::analyze" becomes "MyPlugin.Commands.Analyze".
        let format_target = |target: &str| -> String {
            let mut result = String::with_capacity(target.len());
            let mut capitalize_next = true;
            let mut chars = target.chars().peekable();

            while let Some(c) = chars.next() {
                match c {
                    ':' if chars.peek() == Some(&':') => {
                        // Found "::", consume the second ':' and treat as a dot separator
                        chars.next();
                        result.push('.');
                        capitalize_next = true;
                    }
                    '.' => {
                        result.push('.');
                        capitalize_next = true;
                    }
                    '_' => {
                        // Treat underscore as a separator: strip it and capitalize next
                        capitalize_next = true;
                    }
                    _ if capitalize_next => {
                        for upper in c.to_uppercase() {
                            result.push(upper);
                        }
                        capitalize_next = false;
                    }
                    _ => {
                        result.push(c);
                    }
                }
            }

            result
        };

        // Perform "my_crate" -> "MyPlugin" rewrite rules.
        for (old, new) in &self.target_mappings {
            target = target.replace(old, new);
        }

        if self.format_target {
            target = format_target(&target);
        }

        target
    }
}

impl Default for BinaryNinjaLayer {
    fn default() -> Self {
        Self {
            target_mappings: vec![("binaryninja".to_string(), "Binary Ninja".to_string())],
            format_target: true,
        }
    }
}

impl<S> Layer<S> for BinaryNinjaLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &tracing::span::Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span not found in registry");

        let mut visitor = BnFieldVisitor::default();
        attrs.record(&mut visitor);

        // If this span has a session_id, store it in the span's extensions
        if let Some(session_id) = visitor.session_id {
            span.extensions_mut().insert(session_id);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let level = match *event.metadata().level() {
            Level::ERROR => BnLogLevel::ErrorLog,
            Level::WARN => BnLogLevel::WarningLog,
            Level::INFO => BnLogLevel::InfoLog,
            Level::DEBUG | Level::TRACE => BnLogLevel::DebugLog,
        };

        let mut visitor = BnFieldVisitor::default();
        event.record(&mut visitor);

        // Walk up the span tree to find the session id.
        // NOTE: Inserted by `BinaryNinjaLayer::on_new_span`.
        let session_from_scope = || {
            ctx.event_scope(event).and_then(|scope| {
                scope
                    .from_root()
                    .find_map(|span| span.extensions().get::<SessionId>().copied())
            })
        };

        // First we check the log event itself, then we check the scope context.
        let session_id = visitor
            .session_id
            .or_else(session_from_scope)
            .unwrap_or(LOGGER_DEFAULT_SESSION_ID);

        let mut logger_name = event.metadata().target().to_string();
        // Target is not overridden, we should try and apply mapping.
        if let Some(module_path) = event.metadata().module_path() {
            if module_path == logger_name {
                // Target is the default module path, rewrite it into a more friendly format.
                logger_name = self.rewrite_target(logger_name);
            }
        }

        bn_log_with_session(session_id, &logger_name, level, &visitor.message);
    }
}

#[derive(Default)]
struct BnFieldVisitor {
    message: String,
    session_id: Option<SessionId>,
}

impl tracing::field::Visit for BnFieldVisitor {
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if field.name() == "session_id" {
            self.session_id = Some(SessionId(value as usize));
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "session_id" {
            self.session_id = Some(SessionId(value as usize));
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write;
            let _ = write!(self.message, "{:?}", value);
        }
    }
}

/// A [`LogListener`] that forwards logs to the registered [`Subscriber`].
///
/// This should **never** be registered if the [`BinaryNinjaLayer`] is active. The [`BinaryNinjaLayer`]
/// will consume our events we send in this log listener and send them back to the core, causing a
/// never-ending cycle of sending and receiving the same logs.
///
/// Typically, you will register this listener for headless applications. You can technically use this
/// in a plugin, but it is likely that you are sending tracing logs to the core, in which case you will
/// run into the problem above.
///
/// ```no_run
/// use binaryninja::tracing::TracingLogListener;
/// use binaryninja::logger::{register_log_listener, BnLogLevel, bn_log};
/// use binaryninja::headless::Session;
///
/// pub fn main() {
///     // Register our tracing subscriber, this will send tracing events to stdout.
///     tracing_subscriber::fmt::init();
///     // Register our log listener, this will send logs from the core to our tracing subscriber.
///     let _listener = TracingLogListener::new().register();
///     // Should see logs from the core in regard to initialization show up.
///     let _session = Session::new().expect("Failed to create session");
///     bn_log("Test", BnLogLevel::DebugLog, "Hello, world!");
/// }
/// ```
pub struct TracingLogListener {
    minimum_level: BnLogLevel,
}

impl TracingLogListener {
    /// Create a [`TracingLogListener`] with the minimum log level set to [`BnLogLevel::InfoLog`].
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_lvl(minimum_level: BnLogLevel) -> Self {
        Self { minimum_level }
    }

    /// Register the [`TracingLogListener`] and send logs to the registered tracing subscriber until
    /// the [`LogGuard`] is dropped, make sure to register your tracing subscriber before registering.
    #[must_use]
    pub fn register(self) -> LogGuard<Self> {
        crate::logger::register_log_listener(self)
    }
}

impl Default for TracingLogListener {
    fn default() -> Self {
        Self {
            minimum_level: BnLogLevel::InfoLog,
        }
    }
}

impl LogListener for TracingLogListener {
    fn log(&self, ctx: &LogContext, level: BnLogLevel, message: &str) {
        let session = ctx.session_id.map(|s| s.0);
        match level {
            BnLogLevel::ErrorLog | BnLogLevel::AlertLog => {
                tracing::error!(
                    target: "binaryninja",
                    session_id = session,
                    logger = %ctx.logger_name,
                    "{}",
                    message
                )
            }
            BnLogLevel::WarningLog => {
                tracing::warn!(
                    target: "binaryninja",
                    session_id = session,
                    logger = %ctx.logger_name,
                    "{}",
                    message
                )
            }
            BnLogLevel::InfoLog => {
                tracing::info!(
                    target: "binaryninja",
                    session_id = session,
                    logger = %ctx.logger_name,
                    "{}",
                    message
                )
            }
            BnLogLevel::DebugLog => {
                tracing::debug!(
                    target: "binaryninja",
                    session_id = session,
                    logger = %ctx.logger_name,
                    "{}",
                    message
                )
            }
        };
    }

    fn level(&self) -> BnLogLevel {
        self.minimum_level
    }
}
