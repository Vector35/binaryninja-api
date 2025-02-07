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

use crate::{
    binary_view, bundled_plugin_directory, enterprise, is_license_validated, is_main_thread,
    license_path, set_bundled_plugin_directory, set_license, string::IntoJson,
};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use thiserror::Error;

use crate::enterprise::release_license;
use crate::main_thread::{MainThreadAction, MainThreadHandler};
use crate::progress::ProgressCallback;
use crate::rc::Ref;
use binaryninjacore_sys::{BNInitPlugins, BNInitRepoPlugins};
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::Duration;

static MAIN_THREAD_HANDLE: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

/// Used to prevent shutting down Binary Ninja if there are other [`Session`]'s.
static SESSION_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Error, Debug)]
pub enum InitializationError {
    #[error("main thread could not be started: {0}")]
    MainThreadNotStarted(#[from] io::Error),
    #[error("enterprise license checkout failed: {0:?}")]
    FailedEnterpriseCheckout(#[from] enterprise::EnterpriseCheckoutError),
    #[error("invalid license")]
    InvalidLicense,
    #[error("no license could located, please see `binaryninja::set_license` for details")]
    NoLicenseFound,
}

/// Loads plugins, core architecture, platform, etc.
///
/// ⚠️ Important! Must be called at the beginning of scripts.  Plugins do not need to call this. ⚠️
///
/// You can instead call this through [`Session`].
///
/// If you need to customize initialization, use [`init_with_opts`] instead.
pub fn init() -> Result<(), InitializationError> {
    let options = InitializationOptions::default();
    init_with_opts(options)
}

/// Unloads plugins, stops all worker threads, and closes open logs.
///
/// If the core was initialized using an enterprise license, that will also be freed.
///
/// ⚠️ Important! Must be called at the end of scripts. ⚠️
pub fn shutdown() {
    match crate::product().as_str() {
        "Binary Ninja Enterprise Client" | "Binary Ninja Ultimate" => enterprise::release_license(),
        _ => {}
    }
    unsafe { binaryninjacore_sys::BNShutdown() };
    release_license();
    // TODO: We might want to drop the main thread here, however that requires getting the handler ctx to drop the sender.
}

pub fn is_shutdown_requested() -> bool {
    unsafe { binaryninjacore_sys::BNIsShutdownRequested() }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InitializationOptions {
    /// A license to override with, you can use this to make sure you initialize with a specific license.
    pub license: Option<String>,
    /// If you need to make sure that you do not check out a license set this to false.
    ///
    /// This is really only useful if you have a headless license but are using an enterprise enabled core.
    pub checkout_license: bool,
    /// Whether to register the default main thread handler.
    ///
    /// Set this to false if you have your own main thread handler.
    pub register_main_thread_handler: bool,
    /// How long you want to check out for.
    pub floating_license_duration: Duration,
    /// The bundled plugin directory to use.
    pub bundled_plugin_directory: PathBuf,
    /// Whether to initialize user plugins.
    ///
    /// Set this to false if your use might be impacted by a user installed plugin.
    pub user_plugins: bool,
    /// Whether to initialize repo plugins.
    ///
    /// Set this to false if your use might be impacted by a repo installed plugin.
    pub repo_plugins: bool,
}

impl InitializationOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn minimal() -> Self {
        Self {
            user_plugins: false,
            repo_plugins: false,
            ..Self::default()
        }
    }

    /// A license to override with, you can use this to make sure you initialize with a specific license.
    ///
    /// This takes the form of a JSON array. The string should be formed like:
    /// ```json
    /// [{ /* json object with license data */ }]
    /// ```
    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.license = Some(license.into());
        self
    }

    /// If you need to make sure that you do not check out a license set this to false.
    ///
    /// This is really only useful if you have a headless license but are using an enterprise enabled core.
    pub fn with_license_checkout(mut self, should_checkout: bool) -> Self {
        self.checkout_license = should_checkout;
        self
    }

    /// Whether to register the default main thread handler.
    ///
    /// Set this to false if you have your own main thread handler.
    pub fn with_main_thread_handler(mut self, should_register: bool) -> Self {
        self.register_main_thread_handler = should_register;
        self
    }

    /// How long you want to check out for, only used if you are using a floating license.
    pub fn with_floating_license_duration(mut self, duration: Duration) -> Self {
        self.floating_license_duration = duration;
        self
    }

    /// Set this to false if your use might be impacted by a user installed plugin.
    pub fn with_user_plugins(mut self, should_initialize: bool) -> Self {
        self.user_plugins = should_initialize;
        self
    }

    /// Set this to false if your use might be impacted by a repo installed plugin.
    pub fn with_repo_plugins(mut self, should_initialize: bool) -> Self {
        self.repo_plugins = should_initialize;
        self
    }
}

impl Default for InitializationOptions {
    fn default() -> Self {
        Self {
            license: None,
            checkout_license: true,
            register_main_thread_handler: true,
            floating_license_duration: Duration::from_secs(900),
            bundled_plugin_directory: bundled_plugin_directory()
                .expect("Failed to get bundled plugin directory"),
            user_plugins: true,
            repo_plugins: true,
        }
    }
}

/// This initializes the core with the given [`InitializationOptions`].
pub fn init_with_opts(options: InitializationOptions) -> Result<(), InitializationError> {
    // If we are the main thread that means there is no main thread, we should register a main thread handler.
    if options.register_main_thread_handler && is_main_thread() {
        let mut main_thread_handle = MAIN_THREAD_HANDLE.lock().unwrap();
        if main_thread_handle.is_none() {
            let (sender, receiver) = std::sync::mpsc::channel();
            let main_thread = HeadlessMainThreadSender::new(sender);

            // This thread will act as our main thread.
            let join_handle = std::thread::Builder::new()
                .name("HeadlessMainThread".to_string())
                .spawn(move || {
                    // We must register the main thread within said thread.
                    main_thread.register();
                    while let Ok(action) = receiver.recv() {
                        action.execute();
                    }
                })?;

            // Set the static MAIN_THREAD_HANDLER so that we can close the thread on shutdown.
            *main_thread_handle = Some(join_handle);
        }
    }

    match crate::product().as_str() {
        "Binary Ninja Enterprise Client" | "Binary Ninja Ultimate" => {
            if options.checkout_license {
                // We are allowed to check out a license, so do it!
                enterprise::checkout_license(options.floating_license_duration)?;
            }
        }
        _ => {}
    }

    if let Some(license) = options.license {
        // We were given a license override, use it!
        set_license(Some(license));
    }

    set_bundled_plugin_directory(options.bundled_plugin_directory);

    unsafe {
        BNInitPlugins(options.user_plugins);
        if options.repo_plugins {
            // We are allowed to initialize repo plugins, so do it!
            BNInitRepoPlugins();
        }
    }

    if !is_license_validated() {
        // Unfortunately you must have a valid license to use Binary Ninja.
        Err(InitializationError::InvalidLicense)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub struct HeadlessMainThreadSender {
    sender: Sender<Ref<MainThreadAction>>,
}

impl HeadlessMainThreadSender {
    pub fn new(sender: Sender<Ref<MainThreadAction>>) -> Self {
        Self { sender }
    }
}

impl MainThreadHandler for HeadlessMainThreadSender {
    fn add_action(&self, action: Ref<MainThreadAction>) {
        self.sender
            .send(action)
            .expect("Failed to send action to main thread");
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum LicenseLocation {
    /// The license used when initializing will be the environment variable `BN_LICENSE`.
    EnvironmentVariable,
    /// The license used when initializing will be the file in the Binary Ninja user directory.
    File,
}

/// Attempts to identify the license location type, this follows the same order as core initialization.
///
/// This is useful if you want to know whether the core will use your license. If this returns `None`
/// you should look setting the `BN_LICENSE` environment variable, or calling [`set_license`].
pub fn license_location() -> Option<LicenseLocation> {
    match std::env::var("BN_LICENSE") {
        Ok(_) => Some(LicenseLocation::EnvironmentVariable),
        Err(_) => {
            // Check the license_path to see if a file is there.
            if license_path().exists() {
                Some(LicenseLocation::File)
            } else {
                None
            }
        }
    }
}

/// Wrapper for [`init`] and [`shutdown`]. Instantiating this at the top of your script will initialize everything correctly and then clean itself up at exit as well.
pub struct Session {}

impl Session {
    /// Get a registered [`Session`] for use.
    ///
    /// This is required so that we can keep track of the [`SESSION_COUNT`].
    fn registered_session() -> Self {
        let _previous_count = SESSION_COUNT.fetch_add(1, SeqCst);
        Self {}
    }

    /// Before calling new you must make sure that the license is retrievable, otherwise the core won't be able to initialize.
    ///
    /// If you cannot otherwise provide a license via `BN_LICENSE_FILE` environment variable or the Binary Ninja user directory
    /// you can call [`Session::new_with_opts`] instead of this function.
    pub fn new() -> Result<Self, InitializationError> {
        if license_location().is_some() {
            // We were able to locate a license, continue with initialization.
            // Grab the session before initialization to prevent another thread from initializing
            // and shutting down before this thread can increment the SESSION_COUNT.
            let session = Self::registered_session();
            init()?;
            Ok(session)
        } else {
            // There was no license that could be automatically retrieved, you must call [Self::new_with_license].
            Err(InitializationError::NoLicenseFound)
        }
    }

    /// Initialize with options, the same rules apply as [`Session::new`], see [`InitializationOptions::default`] for the regular options passed.
    ///
    /// This differs from [`Session::new`] in that it does not check to see if there is a license that the core
    /// can discover by itself, therefor it is expected that you know where your license is when calling this directly.
    pub fn new_with_opts(options: InitializationOptions) -> Result<Self, InitializationError> {
        init_with_opts(options)?;
        Ok(Self::registered_session())
    }

    /// ```no_run
    /// let headless_session = binaryninja::headless::Session::new().unwrap();
    ///
    /// let bv = headless_session
    ///     .load("/bin/cat")
    ///     .expect("Couldn't open `/bin/cat`");
    /// ```
    pub fn load(&self, file_path: impl AsRef<Path>) -> Option<Ref<binary_view::BinaryView>> {
        crate::load(file_path)
    }

    /// Load the file with a progress callback, the callback will _only_ be called for BNDBs currently.
    ///
    /// ```no_run
    /// let headless_session = binaryninja::headless::Session::new().unwrap();
    ///
    /// let print_progress = |progress, total| {
    ///     println!("{}/{}", progress, total);
    ///     true
    /// };
    ///
    /// let bv = headless_session
    ///     .load_with_progress("cat.bndb", print_progress)
    ///     .expect("Couldn't open `cat.bndb`");
    /// ```
    pub fn load_with_progress(
        &self,
        file_path: impl AsRef<Path>,
        progress: impl ProgressCallback,
    ) -> Option<Ref<binary_view::BinaryView>> {
        crate::load_with_progress(file_path, progress)
    }

    /// ```no_run
    /// use binaryninja::{metadata::Metadata, rc::Ref};
    /// use std::collections::HashMap;
    ///
    /// let settings: Ref<Metadata> =
    ///     HashMap::from([("analysis.linearSweep.autorun", false.into())]).into();
    /// let headless_session = binaryninja::headless::Session::new().unwrap();
    ///
    /// let bv = headless_session
    ///     .load_with_options("/bin/cat", true, Some(settings))
    ///     .expect("Couldn't open `/bin/cat`");
    /// ```
    pub fn load_with_options<O: IntoJson>(
        &self,
        file_path: impl AsRef<Path>,
        update_analysis_and_wait: bool,
        options: Option<O>,
    ) -> Option<Ref<binary_view::BinaryView>> {
        crate::load_with_options(file_path, update_analysis_and_wait, options)
    }

    /// Load the file with options and a progress callback, the callback will _only_ be called for BNDBs currently.
    ///
    /// ```no_run
    /// use binaryninja::{metadata::Metadata, rc::Ref};
    /// use std::collections::HashMap;
    ///
    /// let print_progress = |progress, total| {
    ///     println!("{}/{}", progress, total);
    ///     true
    /// };
    ///
    /// let settings: Ref<Metadata> =
    ///     HashMap::from([("analysis.linearSweep.autorun", false.into())]).into();
    /// let headless_session = binaryninja::headless::Session::new().unwrap();
    ///
    /// let bv = headless_session
    ///     .load_with_options_and_progress("cat.bndb", true, Some(settings), print_progress)
    ///     .expect("Couldn't open `cat.bndb`");
    /// ```
    pub fn load_with_options_and_progress<O: IntoJson>(
        &self,
        file_path: impl AsRef<Path>,
        update_analysis_and_wait: bool,
        options: Option<O>,
        progress: impl ProgressCallback,
    ) -> Option<Ref<binary_view::BinaryView>> {
        crate::load_with_options_and_progress(
            file_path,
            update_analysis_and_wait,
            options,
            progress,
        )
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let previous_count = SESSION_COUNT.fetch_sub(1, SeqCst);
        if previous_count == 1 {
            // We were the last session, therefor we can safely shut down.
            shutdown();
        }
    }
}
