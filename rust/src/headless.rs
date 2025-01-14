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
    binaryview, bundled_plugin_directory, enterprise, is_license_validated, is_main_thread,
    license_path, set_bundled_plugin_directory, set_license, string::IntoJson,
};
use std::io;
use thiserror::Error;

use crate::mainthread::{MainThreadAction, MainThreadHandler};
use crate::rc::Ref;
use binaryninjacore_sys::{BNInitPlugins, BNInitRepoPlugins};
use std::sync::mpsc::Sender;
use std::time::Duration;

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

/// Loads plugins, core architecture, platform, etc.
///
/// ⚠️ Important! Must be called at the beginning of scripts.  Plugins do not need to call this. ⚠️
///
/// You can instead call this through [`Session`].
///
/// If you are using a custom [`MainThreadHandler`] than use [`init_without_main_thread`] instead.
pub fn init() -> Result<(), InitializationError> {
    // If we are the main thread that means there is no main thread.
    if is_main_thread() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let main_thread = HeadlessMainThreadSender::new(sender);

        // This thread will act as our main thread.
        std::thread::Builder::new()
            .name("HeadlessMainThread".to_string())
            .spawn(move || {
                // We must register the main thread within said thread.
                main_thread.register();
                while let Ok(action) = receiver.recv() {
                    action.execute();
                }
            })?;
    }

    init_without_main_thread()
}

/// This initializes the core without registering a main thread handler.
///
/// Call this if you have previously registered a [`MainThreadHandler`].
pub fn init_without_main_thread() -> Result<(), InitializationError> {
    match crate::product().as_str() {
        "Binary Ninja Enterprise Client" | "Binary Ninja Ultimate" => {
            enterprise::checkout_license(Duration::from_secs(900))?;
        }
        _ => {}
    }

    let bundled_plugin_dir =
        bundled_plugin_directory().expect("Failed to get bundled plugin directory");
    set_bundled_plugin_directory(bundled_plugin_dir);

    unsafe {
        BNInitPlugins(true);
        BNInitRepoPlugins();
    }

    if !is_license_validated() {
        // Unfortunately you must have a valid license to use Binary Ninja.
        Err(InitializationError::InvalidLicense)
    } else {
        Ok(())
    }
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
}

pub fn is_shutdown_requested() -> bool {
    unsafe { binaryninjacore_sys::BNIsShutdownRequested() }
}

#[derive(Debug)]
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
    /// Before calling new you must make sure that the license is retrievable, otherwise the core won't be able to initialize.
    ///
    /// If you cannot otherwise provide a license via `BN_LICENSE_FILE` environment variable or the Binary Ninja user directory
    /// you can call [`Session::new_with_license`] instead of this function.
    pub fn new() -> Result<Self, InitializationError> {
        if license_location().is_some() {
            // We were able to locate a license, continue with initialization.
            init()?;
            Ok(Self {})
        } else {
            // There was no license that could be automatically retrieved, you must call [Self::new_with_license].
            Err(InitializationError::NoLicenseFound)
        }
    }

    /// Initialize with a provided license, this is useful if you need to manage multiple licenses.
    ///
    /// If you do not need to manage multiple licenses you may also set the `BN_LICENSE` environment variable.
    pub fn new_with_license(license: &str) -> Result<Self, InitializationError> {
        set_license(license);
        init()?;
        Ok(Self {})
    }

    /// ```no_run
    /// let headless_session = binaryninja::headless::Session::new().unwrap();
    ///
    /// let bv = headless_session
    ///     .load("/bin/cat")
    ///     .expect("Couldn't open `/bin/cat`");
    /// ```
    pub fn load(&self, filename: &str) -> Option<Ref<binaryview::BinaryView>> {
        crate::load(filename)
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
        filename: &str,
        update_analysis_and_wait: bool,
        options: Option<O>,
    ) -> Option<Ref<binaryview::BinaryView>> {
        crate::load_with_options(filename, update_analysis_and_wait, options)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        shutdown()
    }
}
