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
    binaryview, bundled_plugin_directory, is_main_thread, rc, set_bundled_plugin_directory,
    string::IntoJson,
};

use crate::mainthread::{MainThreadAction, MainThreadHandler};
use crate::rc::Ref;
use binaryninjacore_sys::{BNInitPlugins, BNInitRepoPlugins};
use std::sync::mpsc::Sender;
use std::time::Duration;

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
pub fn init() {
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
            })
            .expect("Failed to spawn main thread");
    }

    init_without_main_thread();
}

/// This initializes the core without registering a main thread handler.
///
/// Call this if you have previously registered a [`MainThreadHandler`].
pub fn init_without_main_thread() {
    match crate::product().as_str() {
        "Binary Ninja Enterprise Client" | "Binary Ninja Ultimate" => {
            crate::enterprise::checkout_license(Duration::from_secs(900))
                .expect("Failed to checkout license");
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
}

/// Unloads plugins, stops all worker threads, and closes open logs
///
/// ⚠️ Important! Must be called at the end of scripts. ⚠️
pub fn shutdown() {
    match crate::product().as_str() {
        "Binary Ninja Enterprise Client" | "Binary Ninja Ultimate" => {
            crate::enterprise::release_license()
        }
        _ => {}
    }

    unsafe { binaryninjacore_sys::BNShutdown() };
}

pub fn is_shutdown_requested() -> bool {
    unsafe { binaryninjacore_sys::BNIsShutdownRequested() }
}

/// Wrapper for [`init`] and [`shutdown`]. Instantiating this at the top of your script will initialize everything correctly and then clean itself up at exit as well.
pub struct Session {}

impl Session {
    pub fn new() -> Self {
        init();
        Self {}
    }

    /// ```no_run
    /// let headless_session = binaryninja::headless::Session::new();
    ///
    /// let bv = headless_session.load("/bin/cat").expect("Couldn't open `/bin/cat`");
    /// ```
    pub fn load(&self, filename: &str) -> Option<rc::Ref<binaryview::BinaryView>> {
        crate::load(filename)
    }

    /// ```no_run
    /// use binaryninja::{metadata::Metadata, rc::Ref};
    /// use std::collections::HashMap;
    ///
    /// let settings: Ref<Metadata> = HashMap::from([
    ///     ("analysis.linearSweep.autorun", false.into()),
    /// ]).into();
    /// let headless_session = binaryninja::headless::Session::new();
    ///
    /// let bv = headless_session.load_with_options("/bin/cat", true, Some(settings))
    ///     .expect("Couldn't open `/bin/cat`");
    /// ```
    pub fn load_with_options<O: IntoJson>(
        &self,
        filename: &str,
        update_analysis_and_wait: bool,
        options: Option<O>,
    ) -> Option<rc::Ref<binaryview::BinaryView>> {
        crate::load_with_options(filename, update_analysis_and_wait, options)
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        shutdown()
    }
}
