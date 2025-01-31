use crate::cache::register_cache_destructor;
use std::time::Instant;

use crate::cache::container::add_cached_container;
use crate::container::disk::DiskContainer;
use crate::matcher::MatcherSettings;
use crate::plugin::render_layer::HighlightRenderLayer;
use crate::plugin::settings::PluginSettings;
use crate::{core_signature_dir, user_signature_dir};
use binaryninja::background_task::BackgroundTask;
use binaryninja::command::{
    register_command, register_command_for_function, register_command_for_project,
};
use binaryninja::logger::Logger;
use binaryninja::settings::Settings;
use log::LevelFilter;

mod create;
mod debug;
mod ffi;
mod file;
mod function;
mod load;
mod project;
mod render_layer;
mod settings;
mod workflow;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("WARP").with_level(LevelFilter::Debug).init();

    // Register our matcher and plugin settings globally.
    let mut global_bn_settings = Settings::new();
    MatcherSettings::register(&mut global_bn_settings);
    PluginSettings::register(&mut global_bn_settings);

    // Make sure caches are flushed when the views get destructed.
    register_cache_destructor();

    // Register our highlight render layer.
    HighlightRenderLayer::register();

    workflow::insert_workflow();

    let plugin_settings = PluginSettings::from_settings(&global_bn_settings);
    // We want to load all the bundled directories into the container cache.
    let background_task = BackgroundTask::new("Loading WARP files...", false);
    let start = Instant::now();
    if plugin_settings.load_bundled_files {
        let core_disk_container = DiskContainer::new_from_dir(core_signature_dir());
        log::debug!("{:#?}", core_disk_container);
        add_cached_container(core_disk_container);
    }
    if plugin_settings.load_user_files {
        let user_disk_container = DiskContainer::new_from_dir(user_signature_dir());
        log::debug!("{:#?}", user_disk_container);
        add_cached_container(user_disk_container);
    }
    log::info!("Loading bundled files took {:?}", start.elapsed());
    background_task.finish();

    register_command(
        "WARP\\Run Matcher",
        "Run the matcher manually",
        workflow::RunMatcher {},
    );

    register_command(
        "WARP\\Debug\\Cache",
        "Debug cache sizes... because...",
        debug::DebugCache {},
    );

    register_command(
        "WARP\\Debug\\Invalidate Caches",
        "Invalidate all WARP caches",
        debug::DebugInvalidateCache {},
    );

    register_command_for_function(
        "WARP\\Debug\\Function Signature",
        "Print the entire signature for the function",
        debug::DebugFunction {},
    );

    register_command(
        "WARP\\Load File",
        "Load file into the matcher, this does NOT kick off matcher analysis",
        load::LoadSignatureFile {},
    );

    register_command_for_function(
        "WARP\\Function\\Include",
        "Add current function to the list of functions to add to the signature file",
        function::IncludeFunction {},
    );

    register_command_for_function(
        "WARP\\Function\\Copy GUID",
        "Copy the computed GUID for the function",
        function::CopyFunctionGUID {},
    );

    register_command(
        "WARP\\Function\\Find GUID",
        "Locate the function in the view using a GUID",
        function::FindFunctionFromGUID {},
    );

    register_command(
        "WARP\\Create\\From Current View",
        "Creates a signature file containing all selected functions",
        create::CreateSignatureFile {},
    );

    register_command(
        "WARP\\Show Report",
        "Creates a report for the selected file, displaying info on functions and types",
        file::ShowFileReport {},
    );

    register_command_for_project(
        "WARP\\Create\\From Project",
        "Create signature files from select project files",
        project::CreateSignatures {},
    );

    true
}
