use crate::cache::register_cache_destructor;
use std::time::Instant;

use crate::cache::container::add_cached_container;
use crate::container::disk::DiskContainer;
use crate::container::network::{NetworkClient, NetworkContainer};
use crate::matcher::MatcherSettings;
use crate::plugin::render_layer::HighlightRenderLayer;
use crate::plugin::settings::PluginSettings;
use crate::{core_signature_dir, user_signature_dir};
use binaryninja::background_task::BackgroundTask;
use binaryninja::command::{
    register_command, register_command_for_function, register_command_for_project,
};
use binaryninja::is_ui_enabled;
use binaryninja::logger::Logger;
use binaryninja::settings::{QueryOptions, Settings};
use log::LevelFilter;
use reqwest::StatusCode;

mod commit;
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

fn load_bundled_signatures() {
    let global_bn_settings = Settings::new();
    let plugin_settings =
        PluginSettings::from_settings(&global_bn_settings, &mut QueryOptions::new());
    // We want to load all the bundled directories into the container cache.
    let background_task = BackgroundTask::new("Loading WARP files...", false);
    let start = Instant::now();
    if plugin_settings.load_bundled_files {
        let mut core_disk_container = DiskContainer::new_from_dir(core_signature_dir());
        core_disk_container.name = "Bundled".to_string();
        core_disk_container.writable = false;
        log::debug!("{:#?}", core_disk_container);
        add_cached_container(core_disk_container);
    }
    if plugin_settings.load_user_files {
        let mut user_disk_container = DiskContainer::new_from_dir(user_signature_dir());
        user_disk_container.name = "User".to_string();
        log::debug!("{:#?}", user_disk_container);
        add_cached_container(user_disk_container);
    }
    log::info!("Loading bundled files took {:?}", start.elapsed());
    background_task.finish();
}

fn load_network_container() {
    let global_bn_settings = Settings::new();

    let add_network_container = |url: String, api_key: Option<String>| {
        let https_proxy_str = global_bn_settings.get_string("network.httpsProxy");
        let https_proxy = if https_proxy_str.is_empty() {
            None
        } else {
            Some(https_proxy_str)
        };
        match NetworkClient::new(url.clone(), api_key.clone(), https_proxy) {
            Ok(network_client) => {
                // Before constructing the container, let's make sure that the server is OK.
                if let Ok(StatusCode::OK) = network_client.status() {
                    // Check if the user is logged in. If so, we should collect the writable sources.
                    let mut writable_sources = Vec::new();
                    match network_client.current_user() {
                        Ok((id, username)) => {
                            log::info!(
                                "Server '{}' connected, logged in as user '{}'",
                                url,
                                username
                            );
                            match network_client.query_sources(Some(id)) {
                                Ok(sources) => {
                                    writable_sources = sources;
                                }
                                Err(e) => {
                                    log::error!(
                                        "Server '{}' failed to get sources for user: {}",
                                        url,
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) if api_key.is_some() => {
                            log::error!(
                                "Server '{}' failed to authenticate with provided API key: {}",
                                url,
                                e
                            );
                        }
                        Err(_) => {
                            log::info!("Server '{}' connected, logged in as guest", url);
                        }
                    }

                    // TODO: Make the cache path include the domain or url, so that we can have multiple servers.
                    let main_cache_path = NetworkContainer::root_cache_location().join("main");
                    let network_container =
                        NetworkContainer::new(network_client, main_cache_path, &writable_sources);
                    log::debug!("{:#?}", network_container);
                    add_cached_container(network_container);
                } else {
                    log::error!("Server '{}' is not reachable, disabling container...", url);
                }
            }
            Err(e) => {
                log::error!("Failed to add networked container: {}", e);
            }
        }
    };

    let plugin_settings =
        PluginSettings::from_settings(&global_bn_settings, &mut QueryOptions::new());
    let background_task = BackgroundTask::new("Initializing WARP server...", false);
    let start = Instant::now();
    if plugin_settings.enable_server {
        add_network_container(plugin_settings.server_url, plugin_settings.server_api_key);
        if let Some(second_server_url) = plugin_settings.second_server_url {
            add_network_container(second_server_url, plugin_settings.second_server_api_key);
        }
    }
    log::debug!("Initializing warp server took {:?}", start.elapsed());
    background_task.finish();
}

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

    if workflow::insert_workflow().is_err() {
        log::error!("Failed to register WARP workflow");
        return false;
    }

    // TODO: Make the retrieval of containers wait on this to be done.
    // TODO: We could also have a mechanism for lazily loading the files using the chunk header target.
    // Loading bundled signatures might take a few hundred milliseconds.
    if is_ui_enabled() {
        std::thread::spawn(|| {
            load_bundled_signatures();
            load_network_container();
        });
    } else {
        load_bundled_signatures();
        std::thread::spawn(|| {
            // Dependence on this is likely to not matter in headless, so we throw it on another thread.
            load_network_container();
        });
    }

    register_command(
        "WARP\\Run Matcher",
        "Run the matcher manually",
        workflow::RunMatcher {},
    );

    #[cfg(debug_assertions)]
    register_command(
        "WARP\\Debug\\Cache",
        "Debug cache sizes... because...",
        debug::DebugCache {},
    );

    #[cfg(debug_assertions)]
    register_command(
        "WARP\\Debug\\Invalidate Caches",
        "Invalidate all WARP caches",
        debug::DebugInvalidateCache {},
    );

    #[cfg(debug_assertions)]
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

    register_command(
        "WARP\\Commit File",
        "Commit file to a source",
        commit::CommitFile {},
    );

    register_command_for_function(
        "WARP\\Include Function",
        "Add current function to the list of functions to add to the signature file",
        function::IncludeFunction {},
    );

    register_command_for_function(
        "WARP\\Copy GUID",
        "Copy the computed GUID for the function",
        function::CopyFunctionGUID {},
    );

    register_command(
        "WARP\\Find GUID",
        "Locate the function in the view using a GUID",
        function::FindFunctionFromGUID {},
    );

    register_command(
        "WARP\\Create\\From Current View",
        "Creates a signature file containing all selected functions",
        create::CreateFromCurrentView {},
    );

    register_command(
        "WARP\\Create\\From File(s)",
        "Creates a signature file containing all selected functions",
        create::CreateFromFiles {},
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
