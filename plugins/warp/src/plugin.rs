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
use binaryninja::command::{register_command, register_command_for_function};
use binaryninja::is_ui_enabled;
use binaryninja::settings::{QueryOptions, Settings};

mod ffi;
mod function;
mod load;
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
        tracing::debug!("{:#?}", core_disk_container);
        add_cached_container(core_disk_container);
    }
    if plugin_settings.load_user_files {
        let mut user_disk_container = DiskContainer::new_from_dir(user_signature_dir());
        user_disk_container.name = "User".to_string();
        tracing::debug!("{:#?}", user_disk_container);
        add_cached_container(user_disk_container);
    }
    tracing::info!("Loading files took {:?}", start.elapsed());
    background_task.finish();
}

fn load_network_container() {
    let global_bn_settings = Settings::new();

    let add_network_container = |url: String, api_key: Option<String>| {
        let network_client = NetworkClient::new(url.clone(), api_key.clone());
        // Before constructing the container, let's make sure that the server is OK.
        if let Err(e) = network_client.status() {
            tracing::warn!("Server '{}' failed to connect: {}", url, e);
            return;
        }

        // Check if the user is logged in. If so, we should collect the writable sources.
        let mut writable_sources = Vec::new();
        match network_client.current_user() {
            Ok((id, username)) => {
                tracing::info!(
                    "Server '{}' connected, logged in as user '{}'",
                    url,
                    username
                );
                match network_client.query_sources(Some(id)) {
                    Ok(sources) => {
                        writable_sources = sources;
                    }
                    Err(e) => {
                        tracing::error!("Server '{}' failed to get sources for user: {}", url, e);
                    }
                }
            }
            Err(e) if api_key.is_some() => {
                tracing::error!(
                    "Server '{}' failed to authenticate with provided API key: {}",
                    url,
                    e
                );
            }
            Err(_) => {
                tracing::info!("Server '{}' connected, logged in as guest", url);
            }
        }

        // TODO: Make the cache path include the domain or url, so that we can have multiple servers.
        let main_cache_path = NetworkContainer::root_cache_location().join("main");
        let network_container =
            NetworkContainer::new(network_client, main_cache_path, &writable_sources);
        tracing::debug!("{:#?}", network_container);
        add_cached_container(network_container);
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
    tracing::debug!("Initializing warp server took {:?}", start.elapsed());
    background_task.finish();
}

fn plugin_init() -> bool {
    binaryninja::tracing_init!("WARP");

    // Create the user signature directory if it does not exist, otherwise we will not be able to write to it.
    if !user_signature_dir().exists() {
        if let Err(e) = std::fs::create_dir_all(&user_signature_dir()) {
            tracing::error!("Failed to create user signature directory: {}", e);
        }
    }

    // Register our matcher and plugin settings globally.
    let mut global_bn_settings = Settings::new();
    global_bn_settings.register_group("warp", "WARP");
    MatcherSettings::register(&mut global_bn_settings);
    PluginSettings::register(&mut global_bn_settings);

    // Make sure caches are flushed when the views get destructed.
    register_cache_destructor();

    // Register our highlight render layer.
    HighlightRenderLayer::register();

    if workflow::insert_workflow().is_err() {
        tracing::error!("Failed to register WARP workflow");
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

    register_command(
        "WARP\\Load File",
        "Load WARP file",
        load::LoadSignatureFile {},
    );

    register_command_for_function(
        "WARP\\Include Function",
        "Add current function to the list of functions to add to the signature file",
        function::IncludeFunction {},
    );

    register_command_for_function(
        "WARP\\Ignore Function",
        "Add current function to the list of functions to ignore when matching",
        function::IgnoreFunction {},
    );

    register_command_for_function(
        "WARP\\Remove Matched Function",
        "Remove the current match from the selected function, to prevent matches in future use 'Ignore Function'",
        function::RemoveFunction {},
    );

    true
}

#[no_mangle]
#[allow(non_snake_case)]
#[cfg(feature = "demo")]
pub extern "C" fn WarpPluginInit() -> bool {
    plugin_init();
    true
}

#[no_mangle]
#[allow(non_snake_case)]
#[cfg(not(feature = "demo"))]
pub extern "C" fn CorePluginInit() -> bool {
    plugin_init();
    true
}
