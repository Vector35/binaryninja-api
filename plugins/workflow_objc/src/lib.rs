use binaryninja::{add_optional_plugin_dependency, settings::Settings};

mod activities;
mod error;
mod metadata;
mod workflow;

pub use error::Error;
use metadata::GlobalState;

fn plugin_init() -> bool {
    binaryninja::tracing_init!("Plugin.Objective-C");

    if workflow::register_activities().is_err() {
        tracing::warn!("Failed to register Objective-C workflow");
        return false;
    };

    let settings = Settings::new();
    settings.register_setting_json(
        "analysis.objectiveC.resolveDynamicDispatch",
        r#"{
        "title" : "Resolve Dynamic Dispatch Calls",
        "type" : "boolean",
        "default" : false,
        "aliases": ["core.function.objectiveC.assumeMessageSendTarget", "core.function.objectiveC.rewriteMessageSendTarget"],
        "description" : "Replaces objc_msgSend calls with direct calls to the first found implementation when the target method is visible. May produce false positives when multiple classes implement the same selector or when selectors conflict with system framework methods."
        }"#,
    );

    GlobalState::register_cleanup();

    true
}

#[no_mangle]
#[allow(non_snake_case)]
#[cfg(not(feature = "demo"))]
pub extern "C" fn CorePluginDependencies() {
    add_optional_plugin_dependency("arch_x86");
    add_optional_plugin_dependency("arch_armv7");
    add_optional_plugin_dependency("arch_arm64");
}

#[no_mangle]
#[allow(non_snake_case)]
#[cfg(not(feature = "demo"))]
pub extern "C" fn CorePluginInit() -> bool {
    plugin_init()
}

#[no_mangle]
#[allow(non_snake_case)]
#[cfg(feature = "demo")]
pub extern "C" fn WorkflowObjcPluginInit() -> bool {
    plugin_init()
}
