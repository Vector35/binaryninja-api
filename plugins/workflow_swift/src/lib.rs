mod demangler;

use binaryninja::add_optional_plugin_dependency;
use binaryninja::demangle::Demangler;
use binaryninja::settings::Settings;
use demangler::SwiftDemangler;

pub const SETTING_EXTRACT_TYPES: &str = "analysis.swift.extractTypesFromMangledNames";

#[cfg(test)]
fn test_session() -> &'static binaryninja::headless::Session {
    use std::sync::OnceLock;

    static SESSION: OnceLock<binaryninja::headless::Session> = OnceLock::new();
    SESSION.get_or_init(|| binaryninja::headless::Session::new().expect("headless session"))
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginDependencies() {
    add_optional_plugin_dependency("arch_x86");
    add_optional_plugin_dependency("arch_arm64");
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    binaryninja::tracing_init!("Plugin.Swift");

    let settings = Settings::global();
    settings.register_setting_json(
        SETTING_EXTRACT_TYPES,
        r#"{
        "title" : "Extract Types from Mangled Names",
        "type" : "boolean",
        "default" : true,
        "description" : "Extract parameter and return type information from Swift mangled names and apply them to function signatures. When disabled, only the demangled name is applied."
        }"#,
    );

    Demangler::register("Swift", SwiftDemangler)
}
