use binaryninja::binary_view::BinaryView;
use binaryninja::settings::{QueryOptions, Settings};
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct LoadSettings {
    pub auto_load_file: Option<PathBuf>,
}

impl LoadSettings {
    pub const AUTO_LOAD_FILE_DEFAULT: &'static str = "";
    pub const AUTO_LOAD_FILE_SETTING: &'static str = "analysis.idb.autoLoadFile";

    pub fn register() {
        let bn_settings = Settings::new();

        let file_props = json!({
            "title" : "IDB File",
            "type" : "string",
            "default" : Self::AUTO_LOAD_FILE_DEFAULT,
            "description" : "The IDB File to automatically load when opening the view.",
            "uiSelectionAction" : "file"
        });
        bn_settings.register_setting_json(Self::AUTO_LOAD_FILE_SETTING, &file_props.to_string());
    }

    pub fn from_view_settings(view: &BinaryView) -> Self {
        let mut load_settings = LoadSettings::default();
        let settings = Settings::new();
        let mut query_opts = QueryOptions::new_with_view(view);
        if settings.contains(Self::AUTO_LOAD_FILE_SETTING) {
            let path_str =
                settings.get_string_with_opts(Self::AUTO_LOAD_FILE_SETTING, &mut query_opts);
            if !path_str.is_empty() {
                let path = PathBuf::from(path_str.to_string());
                load_settings.auto_load_file = Some(path);
            }
        }
        load_settings
    }
}

impl Default for LoadSettings {
    fn default() -> Self {
        Self {
            auto_load_file: None,
        }
    }
}
