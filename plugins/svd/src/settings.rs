use binaryninja::binary_view::BinaryView;
use binaryninja::settings::{QueryOptions, Settings};
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct LoadSettings {
    pub add_bitfields: bool,
    pub add_comments: bool,
    pub auto_load_file: Option<PathBuf>,
}

impl LoadSettings {
    pub const ADD_BITFIELDS_DEFAULT: bool = true;
    pub const ADD_BITFIELDS_SETTING: &'static str = "analysis.svd.addBitfields";
    pub const ADD_COMMENTS_DEFAULT: bool = true;
    pub const ADD_COMMENTS_SETTING: &'static str = "analysis.svd.addComments";
    pub const AUTO_LOAD_FILE_DEFAULT: &'static str = "";
    pub const AUTO_LOAD_FILE_SETTING: &'static str = "analysis.svd.autoLoadFile";

    pub fn register() {
        let bn_settings = Settings::new();

        let add_bitfields_props = json!({
            "title" : "Add Bitfields",
            "type" : "boolean",
            "default" : Self::ADD_BITFIELDS_DEFAULT,
            "description" : "Whether to add bitfields. Bitfields are not supported by Binary Ninja, so this is a workaround using unions.",
        });
        bn_settings
            .register_setting_json(Self::ADD_BITFIELDS_SETTING, add_bitfields_props.to_string());

        let add_comments_props = json!({
            "title" : "Add Comments",
            "type" : "boolean",
            "default" : Self::ADD_COMMENTS_DEFAULT,
            "description" : "Whether to add comments. If you see comment placement is off, try disabling this.",
        });
        bn_settings
            .register_setting_json(Self::ADD_COMMENTS_SETTING, add_comments_props.to_string());

        let file_props = json!({
            "title" : "SVD File",
            "type" : "string",
            "default" : Self::AUTO_LOAD_FILE_DEFAULT,
            "description" : "The SVD File to automatically load when opening the view.",
            "uiSelectionAction" : "file"
        });
        bn_settings.register_setting_json(Self::AUTO_LOAD_FILE_SETTING, file_props.to_string());
    }

    pub fn from_view_settings(view: &BinaryView) -> Self {
        let mut load_settings = LoadSettings::default();
        let settings = Settings::new();
        let mut query_opts = QueryOptions::new_with_view(view);
        if settings.contains(Self::ADD_BITFIELDS_SETTING) {
            load_settings.add_bitfields =
                settings.get_bool_with_opts(Self::ADD_BITFIELDS_SETTING, &mut query_opts);
        }
        if settings.contains(Self::ADD_COMMENTS_SETTING) {
            load_settings.add_comments =
                settings.get_bool_with_opts(Self::ADD_COMMENTS_SETTING, &mut query_opts);
        }
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
            add_bitfields: Self::ADD_BITFIELDS_DEFAULT,
            add_comments: Self::ADD_COMMENTS_DEFAULT,
            auto_load_file: None,
        }
    }
}
