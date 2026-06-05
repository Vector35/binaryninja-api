use binaryninja::binary_view::BinaryView;
use binaryninja::settings::{QueryOptions, Settings};
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct LoadSettings {
    pub auto_load_file: Option<PathBuf>,
    pub apply_operand_formats: bool,
}

impl LoadSettings {
    pub const AUTO_LOAD_FILE_DEFAULT: &'static str = "";
    pub const AUTO_LOAD_FILE_SETTING: &'static str = "analysis.idb.autoLoadFile";
    pub const APPLY_OPERAND_FORMATS_SETTING: &'static str = "analysis.idb.applyOperandFormats";

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

        let operand_formats_props = json!({
            "title" : "Apply IDB Operand Formats",
            "type" : "boolean",
            "default" : false,
            "description" : "Apply the per-operand number formats (hexadecimal, decimal, \
                character, octal, binary, offset) recorded in the IDB to the disassembly. This \
                disassembles each formatted instruction during import and can be slow on large \
                databases."
        });
        bn_settings.register_setting_json(
            Self::APPLY_OPERAND_FORMATS_SETTING,
            &operand_formats_props.to_string(),
        );
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
        if settings.contains(Self::APPLY_OPERAND_FORMATS_SETTING) {
            load_settings.apply_operand_formats =
                settings.get_bool_with_opts(Self::APPLY_OPERAND_FORMATS_SETTING, &mut query_opts);
        }
        load_settings
    }
}

impl Default for LoadSettings {
    fn default() -> Self {
        Self {
            auto_load_file: None,
            apply_operand_formats: false,
        }
    }
}
