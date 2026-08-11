use binaryninja::binary_view::BinaryView;
use binaryninja::settings::{QueryOptions, Settings};
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct LoadSettings {
    pub auto_load_file: Option<PathBuf>,
    pub apply_operand_enums: bool,
    pub apply_operand_formats: bool,
    pub skip_default_operand_formats: bool,
}

impl LoadSettings {
    pub const AUTO_LOAD_FILE_DEFAULT: &'static str = "";
    pub const AUTO_LOAD_FILE_SETTING: &'static str = "analysis.idb.autoLoadFile";
    pub const APPLY_OPERAND_ENUMS_SETTING: &'static str = "analysis.idb.applyOperandEnums";
    pub const APPLY_OPERAND_FORMATS_SETTING: &'static str = "analysis.idb.applyOperandFormats";
    pub const SKIP_DEFAULT_OPERAND_FORMATS_SETTING: &'static str =
        "analysis.idb.skipDefaultOperandFormats";

    pub fn register() {
        let bn_settings = Settings::global();

        let file_props = json!({
            "title" : "IDB File",
            "type" : "string",
            "default" : Self::AUTO_LOAD_FILE_DEFAULT,
            "description" : "The IDB File to automatically load when opening the view.",
            "uiSelectionAction" : "file"
        });
        bn_settings.register_setting_json(Self::AUTO_LOAD_FILE_SETTING, &file_props.to_string());

        let operand_enums_props = json!({
            "title" : "Apply IDB Enum Operands",
            "type" : "boolean",
            "default" : false,
            "description" : "Display operands against the enumeration IDA assigned them. This is \
                applied once analysis has created the functions and only affects the handful of \
                operands IDA displays as enumeration members, so it is inexpensive."
        });
        bn_settings.register_setting_json(
            Self::APPLY_OPERAND_ENUMS_SETTING,
            &operand_enums_props.to_string(),
        );

        let operand_formats_props = json!({
            "title" : "Apply IDB Operand Number Formats",
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

        let skip_default_formats_props = json!({
            "title" : "Skip Default IDB Operand Number Formats",
            "type" : "boolean",
            "default" : true,
            "description" : "When applying IDB operand number formats, skip operands whose format \
                already matches Binary Ninja's default rendering (hexadecimal). On large databases \
                most formatted operands are plain hexadecimal, so skipping them greatly reduces \
                the work without changing the displayed result."
        });
        bn_settings.register_setting_json(
            Self::SKIP_DEFAULT_OPERAND_FORMATS_SETTING,
            &skip_default_formats_props.to_string(),
        );
    }

    pub fn from_view_settings(view: &BinaryView) -> Self {
        let mut load_settings = LoadSettings::default();
        let settings = Settings::global();
        let mut query_opts = QueryOptions::new_with_view(view);
        if settings.contains(Self::AUTO_LOAD_FILE_SETTING) {
            let path_str =
                settings.get_string_with_opts(Self::AUTO_LOAD_FILE_SETTING, &mut query_opts);
            if !path_str.is_empty() {
                let path = PathBuf::from(path_str.to_string());
                load_settings.auto_load_file = Some(path);
            }
        }
        if settings.contains(Self::APPLY_OPERAND_ENUMS_SETTING) {
            load_settings.apply_operand_enums =
                settings.get_bool_with_opts(Self::APPLY_OPERAND_ENUMS_SETTING, &mut query_opts);
        }
        if settings.contains(Self::APPLY_OPERAND_FORMATS_SETTING) {
            load_settings.apply_operand_formats =
                settings.get_bool_with_opts(Self::APPLY_OPERAND_FORMATS_SETTING, &mut query_opts);
        }
        if settings.contains(Self::SKIP_DEFAULT_OPERAND_FORMATS_SETTING) {
            load_settings.skip_default_operand_formats = settings
                .get_bool_with_opts(Self::SKIP_DEFAULT_OPERAND_FORMATS_SETTING, &mut query_opts);
        }
        load_settings
    }
}

impl Default for LoadSettings {
    fn default() -> Self {
        Self {
            auto_load_file: None,
            apply_operand_enums: false,
            apply_operand_formats: false,
            skip_default_operand_formats: true,
        }
    }
}
