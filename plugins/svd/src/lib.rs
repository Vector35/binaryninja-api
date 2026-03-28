pub mod mapper;
pub mod settings;

use crate::mapper::DeviceMapper;
use crate::settings::LoadSettings;
use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::command::Command;
use binaryninja::interaction::{Form, FormInputField};
use binaryninja::workflow::{activity, Activity, AnalysisContext, Workflow};
use std::path::PathBuf;
use svd_parser::ValidateLevel;

pub struct LoadFileField;

impl LoadFileField {
    pub fn field() -> FormInputField {
        FormInputField::OpenFileName {
            prompt: "File Path".to_string(),
            // TODO: This is called extension but is really a filter.
            extension: Some("*.svd".to_string()),
            default: None,
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("File Path")?;
        let field_value = field.try_value_string()?;
        Some(PathBuf::from(field_value))
    }
}

pub struct AddCommentsField;

impl AddCommentsField {
    pub fn field(default: bool) -> FormInputField {
        FormInputField::Checkbox {
            prompt: "Add Comments".to_string(),
            default: Some(default),
            value: false,
        }
    }

    pub fn from_form(form: &Form) -> Option<bool> {
        let field = form.get_field_with_name("Add Comments")?;
        let field_value = field.try_value_int()?;
        match field_value {
            1 => Some(true),
            _ => Some(false),
        }
    }
}

pub struct AddMemoryRegionsField;

impl AddMemoryRegionsField {
    pub fn field(default: bool) -> FormInputField {
        FormInputField::Checkbox {
            prompt: "Add Memory Regions".to_string(),
            default: Some(default),
            value: false,
        }
    }

    pub fn from_form(form: &Form) -> Option<bool> {
        let field = form.get_field_with_name("Add Memory Regions")?;
        let field_value = field.try_value_int()?;
        match field_value {
            1 => Some(true),
            _ => Some(false),
        }
    }
}

struct LoadSVDFile;

impl Command for LoadSVDFile {
    fn action(&self, view: &BinaryView) {
        let mut form = Form::new("Load SVD File");
        let mut load_settings = LoadSettings::from_view_settings(view);
        form.add_field(LoadFileField::field());
        form.add_field(AddCommentsField::field(load_settings.add_comments));
        form.add_field(AddMemoryRegionsField::field(
            load_settings.add_backing_regions,
        ));
        if !form.prompt() {
            return;
        }
        let Some(file_path) = LoadFileField::from_form(&form) else {
            return;
        };
        load_settings.add_comments = AddCommentsField::from_form(&form).unwrap_or(true);
        load_settings.add_backing_regions = AddMemoryRegionsField::from_form(&form).unwrap_or(true);

        let file_content = match std::fs::read_to_string(&file_path) {
            Ok(content) => content,
            Err(e) => {
                tracing::error!("Failed to read file: {:?}", e);
                return;
            }
        };

        // Disabling validation since vendors are lazy and don't follow the spec.
        let mut config = svd_parser::Config::default();
        config.validate_level = ValidateLevel::Disabled;
        match svd_parser::parse_with_config(&file_content, &config) {
            Ok(device) => {
                // We have a supported svd device. map it!
                let address_size = view.address_size();
                let mapper = DeviceMapper::new(load_settings, address_size, device);
                mapper.map_to_view(view);
                view.update_analysis();
            }
            Err(e) => {
                tracing::error!("Failed to parse SVD file: {:?}", e);
            }
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
#[allow(non_snake_case)]
#[cfg(not(feature = "demo"))]
pub extern "C" fn CorePluginInit() -> bool {
    if plugin_init().is_err() {
        tracing::error!("Failed to initialize SVD plug-in");
        return false;
    }
    true
}

#[no_mangle]
#[allow(non_snake_case)]
#[cfg(feature = "demo")]
pub extern "C" fn SVDPluginInit() -> bool {
    if plugin_init().is_err() {
        tracing::error!("Failed to initialize SVD plug-in");
        return false;
    }
    true
}

fn plugin_init() -> Result<(), ()> {
    binaryninja::tracing_init!("SVD");

    binaryninja::command::register_command(
        "Load SVD File",
        "Loads an SVD file into the current view.",
        LoadSVDFile {},
    );

    // Register settings globally.
    LoadSettings::register();

    let loader_activity = |ctx: &AnalysisContext| {
        let view = ctx.view();
        let load_settings = LoadSettings::from_view_settings(&view);
        let Some(file) = &load_settings.auto_load_file else {
            tracing::debug!("No SVD file specified, skipping...");
            return;
        };
        let file_content = match std::fs::read_to_string(file) {
            Ok(content) => content,
            Err(e) => {
                tracing::error!("Failed to read file: {}", e);
                return;
            }
        };
        let mut config = svd_parser::Config::default();
        config.validate_level = ValidateLevel::Disabled;
        match svd_parser::parse_with_config(&file_content, &config) {
            Ok(device) => {
                let address_size = view.address_size();
                let mapper = DeviceMapper::new(load_settings, address_size, device);
                mapper.map_to_view(&view);
            }
            Err(e) => {
                tracing::error!("Failed to parse SVD file: {:?}", e);
            }
        }
    };

    // Register new workflow activity to load svd information.
    let loader_config = activity::Config::action(
        "analysis.svd.loader",
        "SVD Loader",
        "This analysis step applies SVD info to the view...",
    )
    .eligibility(activity::Eligibility::auto().run_once(true));
    let loader_activity = Activity::new_with_action(loader_config, loader_activity);
    Workflow::cloned("core.module.metaAnalysis")
        .ok_or(())?
        .activity_before(&loader_activity, "core.module.loadDebugInfo")?
        .register()?;
    Ok(())
}
