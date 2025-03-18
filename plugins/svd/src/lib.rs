pub mod mapper;
pub mod settings;

use crate::mapper::DeviceMapper;
use crate::settings::LoadSettings;
use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::command::Command;
use binaryninja::logger::Logger;
use binaryninja::workflow::{Activity, AnalysisContext, Workflow};
use log::LevelFilter;

pub const LOADER_ACTIVITY_NAME: &str = "analysis.svd.loader";
const LOADER_ACTIVITY_CONFIG: &str = r#"{
    "name": "analysis.svd.loader",
    "title" : "SVD Loader",
    "description": "This analysis step applies SVD info to the view...",
    "eligibility": {
        "auto": {},
        "runOnce": true
    }
}"#;

struct LoadSVDFile;

impl Command for LoadSVDFile {
    fn action(&self, view: &BinaryView) {
        let Some(file) =
            binaryninja::interaction::get_open_filename_input("Select a .svd file", "*.svd")
        else {
            return;
        };

        let file_content = match std::fs::read_to_string(&file) {
            Ok(content) => content,
            Err(e) => {
                log::error!("Failed to read file: {}", e);
                return;
            }
        };

        match svd_parser::parse(&file_content) {
            Ok(device) => {
                // We have a supported svd device. map it!
                let load_settings = LoadSettings::from_view_settings(view);
                let address_size = view.address_size();
                let mapper = DeviceMapper::new(load_settings, address_size, device);
                mapper.map_to_view(view);
                view.update_analysis();
            }
            Err(e) => {
                log::error!("Failed to parse SVD file: {}", e);
            }
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("SVD").with_level(LevelFilter::Debug).init();

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
            log::debug!("No SVD file specified, skipping...");
            return;
        };
        let file_content = match std::fs::read_to_string(file) {
            Ok(content) => content,
            Err(e) => {
                log::error!("Failed to read file: {}", e);
                return;
            }
        };
        match svd_parser::parse(&file_content) {
            Ok(device) => {
                let address_size = view.address_size();
                let mapper = DeviceMapper::new(load_settings, address_size, device);
                mapper.map_to_view(&view);
            }
            Err(e) => {
                log::error!("Failed to parse SVD file: {}", e);
            }
        }
    };

    // Register new workflow activity to load svd information.
    let old_module_meta_workflow = Workflow::instance("core.module.metaAnalysis");
    let module_meta_workflow = old_module_meta_workflow.clone("core.module.metaAnalysis");
    let loader_activity = Activity::new_with_action(LOADER_ACTIVITY_CONFIG, loader_activity);
    module_meta_workflow
        .register_activity(&loader_activity)
        .unwrap();
    module_meta_workflow.insert("core.module.loadDebugInfo", [LOADER_ACTIVITY_NAME]);
    module_meta_workflow.register().unwrap();

    true
}
