use crate::mapper::IDBMapper;
use crate::parse::IDBFileParser;
use crate::settings::LoadSettings;
use binaryninja::binary_view::AnalysisContext;
use binaryninja::workflow::{activity, Activity, Workflow};
use std::fs::File;
use std::io::BufReader;

mod commands;
pub mod mapper;
pub mod parse;
mod settings;
pub mod translate;

fn plugin_init() -> Result<(), ()> {
    binaryninja::tracing_init!("IDB Import");

    binaryninja::command::register_command(
        "Load IDB File",
        "Loads an IDB file into the current view.",
        commands::load_file::LoadIDBFile,
    );

    // Register settings globally.
    LoadSettings::register();

    let loader_activity = |ctx: &AnalysisContext| {
        let view = ctx.view();
        let load_settings = LoadSettings::from_view_settings(&view);
        let Some(file_path) = &load_settings.auto_load_file else {
            tracing::debug!("No IDB file specified, skipping...");
            return;
        };
        let Ok(file) = File::open(&file_path) else {
            tracing::error!("Failed to open file: {}", file_path.display());
            return;
        };
        let mut file_reader = BufReader::new(file);
        let file_parser = IDBFileParser::new();
        match file_parser.parse(&mut file_reader) {
            Ok(idb_info) => {
                IDBMapper::new(idb_info).map_to_view(&view);
            }
            Err(e) => {
                tracing::error!("Failed to parse IDB file: {}", e);
            }
        }
    };

    // Register new workflow activity to load svd information.
    let loader_config = activity::Config::action(
        "analysis.idb.loader",
        "IDB Loader",
        "This analysis step applies IDB info to the view...",
    )
    .eligibility(activity::Eligibility::auto().run_once(true));
    let loader_activity = Activity::new_with_action(loader_config, loader_activity);
    Workflow::cloned("core.module.metaAnalysis")
        .ok_or(())?
        .activity_before(&loader_activity, "core.module.loadDebugInfo")?
        .register()?;

    Ok(())
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    plugin_init().is_ok()
}
