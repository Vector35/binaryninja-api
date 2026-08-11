use crate::mapper::IDBMapper;
use crate::parse::IDBFileParser;
use crate::settings::LoadSettings;
use binaryninja::binary_view::{
    register_binary_view_event, AnalysisContext, BinaryView, BinaryViewEventHandler,
    BinaryViewEventType,
};
use binaryninja::workflow::{activity, Activity, Workflow};
use std::fs::File;
use std::io::BufReader;

/// Applies the per-operand display overrides (number formats and enum displays) that the import
/// deferred because they require the view's functions to exist. By the time initial analysis
/// completes the functions are present, so the overrides can be set and a re-analysis requested to
/// render them.
struct OperandDisplayApplier;

impl BinaryViewEventHandler for OperandDisplayApplier {
    fn on_event(&self, view: &BinaryView) {
        if crate::mapper::apply_pending_operand_display(view) {
            // The overrides only affect rendering once analysis re-runs over the functions.
            view.update_analysis();
        }
    }
}

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

    // Apply deferred per-operand display overrides once functions exist.
    register_binary_view_event(
        BinaryViewEventType::BinaryViewInitialAnalysisCompletionEvent,
        OperandDisplayApplier,
    );

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
                IDBMapper::new(idb_info)
                    .with_operand_enums(load_settings.apply_operand_enums)
                    .with_operand_formats(load_settings.apply_operand_formats)
                    .with_skip_default_operand_formats(load_settings.skip_default_operand_formats)
                    .map_to_view(&view);
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

#[cfg(not(feature = "demo"))]
#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    plugin_init().is_ok()
}

#[cfg(feature = "demo")]
#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn IdbImportPluginInit() -> bool {
    plugin_init().is_ok()
}
