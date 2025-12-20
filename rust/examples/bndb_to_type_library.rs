// Usage: cargo run --example bndb_to_type_library <bndb_path> <type_library_path>

use binaryninja::binary_view::BinaryViewExt;
use binaryninja::tracing::TracingLogListener;
use binaryninja::types::{QualifiedName, TypeLibrary};
use tracing_indicatif::span_ext::IndicatifSpanExt;
use tracing_indicatif::style::ProgressStyle;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() {
    let indicatif_layer = tracing_indicatif::IndicatifLayer::new();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(indicatif_layer.get_stderr_writer()))
        .with(indicatif_layer)
        .init();
    let _listener = TracingLogListener::new().register();

    let bndb_path_str = std::env::args().nth(1).expect("No header provided");
    let bndb_path = std::path::Path::new(&bndb_path_str);

    let type_lib_path_str = std::env::args().nth(2).expect("No type library provided");
    let type_lib_path = std::path::Path::new(&type_lib_path_str);
    let type_lib_name = type_lib_path.file_stem().unwrap().to_str().unwrap();

    // This loads all the core architecture, platform, etc plugins
    let headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    let file = {
        let loading_span = tracing::info_span!("loading");
        let progress_style = ProgressStyle::with_template("{msg} {elapsed} {wide_bar}").unwrap();
        loading_span.pb_set_style(&progress_style);
        loading_span.pb_set_message("Loading database");
        loading_span.pb_set_finish_message("Database loaded");
        loading_span.in_scope(|| {
            headless_session
                .load_with_progress(bndb_path, |pos, total| {
                    loading_span.pb_set_length(total as u64);
                    loading_span.pb_set_position(pos as u64);
                    true
                })
                .expect("Failed to load BNDB")
        })
    };

    let type_lib = TypeLibrary::new(file.default_arch().unwrap(), type_lib_name);

    let types = file.types();
    tracing::info!("Adding {} types", types.len());
    for ty in &types {
        type_lib.add_named_type(ty.name, &ty.ty);
    }

    let functions = file.functions();
    tracing::info!("Adding {} functions", functions.len());
    for func in &functions {
        let qualified_name =
            QualifiedName::from(func.symbol().short_name().to_string_lossy().to_string());
        type_lib.add_named_object(qualified_name, &func.function_type());
    }

    tracing::info!("Writing out file... {:?}", type_lib_path);
    type_lib.write_to_file(&type_lib_path);
}
