// Usage: cargo run --example create_type_library <header_file_path> <platform> <type_library_path>

use binaryninja::platform::Platform;
use binaryninja::tracing::TracingLogListener;
use binaryninja::types::{CoreTypeParser, TypeLibrary, TypeParser};

fn main() {
    tracing_subscriber::fmt::init();
    let _listener = TracingLogListener::new().register();

    let header_path_str = std::env::args().nth(1).expect("No header provided");
    let header_path = std::path::Path::new(&header_path_str);
    let header_name = header_path.file_stem().unwrap().to_str().unwrap();
    let type_lib_plat_str = std::env::args().nth(2).expect("No type library provided");
    let type_lib_path_str = std::env::args().nth(3).expect("No type library provided");
    let type_lib_path = std::path::Path::new(&type_lib_path_str);
    let type_lib_name = type_lib_path.file_stem().unwrap().to_str().unwrap();

    let header_contents = std::fs::read_to_string(header_path).expect("Failed to read header file");

    // This loads all the core architecture, platform, etc plugins
    let _headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    let type_lib_plat = Platform::by_name(&type_lib_plat_str).expect("Invalid platform");

    let type_lib = TypeLibrary::new(type_lib_plat.arch(), type_lib_name);

    let plat_type_container = type_lib_plat.type_container();
    let parser = CoreTypeParser::default();
    let parsed_types = parser
        .parse_types_from_source(
            &header_contents,
            header_name,
            &type_lib_plat,
            &plat_type_container,
            &[],
            &[],
            "",
        )
        .expect("Parsed types");

    for ty in parsed_types.types {
        tracing::debug!("Adding type: {}", ty.name);
        type_lib.add_named_type(ty.name, &ty.ty);
    }

    for func in parsed_types.functions {
        tracing::debug!("Adding function: {}", func.name);
        type_lib.add_named_object(func.name, &func.ty);
    }

    tracing::info!(
        "Created type library with {} types and {} functions",
        type_lib.named_types().len(),
        type_lib.named_objects().len()
    );
    type_lib.write_to_file(&type_lib_path);
}
