// Usage: cargo run --example bndb_to_type_library <bndb_path> <type_library_path>

use binaryninja::binary_view::BinaryViewExt;
use binaryninja::type_library::TypeLibrary;
use binaryninja::types::QualifiedName;

fn main() {
    let bndb_path_str = std::env::args().nth(1).expect("No header provided");
    let bndb_path = std::path::Path::new(&bndb_path_str);

    let type_lib_path_str = std::env::args().nth(2).expect("No type library provided");
    let type_lib_path = std::path::Path::new(&type_lib_path_str);
    let type_lib_name = type_lib_path.file_stem().unwrap().to_str().unwrap();

    println!("Starting session...");
    // This loads all the core architecture, platform, etc plugins
    let headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    let file = headless_session
        .load(bndb_path)
        .expect("Failed to load BNDB");

    let type_lib = TypeLibrary::new(file.default_arch().unwrap(), type_lib_name);

    for ty in &file.types() {
        println!("Adding type: {}", ty.name);
        type_lib.add_named_type(ty.name, &ty.ty);
    }

    for func in &file.functions() {
        println!("Adding function: {}", func.symbol());
        let qualified_name =
            QualifiedName::from(func.symbol().short_name().to_string_lossy().to_string());
        type_lib.add_named_object(qualified_name, &func.function_type());
    }

    type_lib.write_to_file(&type_lib_path);
}
