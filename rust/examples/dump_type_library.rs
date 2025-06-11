// Usage: cargo run --example dump_type_library <type_library_path>

use binaryninja::binary_view::BinaryView;
use binaryninja::file_metadata::FileMetadata;
use binaryninja::type_library::TypeLibrary;
use binaryninja::type_printer::{CoreTypePrinter, TokenEscapingType};

fn main() {
    let type_lib_str = std::env::args().nth(1).expect("No type library provided");
    let type_lib_path = std::path::Path::new(&type_lib_str);

    println!("Starting session...");
    // This loads all the core architecture, platform, etc plugins
    let _headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    let type_lib = TypeLibrary::load_from_file(type_lib_path).expect("Failed to load type library");
    let named_types = type_lib.named_types();
    println!("Name: `{}`", type_lib.name());
    println!("GUID: `{}`", type_lib.guid());

    // Print out all the types as a c header.
    let type_lib_header_path = type_lib_path.with_extension("h");
    println!(
        "Dumping {} types to: `{:?}`",
        named_types.len(),
        type_lib_header_path
    );
    let type_printer = CoreTypePrinter::default();
    let empty_bv =
        BinaryView::from_data(&FileMetadata::new(), &[]).expect("Failed to create empty view");
    let printed_types = type_printer
        .print_all_types(
            &type_lib.named_types(),
            &empty_bv,
            4,
            TokenEscapingType::NoTokenEscapingType,
        )
        .expect("Failed to print types");

    // Write the header to disk.
    std::fs::write(type_lib_header_path, printed_types)
        .expect("Failed to write type library header");
}
