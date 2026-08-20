use binaryninja::architecture::{ArchitectureExt, CoreArchitecture};
use binaryninja::binary_view::BinaryView;
use binaryninja::file_metadata::FileMetadata;
use binaryninja::headless::Session;
use warp::symbol::{Symbol, SymbolClass, SymbolModifiers};
use warp_ninja::convert::to_bn_symbol_at_address;

#[test]
fn demangled_symbol_names_include_parameters_only_in_the_full_name() {
    let _session = Session::new().expect("Failed to create session");
    let view = BinaryView::from_data(&FileMetadata::new(), &[]);
    let platform = CoreArchitecture::by_name("x86_64")
        .expect("x86_64 exists")
        .standalone_platform()
        .expect("x86_64 standalone platform exists");
    view.set_default_platform(&platform);

    let symbol = Symbol::new("_Z3fooi", SymbolClass::Function, SymbolModifiers::default());
    let bn_symbol = to_bn_symbol_at_address(&view, &symbol, 0);

    assert_eq!(bn_symbol.short_name().to_string_lossy(), "foo");
    assert_eq!(bn_symbol.full_name().to_string_lossy(), "foo(int32_t)");
}
