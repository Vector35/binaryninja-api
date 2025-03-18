use binaryninja::binary_view::BinaryViewExt;
use binaryninja::component::ComponentBuilder;
use binaryninja::headless::Session;
use std::path::PathBuf;

#[test]
fn test_component_creation() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let component = ComponentBuilder::new(view.clone()).name("test").finalize();
    assert_eq!(component.name().as_str(), "test");
    let root_component = view.root_component().unwrap();
    // We should only have our component.
    assert_eq!(root_component.components().len(), 1);
    assert!(
        root_component.contains_component(&component),
        "Component not found in root component"
    );
}
