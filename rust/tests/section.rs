use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use binaryninja::section::{SectionBuilder, Semantics};
use std::path::PathBuf;

#[test]
fn test_binary_section() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    // This binary has a lot of sections!
    assert_eq!(view.sections().len(), 139);

    // Make sure we are not grabbing garbage.
    assert_eq!(view.section_by_name("test"), None);

    // Just test a bunch of properties of a section.
    let section = view.section_by_name(".rdata").unwrap();
    assert_eq!(section.name(), ".rdata".into());
    let image_base = view.original_image_base();
    let section_start = image_base + 0x25efc;
    let section_end = image_base + 0x25f04;
    assert_eq!(section.start(), section_start);
    assert_eq!(section.end(), image_base + 0x25f04);
    assert_eq!(section.len(), 0x8);
    assert_eq!(section.address_range(), section_start..section_end);
    assert_eq!(section.auto_defined(), true);
    assert_eq!(section.semantics(), Semantics::ReadOnlyData);

    let sections_at = view.sections_at(image_base + 0x25efc);
    assert_eq!(sections_at.len(), 1);
    let same_section = sections_at.to_vec()[0].to_owned();
    assert_eq!(section, same_section);
}

#[test]
fn test_add_remove_section() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");

    // Remove the rdata section!
    let old_section = view
        .section_by_name(".rdata")
        .expect("Failed to find rdata section");
    view.remove_auto_section(".rdata");
    assert!(view.section_by_name(".rdata").is_none());

    // Add a new section and compare with the old section
    let new_section_builder = SectionBuilder::from(&old_section);
    view.add_section(new_section_builder);
    let new_section = view
        .section_by_name(".rdata")
        .expect("Failed to find new section");
    assert_eq!(old_section, new_section);
}
