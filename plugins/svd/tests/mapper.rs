use binaryninja::binary_view::BinaryView;
use binaryninja::binary_view::BinaryViewExt;
use binaryninja::file_metadata::FileMetadata;
use binaryninja::headless::Session;
use std::path::PathBuf;
use svd_ninja::mapper::DeviceMapper;

// These are the target files present in OUT_DIR
// Add the files to fixtures
static TARGET_FILES: [&str; 2] = ["ARM_Sample.svd", "esp32c2.svd"];

#[test]
fn insta_types() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    for file_name in TARGET_FILES {
        let path = out_dir.join(file_name);
        let svd_str = std::fs::read_to_string(&path).expect("Failed to read svd file");
        let device = svd_parser::parse(&svd_str).expect("Failed to parse svd file");
        let view = BinaryView::from_data(&FileMetadata::new(), &[]).expect("Failed to create view");
        DeviceMapper::new(device).map_to_view(&view);
        let types = view.types().to_vec();

        let snapshot_name = format!("{}_types", file_name);
        insta::assert_debug_snapshot!(snapshot_name, types);
    }
}

#[test]
fn insta_memory_regions() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    for file_name in TARGET_FILES {
        let path = out_dir.join(file_name);
        let svd_str = std::fs::read_to_string(&path).expect("Failed to read svd file");
        let device = svd_parser::parse(&svd_str).expect("Failed to parse svd file");
        let view = BinaryView::from_data(&FileMetadata::new(), &[]).expect("Failed to create view");
        DeviceMapper::new(device).map_to_view(&view);

        // TODO: This is returning nothing in memory_region or segments???
        let snapshot_name = format!("{}_memory_map", file_name);
        insta::assert_debug_snapshot!(snapshot_name, view);
    }
}
