use binaryninja::binary_view::BinaryViewExt;
use binaryninja::binary_view::{BinaryView, BinaryViewBase};
use binaryninja::file_metadata::FileMetadata;
use binaryninja::headless::Session;
use std::path::PathBuf;
use svd_ninja::mapper::DeviceMapper;
use svd_ninja::settings::LoadSettings;

// These are the target files present in OUT_DIR
// Add the files to fixtures
static TARGET_FILES: [&str; 2] = ["ARM_Sample.svd", "esp32c2.svd"];

#[test]
fn insta_snapshots() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    for file_name in TARGET_FILES {
        let path = out_dir.join(file_name);
        let svd_str = std::fs::read_to_string(&path).expect("Failed to read svd file");
        let device = svd_parser::parse(&svd_str).expect("Failed to parse svd file");
        let view = BinaryView::from_data(&FileMetadata::new(), &[]).expect("Failed to create view");
        let address_size = view.address_size();
        DeviceMapper::new(LoadSettings::default(), address_size, device).map_to_view(&view);

        let types = view
            .types()
            .to_vec()
            .iter()
            .map(|ty| ty.ty.to_string())
            .collect::<Vec<String>>();
        let types_snapshot_name = format!("{}_types", file_name);
        insta::assert_debug_snapshot!(types_snapshot_name, types);

        // TODO: This does not work yet because memory map is not turned on for raw view?
        // let value: Value = serde_json::from_str(&view.memory_map().description()).unwrap();
        // let map = view.memory_map().description();
        // let memory_snapshot_name = format!("{}_memory_map", file_name);
        // insta::assert_debug_snapshot!(memory_snapshot_name, value);
    }
}

#[test]
fn test_bitfield_unions() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let path = out_dir.join("ARM_Sample.svd");
    let svd_str = std::fs::read_to_string(&path).expect("Failed to read svd file");
    let device = svd_parser::parse(&svd_str).expect("Failed to parse svd file");
    let view = BinaryView::from_data(&FileMetadata::new(), &[]).expect("Failed to create view");
    let address_size = view.address_size();
    let mapper = DeviceMapper::new(LoadSettings::default(), address_size, device.clone());

    let peripheral = device.get_peripheral("TIMER0").unwrap();
    let register = peripheral.get_register("SR").unwrap();
    let register_ty = mapper.register_type(&register);
    insta::assert_debug_snapshot!("bitfield_union_types", register_ty);
}
