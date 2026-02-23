use binaryninja::binary_view::search::SearchQuery;
use binaryninja::binary_view::{
    AnalysisProgress, AnalysisState, BinaryViewBase, BinaryViewExt, StringType,
};
use binaryninja::data_buffer::DataBuffer;
use binaryninja::file_metadata::SaveSettings;
use binaryninja::function::{Function, FunctionViewType};
use binaryninja::headless::Session;
use binaryninja::main_thread::execute_on_main_thread_and_wait;
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::symbol::{Symbol, SymbolBuilder, SymbolType};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

#[test]
fn test_binary_loading() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    assert!(view.has_initial_analysis(), "No initial analysis");
    assert_eq!(view.analysis_progress(), AnalysisProgress::Idle);
    assert_eq!(view.file().is_analysis_changed(), false);
    assert_eq!(view.file().is_database_backed(), false);
}

#[test]
fn test_binary_saving() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    // Verify the contents before we modify.
    let contents_addr = view.original_image_base() + 0x1560;
    let original_contents = view.read_vec(contents_addr, 4);
    assert_eq!(original_contents, [0x00, 0xf1, 0x00, 0x00]);
    assert_eq!(view.write(contents_addr, &[0xff, 0xff, 0xff, 0xff]), 4);
    // Verify that we modified the binary
    let modified_contents = view.read_vec(contents_addr, 4);
    assert_eq!(modified_contents, [0xff, 0xff, 0xff, 0xff]);

    // HACK: To prevent us from deadlocking in save_to_path, we wait for all main thread actions to finish.
    execute_on_main_thread_and_wait(|| {});

    let temp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
    let temp_path = temp_dir.path().join("atox.obj.new");
    // Save the modified file
    assert!(view.save_to_path(&temp_path));
    // Verify that the file exists and is modified.
    let new_view = binaryninja::load(temp_path).expect("Failed to load new view");
    assert_eq!(
        new_view.read_vec(contents_addr, 4),
        [0xff, 0xff, 0xff, 0xff]
    );
}

#[test]
fn test_binary_saving_database() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    // Update a symbol to verify modification
    let entry_function = view
        .entry_point_function()
        .expect("Failed to get entry point function");
    let new_entry_func_symbol =
        SymbolBuilder::new(SymbolType::Function, "test", entry_function.start()).create();
    view.define_user_symbol(&new_entry_func_symbol);
    // Verify that we modified the binary
    assert_eq!(entry_function.symbol().raw_name().to_string_lossy(), "test");
    // Save the modified database.
    let temp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
    let temp_path = temp_dir.path().join("atox.obj.bndb");
    assert!(view
        .file()
        .create_database(&temp_path, &SaveSettings::new()));
    // Verify that the file exists and is modified.
    let new_view = binaryninja::load(temp_path).expect("Failed to load new view");
    let new_entry_function = new_view
        .entry_point_function()
        .expect("Failed to get entry point function");
    assert_eq!(
        new_entry_function.symbol().raw_name().to_string_lossy(),
        "test"
    );
}

#[test]
fn test_binary_view_strings() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let image_base = view.original_image_base();
    assert!(view.strings().len() > 0);
    let str_15dc = view
        .strings()
        .iter()
        .find(|s| {
            let buffer = view
                .read_buffer(s.start, s.length)
                .expect("Failed to read string reference");
            let str = buffer.to_escaped_string(false, false);
            str.contains("Microsoft")
        })
        .expect("Failed to find string 'Microsoft (R) Optimizing Compiler'");
    assert_eq!(str_15dc.start, image_base + 0x15dc);
    assert_eq!(str_15dc.length, 33);
    assert_eq!(str_15dc.ty, StringType::AsciiString);

    let string = view
        .read_c_string_at(str_15dc.start, str_15dc.length)
        .expect("Failed to read string");
    assert_eq!(string, c"Microsoft (R) Optimizing Compiler");
}

#[test]
fn test_binary_view_search() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let image_base = view.original_image_base();

    // Test text search.
    let txt_1580 = view
        .find_next_text(0, view.end(), "minkernel", FunctionViewType::MediumLevelIL)
        .expect("Failed to find text 'minkernel'");
    assert_eq!(txt_1580, image_base + 0x1580);

    // Test data search.
    // 65 5c 6d 69 6e 6b 65 72 6e 65 6c (prepend bytes + minkernel)
    let data = DataBuffer::new(&[
        0x65, 0x5c, 0x6d, 0x69, 0x6e, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c,
    ]);
    let data_1580 = view
        .find_next_data(0, view.end(), &data)
        .expect("Failed to find data");
    assert_eq!(data_1580, image_base + 0x1580);

    // Test constant search.
    let constant = 0x80000000;
    let const_2607b = view
        .find_next_constant(0, view.end(), constant, FunctionViewType::MediumLevelIL)
        .expect("Failed to find constant");
    assert_eq!(const_2607b, image_base + 0x2607b);

    // Test binary search.
    let query = SearchQuery::new("42 2e 64 65 ?? 75 67 24");
    let mut found: HashSet<u64> = HashSet::new();
    let found_any = view.search(&query, |offset, _data| {
        found.insert(offset);
        true
    });
    assert!(found_any);
    assert_eq!(found.len(), 1);
    assert_eq!(found.contains(&(&image_base + 0x63)), true);
}

#[test]
fn test_binary_tags() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let tag_ty = view.create_tag_type("Test", "");
    view.add_tag(0x0, &tag_ty, "t", false);
    view.tag_type_by_name("Test")
        .expect("Failed to get tag type");
}

// These are the target files present in OUT_DIR
// Add the files to fixtures/bin
static TARGET_FILES: [&str; 2] = ["atox.obj", "atof.obj"];

// This is what we store to check if a function matches the expected function.
// See `test_deterministic_functions` for details.
#[derive(Debug, PartialEq)]
pub struct FunctionSnapshot {
    platform: Ref<Platform>,
    symbol: Ref<Symbol>,
}

impl From<&Function> for FunctionSnapshot {
    fn from(func: &Function) -> Self {
        Self {
            platform: func.platform().to_owned(),
            symbol: func.symbol().to_owned(),
        }
    }
}

#[test]
fn test_deterministic_functions() {
    let session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    for file_name in TARGET_FILES {
        let path = out_dir.join(file_name);
        let view = session.load(&path).expect("Failed to load view");
        assert_eq!(view.analysis_progress(), AnalysisProgress::Idle);
        let functions: BTreeMap<u64, FunctionSnapshot> = view
            .functions()
            .iter()
            .map(|f| (f.start(), FunctionSnapshot::from(f.as_ref())))
            .collect();
        let snapshot_name = path.file_stem().unwrap().to_str().unwrap();
        insta::assert_debug_snapshot!(snapshot_name, functions);
    }
}
