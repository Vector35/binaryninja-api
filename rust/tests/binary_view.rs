use binaryninja::binary_view::{AnalysisState, BinaryViewBase, BinaryViewExt};
use binaryninja::function::Function;
use binaryninja::headless::Session;
use binaryninja::main_thread::execute_on_main_thread_and_wait;
use binaryninja::symbol::{SymbolBuilder, SymbolType};
use std::path::PathBuf;

#[test]
fn test_binary_loading() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    assert!(view.has_initial_analysis(), "No initial analysis");
    assert_eq!(view.analysis_progress().state, AnalysisState::IdleState);
    assert_eq!(view.file().is_analysis_changed(), true);
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
    assert_eq!(new_view.read_vec(contents_addr, 4), [0xff, 0xff, 0xff, 0xff]);
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
    assert!(view.file().create_database(&temp_path));
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
}

// This is what we store to check if a function matches the expected function.
// See `test_deterministic_functions` for details.
#[derive(Debug, PartialEq)]
pub struct FunctionSnapshot {
    name: String,
    platform: Ref<Platform>,
    symbol: Ref<Symbol>,
}

impl From<&Function> for FunctionSnapshot {
    fn from(func: &Function) -> Self {
        Self {
            name: func.symbol().raw_name().to_string(),
            platform: func.platform().to_owned(),
            symbol: func.symbol().to_owned(),
        }
    }
}

#[rstest]
fn test_deterministic_functions(session: &Session) {
    // Test to make sure that analysis always collects the same information on functions.
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    for entry in std::fs::read_dir(out_dir).expect("Failed to read OUT_DIR") {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();
        if path.is_file() {
            let view = session.load(&path).expect("Failed to load view");
            assert_eq!(view.analysis_progress().state, AnalysisState::IdleState);
            let functions: BTreeMap<u64, FunctionSnapshot> = view
                .functions()
                .iter()
                .map(|f| (f.start(), FunctionSnapshot::from(f.as_ref())))
                .collect();
            let snapshot_name = path.file_stem().unwrap().to_str().unwrap();
            insta::assert_debug_snapshot!(snapshot_name, functions);
        }
    }
}
