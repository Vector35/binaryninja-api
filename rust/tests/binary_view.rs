use binaryninja::binary_view::{AnalysisState, BinaryViewBase, BinaryViewExt};
use binaryninja::headless::Session;
use binaryninja::main_thread::execute_on_main_thread_and_wait;
use binaryninja::symbol::{SymbolBuilder, SymbolType};
use rstest::*;
use std::path::PathBuf;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_binary_loading(_session: &Session) {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    assert!(view.has_initial_analysis(), "No initial analysis");
    assert_eq!(view.analysis_progress().state, AnalysisState::IdleState);
    assert_eq!(view.file().is_analysis_changed(), true);
    assert_eq!(view.file().is_database_backed(), false);
}

#[rstest]
fn test_binary_saving(_session: &Session) {
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

    // HACK: To prevent us from deadlocking in save_to_path we wait for all main thread actions to finish.
    execute_on_main_thread_and_wait(|| {});

    // Save the modified file
    assert!(view.save_to_path(out_dir.join("atox.obj.new")));
    // Verify that the file exists and is modified.
    let new_view =
        binaryninja::load(out_dir.join("atox.obj.new")).expect("Failed to load new view");
    assert_eq!(
        new_view.read_vec(contents_addr, 4),
        [0xff, 0xff, 0xff, 0xff]
    );
}

#[rstest]
fn test_binary_saving_database(_session: &Session) {
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
    assert_eq!(entry_function.symbol().raw_name().as_str(), "test");
    // Save the modified database.
    assert!(view.file().create_database(out_dir.join("atox.obj.bndb")));
    // Verify that the file exists and is modified.
    let new_view =
        binaryninja::load(out_dir.join("atox.obj.bndb")).expect("Failed to load new view");
    let new_entry_function = new_view
        .entry_point_function()
        .expect("Failed to get entry point function");
    assert_eq!(new_entry_function.symbol().raw_name().as_str(), "test");
}
