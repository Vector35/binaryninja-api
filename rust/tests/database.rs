use binaryninja::database::Database;
use binaryninja::file_metadata::SaveSettings;
use binaryninja::headless::Session;
use std::path::PathBuf;

#[test]
fn test_open_existing() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    // Save the modified database.
    let temp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
    let temp_path = temp_dir.path().join("atox.obj.bndb");
    assert!(view
        .file()
        .create_database(&temp_path, &SaveSettings::new()));
    // Verify that the file exists and is modified.
    drop(view);
    let db = Database::open_existing(&temp_path).unwrap();
    // Make sure the database has data
    assert!(db.snapshots().len() > 0);
}
