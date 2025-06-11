use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use binaryninja::metadata::Metadata;
use binaryninja::rc::Ref;
use std::path::PathBuf;

#[test]
fn store_and_query_function_metadata() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let func = view
        .entry_point_function()
        .expect("Failed to get entry point function");

    // Store key/value pairs to user and auto metadata
    func.store_metadata("one", "one", false);
    func.store_metadata("two", 2 as u64, true);
    func.store_metadata("three", "three", true);
    func.remove_metadata("three");

    // Assert that we can query from both user and auto metadata
    assert_eq!(
        func.query_metadata("one")
            .expect("Failed to query key \"one\"")
            .get_string()
            .unwrap()
            .to_string_lossy(),
        "one"
    );
    assert_eq!(
        func.query_metadata("two")
            .expect("Failed to query key \"two\"")
            .get_unsigned_integer()
            .unwrap(),
        2
    );
    assert!(
        func.query_metadata("three") == None,
        "Query for key \"three\" returned a value"
    );

    // Assert that user metadata only includes key/values from user data (not auto) and vice-versa
    let user_metadata = func.get_metadata().expect("Failed to query user metadata");
    assert_eq!(
        user_metadata
            .get("one")
            .expect("Failed to query key \"one\" from user metadata")
            .expect("User metadata ref is None")
            .get_string()
            .unwrap()
            .to_string_lossy(),
        "one"
    );
    assert_eq!(user_metadata.get("two"), Ok(None));
    let auto_metadata = func
        .get_auto_metadata()
        .expect("Failed to query auto metadata");
    assert_eq!(
        auto_metadata
            .get("two")
            .expect("Failed to query key \"two\" from auto metadata")
            .expect("Auto metadata ref is None")
            .get_unsigned_integer()
            .unwrap(),
        2
    );
    assert_eq!(auto_metadata.get("one"), Ok(None));
}
