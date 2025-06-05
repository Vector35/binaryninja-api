use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::file_metadata::FileMetadata;
use binaryninja::headless::Session;
use binaryninja::platform::Platform;
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
    func.store_metadata("two", 2u64, true);
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
    assert_eq!(
        func.query_metadata("three"),
        None,
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

#[test]
fn add_function() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let mut func = view
        .entry_point_function()
        .expect("Failed to get entry point function");

    // Remove the function then as an auto function then add as auto function.
    // This tests to make sure that the function is not blacklisted from being added back.
    view.remove_auto_function(&func, false);

    assert_eq!(
        view.functions_at(func.start()).len(),
        0,
        "Function was not removed"
    );
    func = view
        .add_auto_function(func.start())
        .expect("Failed to add function");
    assert_eq!(
        view.functions_at(func.start()).len(),
        1,
        "Function was not added back"
    );

    // Use the user version of remove to blacklist the function, auto function should be prohibited.
    view.remove_user_function(&func);
    assert_eq!(
        view.add_auto_function(func.start()),
        None,
        "Function was not blacklisted"
    );

    // Adding back as a user should override the blacklist.
    func = view
        .add_user_function(func.start())
        .expect("Failed to add function as user");
    assert_eq!(
        view.functions_at(func.start()).len(),
        1,
        "Function was not added back"
    );

    // Make sure you cannot add a function without a default platform.
    let code = &[0xa1, 0xfa, 0xf8, 0xf0, 0x99, 0x83, 0xc0, 0x37, 0xc3];
    let view = BinaryView::from_data(&FileMetadata::new(), code).expect("Failed to create view");
    assert!(view.add_user_function(0).is_none());
    assert!(view.add_auto_function(0).is_none());

    // Now set it to verify we can add it.
    let platform = Platform::by_name("x86").expect("Failed to get platform");
    assert!(view.add_user_function_with_platform(0, &platform).is_some());
}
