use binaryninja::binary_view::BinaryView;
use binaryninja::enterprise::release_license;
use binaryninja::file_metadata::FileMetadata;
use binaryninja::headless::{
    init, init_with_opts, shutdown, InitializationError, InitializationOptions,
};
use binaryninja::set_license;
use rstest::rstest;

// NOTE: Do not add any tests here, behavior will change (i.e. a failure might pass) if we initialize
// NOTE: The core in another test. The only test here should be `test_license_validation`.

#[rstest]
fn test_license_validation() {
    // Release floating license if we already have one, otherwise the failure will succeed.
    release_license();
    // Make sure we properly report invalid license.
    let options = InitializationOptions::default()
        .with_license_checkout(false)
        .with_license("blah blag");
    match init_with_opts(options) {
        Ok(_) => panic!("Expected license validation to fail, but it succeeded!"),
        Err(InitializationError::InvalidLicense) => {}
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
    // Reset the license so that it actually can validate license.
    set_license::<String>(None);
    // Actually make sure we can initialize.
    init().expect("Failed to initialize, make sure you have a license before trying to run tests!");
    // Open an empty binary and make sure it succeeds.
    let view = BinaryView::from_data(&FileMetadata::new(), &[]);
    assert!(
        view.is_ok(),
        "Failed to open empty binary, core initialization failed!"
    );
    shutdown();
}
