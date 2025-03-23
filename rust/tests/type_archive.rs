use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::type_archive::TypeArchive;

#[test]
fn test_create_archive() {
    let _session = Session::new().expect("Failed to initialize session");
    let placeholder_platform = Platform::by_name("x86_64").expect("Failed to get platform");

    let temp_dir = tempfile::tempdir().unwrap();
    let type_archive_path = temp_dir.path().with_file_name("type_archive_0");
    let type_archive = TypeArchive::create(type_archive_path, &placeholder_platform).unwrap();
    println!("{:?}", type_archive);
    // TODO: It seems that type archives have to be closed.
    type_archive.close();
}
