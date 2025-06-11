use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::type_archive::TypeArchive;
use binaryninja::types::{Type, TypeClass};

#[test]
fn test_create_archive() {
    let _session = Session::new().expect("Failed to initialize session");
    let placeholder_platform = Platform::by_name("x86_64").expect("Failed to get platform");

    let temp_dir = tempfile::tempdir().unwrap();
    let type_archive_path = temp_dir.path().with_file_name("type_archive_0");
    let type_archive = TypeArchive::create(&type_archive_path, &placeholder_platform).unwrap();
    type_archive.add_type(("test", Type::int(7, true)).into());
    println!("{:?}", type_archive);
    // TODO: It seems that type archives have to be closed.
    type_archive.close();

    // Now open the type archive to check.
    let type_archive = TypeArchive::open(&type_archive_path).expect("Opened type archive");
    let test_type = type_archive
        .get_type_by_name("test".into())
        .expect("Found test type");
    assert_eq!(test_type.width(), 7);
    assert_eq!(test_type.type_class(), TypeClass::IntegerTypeClass);
}
