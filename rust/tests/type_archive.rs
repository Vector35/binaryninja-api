use binaryninja::binary_view::BinaryView;
use binaryninja::file_metadata::FileMetadata;
use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::type_archive::TypeArchive;
use rstest::*;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[fixture]
#[once]
fn empty_view() -> Ref<BinaryView> {
    BinaryView::from_data(&FileMetadata::new(), &[]).expect("Failed to create view")
}

#[rstest]
fn test_create_archive(_session: &Session) {
    let placeholder_platform = Platform::by_name("x86_64").expect("Failed to get platform");

    let temp_dir = tempfile::tempdir().unwrap();
    let type_archive_path = temp_dir.path().with_file_name("type_archive_0");
    let type_archive = TypeArchive::create(type_archive_path, &placeholder_platform).unwrap();
    println!("{:?}", type_archive);
    // TODO: It seems that type archives have to be closed.
    type_archive.close();
}
