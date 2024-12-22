use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::file_metadata::FileMetadata;
use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::types::Type;
use rstest::*;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[fixture]
#[once]
fn platform() -> Ref<Platform> {
    // TODO: Because some behavior might be platform specific we might need to move this back into each test.
    // TODO: See test_parse_type
    Platform::by_name("windows-x86_64").expect("windows-x86_64 exists")
}

#[fixture]
#[once]
fn empty_view() -> Ref<BinaryView> {
    BinaryView::from_data(&FileMetadata::new(), &[]).expect("Failed to create view")
}

#[rstest]
fn test_types(_session: &Session, platform: &Platform) {
    let type_container = platform.type_container();
    let types = type_container.types().unwrap();
    // windows-x86_64 has a few thousand, not zero.
    assert_eq!(types.len(), platform.types().len());
}

#[rstest]
fn test_type_id(_session: &Session, platform: &Platform) {
    let type_container = platform.type_container();
    let type_ids = type_container.type_ids().unwrap();
    let first_type_id = type_ids.iter().next().unwrap();
    let found_type = type_container
        .type_by_id(first_type_id)
        .expect("Type ID not valid!");
    let found_type_name = type_container
        .type_name(first_type_id)
        .expect("Type name not found for Type ID");
    let found_type_for_type_name = type_container
        .type_by_name(found_type_name)
        .expect("Found type name not valid!");
    // These _should_ be the same type.
    assert_eq!(found_type, found_type_for_type_name);
}

#[rstest]
fn test_add_delete_type(_session: &Session, empty_view: &BinaryView) {
    let view_type_container = empty_view.type_container();
    let test_type = Type::int(4, true);
    assert!(
        view_type_container.add_types([("mytype", test_type)]),
        "Failed to add types!"
    );
    let my_type_id = view_type_container
        .type_id("mytype")
        .expect("mytype not found");
    assert!(
        view_type_container.delete_type(my_type_id),
        "Type was deleted!"
    );
    // There should be no type ids if the type was actually deleted
    assert_eq!(view_type_container.type_ids().unwrap().len(), 0)
}

#[rstest]
fn test_immutable_container(_session: &Session, platform: &Platform) {
    // Platform type containers are immutable, so we shouldn't be able to delete/add/rename types.
    let plat_type_container = platform.type_container();
    assert!(
        !plat_type_container.is_mutable(),
        "Platform should NOT be mutable!"
    );
    assert_ne!(
        platform.types().len(),
        0,
        "Something deleted all the platform types!"
    );
    let type_ids = plat_type_container.type_ids().unwrap();
    let first_type_id = type_ids.iter().next().unwrap();
    // Platform type containers are immutable so these should be false!
    assert!(
        !plat_type_container.delete_type(first_type_id),
        "Type was deleted!"
    );
    assert!(
        !plat_type_container.add_types([("new_type", Type::int(4, true))]),
        "Type was added!"
    );
    assert!(
        !plat_type_container.rename_type(first_type_id, "renamed_type"),
        "Type was renamed!"
    );
}

#[rstest]
fn test_parse_type(_session: &Session, platform: &Platform) {
    let type_container = platform.type_container();
    // HANDLE will be pulled in from the platform, which is `windows-x86_64`.
    let parsed_type = type_container
        .parse_type_string("typedef HANDLE test;", false)
        .map_err(|e| e.to_vec())
        .expect("Failed to parse type");
    assert_eq!(parsed_type.name, "test".into());
    assert_eq!(parsed_type.ty.to_string(), "HANDLE");
}

#[rstest]
fn test_container_lifetime(_session: &Session, platform: &Platform, empty_view: &BinaryView) {
    let plat_type_container_dropped = platform.type_container();
    let view_type_container_dropped = empty_view.type_container();
    let _plat_types_dropped = plat_type_container_dropped.types();
    let _view_types_dropped = view_type_container_dropped.types();
    drop(plat_type_container_dropped);
    drop(view_type_container_dropped);
    let plat_type_container_0 = platform.type_container();
    let view_type_container_0 = empty_view.type_container();
    let test_type = Type::int(4, true);
    view_type_container_0.add_types([("mytype", test_type)]);
    let plat_types_0 = plat_type_container_0.types();
    let view_types_0 = view_type_container_0.types();
    let plat_type_container_1 = platform.type_container();
    let view_type_container_1 = empty_view.type_container();
    let plat_types_1 = plat_type_container_1.types();
    let view_types_1 = view_type_container_1.types();
    // If the types do not equal the container is being freed from the first set of calls.
    assert_eq!(plat_types_0, plat_types_1);
    assert_eq!(view_types_0, view_types_1);
}
