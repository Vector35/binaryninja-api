use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::type_library::TypeLibrary;
use binaryninja::types::{Type, TypeClass};
use std::path::PathBuf;

#[test]
fn test_type_library() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform = Platform::by_name("windows-x86").expect("windows-x86 exists");
    let library = platform
        .get_type_library_by_name("crypt32.dll")
        .expect("crypt32.dll exists");

    println!("{:#?}", library);
    assert_eq!(library.name(), "crypt32.dll");
    assert_eq!(library.dependency_name(), "crypt32.dll");
    assert!(library.alternate_names().is_empty());
    assert_eq!(library.platform_names().to_vec(), vec!["windows-x86"]);

    // Check some types.
    let type_0 = library
        .get_named_type("SIP_ADD_NEWPROVIDER".into())
        .unwrap();
    println!("{:#?}", type_0);
    assert_eq!(type_0.width(), 48);
    assert_eq!(type_0.type_class(), TypeClass::StructureTypeClass);
}

#[test]
fn test_applying_type_library() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform = Platform::by_name("windows-x86").expect("windows-x86 exists");
    let library = platform
        .get_type_library_by_name("crypt32.dll")
        .expect("crypt32.dll exists");

    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    view.add_type_library(&library);

    let view_library = view
        .type_library_by_name("crypt32.dll")
        .expect("crypt32.dll exists");
    assert_eq!(view_library.name(), "crypt32.dll");

    // Type library types don't exist in the view until they are imported.
    // Adding the type library to the view will let you import types from it without necessarily knowing "where" they came from.
    let found_lib_type = view
        .import_type_library("SIP_ADD_NEWPROVIDER", None)
        .expect("SIP_ADD_NEWPROVIDER exists");
    assert_eq!(found_lib_type.width(), 48);
    // Per docs type is returned as a NamedTypeReferenceClass.
    assert_eq!(
        found_lib_type.type_class(),
        TypeClass::NamedTypeReferenceClass
    );

    // Check that the type is actually in the view now.
    view.type_by_name("SIP_ADD_NEWPROVIDER")
        .expect("SIP_ADD_NEWPROVIDER exists");
}

#[test]
fn test_create_type_library() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform = Platform::by_name("windows-x86").expect("windows-x86 exists");
    let arch = platform.arch();

    // Create the new type library.
    let my_library = TypeLibrary::new(arch, "test_type_lib");
    my_library.add_alternate_name("alternate_test");
    my_library.add_platform(&platform);
    my_library.add_named_type("test_type".into(), &Type::int(7, true));

    // Write the library to a file.
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let my_library_path = temp_dir.path().join("test_type_lib.bntl");
    assert!(my_library.write_to_file(&my_library_path));

    // Verify the contents of the created file.
    let loaded_library =
        TypeLibrary::load_from_file(&my_library_path).expect("Failed to load type library");
    assert_eq!(loaded_library.name(), "test_type_lib");
    assert_eq!(
        loaded_library.alternate_names().to_vec(),
        vec!["alternate_test"]
    );
    assert_eq!(
        loaded_library.platform_names().to_vec(),
        vec!["windows-x86"]
    );
    assert_eq!(
        loaded_library
            .get_named_type("test_type".into())
            .unwrap()
            .width(),
        7
    );
}
