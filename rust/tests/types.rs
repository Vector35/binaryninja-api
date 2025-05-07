use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::confidence::Conf;
use binaryninja::file_metadata::FileMetadata;
use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::types::{MemberAccess, MemberScope, StructureBuilder, StructureMember, Type};

#[test]
fn test_type_to_string() {
    let _session = Session::new().expect("Failed to initialize session");
    let test_type = Type::int(4, true);
    assert_eq!(test_type.to_string(), "int32_t".to_string());

    let platform = Platform::by_name("x86").expect("Failed to get platform");
    let calling_conv = platform
        .get_default_calling_convention()
        .expect("Failed to get calling convention");
    let test_fn_type =
        Type::function_with_opts(&test_type, &[], false, calling_conv, Conf::new(0, 0));
    assert_eq!(test_fn_type.to_string(), "int32_t()");
}

#[test]
fn test_structure_builder() {
    let _session = Session::new().expect("Failed to initialize session");
    let mut builder = StructureBuilder::new();
    builder.insert(
        &Type::int(4, true),
        "field_1",
        0,
        false,
        MemberAccess::PrivateAccess,
        MemberScope::FriendScope,
    );
    builder.insert(
        &Type::float(8),
        "field_2",
        4,
        false,
        MemberAccess::PublicAccess,
        MemberScope::NoScope,
    );

    let structure = builder.finalize();
    let members = structure.members();
    assert_eq!(members.len(), 2);
    assert_eq!(
        members[0],
        StructureMember {
            name: "field_1".to_string(),
            ty: Type::int(4, true).into(),
            offset: 0,
            access: MemberAccess::PrivateAccess,
            scope: MemberScope::FriendScope,
        }
    );
}

#[test]
fn add_type_to_view() {
    let _session = Session::new().expect("Failed to initialize session");
    let empty_view =
        BinaryView::from_data(&FileMetadata::new(), &[]).expect("Failed to create view");
    let test_type = Type::int(4, true);
    empty_view.define_auto_type("test", "me", &test_type);
    assert!(empty_view.type_by_name("test").is_some());
    empty_view.undefine_auto_type(
        &empty_view
            .type_id_by_name("test")
            .expect("Failed to get type id"),
    );
    assert!(empty_view.type_by_name("test").is_none());
}
