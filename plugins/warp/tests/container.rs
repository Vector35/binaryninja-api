use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;
use uuid::Uuid;
use warp::r#type::class::BooleanClass;
use warp::r#type::class::TypeClass::Void;
use warp::r#type::guid::TypeGUID;
use warp::r#type::{ComputedType, Type};
use warp::signature::function::{Function, FunctionGUID};
use warp::symbol::{Symbol, SymbolClass};
use warp::target::Target;
use warp_ninja::container::disk::DiskContainer;
use warp_ninja::container::memory::{MemoryContainer, MemorySource};
use warp_ninja::container::{Container, ContainerError, SourceId, SourcePath};

fn type_0() -> (TypeGUID, Type) {
    let ty = Type::builder()
        .name("type_0")
        .class(BooleanClass::builder().width(1).build())
        .build();
    (TypeGUID::from(&ty), ty)
}

fn type_1() -> (TypeGUID, Type) {
    let ty = Type::builder()
        .name("type_1")
        .class(BooleanClass::builder().width(4).build())
        .build();
    (TypeGUID::from(&ty), ty)
}

fn type_2() -> (TypeGUID, Type) {
    let ty = Type::builder()
        .name("type_2")
        .class(BooleanClass::builder().width(8).build())
        .build();
    (TypeGUID::from(&ty), ty)
}

fn func_0() -> (FunctionGUID, Function) {
    let guid = FunctionGUID::from(Uuid::from_str("d4e56ec8-1f2b-4a87-9f2c-bc3f10c4d8e9").unwrap());
    let function = Function {
        guid,
        symbol: Symbol {
            name: "func_0".to_string(),
            modifiers: Default::default(),
            class: SymbolClass::Function,
        },
        // TODO: We might want to give this an actual function type.
        ty: Some(Type::builder::<String, _>().class(Void).build()),
        constraints: Default::default(),
        comments: vec![],
        variables: vec![],
    };
    (guid, function)
}

fn func_1() -> (FunctionGUID, Function) {
    let guid = FunctionGUID::from(Uuid::from_str("b713c293-463a-5baa-b31b-ed010510d5c0").unwrap());
    let function = Function {
        guid,
        symbol: Symbol {
            name: "func_1".to_string(),
            modifiers: Default::default(),
            class: SymbolClass::Function,
        },
        // TODO: We might want to give this an actual function type.
        ty: Some(Type::builder::<String, _>().class(Void).build()),
        constraints: Default::default(),
        comments: vec![],
        variables: vec![],
    };
    (guid, function)
}

#[test]
fn test_sources_with_type_guid() {
    let source1 = SourceId::new();
    let source2 = SourceId::new();
    let (guid_1, ty_1) = type_0();
    let (guid_2, ty_2) = type_1();

    let container = MemoryContainer::new()
        .with_source_type(source1, guid_1, ty_1)
        .with_source_type(source1, guid_2, ty_2.clone())
        .with_source_type(source2, guid_2, ty_2);

    let result = container
        .sources_with_type_guid(&guid_2)
        .expect("Failed to get sources");
    // HashSet used for unordered comparison
    let result_set: HashSet<_> = result.into_iter().collect();
    let expected_set: HashSet<_> = vec![source1, source2].into_iter().collect();
    assert_eq!(result_set, expected_set);

    let result = container
        .sources_with_type_guid(&guid_1)
        .expect("Failed to get sources");
    // HashSet used for unordered comparison
    let result_set: HashSet<_> = result.into_iter().collect();
    let expected_set: HashSet<_> = vec![source1].into_iter().collect();
    assert_eq!(result_set, expected_set);
}

#[test]
fn test_sources_with_function_guid() {
    let target = Target::default();

    let source1 = SourceId::new();
    let source2 = SourceId::new();
    let (guid_1, fn_1) = func_0();
    let (guid_2, fn_2) = func_1();

    let container = MemoryContainer::new()
        .with_source_function(source1, guid_1, fn_1)
        .with_source_function(source1, guid_2, fn_2.clone())
        .with_source_function(source2, guid_2, fn_2);

    let result = container
        .sources_with_function_guid(&target, &guid_2)
        .expect("Failed to get sources");
    // HashSet used for unordered comparison
    let result_set: HashSet<_> = result.into_iter().collect();
    let expected_set: HashSet<_> = vec![source1, source2].into_iter().collect();
    assert_eq!(result_set, expected_set);

    let result = container
        .sources_with_function_guid(&target, &guid_1)
        .expect("Failed to get sources");
    assert_eq!(result, vec![source1]);
}

#[test]
fn test_sources_with_type_guids() {
    let source1 = SourceId::new();
    let source2 = SourceId::new();
    let (guid_1, ty_1) = type_0();
    let (guid_2, ty_2) = type_1();
    let (guid_3, ty_3) = type_2();

    let container = MemoryContainer::new()
        .with_source_type(source1, guid_1, ty_1)
        .with_source_type(source1, guid_2, ty_2.clone())
        .with_source_type(source2, guid_2, ty_2)
        .with_source_type(source2, guid_3, ty_3);

    let result = container
        .sources_with_type_guids(&[guid_2.clone(), guid_3.clone()])
        .expect("Failed to get sources");
    assert_eq!(result.len(), 2);
    assert!(result.get(&guid_2).unwrap().contains(&source1));
    assert!(result.get(&guid_2).unwrap().contains(&source2));
    assert!(result.get(&guid_3).unwrap().contains(&source2));
}

#[test]
fn test_add_types() {
    let source1 = SourceId::new();
    let source2 = SourceId::new();
    let (guid_1, ty_1) = type_0();
    let (guid_2, ty_2) = type_1();
    let mut container = MemoryContainer::new()
        .with_source(
            source1,
            MemorySource {
                writable: false,
                ..Default::default()
            },
        )
        .with_source_type(source1, guid_1, ty_1.clone())
        .with_source_type(source2, guid_2, ty_2.clone());

    assert_eq!(
        container.add_types(&source1, &[ty_1.clone()]),
        Err(ContainerError::SourceNotWritable(source1)),
        "Source should not be writable"
    );
    assert_eq!(
        container.add_types(&source2, &[ty_1.clone()]),
        Ok(()),
        "Source should be writable"
    );
    container
        .type_with_guid(&source1, &guid_1)
        .expect("Failed to get existing type");
    container
        .type_with_guid(&source2, &guid_1)
        .expect("Failed to get added type");
    container
        .type_with_guid(&source2, &guid_2)
        .expect("Failed to get existing type");
}

#[test]
fn test_disk_container() {
    // We are going to use the OUT_DIR as the disk container path, this might have other artifacts in it
    // so it's a good test to make sure that we handle bad files gracefully.
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR environment variable is not set");
    let out_dir_path: PathBuf = out_dir.parse().expect("Failed to parse OUT_DIR as path");

    // TODO: Use a temp file for this instead lol.
    let added_type_path = out_dir_path.join("added_type.warp");
    // Make sure that we have deleted the previous runs artifacts.
    if std::fs::exists(&added_type_path).unwrap() {
        std::fs::remove_file(&added_type_path).expect("Failed to remove existing file");
    }

    // Write a simple test to open a file with DiskContainer
    let mut container = DiskContainer::new_from_dir(out_dir_path.clone());

    // Just pass in the default target, there is no target specified in the file.
    let target = Target::default();

    // Test type retrieval.
    // Type -> type_10 : 2f6d2876-ec42-5ca1-bee3-f12fe91d7e13
    let type_0 = TypeGUID::from(Uuid::from_str("2f6d2876-ec42-5ca1-bee3-f12fe91d7e13").unwrap());
    let sources: Vec<SourceId> = container
        .sources_with_type_guid(&type_0)
        .expect("Failed to get sources")
        .into_iter()
        .collect();
    assert_eq!(sources.len(), 1);
    let result_type_0 = container
        .type_with_guid(&sources[0], &type_0)
        .expect("Failed to get type")
        .expect("Type not found");
    assert_eq!(result_type_0.name, Some("type_10".to_string()));
    let result_type_guids_0 = container
        .type_guids_with_name(&sources[0], "type_10")
        .expect("Failed to get type guids");
    assert_eq!(result_type_guids_0.len(), 1);
    assert_eq!(result_type_guids_0[0], type_0);

    // Test function retrieval.
    // Function -> function_95 : d5da0413-a020-5db8-b838-4d0ea8bd3dcb
    let func_0 =
        FunctionGUID::from(Uuid::from_str("d5da0413-a020-5db8-b838-4d0ea8bd3dcb").unwrap());
    let func_sources = container
        .sources_with_function_guid(&target, &func_0)
        .expect("Failed to get sources");
    assert_eq!(func_sources.len(), 1);
    let result_func_0 = container
        .functions_with_guid(&target, &func_sources[0], &func_0)
        .expect("Failed to get functions");
    assert_eq!(result_func_0.len(), 1);
    assert_eq!(result_func_0[0].symbol.name, "function_95".to_string());

    // Test adding a type to an existing disk source.
    let mut result_type_0_mut = result_type_0.clone();
    result_type_0_mut.name = Some("added_type".to_string());
    let computed_result_type_0 = ComputedType::new(result_type_0_mut);
    container
        .add_types(&sources[0], &[computed_result_type_0.ty])
        .expect("Failed to add type");
    let result_type_1 = container
        .type_guids_with_name(&sources[0], "added_type")
        .expect("Failed to get added type");
    assert_eq!(
        result_type_1,
        vec![computed_result_type_0.guid],
        "Added type was not found in the existing source"
    );

    // Test commiting the updated source.
    // NOTE: Because we don't want to modify the file, we are going to change the source path
    // before trying to commit it, this is a bit hacky and should not really be done in real code.
    let source = container
        .sources
        .get_mut(&sources[0])
        .expect("Container does not contain the source");
    source.path = SourcePath::new(out_dir_path.join("added_type.warp"));
    container
        .commit_source(&sources[0])
        .expect("Failed to commit source");
    assert_eq!(
        std::fs::exists(&added_type_path).unwrap(),
        true,
        "File was not created"
    );
}
