use binaryninja::architecture::CoreArchitecture;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::file_metadata::FileMetadata;
use binaryninja::function::Function as BNFunction;
use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::symbol::{Symbol as BNSymbol, SymbolType};
use binaryninja::types::TypeClass as BNTypeClass;
use std::str::FromStr;
use warp::mock::{mock_constraint, mock_function};
use warp::r#type::class::{IntegerClass, ReferrerClass, StructureClass, StructureMember};
use warp::r#type::guid::TypeGUID;
use warp::r#type::Type;
use warp::signature::function::FunctionGUID;
use warp::target::Target;
use warp_ninja::container::memory::MemoryContainer;
use warp_ninja::container::{Container, SourceId};
use warp_ninja::function_guid;
use warp_ninja::matcher::{Matcher, MatcherSettings};

const MOCK_FUNCTION_GUID: &'static str = "02e8690a-bd1e-54df-9a75-5e7bca594c30";
const MOCK_FUNCTION_BYTES: &[u8] = &[
    // first_function
    0xA1, 0xFA, 0xF8, 0xF0, 0x99, // ; mov eax, [0x99f0f8fa]
    0x83, 0xC0, 0x37, // ; add eax, 55
    0xC3, // ; ret
    // second_function
    0xA1, 0xFA, 0xF8, 0xF0, 0x91, // ; mov eax, [0x91f0f8fa]
    0x83, 0xC0, 0x37, // ; add eax, 55
    0xC3, // ; ret
];

fn create_mock_bn_function(_session: &Session) -> Ref<BNFunction> {
    let file = FileMetadata::new();
    let view =
        BinaryView::from_data(&file, MOCK_FUNCTION_BYTES).expect("Failed to create mock view");
    let platform = Platform::by_name("x86").unwrap();
    // Add the constraint symbol so that the matcher picks it up, so we can test constraint matching.
    let constraint_symbol =
        BNSymbol::builder(SymbolType::Function, "second_function", 0x9).create();
    view.define_user_symbol(&constraint_symbol);
    let function_symbol = BNSymbol::builder(SymbolType::Function, "first_function", 0x0).create();
    view.define_user_symbol(&function_symbol);
    // Define the constraint function.
    view.add_user_function_with_platform(0x9, &platform)
        .expect("Failed to create constraint function");
    // Actually define the function and return it.
    view.add_user_function_with_platform(0x0, &platform)
        .expect("Failed to create mock function")
}

#[test]
fn test_match_function() {
    let mut matcher_settings = MatcherSettings::default();
    matcher_settings.trivial_function_len = 0;
    let matcher = Matcher::new(matcher_settings);

    // The memory container does not currently reference a target.
    let target = Target::default();

    let func = mock_function(MOCK_FUNCTION_GUID);
    let func_guid = func.guid.clone();

    let source = SourceId::new();
    let memory_container =
        MemoryContainer::new().with_source_function(source, func_guid, func.clone());

    // Create mock binary ninja function.
    let session = Session::new().expect("Failed to create session");
    let bn_function = create_mock_bn_function(&session);

    let possible_funcs = memory_container
        .functions_with_guid(&target, &source, &func_guid)
        .expect("Failed to get functions");

    // Because there is only a single possible function this should just return that function.
    let matched_function = matcher
        .match_function_from_constraints(&bn_function, &possible_funcs)
        .expect("Failed to match function");
    assert_eq!(matched_function, &func);
}

#[test]
fn test_match_function_from_constraints() {
    let mut matcher_settings = MatcherSettings::default();
    // TODO: This is needed to make the test pass, the functions are "trivial" in length.
    matcher_settings.trivial_function_adjacent_allowed = true;
    let matcher = Matcher::new(matcher_settings);
    let mut function = mock_function("first_function");
    function.guid = FunctionGUID::from_str(MOCK_FUNCTION_GUID).expect("Failed to parse guid");
    let func_guid = function.guid.clone();
    // Add constraint
    function
        .constraints
        .insert(mock_constraint("second_function", Some(0x9)));

    let matched_func_1 = function.clone();
    let mut matched_func_2 = function.clone();
    // Remove the constraint from 2, this means that the first matched_func should match.
    matched_func_2.constraints.clear();
    let mut matched_functions = vec![matched_func_1.clone(), matched_func_2];

    // Create a mock binary ninja function.
    let session = Session::new().expect("Failed to create session");
    let bn_function = create_mock_bn_function(&session);
    let bn_function_guid = function_guid(&bn_function, &bn_function.lifted_il().unwrap());
    assert_eq!(bn_function_guid, func_guid);

    // We should match on the first as it has the adjacent constraint still.
    let matched_0 = matcher
        .match_function_from_constraints(&bn_function, &matched_functions)
        .expect("Failed to match function");
    assert_eq!(matched_0, &function);

    // Now we want to verify we do not match when the matched function is duplicated.
    // NOTE: That in the case of identical functions in a set, we would prune them eagerly, so this is
    // NOTE: not really indicative of a real scenario.
    matched_functions.push(matched_func_1);

    let matched_1 = matcher.match_function_from_constraints(&bn_function, &matched_functions);
    assert_eq!(matched_1, None);
}

fn create_mock_type() -> Type {
    // Build the type, this is quite annoying.
    let int_class = IntegerClass::builder().width(64).signed(true).build();
    let int_type = Type::builder()
        .name("my_int".to_owned())
        .class(int_class)
        .build();

    let struct_member_0 = StructureMember::builder()
        .name("field_0")
        .ty(int_type)
        .offset(0)
        .build();
    let struct_class = StructureClass::builder()
        .members(vec![struct_member_0])
        .build();

    Type::builder()
        .name("my_struct")
        .class(struct_class)
        .build()
}

#[test]
fn test_add_type_to_view() {
    let matcher_settings = MatcherSettings::default();
    let matcher = Matcher::new(matcher_settings);

    // Add a source type that we can reference and pull in from the container.
    let struct_type = create_mock_type();
    let struct_type_guid = TypeGUID::from(&struct_type);
    let struct_type_name = struct_type.name.clone().expect("Type should have name");

    let source = SourceId::new();
    let container = MemoryContainer::new().with_source_type(source, struct_type_guid, struct_type);

    let _session = Session::new().expect("Failed to create session");
    let file = FileMetadata::new();
    let view = BinaryView::from_data(&file, &[]).expect("Failed to create view");
    let arch = CoreArchitecture::by_name("x86").expect("Failed to get architecture");

    // Try and add a NTR to the view, this should also add the referenced struct type.
    let ref_class = ReferrerClass::builder()
        .name(struct_type_name)
        .guid(struct_type_guid)
        .build();
    let ref_type = Type::builder().name("my_ref").class(ref_class).build();
    matcher.add_type_to_view(&container, &source, &view, arch, &ref_type);

    println!("{:#?}", view.types().to_vec());

    // Verify the type was added to the view.
    let found_type = view
        .type_by_name("my_struct")
        .expect("Failed to find added type");
    // Make sure we actually added it as a structure type.
    assert_eq!(found_type.type_class(), BNTypeClass::StructureTypeClass);
}
