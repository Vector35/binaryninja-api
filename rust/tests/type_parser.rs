use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::type_parser::{CoreTypeParser, TypeParser, TypeParserError};
use binaryninja::types::Type;
use binaryninjacore_sys::BNTypeParserErrorSeverity::ErrorSeverity;
use rstest::*;

const TEST_TYPES: &str = r#"
typedef int int32_t;
typedef unsigned int uint32_t;
typedef float float_t;
typedef double double_t;
typedef char char_t;
typedef unsigned char uchar_t;
typedef short short_t;
typedef unsigned short ushort_t;
typedef long long_t;
typedef unsigned long ulong_t;
typedef long long longlong_t;
typedef unsigned long long ulonglong_t;
typedef void* void_ptr_t;
typedef int (*function_type)(int arg1, float arg2);
// This should be 2 types
typedef struct {
    int a;
    float b;
} struct_type;
"#;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_string_to_type(_session: &Session) {
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let plat_type_container = platform.type_container();
    let parser = CoreTypeParser::default();
    let parsed_type = parser
        .parse_type_string("int32_t", &platform, &plat_type_container)
        .expect("Parsed int32_t");
    let test_type = Type::int(4, true);
    assert_eq!(test_type, parsed_type.ty);
}

#[rstest]
fn test_string_to_types(_session: &Session) {
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let plat_type_container = platform.type_container();
    let parser = CoreTypeParser::default();
    let parsed_type = parser
        .parse_types_from_source(
            TEST_TYPES,
            "test_file.h",
            &platform,
            &plat_type_container,
            &[],
            &[],
            "",
        )
        .expect("Parsed types");
    assert_eq!(14, parsed_type.types.len());
}

#[rstest]
fn test_parse_error(_session: &Session) {
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let plat_type_container = platform.type_container();
    let parser = CoreTypeParser::default();
    let parser_error = parser
        .parse_type_string("AAAAA", &platform, &plat_type_container)
        .expect_err("Parsing should fail!");
    assert_eq!(
        parser_error,
        vec![TypeParserError {
            severity: ErrorSeverity,
            message: "a type specifier is required for all declarations".to_string(),
            file_name: "string.hpp".to_string(),
            line: 1,
            column: 1
        }]
    );
}
