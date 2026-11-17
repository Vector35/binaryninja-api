use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::types::parser::{register_type_parser, ParsedType, TypeParserOption};
use binaryninja::types::{
    CoreTypeParser, QualifiedNameAndType, Type, TypeContainer, TypeParser, TypeParserError,
    TypeParserResult,
};
use binaryninjacore_sys::BNTypeParserErrorSeverity::ErrorSeverity;
use std::path::PathBuf;

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

#[test]
fn test_string_to_type() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let plat_type_container = platform.type_container();
    let parser = CoreTypeParser::default();
    let parsed_type = parser
        .parse_type_string("int32_t", &platform, Some(&plat_type_container))
        .expect("Parsed int32_t");
    let test_type = Type::int(4, true);
    assert_eq!(test_type, parsed_type.ty);
}

struct OptionTextTypeParser;

impl TypeParser for OptionTextTypeParser {
    fn get_option_text(&self, option: TypeParserOption, value: &str) -> Option<String> {
        match (option, value) {
            (TypeParserOption::IncludeSystemTypes, "true") => Some("--option-text".to_string()),
            _ => None,
        }
    }

    fn preprocess_source(
        &self,
        _source: &str,
        _file_name: &str,
        _platform: &Platform,
        _existing_types: Option<&TypeContainer>,
        _options: &[String],
        _include_dirs: &[PathBuf],
    ) -> Result<String, Vec<TypeParserError>> {
        Err(vec![])
    }

    fn parse_types_from_source(
        &self,
        _source: &str,
        _file_name: &str,
        _platform: &Platform,
        _existing_types: Option<&TypeContainer>,
        _options: &[String],
        _include_dirs: &[PathBuf],
        _auto_type_source: &str,
    ) -> Result<TypeParserResult, Vec<TypeParserError>> {
        Err(vec![])
    }

    fn parse_type_string(
        &self,
        _source: &str,
        _platform: &Platform,
        _existing_types: Option<&TypeContainer>,
    ) -> Result<QualifiedNameAndType, Vec<TypeParserError>> {
        Err(vec![])
    }
}

#[test]
fn test_option_text() {
    let _session = Session::new().expect("Failed to initialize session");
    let (_, parser) = register_type_parser("option_text_type_parser", OptionTextTypeParser);
    assert_eq!(
        parser.get_option_text(TypeParserOption::IncludeSystemTypes, "true"),
        Some("--option-text".to_string())
    );
    assert_eq!(
        parser.get_option_text(TypeParserOption::IncludeSystemTypes, "maybe"),
        None
    );
}

#[test]
fn test_string_to_types() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let plat_type_container = platform.type_container();
    let parser = CoreTypeParser::default();
    let parsed_type = parser
        .parse_types_from_source(
            TEST_TYPES,
            "test_file.h",
            &platform,
            Some(&plat_type_container),
            &[],
            &[],
            "",
        )
        .expect("Parsed types");
    assert_eq!(14, parsed_type.types.len());
}

#[test]
fn test_parse_error() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let plat_type_container = platform.type_container();
    let parser = CoreTypeParser::default();
    let parser_error = parser
        .parse_type_string("AAAAA", &platform, Some(&plat_type_container))
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

struct CannedTypeParser;

impl TypeParser for CannedTypeParser {
    fn get_option_text(&self, _option: TypeParserOption, _value: &str) -> Option<String> {
        None
    }

    fn preprocess_source(
        &self,
        source: &str,
        _file_name: &str,
        _platform: &Platform,
        _existing_types: Option<&TypeContainer>,
        options: &[String],
        include_dirs: &[PathBuf],
    ) -> Result<String, Vec<TypeParserError>> {
        Ok(format!(
            "{source}: {} options, {} include dirs",
            options.len(),
            include_dirs.len()
        ))
    }

    fn parse_types_from_source(
        &self,
        _source: &str,
        file_name: &str,
        _platform: &Platform,
        _existing_types: Option<&TypeContainer>,
        options: &[String],
        include_dirs: &[PathBuf],
        _auto_type_source: &str,
    ) -> Result<TypeParserResult, Vec<TypeParserError>> {
        let name = format!(
            "{file_name}: {} options, {} include dirs",
            options.len(),
            include_dirs.len()
        );
        Ok(TypeParserResult {
            types: vec![ParsedType {
                name: name.into(),
                ty: Type::int(4, true),
                user: true,
            }],
            variables: vec![],
            functions: vec![],
        })
    }

    fn parse_type_string(
        &self,
        source: &str,
        _platform: &Platform,
        _existing_types: Option<&TypeContainer>,
    ) -> Result<QualifiedNameAndType, Vec<TypeParserError>> {
        Ok(QualifiedNameAndType {
            name: source.into(),
            ty: Type::int(4, true),
        })
    }
}

#[test]
fn test_custom_parser_success() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let plat_type_container = platform.type_container();
    let (_, parser) = register_type_parser("canned_type_parser", CannedTypeParser);

    let preprocessed = parser
        .preprocess_source(
            "int value;",
            "test_file.h",
            &platform,
            Some(&plat_type_container),
            &[],
            &[],
        )
        .expect("Preprocessed source");
    assert_eq!(preprocessed, "int value;: 0 options, 0 include dirs");

    let parsed_types = parser
        .parse_types_from_source(
            "int value;",
            "test_file.h",
            &platform,
            Some(&plat_type_container),
            &[],
            &[],
            "",
        )
        .expect("Parsed types");
    assert_eq!(
        parsed_types,
        TypeParserResult {
            types: vec![ParsedType {
                name: "test_file.h: 0 options, 0 include dirs".into(),
                ty: Type::int(4, true),
                user: true,
            }],
            variables: vec![],
            functions: vec![],
        }
    );

    let parsed_type = parser
        .parse_type_string("value_t", &platform, None)
        .expect("Parsed value_t");
    assert_eq!(parsed_type.name, "value_t".into());
    assert_eq!(Type::int(4, true), parsed_type.ty);
}
