use binaryninja::types::Type;

#[test]
fn test_type_to_string() {
    let _session = binaryninja::headless::Session::new();
    let test_type = Type::int(4, true);
    assert_eq!(test_type.to_string(), "int32_t".to_string());
}
