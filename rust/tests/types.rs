use binaryninja::headless::Session;
use binaryninja::types::Type;
use rstest::*;

#[fixture]
#[once]
fn session() -> Session {
    Session::new()
}

#[rstest]
fn test_type_to_string(_session: &Session) {
    let test_type = Type::int(4, true);
    assert_eq!(test_type.to_string(), "int32_t".to_string());
}
