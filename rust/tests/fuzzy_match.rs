use binaryninja::{fuzzy_match_contextual, fuzzy_match_single};

#[test]
fn test_fuzzy_match_matches() {
    assert!(matches!(fuzzy_match_single("foo", "foo"), Some(_)));
    assert!(matches!(fuzzy_match_contextual("foo", "foo"), Some(_)));
}

#[test]
fn test_fuzzy_match_no_match() {
    for (target, query) in [
        ("", ""),
        ("foo", ""),
        ("", "foo"),
        ("foo", "bar"),
        ("foo", "oof"),
    ] {
        assert_eq!(fuzzy_match_single(target, query), None);
        assert_eq!(fuzzy_match_contextual(target, query), None);
    }
}
