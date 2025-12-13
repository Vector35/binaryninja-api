use binaryninja::qualified_name::QualifiedName;

#[test]
fn test_new_from_vec_string() {
    let items = vec!["std".to_string(), "vector".to_string(), "int".to_string()];
    let qn = QualifiedName::new(items);
    assert_eq!(qn.len(), 3);
    assert_eq!(qn.to_string(), "std::vector::int");
    assert_eq!(qn.separator, "::");
}

#[test]
fn test_new_from_array() {
    let items = ["root", "data"];
    let qn = QualifiedName::new(items);
    assert_eq!(qn.len(), 2);
    assert_eq!(qn.to_string(), "root::data");
}

#[test]
fn test_new_empty() {
    let items: Vec<String> = Vec::new();
    let qn = QualifiedName::new(items);
    assert!(qn.is_empty());
    assert_eq!(qn.to_string(), "");
}

#[test]
fn test_new_with_custom_separator() {
    let items = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let separator = ".".to_string();
    let qn = QualifiedName::new_with_separator(items, separator);
    assert_eq!(qn.to_string(), "a.b.c");
    assert_eq!(qn.separator, ".");
}

#[test]
fn test_from_string() {
    let qn: QualifiedName = "SingleName".to_string().into();
    assert_eq!(qn.len(), 1);
    assert_eq!(qn[0], "SingleName");
    assert_eq!(qn.to_string(), "SingleName");
}

#[test]
fn test_from_str_literal() {
    let qn: QualifiedName = "AnotherName".into();
    assert_eq!(qn.len(), 1);
    assert_eq!(qn[0], "AnotherName");
}

#[test]
fn test_into_string() {
    let qn = QualifiedName::new(vec!["A", "B", "C"]);
    let s: String = qn.into();
    assert_eq!(s, "A::B::C");
}

#[test]
fn test_push_pop_and_last() {
    let mut qn = QualifiedName::new(vec!["ns1"]);

    qn.push("TypeA".to_string());
    assert_eq!(qn.len(), 2);
    assert_eq!(qn.to_string(), "ns1::TypeA");

    assert_eq!(qn.last().unwrap(), "TypeA");
    *qn.last_mut().unwrap() = "TypeB".to_string();
    assert_eq!(qn.to_string(), "ns1::TypeB");

    assert_eq!(qn.pop().unwrap(), "TypeB");
    assert_eq!(qn.len(), 1);
    assert_eq!(qn.to_string(), "ns1");

    assert_eq!(qn.pop().unwrap(), "ns1");
    assert!(qn.is_empty());
    assert_eq!(qn.pop(), None);
}

#[test]
fn test_with_item() {
    let qn_a = QualifiedName::from("ns1");
    let qn_b = qn_a.with_item("ns2");
    let qn_c = qn_b.with_item("symbol");

    assert_eq!(qn_a.to_string(), "ns1");
    assert_eq!(qn_b.to_string(), "ns1::ns2");
    assert_eq!(qn_c.to_string(), "ns1::ns2::symbol");

    // Ensure the original is unchanged
    assert_eq!(qn_a.len(), 1);
}

#[test]
fn test_split_last() {
    let qn = QualifiedName::new(vec!["A", "B", "C"]);

    let (last, prefix) = qn.split_last().unwrap();
    assert_eq!(last, "C");
    assert_eq!(prefix.to_string(), "A::B");

    let (last2, prefix2) = prefix.split_last().unwrap();
    assert_eq!(last2, "B");
    assert_eq!(prefix2.to_string(), "A");

    let (last3, prefix3) = prefix2.split_last().unwrap();
    assert_eq!(last3, "A");
    assert!(prefix3.is_empty());

    // Split on an empty name
    assert_eq!(prefix3.split_last(), None);
}

#[test]
fn test_replace() {
    let qualified_name =
        QualifiedName::new(vec!["my_prefix::ns".to_string(), "my_Type".to_string()]);

    let replaced = qualified_name.replace("my", "your");
    assert_eq!(
        replaced.items,
        vec!["your_prefix::ns".to_string(), "your_Type".to_string()]
    );
    assert_eq!(replaced.to_string(), "your_prefix::ns::your_Type");

    let qualified_name_dot = QualifiedName::new_with_separator(vec!["foo", "bar"], ".".to_string());
    let replaced_dot = qualified_name_dot.replace("foo", "baz");
    assert_eq!(replaced_dot.to_string(), "baz.bar");
}

#[test]
fn test_index_and_index_mut() {
    let mut qn = QualifiedName::new(vec!["a", "b", "c"]);
    assert_eq!(qn[0], "a");
    assert_eq!(qn[2], "c");
    qn[1] = "NEW_ITEM".to_string();
    assert_eq!(qn.to_string(), "a::NEW_ITEM::c");
}

#[test]
#[should_panic]
fn test_index_out_of_bounds() {
    let qn = QualifiedName::new(vec!["a"]);
    // This should panic
    let _ = qn[1];
}

#[test]
fn test_insert() {
    let mut qn = QualifiedName::new(vec!["start", "end"]);

    qn.insert(1, "middle".to_string());
    assert_eq!(qn.to_string(), "start::middle::end");

    qn.insert(0, "HEAD".to_string());
    assert_eq!(qn.to_string(), "HEAD::start::middle::end");

    qn.insert(4, "TAIL".to_string());
    assert_eq!(qn.to_string(), "HEAD::start::middle::end::TAIL");

    let initial_len = qn.len();
    qn.insert(initial_len + 5, "NOPE".to_string());
    assert_eq!(qn.len(), initial_len);
}

#[test]
fn test_into_and_from_raw() {
    let original_qn = QualifiedName::new(["std", "vector"]);
    assert_eq!(original_qn.to_string(), "std::vector");

    let raw_qn = QualifiedName::into_raw(original_qn);
    assert_eq!(raw_qn.nameCount, 2);
    assert!(!raw_qn.join.is_null());

    let restored_qn = QualifiedName::from_owned_raw(raw_qn);
    assert_eq!(restored_qn.len(), 2);
    assert_eq!(restored_qn.to_string(), "std::vector");
}

#[test]
fn test_raw_freeing() {
    let qn = QualifiedName::new(["std", "vector"]);
    let raw_qn = QualifiedName::into_raw(qn);
    assert!(!raw_qn.join.is_null());
    assert!(!raw_qn.name.is_null());
    QualifiedName::free_raw(raw_qn);
}
