use binaryninja::metadata::{Metadata, MetadataType};
use binaryninja::rc::Ref;
use std::collections::HashMap;

#[test]
fn basic_metadata() {
    let metadata = Metadata::new_of_type(MetadataType::UnsignedIntegerDataType);
    assert_eq!(metadata.get_type(), MetadataType::UnsignedIntegerDataType);
    assert_eq!(metadata.get_unsigned_integer(), Some(0));

    let metadata_0: Ref<Metadata> = 1u64.into();
    assert_eq!(metadata_0.get_type(), MetadataType::UnsignedIntegerDataType);
    assert_eq!(metadata_0.get_unsigned_integer(), Some(1));

    let metadata_1: Ref<Metadata> = true.into();
    assert_eq!(metadata_1.get_type(), MetadataType::BooleanDataType);
    assert_eq!(metadata_1.get_boolean(), Some(true));

    let metadata_2: Ref<Metadata> = 0.55f64.into();
    assert_eq!(metadata_2.get_type(), MetadataType::DoubleDataType);
    assert_eq!(metadata_2.get_double(), Some(0.55f64));

    let metadata_3: Ref<Metadata> = From::from(&vec![1i64, 2i64]);
    assert_eq!(metadata_3.get_type(), MetadataType::ArrayDataType);
    assert_eq!(metadata_3.get_signed_integer_list(), Some(vec![1i64, 2i64]));

    let metadata_4: Ref<Metadata> = From::from(&vec![1.55f64, 2.55f64]);
    assert_eq!(metadata_4.get_type(), MetadataType::ArrayDataType);
    assert_eq!(metadata_4.get_double_list(), Some(vec![1.55f64, 2.55f64]));
}

#[test]
fn object_metadata() {
    let metadata = Metadata::new_of_type(MetadataType::UnsignedIntegerDataType);
    assert_eq!(metadata.get_type(), MetadataType::UnsignedIntegerDataType);
    assert_eq!(metadata.get_unsigned_integer(), Some(0));

    let mut map = HashMap::new();
    map.insert("key", 1u64);

    let metadata_0: Ref<Metadata> = From::from(map);
    assert_eq!(metadata_0.get_type(), MetadataType::KeyValueDataType);

    let value_store = metadata_0
        .get_value_store()
        .expect("Expected a value store");
    let key_value = value_store.get("key").expect("Expected a key to exist");
    assert_eq!(key_value.get_type(), MetadataType::UnsignedIntegerDataType);
    assert_eq!(key_value.get_unsigned_integer(), Some(1));
}
