use binaryninja::string::{BnString, IntoCStr};
use std::ffi::{CStr, CString};

#[test]
fn test_bnstring() {
    // Test a basic ASCII string
    let str_0 = BnString::new("test");
    assert_eq!(str_0.to_string_lossy(), "test");
    assert_eq!(str_0.to_bytes_with_nul(), b"test\0");

    // Test non-UTF8 bytes
    let invalid_utf8 = CStr::from_bytes_with_nul(&[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xFF, 0x00])
        .expect("Failed to create string");
    let str_2 = BnString::new(invalid_utf8);
    assert_eq!(str_2.to_string_lossy(), "Hello�");
    assert_eq!(
        str_2.to_bytes_with_nul(),
        &[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xFF, 0x00]
    );

    // Test empty string
    let str_3 = BnString::new("");
    assert_eq!(str_3.to_string_lossy(), "");
    assert_eq!(str_3.to_bytes_with_nul(), b"\0");

    // Test string with Unicode
    let str_4 = BnString::new("Hello 世界");
    assert_eq!(str_4.to_string_lossy(), "Hello 世界");
    assert_eq!(
        str_4.to_bytes_with_nul(),
        b"Hello \xE4\xB8\x96\xE7\x95\x8C\0"
    );
}

#[test]
fn test_cstr() {
    let str_0 = BnString::new("test");
    let cstr_0: BnString = str_0.to_cstr();
    assert_eq!(cstr_0.to_str().unwrap(), "test");
    assert_eq!(cstr_0.to_bytes_with_nul(), b"test\0");

    let str_1 = String::from("test");
    let cstr_1: CString = str_1.to_cstr();
    assert_eq!(cstr_1.to_str().unwrap(), "test");
    assert_eq!(cstr_1.to_bytes_with_nul(), b"test\0");

    let str_2 = "test";
    let cstr_2: CString = str_2.to_cstr();
    assert_eq!(cstr_2.to_str().unwrap(), "test");
    assert_eq!(cstr_2.to_bytes_with_nul(), b"test\0");
}
