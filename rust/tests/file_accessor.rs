use binaryninja::file_accessor::FileAccessor;
use std::io::Cursor;

#[test]
fn test_file_accessor() {
    let mut mock_data = Cursor::new(vec![0u8; 100]);
    let accessor = FileAccessor::new(&mut mock_data);
    assert_eq!(
        accessor.length(),
        100,
        "File accessor length does not match"
    );
    assert_eq!(
        accessor.write(0x10, &[0xff]),
        1,
        "Failed to write to file accessor"
    );
    let read_value = accessor
        .read(0x10, 1)
        .expect("Failed to read from file accessor");
    assert_eq!(read_value, &[0xff], "Read value does not match");
}
