use binaryninja::binary_reader::BinaryReader;
use binaryninja::binary_view::{BinaryViewBase, BinaryViewExt};
use binaryninja::headless::Session;
use rstest::*;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_binary_reader_seek(_session: &Session) {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let mut reader = BinaryReader::new(&view);
    let end_offset = view.len();

    // Test seeking to a specific position
    reader
        .seek(SeekFrom::Start(0))
        .expect("Failed to seek to start");
    assert_eq!(reader.offset(), 0, "Reader failed to seek to the start");

    reader
        .seek(SeekFrom::End(0))
        .expect("Failed to seek to end");
    assert_eq!(
        reader.offset(),
        end_offset,
        "Reader failed to seek to the end"
    );

    // Test relative seeking
    reader
        .seek(SeekFrom::Start(10))
        .expect("Failed to seek to position 10");
    assert_eq!(reader.offset(), 10, "Reader failed to seek to position 10");

    reader
        .seek(SeekFrom::Current(-5))
        .expect("Failed to perform relative seek");
    assert_eq!(
        reader.offset(),
        5,
        "Reader failed to perform relative seek correctly"
    );
}

#[rstest]
fn test_binary_reader_read(_session: &Session) {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let mut reader = BinaryReader::new(&view);

    // We want to do seeks with the image base.
    reader.set_virtual_base(view.original_image_base());

    reader
        .seek(SeekFrom::Start(0))
        .expect("Failed to seek to start");
    let mut buffer = [0u8; 4];
    reader
        .read_exact(&mut buffer)
        .expect("Failed to read 4 bytes");
    assert_eq!(
        buffer.len(),
        4,
        "Failed to read the correct number of bytes"
    );

    // Validate the buffer.
    assert_eq!(
        &buffer,
        &[0x4c, 0x01, 0x87, 0x00],
        "Buffer content does not match the expected bytes"
    );

    // Test attempting to read beyond the end of the file.
    reader
        .seek(SeekFrom::End(0))
        .expect("Failed to seek to end");
    let mut eof_buffer = [0u8; 1];
    let result = reader.read(&mut eof_buffer);
    assert!(
        result.is_err(),
        "Expected an error when reading past EOF, got success instead"
    );
}
