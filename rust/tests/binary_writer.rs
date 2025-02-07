use binaryninja::binary_reader::BinaryReader;
use binaryninja::binary_view::{BinaryViewBase, BinaryViewExt};
use binaryninja::binary_writer::BinaryWriter;
use binaryninja::headless::Session;
use rstest::*;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_binary_writer_seek(_session: &Session) {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let mut writer = BinaryWriter::new(&view);
    let end_offset = view.original_image_base() + view.len();

    // Test seeking to a specific position
    writer
        .seek(SeekFrom::Start(0))
        .expect("Failed to seek to start");
    assert_eq!(writer.offset(), 0, "Writer failed to seek to the start");

    writer
        .seek(SeekFrom::End(0))
        .expect("Failed to seek to end");
    assert_eq!(
        writer.offset(),
        end_offset,
        "Writer failed to seek to the end"
    );

    // Test relative seeking
    writer
        .seek(SeekFrom::Start(10))
        .expect("Failed to seek to position 10");
    assert_eq!(writer.offset(), 10, "Writer failed to seek to position 10");

    writer
        .seek(SeekFrom::Current(-5))
        .expect("Failed to perform relative seek");
    assert_eq!(
        writer.offset(),
        5,
        "Writer failed to perform relative seek correctly"
    );
}

#[rstest]
fn test_binary_writer_write(_session: &Session) {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let mut reader = BinaryReader::new(&view);
    let mut writer = BinaryWriter::new(&view);

    // Validate bytes are written.
    let mut buffer = [5u8; 4];
    let mut verify_buffer = [0u8; 4];
    writer.write(&mut buffer).expect("Failed to write 4 bytes");
    reader
        .read_exact(&mut verify_buffer)
        .expect("Failed to read 4 bytes");
    assert_eq!(buffer, verify_buffer, "Failed to write the correct bytes");

    // Test attempting to write beyond the end of the file.
    writer
        .seek(SeekFrom::End(0))
        .expect("Failed to seek to end");
    let mut eof_buffer = [0u8; 1];
    let result = writer.write(&mut eof_buffer);
    assert!(
        result.is_err(),
        "Expected an error when writing past EOF, got success instead"
    );
}
