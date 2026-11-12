//! Transform session tests.
//!
//! These are kept apart from `transform.rs`, which registers a detection transform that accepts any
//! input. Tests in the same process would apply it while processing a session.

use binaryninja::binary_view::BinaryView;
use binaryninja::file_metadata::FileMetadata;
use binaryninja::transform::{TransformSession, TransformSessionMode};

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// Builds a ZIP archive that stores (doesn't compress) the given files.
fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut central_directory = Vec::new();
    for (name, data) in files {
        let offset = archive.len() as u32;
        let mut fields = Vec::new();
        fields.extend_from_slice(&20u16.to_le_bytes()); // Version needed to extract
        fields.extend_from_slice(&0u16.to_le_bytes()); // Flags
        fields.extend_from_slice(&0u16.to_le_bytes()); // Compression method: stored
        fields.extend_from_slice(&0u16.to_le_bytes()); // Modification time
        fields.extend_from_slice(&0x21u16.to_le_bytes()); // Modification date: 1980-01-01
        fields.extend_from_slice(&crc32(data).to_le_bytes());
        fields.extend_from_slice(&(data.len() as u32).to_le_bytes()); // Compressed size
        fields.extend_from_slice(&(data.len() as u32).to_le_bytes()); // Uncompressed size
        fields.extend_from_slice(&(name.len() as u16).to_le_bytes());
        fields.extend_from_slice(&0u16.to_le_bytes()); // Extra field length

        archive.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // Local file header
        archive.extend_from_slice(&fields);
        archive.extend_from_slice(name.as_bytes());
        archive.extend_from_slice(data);

        central_directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // Central directory header
        central_directory.extend_from_slice(&20u16.to_le_bytes()); // Version made by
        central_directory.extend_from_slice(&fields);
        central_directory.extend_from_slice(&[0; 6]); // Comment length, disk number, internal attributes
        central_directory.extend_from_slice(&0u32.to_le_bytes()); // External attributes
        central_directory.extend_from_slice(&offset.to_le_bytes());
        central_directory.extend_from_slice(name.as_bytes());
    }
    let central_directory_offset = archive.len() as u32;
    archive.extend_from_slice(&central_directory);
    archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // End of central directory record
    archive.extend_from_slice(&[0; 4]); // Disk numbers
    archive.extend_from_slice(&(files.len() as u16).to_le_bytes()); // Entries on this disk
    archive.extend_from_slice(&(files.len() as u16).to_le_bytes()); // Total entries
    archive.extend_from_slice(&(central_directory.len() as u32).to_le_bytes());
    archive.extend_from_slice(&central_directory_offset.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes()); // Comment length
    archive
}

/// Processes the session and returns the root context's transform name and child count.
fn process_root(session: &TransformSession) -> (String, usize) {
    session.process();
    let root = session.root_context().expect("Should have root context");
    (root.transform_name(), root.children().len())
}

#[test]
fn test_session_options() {
    let _session = binaryninja::headless::Session::new().expect("Failed to create session");
    let zip = stored_zip(&[("a.bin", b"AAAA"), ("b.bin", b"BBBBBBBB")]);
    let temp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
    let zip_path = temp_dir.path().join("two.zip");
    std::fs::write(&zip_path, &zip).expect("Failed to write ZIP");
    let view = BinaryView::from_data(&FileMetadata::new(), &zip);
    let mode = TransformSessionMode::TransformSessionModeFull;
    let unzipped = ("Zip".to_string(), 2);
    let not_unzipped = (String::new(), 0);

    // Without options the session uses the settings as they are, so the ZIP is extracted.
    let session = TransformSession::new_with_mode(&zip_path, None::<&str>, mode).unwrap();
    assert_eq!(process_root(&session), unzipped);
    let session = TransformSession::from_view_with_mode(&view, None::<&str>, mode).unwrap();
    assert_eq!(process_root(&session), unzipped);

    // Excluding the Zip transform for the session leaves the ZIP as it is.
    let options = r#"{"files.container.excludedTransforms": ["Zip"]}"#;
    let session = TransformSession::new_with_mode(&zip_path, Some(options), mode).unwrap();
    assert_eq!(process_root(&session), not_unzipped);
    let session = TransformSession::from_view_with_mode(&view, Some(options), mode).unwrap();
    assert_eq!(process_root(&session), not_unzipped);
}
