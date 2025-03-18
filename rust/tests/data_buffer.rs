use binaryninja::data_buffer::DataBuffer;

const DUMMY_DATA_0: &[u8] = b"0123456789\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x09\xFF";
const DUMMY_DATA_1: &[u8] = b"qwertyuiopasdfghjkl\xE7zxcvbnm\x00\x01\x00";

#[test]
fn get_slice() {
    let data = DataBuffer::new(DUMMY_DATA_0).unwrap();
    let slice = data.get_slice(9, 10).unwrap();
    assert_eq!(slice.get_data(), &DUMMY_DATA_0[9..19]);
}

#[test]
fn set_len_write() {
    let mut data = DataBuffer::default();
    assert_eq!(data.get_data(), &[]);
    unsafe { data.set_len(DUMMY_DATA_0.len()) };
    assert_eq!(data.len(), DUMMY_DATA_0.len());
    let mut contents = DUMMY_DATA_0.to_vec();
    data.set_data(&contents);
    // modify the orinal contents, to make sure DataBuffer copied the data
    // and is not using the original pointer
    contents.as_mut_slice().fill(0x55);
    drop(contents);
    assert_eq!(data.get_data(), DUMMY_DATA_0);

    // make sure the new len truncate the original data
    unsafe { data.set_len(13) };
    assert_eq!(data.get_data(), &DUMMY_DATA_0[..13]);

    data.clear();
    assert_eq!(data.get_data(), &[]);
}

#[test]
fn assign_append() {
    let mut dst = DataBuffer::new(DUMMY_DATA_0).unwrap();
    let mut src = DataBuffer::new(DUMMY_DATA_1).unwrap();
    DataBuffer::assign(&mut dst, &src);

    assert_eq!(dst.get_data(), DUMMY_DATA_1);
    assert_eq!(src.get_data(), DUMMY_DATA_1);
    // overwrite the src, to make sure that src is copied to dst, and not
    // moved into it
    src.set_data(DUMMY_DATA_0);
    assert_eq!(dst.get_data(), DUMMY_DATA_1);
    assert_eq!(src.get_data(), DUMMY_DATA_0);

    DataBuffer::append(&mut dst, &src);
    let result: Vec<_> = DUMMY_DATA_1.iter().chain(DUMMY_DATA_0).copied().collect();
    assert_eq!(dst.get_data(), &result);

    assert_eq!(src.get_data(), DUMMY_DATA_0);
    src.set_data(DUMMY_DATA_1);
    assert_eq!(src.get_data(), DUMMY_DATA_1);
    assert_eq!(dst.get_data(), &result);
}

#[test]
fn to_from_formats() {
    let data = DataBuffer::new(DUMMY_DATA_0).unwrap();
    let escaped = data.to_escaped_string(false, false);
    let unescaped = DataBuffer::from_escaped_string(&escaped);
    drop(escaped);
    let escaped_part = data.to_escaped_string(true, false);
    let unescaped_part = DataBuffer::from_escaped_string(&escaped_part);
    drop(escaped_part);

    let part = &DUMMY_DATA_0[0..DUMMY_DATA_0
        .iter()
        .position(|x| *x == 0)
        .unwrap_or(DUMMY_DATA_0.len())];
    assert_eq!(data.get_data(), DUMMY_DATA_0);
    assert_eq!(unescaped.get_data(), DUMMY_DATA_0);
    assert_eq!(unescaped_part.get_data(), part);

    let escaped = data.to_base64();
    let unescaped = DataBuffer::from_base64(&escaped);
    drop(escaped);
    assert_eq!(data.get_data(), DUMMY_DATA_0);
    assert_eq!(unescaped.get_data(), DUMMY_DATA_0);

    let compressed = data.zlib_compress();
    let decompressed = compressed.zlib_decompress();
    drop(compressed);
    assert_eq!(data.get_data(), DUMMY_DATA_0);
    assert_eq!(decompressed.get_data(), DUMMY_DATA_0);
}
