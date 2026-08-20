use binaryninja::binary_view::{BinaryReader, BinaryView, BinaryViewBase};
use binaryninja::data_buffer::DataBuffer;
use binaryninja::file_metadata::FileMetadata;
use binaryninja::settings::Settings;
use binaryninja::transform::{
    register_transform, register_transform_with_context, register_transform_with_detection,
    ContextTransform, CustomTransform, DetectionTransform, ProcessResult, Transform,
    TransformContext, TransformInputParameters, TransformResult, TransformSession, TransformType,
};
use std::io::Read;

const DUMMY_DATA_0: &[u8] = b"0123456789\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x09\xFF";

#[test]
fn test_builtin_rc4() {
    let _session = binaryninja::headless::Session::new();
    let ciphertext = [
        0xEF, 0xC8, 0xB8, 0xEE, 0x26, 0x02, 0x53, 0xEC, 0xEA, 0x4B, 0xC5,
    ];
    let rc4 = Transform::by_name("RC4").expect("RC4 transform not found");
    let mut params = TransformInputParameters::new();
    params.insert("key".to_string(), DataBuffer::new(b"Secrett"));
    let decoded = rc4.decode(&ciphertext, &params).expect("RC4 decode failed");
    assert_eq!(decoded.get_data(), b"Hello World");
}

struct MyTransform;

impl CustomTransform for MyTransform {
    const TYPE: TransformType = TransformType::BinaryCodecTransform;
    const NAME: &'static str = "MyTransform";
    const GROUP: &'static str = "Blah";

    fn decode(&self, input: &[u8], params: &TransformInputParameters) -> Option<DataBuffer> {
        // Fallback to 0x42 if "XorKey" is missing or empty
        let key = params
            .get("XorKey")
            .and_then(|db| db.get_data().first())
            .copied()
            .unwrap_or(0x42);

        let mut out = input.to_vec();
        for i in 0..std::cmp::min(4, out.len()) {
            out[i] ^= key;
        }
        Some(DataBuffer::new(&out))
    }

    fn encode(&self, input: &[u8], params: &TransformInputParameters) -> Option<DataBuffer> {
        // XOR is symmetric, so encode logic matches decode logic
        self.decode(input, params)
    }
}

#[test]
fn test_custom_transform() {
    let _session = binaryninja::headless::Session::new();
    // Register the custom transform
    let (_, transform) = register_transform(MyTransform);
    assert!(!transform.supports_detection());
    assert!(!transform.supports_context());
    // Add key param
    let mut params = TransformInputParameters::new();
    params.insert("XorKey".to_string(), DataBuffer::new(&[0x11]));
    // Test Encoding
    let encoded = transform
        .encode(DUMMY_DATA_0, &params)
        .expect("Encode failed");
    let encoded_slice = encoded.get_data();
    // Verify first 4 bytes are XOR'd with 0x11
    assert_eq!(encoded_slice[0], DUMMY_DATA_0[0] ^ 0x11);
    assert_eq!(encoded_slice[1], DUMMY_DATA_0[1] ^ 0x11);
    assert_eq!(encoded_slice[2], DUMMY_DATA_0[2] ^ 0x11);
    assert_eq!(encoded_slice[3], DUMMY_DATA_0[3] ^ 0x11);
    // Verify remaining bytes are untouched
    assert_eq!(encoded_slice[4], DUMMY_DATA_0[4]);
    assert_eq!(encoded_slice.len(), DUMMY_DATA_0.len());
    // Verify decoding
    let decoded = transform
        .decode(encoded_slice, &params)
        .expect("Decode failed");
    assert_eq!(decoded.get_data(), DUMMY_DATA_0);
}

struct MyDetectionTransform;

impl CustomTransform for MyDetectionTransform {
    const TYPE: TransformType = TransformType::DecodeTransform;
    const NAME: &'static str = "MyDetectionTransform";
    const GROUP: &'static str = "Blah";

    fn decode(&self, input: &[u8], _params: &TransformInputParameters) -> Option<DataBuffer> {
        Some(DataBuffer::new(input))
    }

    fn encode(&self, _input: &[u8], _params: &TransformInputParameters) -> Option<DataBuffer> {
        None
    }
}

impl DetectionTransform for MyDetectionTransform {
    fn can_decode(&self, reader: &mut BinaryReader) -> bool {
        let mut buffer = [0; 4];
        reader.read(&mut buffer).is_ok_and(|len| len == 4)
    }
}

#[test]
fn test_detection_transform() {
    let _session = binaryninja::headless::Session::new();
    let (_, transform) = register_transform_with_detection(MyDetectionTransform);
    assert!(transform.supports_detection());
    assert!(!transform.supports_context());
    let view = BinaryView::from_data(&FileMetadata::new(), DUMMY_DATA_0);
    assert!(transform.can_decode(&view));
}

struct MyContextTransform;

impl CustomTransform for MyContextTransform {
    const TYPE: TransformType = TransformType::BinaryCodecTransform;
    const NAME: &'static str = "MyContextTransform";
    const GROUP: &'static str = "Blah";

    fn decode(&self, _input: &[u8], _params: &TransformInputParameters) -> Option<DataBuffer> {
        None
    }

    fn encode(&self, _input: &[u8], _params: &TransformInputParameters) -> Option<DataBuffer> {
        None
    }
}

impl ContextTransform for MyContextTransform {
    fn decode_within_context(
        &self,
        context: &TransformContext,
        _params: &TransformInputParameters,
    ) -> bool {
        let decoded_data = DataBuffer::new(b"successfully_decoded_via_context");

        // Push the result to a child context
        context.create_child(
            "child_node",
            &decoded_data,
            TransformResult::TransformSuccess,
            "Success",
            false,
        );
        true
    }
}

#[test]
fn test_context_transform() {
    let _session = binaryninja::headless::Session::new();
    let (_, transform) = register_transform_with_context(MyContextTransform);
    assert!(!transform.supports_detection());
    assert!(transform.supports_context());
    let view = BinaryView::from_data(&FileMetadata::new(), b"initial_data");
    // Create session and grab root context
    let session = TransformSession::from_view(&view, &Settings::global());
    let root = session.root_context().expect("Should have root context");
    // Tell the root context to explicitly use our context transform
    root.set_transform_name("MyContextTransform");
    // Process the session
    assert_eq!(session.process(), ProcessResult::Complete);
    // Verify that our transform created a child context
    let children = root.children();
    assert_eq!(children.len(), 1);
    let child_view = children.get(0).input();
    let mut out = vec![0; child_view.len() as usize];
    child_view.read(&mut out, 0);
    assert_eq!(out, b"successfully_decoded_via_context");
}
