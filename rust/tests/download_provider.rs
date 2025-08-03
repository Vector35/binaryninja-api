use binaryninja::download_provider::{DownloadProvider, DownloadInstanceInputOutputCallbacks};
use binaryninja::headless::Session;
use std::sync::mpsc;

#[test]
fn test_download_provider() {
    let _session = Session::new().expect("Failed to initialize session");
    let provider =
        DownloadProvider::try_default().expect("Couldn't get default download provider");
    let mut inst = provider
        .create_instance()
        .expect("Couldn't create download instance");
    let (tx, rx) = mpsc::channel();
    let write = move |data: &[u8]| -> usize {
        tx.send(data.to_vec()).expect("Couldn't send data");
        data.len()
    };
    let result = inst
        .perform_custom_request(
            "GET",
            "http://httpbin.org/get",
            vec![],
            &DownloadInstanceInputOutputCallbacks {
                read: None,
                write: Some(Box::new(write)),
                progress: None,
            },
        )
        .expect("Couldn't perform custom request");
    assert_eq!(result.status_code, 200);
    let written = rx.recv().expect("Couldn't receive data");
    let written_str = String::from_utf8(written).expect("Couldn't convert data to string");
    println!("{}", written_str);
    assert!(written_str.contains("httpbin.org/get"));
}
