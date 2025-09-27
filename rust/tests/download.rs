use binaryninja::download::{
    register_download_provider, CustomDownloadInstance, CustomDownloadProvider, DownloadInstance,
    DownloadInstanceInputOutputCallbacks, DownloadInstanceOutputCallbacks, DownloadProvider,
    DownloadResponse,
};
use binaryninja::headless::Session;
use binaryninja::rc::Ref;
use std::collections::HashMap;
use std::sync::mpsc;

#[test]
fn test_download_provider() {
    let _session = Session::new().expect("Failed to initialize session");
    let provider = DownloadProvider::try_default().expect("Couldn't get default download provider");
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

struct MyDownloadProvider {
    core: DownloadProvider,
}

impl CustomDownloadProvider for MyDownloadProvider {
    type Instance = MyDownloadInstance;

    fn handle(&self) -> DownloadProvider {
        self.core
    }

    fn from_core(core: DownloadProvider) -> Self {
        Self { core }
    }
}

struct MyDownloadInstance {
    core: Ref<DownloadInstance>,
}

impl CustomDownloadInstance for MyDownloadInstance {
    fn from_core(core: Ref<DownloadInstance>) -> Self {
        Self { core }
    }

    fn handle(&self) -> Ref<DownloadInstance> {
        self.core.clone()
    }

    fn perform_custom_request<I>(
        &self,
        method: &str,
        url: &str,
        headers: I,
    ) -> Result<DownloadResponse, String>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        assert_eq!(method, "GET");
        assert_eq!(url, "test");
        let headers: HashMap<_, _> = headers.into_iter().collect();
        assert_eq!("value", headers.get("test").unwrap_or(&"value".to_string()));

        // Inform the caller of progress and write some data.
        self.core.write_callback(b"Hello World!");

        Ok(DownloadResponse {
            status_code: 200,
            headers: {
                let mut h = HashMap::new();
                h.insert("test".to_string(), "value".to_string());
                h
            },
        })
    }
}

#[test]
fn test_custom_download_provider() {
    let _session = Session::new().expect("Failed to initialize session");
    let custom_provider = register_download_provider::<MyDownloadProvider>("RustDownloadProvider");
    let mut instance = custom_provider
        .create_instance()
        .expect("Couldn't create download instance");

    let write_cb = move |data: &[u8]| -> usize {
        assert_eq!(data, b"Hello World!");
        data.len()
    };
    let callbacks = DownloadInstanceOutputCallbacks {
        write: Some(Box::new(write_cb)),
        progress: None,
    };

    instance
        .perform_request("test", &callbacks)
        .expect("Couldn't perform request");

    let read_cb = move |data: &mut [u8]| -> Option<usize> { None };
    let custom_callbacks = DownloadInstanceInputOutputCallbacks {
        read: Some(Box::new(read_cb)),
        write: Some(Box::new(write_cb)),
        progress: None,
    };

    instance
        .perform_custom_request(
            "GET",
            "test",
            [("test".to_string(), "value".to_string())],
            &custom_callbacks,
        )
        .expect("Couldn't perform custom request");
}
