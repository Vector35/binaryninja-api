use binaryninja::headless::Session;
use binaryninja::rc::Ref;
use binaryninja::websocket::{
    register_websocket_provider, CoreWebsocketClient, CoreWebsocketProvider, WebsocketClient,
    WebsocketClientCallback, WebsocketProvider,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

struct MyWebsocketProvider {
    core: CoreWebsocketProvider,
}

impl WebsocketProvider for MyWebsocketProvider {
    type Client = MyWebsocketClient;

    fn handle(&self) -> CoreWebsocketProvider {
        self.core
    }

    fn from_core(core: CoreWebsocketProvider) -> Self {
        MyWebsocketProvider { core }
    }
}

struct MyWebsocketClient {
    core: Ref<CoreWebsocketClient>,
}

impl WebsocketClient for MyWebsocketClient {
    fn from_core(core: Ref<CoreWebsocketClient>) -> Self {
        Self { core }
    }

    fn connect<I>(&self, host: &str, _headers: I) -> bool
    where
        I: IntoIterator<Item = (String, String)>,
    {
        assert_eq!(host, "url");
        true
    }

    fn write(&self, data: &[u8]) -> bool {
        if !self.core.notify_read("sent: ".as_bytes()) {
            return false;
        }
        if !self.core.notify_read(data) {
            return false;
        }
        self.core.notify_read("\n".as_bytes())
    }

    fn disconnect(&self) -> bool {
        true
    }
}

#[derive(Default)]
struct MyClientCallbacks {
    data_read: RwLock<Vec<u8>>,
    did_disconnect: AtomicBool,
    did_error: AtomicBool,
}

impl WebsocketClientCallback for MyClientCallbacks {
    fn connected(&self) -> bool {
        true
    }

    fn disconnected(&self) {
        self.did_disconnect.store(true, Ordering::Relaxed);
    }

    fn error(&self, msg: &str) {
        assert_eq!(msg, "error");
        self.did_error.store(true, Ordering::Relaxed);
    }

    fn read(&self, data: &[u8]) -> bool {
        self.data_read.write().unwrap().extend_from_slice(data);
        true
    }
}

#[derive(Default)]
struct LifetimeCallbacks {
    data: RwLock<Vec<u8>>,
}

impl WebsocketClientCallback for LifetimeCallbacks {
    fn connected(&self) -> bool {
        true
    }

    fn disconnected(&self) {}

    fn error(&self, _msg: &str) {}

    fn read(&self, data: &[u8]) -> bool {
        if data == "sent: ".as_bytes() || data == "\n".as_bytes() {
            return true;
        }
        assert_eq!(data, &self.data.read().unwrap()[..]);
        true
    }
}

#[test]
fn reg_websocket_provider() {
    let _session = Session::new().expect("Failed to initialize session");
    let provider = register_websocket_provider::<MyWebsocketProvider>("RustWebsocketProvider");
    let client = provider.create_client().unwrap();
    let mut callback = MyClientCallbacks::default();
    let connection = client.connect(
        "url",
        [("header".to_string(), "value".to_string())],
        &mut callback,
    );
    assert!(connection.is_some(), "Failed to initialize connection!");
}

#[test]
fn listen_websocket_provider() {
    let _session = Session::new().expect("Failed to initialize session");
    let provider = register_websocket_provider::<MyWebsocketProvider>("RustWebsocketProvider2");

    let client = provider.create_client().unwrap();
    let mut callback = MyClientCallbacks::default();
    let connection = client
        .connect(
            "url",
            [("header".to_string(), "value".to_string())],
            &callback,
        )
        .expect("Failed to initialize connection!");

    assert!(connection.write("test1".as_bytes()));
    assert!(connection.write("test2".as_bytes()));

    connection.notify_error("error");
    connection.disconnect();

    assert_eq!(
        &callback.data_read.read().unwrap()[..],
        "sent: test1\nsent: test2\n".as_bytes()
    );
    // If we disconnected that means the error callback was not notified.
    assert!(!callback.did_disconnect.load(Ordering::Relaxed));
    assert!(callback.did_error.load(Ordering::Relaxed));
}

#[test]
fn correct_websocket_client_lifetime() {
    let _session = Session::new().expect("Failed to initialize session");
    let provider = register_websocket_provider::<MyWebsocketProvider>("RustWebsocketProvider2");

    let client = provider.create_client().unwrap();
    let callback = LifetimeCallbacks::default();
    let connection = client
        .connect(
            "url",
            [("header".to_string(), "value".to_string())],
            &callback,
        )
        .expect("Failed to initialize connection!");

    println!("{:?}", callback.data);
    callback
        .data
        .write()
        .unwrap()
        .extend(vec![0x55, 0x55, 0x55, 0x55, 0x55]);

    assert!(connection.write(&[0x55, 0x55, 0x55, 0x55, 0x55]));
    assert!(connection.write(&[0x55, 0x55, 0x55, 0x55, 0x55]));
}
