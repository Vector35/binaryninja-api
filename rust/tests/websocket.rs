use binaryninja::headless::Session;
use binaryninja::rc::Ref;
use binaryninja::websocket::{
    register_websocket_provider, CoreWebsocketClient, CoreWebsocketProvider, WebsocketClient,
    WebsocketClientCallback, WebsocketProvider,
};

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
    data_read: Vec<u8>,
    did_disconnect: bool,
    did_error: bool,
}

impl WebsocketClientCallback for MyClientCallbacks {
    fn connected(&mut self) -> bool {
        true
    }

    fn disconnected(&mut self) {
        self.did_disconnect = true;
    }

    fn error(&mut self, msg: &str) {
        assert_eq!(msg, "error");
        self.did_error = true;
    }

    fn read(&mut self, data: &[u8]) -> bool {
        self.data_read.extend_from_slice(data);
        true
    }
}

#[test]
fn reg_websocket_provider() {
    let _session = Session::new().expect("Failed to initialize session");
    let provider = register_websocket_provider::<MyWebsocketProvider>("RustWebsocketProvider");
    let client = provider.create_client().unwrap();
    let mut callback = MyClientCallbacks::default();
    let success = client.initialize_connection(
        "url",
        [("header".to_string(), "value".to_string())],
        &mut callback,
    );
    assert!(success, "Failed to initialize connection!");
}

#[test]
fn listen_websocket_provider() {
    let _session = Session::new().expect("Failed to initialize session");
    let provider = register_websocket_provider::<MyWebsocketProvider>("RustWebsocketProvider2");

    let client = provider.create_client().unwrap();
    let mut callback = MyClientCallbacks::default();
    client.initialize_connection(
        "url",
        [("header".to_string(), "value".to_string())],
        &mut callback,
    );

    assert!(client.write("test1".as_bytes()));
    assert!(client.write("test2".as_bytes()));

    client.notify_error("error");
    client.disconnect();
    drop(client);

    assert_eq!(
        &callback.data_read[..],
        "sent: test1\nsent: test2\n".as_bytes()
    );
    // If we disconnected that means the error callback was not notified.
    assert!(!callback.did_disconnect);
    assert!(callback.did_error);
}
