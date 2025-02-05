use binaryninja::headless::Session;
use binaryninja::string::BnString;
use binaryninja::websocketprovider::{
    register_websocket_provider, CoreWebSocketClient, WebsocketCustomClient,
    WebsocketCustomProvider, WebsocketProvider,
};
use rstest::*;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

struct MyWebsocketProvider {
    core: WebsocketProvider,
}

impl WebsocketCustomProvider for MyWebsocketProvider {
    type Client<'a> = MyWebsocketClient<'a>;

    fn new(core: WebsocketProvider) -> Self {
        Self { core }
    }

    fn get_core(&self) -> &WebsocketProvider {
        &self.core
    }

    fn init_client<'a>(&self, core: CoreWebSocketClient<'a>) -> Self::Client<'a> {
        MyWebsocketClient { core }
    }
}

struct MyWebsocketClient<'a> {
    core: CoreWebSocketClient<'a>,
}

impl WebsocketCustomClient for MyWebsocketClient<'_> {
    fn connect(&self, _host: &str, _header_keys: &[BnString], _header_values: &[BnString]) -> bool {
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

#[rstest]
fn reg_websocket_provider(_session: &Session) {
    let (rust_provider, _core_provider) =
        register_websocket_provider::<_, MyWebsocketProvider>("RustWebsocketProvider");
    let mut handle = |_: &[u8]| true;
    let _client = rust_provider
        .connect("url", [("header", "value")], &mut handle)
        .unwrap();
}

#[rstest]
fn listen_websocket_provider(_session: &Session) {
    let (rust_provider, _core_provider) =
        register_websocket_provider::<_, MyWebsocketProvider>("RustWebsocketProvider2");

    let mut data_read = vec![];
    let mut read_handle = |data: &[u8]| {
        data_read.extend_from_slice(data);
        true
    };
    let client = rust_provider
        .connect("url", [("header", "value")], &mut read_handle)
        .unwrap();
    // NOTE important to enforce that this line will result compilation errors
    //let _ = read_handle(&[]);

    assert!(client.write("test1".as_bytes()));
    assert!(client.write("test2".as_bytes()));

    client.disconnect();
    drop(client);

    assert_eq!(&data_read[..], "sent: test1\nsent: test2\n".as_bytes());
}
