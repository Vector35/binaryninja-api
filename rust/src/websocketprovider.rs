use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct WebsocketProvider {
    handle: ptr::NonNull<BNWebsocketProvider>,
}
unsafe impl Sync for WebsocketProvider {}
unsafe impl Send for WebsocketProvider {}

impl WebsocketProvider {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNWebsocketProvider>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNWebsocketProvider) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNWebsocketProvider {
        &mut *self.handle.as_ptr()
    }

    pub fn all() -> Array<Self> {
        let mut count = 0;
        let result = unsafe { BNGetWebsocketProviderList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn by_name<S: BnStrCompatible>(name: S) -> Option<WebsocketProvider> {
        let name = name.into_bytes_with_nul();
        let result =
            unsafe { BNGetWebsocketProviderByName(name.as_ref().as_ptr() as *const ffi::c_char) };
        ptr::NonNull::new(result).map(|h| unsafe { Self::from_raw(h) })
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNGetWebsocketProviderName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Connect to a given url, asynchronously. The connection will be run in a
    /// separate thread managed by the websocket provider.
    ///
    /// * `host` - Full url with scheme, domain, optionally port, and path
    /// * `headers` - HTTP header keys and values
    /// * `read_handle` - Handles the received data from the Socket
    pub fn connect<'a, U, I, K, V, F>(
        &'a self,
        url: U,
        headers: I,
        read_handle: &'a mut F,
    ) -> Option<Ref<WebsocketClient<'a>>>
    where
        U: BnStrCompatible,
        I: IntoIterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
        F: FnMut(&[u8]) -> bool,
    {
        let cb_callback = BNWebsocketClientOutputCallbacks {
            context: read_handle as *mut _ as *mut ffi::c_void,
            connectedCallback: Some(cb_connected_nop),
            disconnectedCallback: Some(cb_disconnected_nop),
            errorCallback: Some(cb_error_nop),
            readCallback: Some(cb_read_closure::<F>),
        };
        let client_ptr = unsafe { BNCreateWebsocketProviderClient(self.as_raw()) };
        connect_client(client_ptr, url, headers, cb_callback)
    }

    /// Connect to a given url, asynchronously. The connection will be run in a
    /// separate thread managed by the websocket provider.
    ///
    /// Callbacks will be called **on the thread of the connection**, so be sure
    /// to ExecuteOnMainThread any long-running or gui operations in the callbacks.
    ///
    /// If the connection succeeds, [WebsocketClientCallback::connected] will be called. On normal termination, [WebsocketClientCallback::disconnected] will be called.
    ///
    /// If the connection succeeds, but later fails, [WebsocketClientCallback::disconnected] will not be called, and [WebsocketClientCallback::error] will be called instead.
    ///
    /// If the connection fails, neither [WebsocketClientCallback::connected] nor [WebsocketClientCallback::disconnected] will be called, and [WebsocketClientCallback::error] will be called instead.
    ///
    /// If [WebsocketClientCallback::connected] or [WebsocketClientCallback::read] return false, the connection will be aborted.
    ///
    /// * `host` - Full url with scheme, domain, optionally port, and path
    /// * `headers` - HTTP header keys and values
    /// * `callback` - Callbacks for various websocket events
    pub fn connect_with_callback<'a, U, I, K, V, W>(
        &self,
        url: U,
        headers: I,
        callback: &'a mut W,
    ) -> Option<Ref<WebsocketClient<'a>>>
    where
        U: BnStrCompatible,
        I: IntoIterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
        W: WebsocketClientCallback,
    {
        let cb_callback = BNWebsocketClientOutputCallbacks {
            context: callback as *mut W as *mut _,
            connectedCallback: Some(cb_connected::<W>),
            disconnectedCallback: Some(cb_disconnected::<W>),
            errorCallback: Some(cb_error::<W>),
            readCallback: Some(cb_read::<W>),
        };
        let client_ptr = unsafe { BNCreateWebsocketProviderClient(self.as_raw()) };
        connect_client(client_ptr, url, headers, cb_callback)
    }
}

impl CoreArrayProvider for WebsocketProvider {
    type Raw = *mut BNWebsocketProvider;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for WebsocketProvider {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeWebsocketProviderList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

/// Implements a websocket client.
#[repr(transparent)]
pub struct WebsocketClient<'a> {
    handle: ptr::NonNull<BNWebsocketClient>,
    // lifetime of callbacks, AKA don't drop callbacks while the client still running
    _callback: std::marker::PhantomData<&'a ()>,
}
unsafe impl Sync for WebsocketClient<'_> {}
unsafe impl Send for WebsocketClient<'_> {}

impl ToOwned for WebsocketClient<'_> {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { <Self as RefCountable>::inc_ref(self) }
    }
}

unsafe impl RefCountable for WebsocketClient<'_> {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        let result = BNNewWebsocketClientReference(handle.as_raw());
        unsafe { Self::ref_from_raw(ptr::NonNull::new(result).unwrap()) }
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeWebsocketClient(handle.as_raw())
    }
}

impl WebsocketClient<'_> {
    pub(crate) unsafe fn ref_from_raw(handle: ptr::NonNull<BNWebsocketClient>) -> Ref<Self> {
        Ref::new(Self {
            handle,
            _callback: std::marker::PhantomData,
        })
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNWebsocketClient {
        &mut *self.handle.as_ptr()
    }

    /// Write some data to the websocket
    pub fn write(&self, data: &[u8]) -> bool {
        let len = u64::try_from(data.len()).unwrap();
        unsafe { BNWriteWebsocketClientData(self.as_raw(), data.as_ptr(), len) != 0 }
    }

    /// Disconnect the websocket
    pub fn disconnect(&self) -> bool {
        unsafe { BNDisconnectWebsocketClient(self.as_raw()) }
    }
}

pub struct CoreWebSocketClient<'a>(WebsocketClient<'a>);

impl CoreWebSocketClient<'_> {
    /// Call the connect callback function, forward the callback returned value
    pub fn notify_connect(&self) -> bool {
        unsafe { BNNotifyWebsocketClientConnect(self.0.as_raw()) }
    }

    /// Notify the callback function of a disconnect, but don't disconnect,
    /// use the [Self::disconnect] function for that
    pub fn notify_disconnect(&self) {
        unsafe { BNNotifyWebsocketClientDisconnect(self.0.as_raw()) }
    }

    /// Call the error callback function
    pub fn notify_error<S: BnStrCompatible>(&self, error: S) {
        let error = error.into_bytes_with_nul();
        unsafe {
            BNNotifyWebsocketClientError(
                self.0.as_raw(),
                error.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Call the read callback function, forward the callback returned value
    pub fn notify_read(&self, data: &[u8]) -> bool {
        unsafe {
            BNNotifyWebsocketClientReadData(
                self.0.as_raw(),
                data.as_ptr() as *mut _,
                data.len().try_into().unwrap(),
            )
        }
    }
}

pub trait WebsocketCustomProvider: Sync + Send {
    type Client<'a>: WebsocketCustomClient;

    fn new(core: WebsocketProvider) -> Self;
    fn get_core(&self) -> &WebsocketProvider;
    fn init_client<'a>(&self, core: CoreWebSocketClient<'a>) -> Self::Client<'a>;

    /// Connect to a given url, asynchronously. The connection will be run in a
    /// separate thread managed by the websocket provider.
    ///
    /// * `host` - Full url with scheme, domain, optionally port, and path
    /// * `headers` - HTTP header keys and values
    /// * `read_handle` - Handles the received data from the Socket
    fn connect<'a, U, I, K, V, F>(
        &self,
        url: U,
        headers: I,
        read_handle: &'a mut F,
    ) -> Option<Ref<WebsocketClient<'a>>>
    where
        Self: Sized,
        U: BnStrCompatible,
        I: IntoIterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
        F: FnMut(&[u8]) -> bool,
    {
        let cb_callback = BNWebsocketClientOutputCallbacks {
            context: read_handle as *mut _ as *mut ffi::c_void,
            connectedCallback: Some(cb_connected_nop),
            disconnectedCallback: Some(cb_disconnected_nop),
            errorCallback: Some(cb_error_nop),
            readCallback: Some(cb_read_closure::<F>),
        };
        let client_ptr = new_client(self);
        connect_client(client_ptr, url, headers, cb_callback)
    }

    /// Connect to a given url, asynchronously. The connection will be run in a
    /// separate thread managed by the websocket provider.
    ///
    /// Callbacks will be called **on the thread of the connection**, so be sure
    /// to ExecuteOnMainThread any long-running or gui operations in the callbacks.
    ///
    /// If the connection succeeds, [WebsocketClientCallback::connected] will be called. On normal termination, [WebsocketClientCallback::disconnected] will be called.
    ///
    /// If the connection succeeds, but later fails, [WebsocketClientCallback::disconnected] will not be called, and [WebsocketClientCallback::error] will be called instead.
    ///
    /// If the connection fails, neither [WebsocketClientCallback::connected] nor [WebsocketClientCallback::disconnected] will be called, and [WebsocketClientCallback::error] will be called instead.
    ///
    /// If [WebsocketClientCallback::connected] or [WebsocketClientCallback::read] return false, the connection will be aborted.
    ///
    /// * `host` - Full url with scheme, domain, optionally port, and path
    /// * `headers` - HTTP header keys and values
    /// * `callback` - Callbacks for various websocket events
    fn connect_with_callback<'a, U, I, K, V, W>(
        &self,
        url: U,
        headers: I,
        callback: &'a mut W,
    ) -> Option<Ref<WebsocketClient<'a>>>
    where
        Self: Sized,
        U: BnStrCompatible,
        I: IntoIterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
        W: WebsocketClientCallback,
    {
        let cb_callback = BNWebsocketClientOutputCallbacks {
            context: callback as *mut W as *mut _,
            connectedCallback: Some(cb_connected::<W>),
            disconnectedCallback: Some(cb_disconnected::<W>),
            errorCallback: Some(cb_error::<W>),
            readCallback: Some(cb_read::<W>),
        };
        let client_ptr = new_client(self);
        connect_client(client_ptr, url, headers, cb_callback)
    }
}

fn new_client<W: WebsocketCustomProvider>(provider: &W) -> *mut BNWebsocketClient {
    // SAFETY: Websocket client is freed by cb_destroy_client
    let custom_uinit = Box::leak(Box::new(mem::MaybeUninit::zeroed()));
    let mut callbacks = BNWebsocketClientCallbacks {
        context: custom_uinit as *mut _ as *mut ffi::c_void,
        connect: Some(cb_connect::<W::Client<'static>>),
        destroyClient: Some(cb_destroy_client::<W::Client<'static>>),
        disconnect: Some(cb_disconnect::<W::Client<'static>>),
        write: Some(cb_write::<W::Client<'static>>),
    };
    let handle = unsafe { BNInitWebsocketClient(provider.get_core().as_raw(), &mut callbacks) };
    custom_uinit.write(provider.init_client(CoreWebSocketClient(WebsocketClient {
        handle: ptr::NonNull::new(handle).unwrap(),
        _callback: std::marker::PhantomData,
    })));
    handle
}

fn connect_client<'a, U, I, K, V>(
    client_ptr: *mut BNWebsocketClient,
    url: U,
    headers: I,
    mut cb_callback: BNWebsocketClientOutputCallbacks,
) -> Option<Ref<WebsocketClient<'a>>>
where
    U: BnStrCompatible,
    I: IntoIterator<Item = (K, V)>,
    K: BnStrCompatible,
    V: BnStrCompatible,
{
    let client = unsafe { WebsocketClient::ref_from_raw(ptr::NonNull::new(client_ptr).unwrap()) };
    // SAFETY: freed by WebsocketClientConnectedWithCallback::drop
    let url = url.into_bytes_with_nul();
    let (header_keys, header_values): (Vec<K::Result>, Vec<V::Result>) = headers
        .into_iter()
        .map(|(k, v)| (k.into_bytes_with_nul(), v.into_bytes_with_nul()))
        .unzip();
    let header_keys: Vec<*const ffi::c_char> = header_keys
        .iter()
        .map(|k| k.as_ref().as_ptr() as *const ffi::c_char)
        .collect();
    let header_values: Vec<*const ffi::c_char> = header_values
        .iter()
        .map(|v| v.as_ref().as_ptr() as *const ffi::c_char)
        .collect();
    let success = unsafe {
        BNConnectWebsocketClient(
            client.as_raw(),
            url.as_ref().as_ptr() as *const ffi::c_char,
            header_keys.len().try_into().unwrap(),
            header_keys.as_ptr(),
            header_values.as_ptr(),
            &mut cb_callback,
        )
    };
    success.then_some(client)
}

pub trait WebsocketClientCallback: Sync + Send {
    fn connected(&self) -> bool;
    fn disconnected(&self);
    fn error(&self, msg: &str);
    fn read(&self, data: &mut [u8]) -> bool;
}

pub trait WebsocketCustomClient: Sync + Send {
    fn connect(&self, host: &str, header_keys: &[BnString], header_values: &[BnString]) -> bool;
    fn write(&self, data: &[u8]) -> bool;
    fn disconnect(&self) -> bool;
}

pub fn register_websocket_provider<S, W>(name: S) -> (&'static W, WebsocketProvider)
where
    S: BnStrCompatible,
    W: WebsocketCustomProvider + 'static,
{
    let name = name.into_bytes_with_nul();
    // SAFETY: Websocket provider is never freed
    let provider_uinit = Box::leak(Box::new(mem::MaybeUninit::zeroed()));
    let result = unsafe {
        BNRegisterWebsocketProvider(
            name.as_ref().as_ptr() as *const ffi::c_char,
            &mut BNWebsocketProviderCallbacks {
                context: provider_uinit as *mut _ as *mut ffi::c_void,
                createClient: Some(cb_create_client::<W>),
            },
        )
    };
    let provider_core = unsafe { WebsocketProvider::from_raw(ptr::NonNull::new(result).unwrap()) };
    provider_uinit.write(W::new(provider_core));
    (unsafe { provider_uinit.assume_init_ref() }, provider_core)
}

unsafe extern "C" fn cb_create_client<W: WebsocketCustomProvider>(
    ctxt: *mut ::std::os::raw::c_void,
) -> *mut BNWebsocketClient {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    new_client(ctxt)
}

unsafe extern "C" fn cb_destroy_client<W: WebsocketCustomClient>(ctxt: *mut ffi::c_void) {
    let ctxt: Box<W> = Box::from_raw(&mut *(ctxt as *mut W));
    drop(ctxt)
}

unsafe extern "C" fn cb_connect<W: WebsocketCustomClient>(
    ctxt: *mut ffi::c_void,
    host: *const ffi::c_char,
    header_count: u64,
    header_keys: *const *const ffi::c_char,
    header_values: *const *const ffi::c_char,
) -> bool {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    let host = ffi::CStr::from_ptr(host);
    // SAFETY BnString and *mut ffi::c_char are transparnet
    let header_count = usize::try_from(header_count).unwrap();
    let header_keys = core::slice::from_raw_parts(header_keys as *const BnString, header_count);
    let header_values = core::slice::from_raw_parts(header_values as *const BnString, header_count);
    ctxt.connect(&host.to_string_lossy(), header_keys, header_values)
}

unsafe extern "C" fn cb_write<W: WebsocketCustomClient>(
    data: *const u8,
    len: u64,
    ctxt: *mut ffi::c_void,
) -> bool {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    let len = usize::try_from(len).unwrap();
    let data = core::slice::from_raw_parts(data, len);
    ctxt.write(data)
}

unsafe extern "C" fn cb_disconnect<W: WebsocketCustomClient>(ctxt: *mut ffi::c_void) -> bool {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    ctxt.disconnect()
}

unsafe extern "C" fn cb_connected<W: WebsocketClientCallback>(ctxt: *mut ffi::c_void) -> bool {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    ctxt.connected()
}

unsafe extern "C" fn cb_disconnected<W: WebsocketClientCallback>(ctxt: *mut ffi::c_void) {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    ctxt.disconnected()
}

unsafe extern "C" fn cb_error<W: WebsocketClientCallback>(
    msg: *const ffi::c_char,
    ctxt: *mut ffi::c_void,
) {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    let msg = ffi::CStr::from_ptr(msg);
    ctxt.error(&msg.to_string_lossy())
}

unsafe extern "C" fn cb_read<W: WebsocketClientCallback>(
    data: *mut u8,
    len: u64,
    ctxt: *mut ::std::os::raw::c_void,
) -> bool {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    let len = usize::try_from(len).unwrap();
    let data = core::slice::from_raw_parts_mut(data, len);
    ctxt.read(data)
}

unsafe extern "C" fn cb_connected_nop(_ctxt: *mut ffi::c_void) -> bool {
    true
}

unsafe extern "C" fn cb_disconnected_nop(_ctxt: *mut ffi::c_void) {}

unsafe extern "C" fn cb_error_nop(_msg: *const ffi::c_char, _ctxt: *mut ffi::c_void) {}

unsafe extern "C" fn cb_read_closure<F: FnMut(&[u8]) -> bool>(
    data: *mut u8,
    len: u64,
    ctxt: *mut ::std::os::raw::c_void,
) -> bool {
    let ctxt: &mut F = &mut *(ctxt as *mut F);
    let len = usize::try_from(len).unwrap();
    let data = core::slice::from_raw_parts_mut(data, len);
    let ctxt: &mut F = &mut *(ctxt as *mut F);
    ctxt(data)
}
