use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct WebsocketProvider {
    handle: ptr::NonNull<BNWebsocketProvider>,
}

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
    pub fn connect<U, I, K, V>(self, url: U, headers: I) -> Option<WebsocketClient>
    where
        U: BnStrCompatible,
        I: IntoIterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
    {
        let result = unsafe { BNCreateWebsocketProviderClient(self.as_raw()) };
        let client = unsafe { WebsocketClient::from_raw(ptr::NonNull::new(result).unwrap()) };
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
        let mut cb_callback = BNWebsocketClientOutputCallbacks {
            context: ptr::null_mut(),
            connectedCallback: Some(cb_connected_nop),
            disconnectedCallback: Some(cb_disconnected_nop),
            errorCallback: Some(cb_error_nop),
            readCallback: Some(cb_read_nop),
        };
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
    pub fn connect_with_callback<U, I, K, V, W>(
        self,
        url: U,
        headers: I,
        callback: W,
    ) -> Option<WebsocketClientHandleWithCallback<W>>
    where
        U: BnStrCompatible,
        I: IntoIterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
        W: WebsocketClientCallback,
    {
        let result = unsafe { BNCreateWebsocketProviderClient(self.as_raw()) };
        let client = unsafe { WebsocketClient::from_raw(ptr::NonNull::new(result).unwrap()) };
        // SAFETY: freed by WebsocketClientConnectedWithCallback::drop
        let callback = Box::leak(Box::new(callback));
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
        let mut cb_callback = BNWebsocketClientOutputCallbacks {
            context: callback as *mut W as *mut _,
            connectedCallback: Some(cb_connected::<W>),
            disconnectedCallback: Some(cb_disconnected::<W>),
            errorCallback: Some(cb_error::<W>),
            readCallback: Some(cb_read::<W>),
        };
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
        success.then(|| WebsocketClientHandleWithCallback { client, callback })
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

/// Implements a websocket client. See [WebsocketProvider::connect] and [WebsocketProvider::connect_with_callback] for more details.
#[repr(transparent)]
pub struct WebsocketClient {
    handle: ptr::NonNull<BNWebsocketClient>,
}

impl Clone for WebsocketClient {
    fn clone(&self) -> Self {
        let result = unsafe { BNNewWebsocketClientReference(self.as_raw()) };
        unsafe { Self::from_raw(ptr::NonNull::new(result).unwrap()) }
    }
}

impl Drop for WebsocketClient {
    fn drop(&mut self) {
        unsafe { BNFreeWebsocketClient(self.as_raw()) }
    }
}

impl WebsocketClient {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNWebsocketClient>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn into_raw(self) -> *mut BNWebsocketClient {
        mem::ManuallyDrop::new(self).handle.as_ptr()
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNWebsocketClient {
        &mut *self.handle.as_ptr()
    }

    pub fn new_custom<W>(provider: WebsocketProvider) -> WebsocketClient
    where
        W: WebsocketCustomClient,
    {
        // SAFETY: Websocket client is freed by cb_destroy_client
        let custom_uinit = Box::leak(Box::new(mem::MaybeUninit::zeroed()));
        let mut callbacks = BNWebsocketClientCallbacks {
            context: custom_uinit as *mut _ as *mut ffi::c_void,
            connect: Some(cb_connect::<W>),
            destroyClient: Some(cb_destroy_client::<W>),
            disconnect: Some(cb_disconnect::<W>),
            write: Some(cb_write::<W>),
        };
        let result = unsafe { BNInitWebsocketClient(provider.as_raw(), &mut callbacks) };
        let client = unsafe { WebsocketClient::from_raw(ptr::NonNull::new(result).unwrap()) };
        custom_uinit.write(W::new(provider, &client));
        client
    }

    /// Call the connect callback function, forward the callback returned value
    pub fn notify_connect(&self) -> bool {
        unsafe { BNNotifyWebsocketClientConnect(self.as_raw()) }
    }

    /// Notify the callback function of a disconnect, but don't disconnect,
    /// use the [Self::disconnect] function for that
    pub fn notify_disconnect(&self) {
        unsafe { BNNotifyWebsocketClientDisconnect(self.as_raw()) }
    }

    /// Call the error callback function
    pub fn notify_error<S: BnStrCompatible>(&self, error: S) {
        let error = error.into_bytes_with_nul();
        unsafe {
            BNNotifyWebsocketClientError(
                self.as_raw(),
                error.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Call the read callback function, forward the callback returned value
    pub fn notify_read<S: BnStrCompatible>(&self, data: &mut [u8]) -> bool {
        unsafe {
            BNNotifyWebsocketClientReadData(
                self.as_raw(),
                data.as_mut_ptr(),
                data.len().try_into().unwrap(),
            )
        }
    }

    /// Write some data to the websocket
    pub fn write(&self, data: &[u8]) -> usize {
        let len = u64::try_from(data.len()).unwrap();
        let result = unsafe { BNWriteWebsocketClientData(self.as_raw(), data.as_ptr(), len) };
        usize::try_from(result).unwrap()
    }

    /// Disconnect the websocket
    pub fn disconnect(&self) -> bool {
        unsafe { BNDisconnectWebsocketClient(self.as_raw()) }
    }
}

pub struct WebsocketClientHandleWithCallback<W: WebsocketClientCallback> {
    client: WebsocketClient,
    callback: *mut W,
}

impl<W: WebsocketClientCallback> Drop for WebsocketClientHandleWithCallback<W> {
    fn drop(&mut self) {
        let callback: Box<W> = unsafe { Box::from_raw(self.callback) };
        drop(callback);
    }
}

impl<W: WebsocketClientCallback> AsRef<WebsocketClient> for WebsocketClientHandleWithCallback<W> {
    fn as_ref(&self) -> &WebsocketClient {
        &self.client
    }
}

impl<W: WebsocketClientCallback> core::ops::Deref for WebsocketClientHandleWithCallback<W> {
    type Target = WebsocketClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

pub trait WebsocketCustomProvider: Sync + Send {
    fn new(core: WebsocketProvider) -> Self;
    fn create_client(&self) -> WebsocketClient;
}

pub trait WebsocketClientCallback: Sync + Send {
    fn connected(&self) -> bool;
    fn disconnected(&self);
    fn error(&self, msg: &str);
    fn read(&self, data: &mut [u8]) -> bool;
}

pub trait WebsocketCustomClient: Sync + Send {
    fn new(provider: WebsocketProvider, client: &WebsocketClient) -> Self;
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
    let result = ctxt.create_client();
    result.into_raw()
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

unsafe extern "C" fn cb_read_nop(
    _data: *mut u8,
    _len: u64,
    _ctxt: *mut ::std::os::raw::c_void,
) -> bool {
    true
}
