use crate::rc::{Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};
use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void, CStr};
use std::ptr::NonNull;

pub trait WebsocketClientCallback: Sync + Send {
    fn connected(&mut self) -> bool;

    fn disconnected(&mut self);

    fn error(&mut self, msg: &str);

    fn read(&mut self, data: &[u8]) -> bool;
}

pub trait WebsocketClient: Sync + Send {
    /// Called to construct this client object with the given core object.
    fn from_core(core: Ref<CoreWebsocketClient>) -> Self;

    fn connect<I, K, V>(&self, host: &str, headers: I) -> bool
    where
        I: IntoIterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible;

    fn write(&self, data: &[u8]) -> bool;

    fn disconnect(&self) -> bool;
}

/// Implements a websocket client.
#[repr(transparent)]
pub struct CoreWebsocketClient {
    pub(crate) handle: NonNull<BNWebsocketClient>,
}

impl CoreWebsocketClient {
    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNWebsocketClient>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNWebsocketClient {
        &mut *self.handle.as_ptr()
    }

    /// Initializes the web socket connection.
    ///
    /// Connect to a given url, asynchronously. The connection will be run in a
    /// separate thread managed by the websocket provider.
    ///
    /// Callbacks will be called **on the thread of the connection**, so be sure
    /// to ExecuteOnMainThread any long-running or gui operations in the callbacks.
    ///
    /// If the connection succeeds, [WebsocketClientCallback::connected] will be called. On normal
    /// termination, [WebsocketClientCallback::disconnected] will be called.
    ///
    /// If the connection succeeds, but later fails, [WebsocketClientCallback::disconnected] will not
    /// be called, and [WebsocketClientCallback::error] will be called instead.
    ///
    /// If the connection fails, neither [WebsocketClientCallback::connected] nor
    /// [WebsocketClientCallback::disconnected] will be called, and [WebsocketClientCallback::error]
    /// will be called instead.
    ///
    /// If [WebsocketClientCallback::connected] or [WebsocketClientCallback::read] return false, the
    /// connection will be aborted.
    ///
    /// * `host` - Full url with scheme, domain, optionally port, and path
    /// * `headers` - HTTP header keys and values
    /// * `callback` - Callbacks for various websocket events
    pub fn initialize_connection<I, K, V, C>(
        &self,
        host: &str,
        headers: I,
        callbacks: &mut C,
    ) -> bool
    where
        I: IntoIterator<Item = (K, V)>,
        K: BnStrCompatible,
        V: BnStrCompatible,
        C: WebsocketClientCallback,
    {
        let url = host.into_bytes_with_nul();
        let (header_keys, header_values): (Vec<K::Result>, Vec<V::Result>) = headers
            .into_iter()
            .map(|(k, v)| (k.into_bytes_with_nul(), v.into_bytes_with_nul()))
            .unzip();
        let header_keys: Vec<*const c_char> = header_keys
            .iter()
            .map(|k| k.as_ref().as_ptr() as *const c_char)
            .collect();
        let header_values: Vec<*const c_char> = header_values
            .iter()
            .map(|v| v.as_ref().as_ptr() as *const c_char)
            .collect();
        // SAFETY: This context will only be live for the duration of BNConnectWebsocketClient
        // SAFETY: Any subsequent call to BNConnectWebsocketClient will write over the context.
        let mut output_callbacks = BNWebsocketClientOutputCallbacks {
            context: callbacks as *mut C as *mut c_void,
            connectedCallback: Some(cb_connected::<C>),
            disconnectedCallback: Some(cb_disconnected::<C>),
            errorCallback: Some(cb_error::<C>),
            readCallback: Some(cb_read::<C>),
        };
        unsafe {
            BNConnectWebsocketClient(
                self.handle.as_ptr(),
                url.as_ptr() as *const c_char,
                header_keys.len().try_into().unwrap(),
                header_keys.as_ptr(),
                header_values.as_ptr(),
                &mut output_callbacks,
            )
        }
    }

    /// Call the connect callback function, forward the callback returned value
    pub fn notify_connected(&self) -> bool {
        unsafe { BNNotifyWebsocketClientConnect(self.handle.as_ptr()) }
    }

    /// Notify the callback function of a disconnect,
    ///
    /// NOTE: This does not actually disconnect, use the [Self::disconnect] function for that.
    pub fn notify_disconnected(&self) {
        unsafe { BNNotifyWebsocketClientDisconnect(self.handle.as_ptr()) }
    }

    /// Call the error callback function
    pub fn notify_error(&self, msg: &str) {
        let error = msg.into_bytes_with_nul();
        unsafe {
            BNNotifyWebsocketClientError(self.handle.as_ptr(), error.as_ptr() as *const c_char)
        }
    }

    /// Call the read callback function, forward the callback returned value
    pub fn notify_read(&self, data: &[u8]) -> bool {
        unsafe {
            BNNotifyWebsocketClientReadData(
                self.handle.as_ptr(),
                data.as_ptr() as *mut _,
                data.len().try_into().unwrap(),
            )
        }
    }

    pub fn write(&self, data: &[u8]) -> bool {
        let len = u64::try_from(data.len()).unwrap();
        unsafe { BNWriteWebsocketClientData(self.as_raw(), data.as_ptr(), len) != 0 }
    }

    pub fn disconnect(&self) -> bool {
        unsafe { BNDisconnectWebsocketClient(self.as_raw()) }
    }
}

unsafe impl Sync for CoreWebsocketClient {}
unsafe impl Send for CoreWebsocketClient {}

impl ToOwned for CoreWebsocketClient {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for CoreWebsocketClient {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        let result = BNNewWebsocketClientReference(handle.as_raw());
        unsafe { Self::ref_from_raw(NonNull::new(result).unwrap()) }
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeWebsocketClient(handle.as_raw())
    }
}

pub(crate) unsafe extern "C" fn cb_destroy_client<W: WebsocketClient>(ctxt: *mut c_void) {
    let _ = Box::from_raw(ctxt as *mut W);
}

pub(crate) unsafe extern "C" fn cb_connect<W: WebsocketClient>(
    ctxt: *mut c_void,
    host: *const c_char,
    header_count: u64,
    header_keys: *const *const c_char,
    header_values: *const *const c_char,
) -> bool {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    let host = CStr::from_ptr(host);
    // SAFETY BnString and *mut c_char are transparent
    let header_count = usize::try_from(header_count).unwrap();
    let header_keys = core::slice::from_raw_parts(header_keys as *const BnString, header_count);
    let header_values = core::slice::from_raw_parts(header_values as *const BnString, header_count);
    let header_keys_str = header_keys.iter().map(|s| s.to_string_lossy());
    let header_values_str = header_values.iter().map(|s| s.to_string_lossy());
    let header = header_keys_str.zip(header_values_str);
    ctxt.connect(&host.to_string_lossy(), header)
}

pub(crate) unsafe extern "C" fn cb_write<W: WebsocketClient>(
    data: *const u8,
    len: u64,
    ctxt: *mut c_void,
) -> bool {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    let len = usize::try_from(len).unwrap();
    let data = core::slice::from_raw_parts(data, len);
    ctxt.write(data)
}

pub(crate) unsafe extern "C" fn cb_disconnect<W: WebsocketClient>(ctxt: *mut c_void) -> bool {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    ctxt.disconnect()
}

unsafe extern "C" fn cb_connected<W: WebsocketClientCallback>(ctxt: *mut c_void) -> bool {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    ctxt.connected()
}

unsafe extern "C" fn cb_disconnected<W: WebsocketClientCallback>(ctxt: *mut c_void) {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    ctxt.disconnected()
}

unsafe extern "C" fn cb_error<W: WebsocketClientCallback>(msg: *const c_char, ctxt: *mut c_void) {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    let msg = CStr::from_ptr(msg);
    ctxt.error(&msg.to_string_lossy())
}

unsafe extern "C" fn cb_read<W: WebsocketClientCallback>(
    data: *mut u8,
    len: u64,
    ctxt: *mut c_void,
) -> bool {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    let len = usize::try_from(len).unwrap();
    let data = core::slice::from_raw_parts_mut(data, len);
    ctxt.read(data)
}
