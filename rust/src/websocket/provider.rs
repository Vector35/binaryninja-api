use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{BnStrCompatible, BnString};
use crate::websocket::client;
use crate::websocket::client::{CoreWebsocketClient, WebsocketClient};
use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void};
use std::mem::MaybeUninit;
use std::ptr::NonNull;

pub fn register_websocket_provider<W>(name: &str) -> &'static mut W
where
    W: WebsocketProvider,
{
    let name = name.into_bytes_with_nul();
    let provider_uninit = MaybeUninit::uninit();
    // SAFETY: Websocket provider is never freed
    let leaked_provider = Box::leak(Box::new(provider_uninit));
    let result = unsafe {
        BNRegisterWebsocketProvider(
            name.as_ptr() as *const c_char,
            &mut BNWebsocketProviderCallbacks {
                context: leaked_provider as *mut _ as *mut c_void,
                createClient: Some(cb_create_client::<W>),
            },
        )
    };

    let provider_core = unsafe { CoreWebsocketProvider::from_raw(NonNull::new(result).unwrap()) };
    // We now have the core provider so we can actually construct the object.
    leaked_provider.write(W::from_core(provider_core));
    unsafe { leaked_provider.assume_init_mut() }
}

pub trait WebsocketProvider: Sync + Send + Sized {
    type Client: WebsocketClient;

    fn handle(&self) -> CoreWebsocketProvider;

    /// Called to construct this provider object with the given core object.
    fn from_core(core: CoreWebsocketProvider) -> Self;

    /// Create a new instance of the websocket client.
    fn create_client(&self) -> Result<Ref<CoreWebsocketClient>, ()> {
        let client_uninit = MaybeUninit::uninit();
        // SAFETY: Websocket client is freed by cb_destroy_client
        let leaked_client = Box::leak(Box::new(client_uninit));
        let mut callbacks = BNWebsocketClientCallbacks {
            context: leaked_client as *mut _ as *mut c_void,
            connect: Some(client::cb_connect::<Self::Client>),
            destroyClient: Some(client::cb_destroy_client::<Self::Client>),
            disconnect: Some(client::cb_disconnect::<Self::Client>),
            write: Some(client::cb_write::<Self::Client>),
        };
        let client_ptr =
            unsafe { BNInitWebsocketClient(self.handle().handle.as_ptr(), &mut callbacks) };
        // TODO: If possible pass a sensible error back...
        let client_ptr = NonNull::new(client_ptr).ok_or(())?;
        let client_ref = unsafe { CoreWebsocketClient::ref_from_raw(client_ptr) };
        // We now have the core client so we can actually construct the object.
        leaked_client.write(Self::Client::from_core(client_ref.clone()));
        Ok(client_ref)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct CoreWebsocketProvider {
    handle: NonNull<BNWebsocketProvider>,
}

impl CoreWebsocketProvider {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNWebsocketProvider>) -> Self {
        Self { handle }
    }

    pub fn all() -> Array<Self> {
        let mut count = 0;
        let result = unsafe { BNGetWebsocketProviderList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn by_name<S: BnStrCompatible>(name: S) -> Option<CoreWebsocketProvider> {
        let name = name.into_bytes_with_nul();
        let result =
            unsafe { BNGetWebsocketProviderByName(name.as_ref().as_ptr() as *const c_char) };
        NonNull::new(result).map(|h| unsafe { Self::from_raw(h) })
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNGetWebsocketProviderName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }
}

unsafe impl Sync for CoreWebsocketProvider {}
unsafe impl Send for CoreWebsocketProvider {}

impl CoreArrayProvider for CoreWebsocketProvider {
    type Raw = *mut BNWebsocketProvider;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CoreWebsocketProvider {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeWebsocketProviderList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        let handle = NonNull::new(*raw).unwrap();
        Self::from_raw(handle)
    }
}

unsafe extern "C" fn cb_create_client<W: WebsocketProvider>(
    ctxt: *mut c_void,
) -> *mut BNWebsocketClient {
    let ctxt: &mut W = &mut *(ctxt as *mut W);
    match ctxt.create_client() {
        Ok(owned_client) => {
            // SAFETY: The caller is assumed to have picked up this ref.
            Ref::into_raw(owned_client).handle.as_ptr()
        }
        Err(_) => std::ptr::null_mut(),
    }
}
