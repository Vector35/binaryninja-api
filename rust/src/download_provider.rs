use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::settings::Settings;
use crate::string::{BnString, IntoCStr};
use binaryninjacore_sys::*;
use std::collections::HashMap;
use std::ffi::{c_void, CStr};
use std::os::raw::c_char;
use std::ptr::null_mut;
use std::slice;

pub struct DownloadProvider {
    handle: *mut BNDownloadProvider,
}

impl DownloadProvider {
    pub fn get(name: &str) -> Option<DownloadProvider> {
        let name = name.to_cstr();
        let result = unsafe { BNGetDownloadProviderByName(name.as_ptr()) };
        if result.is_null() {
            return None;
        }
        Some(DownloadProvider { handle: result })
    }

    pub fn list() -> Result<Array<DownloadProvider>, ()> {
        let mut count = 0;
        let list: *mut *mut BNDownloadProvider = unsafe { BNGetDownloadProviderList(&mut count) };

        if list.is_null() {
            return Err(());
        }

        Ok(unsafe { Array::new(list, count, ()) })
    }

    /// TODO : We may want to `impl Default`....excessive error checking might be preventing us from doing so
    pub fn try_default() -> Result<DownloadProvider, ()> {
        let s = Settings::new();
        let dp_name = s.get_string("network.downloadProviderName");
        Self::get(&dp_name).ok_or(())
    }

    pub(crate) fn from_raw(handle: *mut BNDownloadProvider) -> DownloadProvider {
        Self { handle }
    }

    pub fn create_instance(&self) -> Result<Ref<DownloadInstance>, ()> {
        let result: *mut BNDownloadInstance =
            unsafe { BNCreateDownloadProviderInstance(self.handle) };
        if result.is_null() {
            return Err(());
        }

        Ok(unsafe { DownloadInstance::ref_from_raw(result) })
    }
}

impl CoreArrayProvider for DownloadProvider {
    type Raw = *mut BNDownloadProvider;
    type Context = ();
    type Wrapped<'a> = Guard<'a, DownloadProvider>;
}

unsafe impl CoreArrayProviderInner for DownloadProvider {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeDownloadProviderList(raw);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(DownloadProvider::from_raw(*raw), &())
    }
}

pub struct DownloadInstanceOutputCallbacks {
    pub write: Option<Box<dyn FnMut(&[u8]) -> usize>>,
    pub progress: Option<Box<dyn FnMut(usize, usize) -> bool>>,
}

pub struct DownloadInstanceInputOutputCallbacks {
    pub read: Option<Box<dyn FnMut(&mut [u8]) -> Option<isize>>>,
    pub write: Option<Box<dyn FnMut(&[u8]) -> usize>>,
    pub progress: Option<Box<dyn FnMut(usize, usize) -> bool>>,
}

pub struct DownloadResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
}

pub struct DownloadInstance {
    handle: *mut BNDownloadInstance,
}

impl DownloadInstance {
    pub(crate) unsafe fn from_raw(handle: *mut BNDownloadInstance) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNDownloadInstance) -> Ref<Self> {
        Ref::new(Self::from_raw(handle))
    }

    fn get_error(&self) -> String {
        let err: *mut c_char = unsafe { BNGetErrorForDownloadInstance(self.handle) };
        unsafe { BnString::into_string(err) }
    }

    unsafe extern "C" fn o_write_callback(data: *mut u8, len: u64, ctxt: *mut c_void) -> u64 {
        let callbacks = ctxt as *mut DownloadInstanceOutputCallbacks;
        if let Some(func) = &mut (*callbacks).write {
            let slice = slice::from_raw_parts(data, len as usize);
            let result = (func)(slice);
            result as u64
        } else {
            0u64
        }
    }

    unsafe extern "C" fn o_progress_callback(
        ctxt: *mut c_void,
        progress: usize,
        total: usize,
    ) -> bool {
        let callbacks = ctxt as *mut DownloadInstanceOutputCallbacks;
        if let Some(func) = &mut (*callbacks).progress {
            (func)(progress, total)
        } else {
            true
        }
    }

    pub fn perform_request(
        &mut self,
        url: &str,
        callbacks: &DownloadInstanceOutputCallbacks,
    ) -> Result<(), String> {
        let mut cbs = BNDownloadInstanceOutputCallbacks {
            writeCallback: Some(Self::o_write_callback),
            writeContext: callbacks as *const _ as *mut c_void,
            progressCallback: Some(Self::o_progress_callback),
            progressContext: callbacks as *const _ as *mut c_void,
        };

        let url_raw = url.to_cstr();
        let result = unsafe {
            BNPerformDownloadRequest(
                self.handle,
                url_raw.as_ptr(),
                &mut cbs as *mut BNDownloadInstanceOutputCallbacks,
            )
        };

        if result < 0 {
            Err(self.get_error())
        } else {
            Ok(())
        }
    }

    unsafe extern "C" fn i_read_callback(data: *mut u8, len: u64, ctxt: *mut c_void) -> i64 {
        let callbacks = ctxt as *mut DownloadInstanceInputOutputCallbacks;
        if let Some(func) = &mut (*callbacks).read {
            let slice = slice::from_raw_parts_mut(data, len as usize);
            let result = (func)(slice);
            if let Some(count) = result {
                count as i64
            } else {
                -1
            }
        } else {
            0
        }
    }

    unsafe extern "C" fn i_write_callback(data: *mut u8, len: u64, ctxt: *mut c_void) -> u64 {
        let callbacks = ctxt as *mut DownloadInstanceInputOutputCallbacks;
        if let Some(func) = &mut (*callbacks).write {
            let slice = slice::from_raw_parts(data, len as usize);
            let result = (func)(slice);
            result as u64
        } else {
            0
        }
    }

    unsafe extern "C" fn i_progress_callback(
        ctxt: *mut c_void,
        progress: usize,
        total: usize,
    ) -> bool {
        let callbacks = ctxt as *mut DownloadInstanceInputOutputCallbacks;
        if let Some(func) = &mut (*callbacks).progress {
            (func)(progress, total)
        } else {
            true
        }
    }

    pub fn perform_custom_request<I>(
        &mut self,
        method: &str,
        url: &str,
        headers: I,
        callbacks: &DownloadInstanceInputOutputCallbacks,
    ) -> Result<DownloadResponse, String>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut header_keys = vec![];
        let mut header_values = vec![];
        for (key, value) in headers {
            header_keys.push(key.to_cstr());
            header_values.push(value.to_cstr());
        }

        let mut header_key_ptrs = vec![];
        let mut header_value_ptrs = vec![];

        for (key, value) in header_keys.iter().zip(header_values.iter()) {
            header_key_ptrs.push(key.as_ptr());
            header_value_ptrs.push(value.as_ptr());
        }

        let mut cbs = BNDownloadInstanceInputOutputCallbacks {
            readCallback: Some(Self::i_read_callback),
            readContext: callbacks as *const _ as *mut c_void,
            writeCallback: Some(Self::i_write_callback),
            writeContext: callbacks as *const _ as *mut c_void,
            progressCallback: Some(Self::i_progress_callback),
            progressContext: callbacks as *const _ as *mut c_void,
        };

        let mut response: *mut BNDownloadInstanceResponse = null_mut();

        let method_raw = method.to_cstr();
        let url_raw = url.to_cstr();
        let result = unsafe {
            BNPerformCustomRequest(
                self.handle,
                method_raw.as_ptr(),
                url_raw.as_ptr(),
                header_key_ptrs.len() as u64,
                header_key_ptrs.as_ptr(),
                header_value_ptrs.as_ptr(),
                &mut response as *mut *mut BNDownloadInstanceResponse,
                &mut cbs as *mut BNDownloadInstanceInputOutputCallbacks,
            )
        };

        if result < 0 {
            unsafe { BNFreeDownloadInstanceResponse(response) };
            return Err(self.get_error());
        }

        let mut response_headers = HashMap::new();
        unsafe {
            let response_header_keys: &[*mut c_char] =
                slice::from_raw_parts((*response).headerKeys, (*response).headerCount as usize);
            let response_header_values: &[*mut c_char] =
                slice::from_raw_parts((*response).headerValues, (*response).headerCount as usize);

            for (key, value) in response_header_keys
                .iter()
                .zip(response_header_values.iter())
            {
                response_headers.insert(
                    CStr::from_ptr(*key).to_str().unwrap().to_owned(),
                    CStr::from_ptr(*value).to_str().unwrap().to_owned(),
                );
            }
        }

        let r = DownloadResponse {
            status_code: unsafe { (*response).statusCode },
            headers: response_headers,
        };

        unsafe { BNFreeDownloadInstanceResponse(response) };

        Ok(r)
    }
}

impl ToOwned for DownloadInstance {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for DownloadInstance {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewDownloadInstanceReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeDownloadInstance(handle.handle);
    }
}
