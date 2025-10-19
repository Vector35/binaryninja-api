use crate::download::DownloadProvider;
use crate::headless::is_shutdown_requested;
use crate::rc::{Ref, RefCountable};
use crate::string::{strings_to_string_list, BnString, IntoCStr};
use binaryninjacore_sys::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_void, CStr};
use std::mem::{ManuallyDrop, MaybeUninit};
use std::os::raw::c_char;
use std::ptr::null_mut;
use std::rc::Rc;
use std::slice;

pub trait CustomDownloadInstance: Sized {
    fn new_with_provider(provider: DownloadProvider) -> Result<Ref<DownloadInstance>, ()> {
        let instance_uninit = MaybeUninit::uninit();
        // SAFETY: Download instance is freed by cb_destroy_instance
        let leaked_instance = Box::leak(Box::new(instance_uninit));
        let mut callbacks = BNDownloadInstanceCallbacks {
            context: leaked_instance as *mut _ as *mut c_void,
            destroyInstance: Some(cb_destroy_instance::<Self>),
            performRequest: Some(cb_perform_request::<Self>),
            performCustomRequest: Some(cb_perform_custom_request::<Self>),
            freeResponse: Some(cb_free_response),
        };
        let instance_ptr = unsafe { BNInitDownloadInstance(provider.handle, &mut callbacks) };
        // TODO: If possible pass a sensible error back...
        let instance_ref = unsafe { DownloadInstance::ref_from_raw(instance_ptr) };
        // We now have the core instance, so we can actually construct the object.
        leaked_instance.write(Self::from_core(instance_ref.clone()));
        Ok(instance_ref)
    }

    /// Construct the object now that the core object has been created.
    fn from_core(core: Ref<DownloadInstance>) -> Self;

    /// Get the core object, typically the handle is stored directly on the object.
    fn handle(&self) -> Ref<DownloadInstance>;

    /// Send an HTTP request on behalf of the caller.
    ///
    /// The caller will expect you to inform them of progress via the following:
    ///
    /// - [DownloadInstance::read_callback]
    /// - [DownloadInstance::write_callback]
    /// - [DownloadInstance::progress_callback]
    fn perform_request(&self, url: &str) -> Result<(), String> {
        self.perform_custom_request("GET", url, vec![])?;
        Ok(())
    }

    /// Send an HTTP request on behalf of the caller.
    ///
    /// The caller will expect you to inform them of progress via the following:
    ///
    /// - [DownloadInstance::read_callback]
    /// - [DownloadInstance::write_callback]
    /// - [DownloadInstance::progress_callback]
    fn perform_custom_request<I>(
        &self,
        method: &str,
        url: &str,
        headers: I,
    ) -> Result<DownloadResponse, String>
    where
        I: IntoIterator<Item = (String, String)>;
}

// TODO: Change this to a trait?
pub struct DownloadInstanceOutputCallbacks {
    pub write: Option<Box<dyn FnMut(&[u8]) -> usize>>,
    pub progress: Option<Box<dyn FnMut(usize, usize) -> bool>>,
}

// TODO: Change this to a trait?
pub struct DownloadInstanceInputOutputCallbacks {
    pub read: Option<Box<dyn FnMut(&mut [u8]) -> Option<usize>>>,
    pub write: Option<Box<dyn FnMut(&[u8]) -> usize>>,
    pub progress: Option<Box<dyn FnMut(usize, usize) -> bool>>,
}

pub struct DownloadResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
}

pub struct OwnedDownloadResponse {
    pub data: Vec<u8>,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
}

impl OwnedDownloadResponse {
    /// Attempt to parse the response body as UTF-8.
    pub fn text(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.data.clone())
    }

    /// Attempt to deserialize the response body as JSON into T.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.data)
    }

    /// Convenience to get a header value by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    /// True if the status code is in the 2xx range.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }
}

/// A reader for a [`DownloadInstance`].
pub struct DownloadInstanceReader {
    pub instance: Ref<DownloadInstance>,
}

impl DownloadInstanceReader {
    pub fn new(instance: Ref<DownloadInstance>) -> Self {
        Self { instance }
    }
}

impl std::io::Read for DownloadInstanceReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let length = self.instance.read_callback(buf);
        if length < 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Connection interrupted",
            ))
        } else {
            Ok(length as usize)
        }
    }
}

/// A writer for a [`DownloadInstance`].
pub struct DownloadInstanceWriter {
    pub instance: Ref<DownloadInstance>,
    /// The expected length of the download.
    pub total_length: Option<u64>,
    /// The current progress of the download.
    pub progress: u64,
}

impl DownloadInstanceWriter {
    pub fn new(instance: Ref<DownloadInstance>, total_length: Option<u64>) -> Self {
        Self {
            instance,
            total_length,
            progress: 0,
        }
    }
}

impl std::io::Write for DownloadInstanceWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let length = self.instance.write_callback(buf);
        if is_shutdown_requested() || length == 0 {
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
        } else {
            self.progress += buf.len() as u64;
            if self
                .instance
                .progress_callback(self.progress, self.total_length.unwrap_or(u64::MAX))
            {
                Ok(length as usize)
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct DownloadInstance {
    pub(crate) handle: *mut BNDownloadInstance,
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

    /// Sets the error for the instance, any later call to [`DownloadInstance::get_error`] will
    /// return the string passed here.
    fn set_error(&self, err: &str) {
        let err = err.to_cstr();
        unsafe { BNSetErrorForDownloadInstance(self.handle, err.as_ptr()) };
    }

    /// Use inside [`CustomDownloadInstance::perform_custom_request`] to pass data back to the caller.
    pub fn write_callback(&self, data: &[u8]) -> u64 {
        unsafe {
            BNWriteDataForDownloadInstance(self.handle, data.as_ptr() as *mut _, data.len() as u64)
        }
    }

    /// Use inside [`CustomDownloadInstance::perform_custom_request`] to read data from the caller.
    pub fn read_callback(&self, data: &mut [u8]) -> i64 {
        unsafe {
            BNReadDataForDownloadInstance(
                self.handle,
                data.as_mut_ptr() as *mut _,
                data.len() as u64,
            )
        }
    }

    /// Use inside [`CustomDownloadInstance::perform_custom_request`] to inform the caller of the request progress.
    pub fn progress_callback(&self, progress: u64, total: u64) -> bool {
        unsafe { BNNotifyProgressForDownloadInstance(self.handle, progress, total) }
    }

    pub fn get<I>(&mut self, url: &str, headers: I) -> Result<OwnedDownloadResponse, String>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let buf: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
        let buf_closure = Rc::clone(&buf);
        let callbacks = DownloadInstanceInputOutputCallbacks {
            read: None,
            write: Some(Box::new(move |data: &[u8]| {
                buf_closure.borrow_mut().extend_from_slice(data);
                data.len()
            })),
            progress: Some(Box::new(|_, _| true)),
        };

        let resp = self.perform_custom_request("GET", url, headers, &callbacks)?;
        drop(callbacks);
        let out = Rc::try_unwrap(buf).map_err(|_| "Buffer held with strong reference")?;
        Ok(OwnedDownloadResponse {
            data: out.into_inner(),
            status_code: resp.status_code,
            headers: resp.headers,
        })
    }

    pub fn post<I>(
        &mut self,
        url: &str,
        headers: I,
        body: Vec<u8>,
    ) -> Result<OwnedDownloadResponse, String>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let resp_buf: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
        let resp_buf_closure = Rc::clone(&resp_buf);
        // Request body position tracker captured by the read closure
        let mut pos = 0usize;
        let total = body.len();
        let callbacks = DownloadInstanceInputOutputCallbacks {
            // Supply request body to the core
            read: Some(Box::new(move |dst: &mut [u8]| -> Option<usize> {
                if pos >= total {
                    return Some(0);
                }
                let remaining = total - pos;
                let to_copy = remaining.min(dst.len());
                dst[..to_copy].copy_from_slice(&body[pos..pos + to_copy]);
                pos += to_copy;
                Some(to_copy)
            })),
            // Collect response body
            write: Some(Box::new(move |data: &[u8]| {
                resp_buf_closure.borrow_mut().extend_from_slice(data);
                data.len()
            })),
            progress: Some(Box::new(|_, _| true)),
        };

        let resp = self.perform_custom_request("POST", url, headers, &callbacks)?;
        drop(callbacks);
        if !(200..300).contains(&(resp.status_code as i32)) {
            return Err(format!("HTTP error: {}", resp.status_code));
        }

        let out = Rc::try_unwrap(resp_buf).map_err(|_| "Buffer held with strong reference")?;
        Ok(OwnedDownloadResponse {
            data: out.into_inner(),
            status_code: resp.status_code,
            headers: resp.headers,
        })
    }

    pub fn post_json<I, T>(
        &mut self,
        url: &str,
        headers: I,
        body: &T,
    ) -> Result<OwnedDownloadResponse, String>
    where
        I: IntoIterator<Item = (String, String)>,
        T: serde::Serialize,
    {
        let mut headers: Vec<(String, String)> = headers.into_iter().collect();
        if !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            headers.push(("content-type".into(), "application/json".into()));
        }
        let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
        self.post(url, headers, bytes)
    }

    pub fn perform_request(
        &mut self,
        url: &str,
        callbacks: &DownloadInstanceOutputCallbacks,
    ) -> Result<(), String> {
        let mut cbs = BNDownloadInstanceOutputCallbacks {
            writeCallback: Some(cb_write_output),
            writeContext: callbacks as *const _ as *mut c_void,
            progressCallback: Some(cb_progress_output),
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
            readCallback: Some(cb_read_input),
            readContext: callbacks as *const _ as *mut c_void,
            writeCallback: Some(cb_write_input),
            writeContext: callbacks as *const _ as *mut c_void,
            progressCallback: Some(cb_progress_input),
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

// TODO: Verify the object is thread safe in the core (hint its not).
unsafe impl Send for DownloadInstance {}
unsafe impl Sync for DownloadInstance {}

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

unsafe extern "C" fn cb_read_input(data: *mut u8, len: u64, ctxt: *mut c_void) -> i64 {
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

unsafe extern "C" fn cb_write_input(data: *mut u8, len: u64, ctxt: *mut c_void) -> u64 {
    let callbacks = ctxt as *mut DownloadInstanceInputOutputCallbacks;
    if let Some(func) = &mut (*callbacks).write {
        let slice = slice::from_raw_parts(data, len as usize);
        let result = (func)(slice);
        result as u64
    } else {
        0
    }
}

unsafe extern "C" fn cb_progress_input(ctxt: *mut c_void, progress: usize, total: usize) -> bool {
    let callbacks = ctxt as *mut DownloadInstanceInputOutputCallbacks;
    if let Some(func) = &mut (*callbacks).progress {
        (func)(progress, total)
    } else {
        true
    }
}

unsafe extern "C" fn cb_write_output(data: *mut u8, len: u64, ctxt: *mut c_void) -> u64 {
    let callbacks = ctxt as *mut DownloadInstanceOutputCallbacks;
    if let Some(func) = &mut (*callbacks).write {
        let slice = slice::from_raw_parts(data, len as usize);
        let result = (func)(slice);
        result as u64
    } else {
        0u64
    }
}

unsafe extern "C" fn cb_progress_output(ctxt: *mut c_void, progress: usize, total: usize) -> bool {
    let callbacks = ctxt as *mut DownloadInstanceOutputCallbacks;
    if let Some(func) = &mut (*callbacks).progress {
        (func)(progress, total)
    } else {
        true
    }
}

pub unsafe extern "C" fn cb_destroy_instance<C: CustomDownloadInstance>(ctxt: *mut c_void) {
    let _ = Box::from_raw(ctxt as *mut C);
}

pub unsafe extern "C" fn cb_perform_request<C: CustomDownloadInstance>(
    ctxt: *mut c_void,
    url: *const c_char,
) -> i32 {
    let c = ManuallyDrop::new(Box::from_raw(ctxt as *mut C));

    let url = match CStr::from_ptr(url).to_str() {
        Ok(url) => url,
        Err(e) => {
            c.handle().set_error(&format!("Invalid URL: {}", e));
            return -1;
        }
    };

    match c.perform_request(url) {
        Ok(()) => 0,
        Err(e) => {
            c.handle().set_error(&e);
            -1
        }
    }
}

pub unsafe extern "C" fn cb_perform_custom_request<C: CustomDownloadInstance>(
    ctxt: *mut c_void,
    method: *const c_char,
    url: *const c_char,
    header_count: u64,
    header_keys: *const *const c_char,
    header_values: *const *const c_char,
    response: *mut *mut BNDownloadInstanceResponse,
) -> i32 {
    let c = ManuallyDrop::new(Box::from_raw(ctxt as *mut C));

    let method = match CStr::from_ptr(method).to_str() {
        Ok(method) => method,
        Err(e) => {
            c.handle().set_error(&format!("Invalid Method: {}", e));
            return -1;
        }
    };

    let url = match CStr::from_ptr(url).to_str() {
        Ok(url) => url,
        Err(e) => {
            c.handle().set_error(&format!("Invalid URL: {}", e));
            return -1;
        }
    };

    // SAFETY BnString and *mut c_char are transparent
    let header_count = usize::try_from(header_count).unwrap();
    let header_keys = slice::from_raw_parts(header_keys as *const BnString, header_count);
    let header_values = slice::from_raw_parts(header_values as *const BnString, header_count);
    let header_keys_str = header_keys.iter().map(|s| s.to_string_lossy().to_string());
    let header_values_str = header_values
        .iter()
        .map(|s| s.to_string_lossy().to_string());
    let headers = header_keys_str.zip(header_values_str);

    match c.perform_custom_request(method, url, headers) {
        Ok(res) => {
            let res_header_keys_ptr = strings_to_string_list(res.headers.keys());
            let res_header_values_ptr = strings_to_string_list(res.headers.values());
            let raw_response = BNDownloadInstanceResponse {
                statusCode: res.status_code,
                headerCount: res.headers.len() as u64,
                headerKeys: res_header_keys_ptr,
                headerValues: res_header_values_ptr,
            };
            // Leak the response and free it with cb_free_response
            unsafe { *response = Box::leak(Box::new(raw_response)) };
            0
        }
        Err(e) => {
            c.handle().set_error(&e);
            -1
        }
    }
}

unsafe extern "C" fn cb_free_response(
    _ctxt: *mut c_void,
    response: *mut BNDownloadInstanceResponse,
) {
    let _ = Box::from_raw(response);
}
