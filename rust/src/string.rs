// Copyright 2021-2024 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! String wrappers for core-owned strings and strings being passed to the core

use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem;
use std::os::raw;

use crate::rc::*;

pub(crate) fn raw_to_string(ptr: *const raw::c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() })
    }
}

/// A nul-terminated C string allocated by the core.
///
/// Received from a variety of core function calls, and must be used when giving strings to the
/// core from many core-invoked callbacks.
///
/// These are strings we're responsible for freeing, such as strings allocated by the core and
/// given to us through the API and then forgotten about by the core.
#[repr(transparent)]
pub struct BnString {
    raw: *mut raw::c_char,
}

impl BnString {
    pub fn new(s: impl AsCStr) -> Self {
        use binaryninjacore_sys::BNAllocString;
        let raw = s.as_cstr();

        unsafe {
            Self {
                raw: BNAllocString(raw.as_ptr()),
            }
        }
    }

    /// Construct a [BnString] from an owned `const char*` allocated by `BNAllocString`.
    pub(crate) unsafe fn from_raw(raw: *mut raw::c_char) -> Self {
        Self { raw }
    }

    pub(crate) fn into_raw(self) -> *mut raw::c_char {
        let res = self.raw;

        // we're surrendering ownership over the *mut c_char to
        // the core, so ensure we don't free it
        mem::forget(self);

        res
    }

    pub(crate) fn as_raw(&self) -> &raw::c_char {
        unsafe { &*self.raw }
    }

    pub fn as_c_str(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.raw) }
    }

    pub fn as_str(&self) -> &str {
        self.as_c_str().to_str().unwrap()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_c_str().to_bytes()
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }
}

impl Drop for BnString {
    fn drop(&mut self) {
        use binaryninjacore_sys::BNFreeString;

        unsafe {
            BNFreeString(self.raw);
        }
    }
}

impl Clone for BnString {
    fn clone(&self) -> Self {
        use binaryninjacore_sys::BNAllocString;
        unsafe {
            Self {
                raw: BNAllocString(self.raw),
            }
        }
    }
}

impl Hash for BnString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_cstr().hash(state)
    }
}

impl PartialEq for BnString {
    fn eq(&self, other: &Self) -> bool {
        self.as_cstr() == other.as_cstr()
    }
}

impl PartialEq<CStr> for BnString {
    fn eq(&self, other: &CStr) -> bool {
        &*self.as_cstr() == other
    }
}

impl PartialEq<str> for BnString {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl Eq for BnString {}

impl fmt::Display for BnString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_cstr().to_string_lossy())
    }
}

impl fmt::Debug for BnString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.as_cstr())
    }
}

impl CoreArrayProvider for BnString {
    type Raw = *mut raw::c_char;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for BnString {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        use binaryninjacore_sys::BNFreeStringList;
        BNFreeStringList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        debug_assert!(!raw.is_null());
        // SAFETY: `BnString` is repr(transparent)
        unsafe { &*(raw as *const _ as *const Self) }
    }
}

pub trait AsCStr {
    fn as_cstr(&self) -> Cow<'_, CStr>;
}

impl AsCStr for CStr {
    fn as_cstr(&self) -> Cow<'_, CStr> {
        self.into()
    }
}

impl AsCStr for CString {
    fn as_cstr(&self) -> Cow<'_, CStr> {
        self.into()
    }
}

impl AsCStr for BnString {
    fn as_cstr(&self) -> Cow<'_, CStr> {
        self.as_c_str().into()
    }
}

impl AsCStr for str {
    fn as_cstr(&self) -> Cow<'_, CStr> {
        CString::new(self)
            .expect("can't pass strings with internal nul bytes to core!")
            .into()
    }
}

impl AsCStr for String {
    fn as_cstr(&self) -> Cow<'_, CStr> {
        self.as_str().as_cstr()
    }
}

impl AsCStr for Cow<'_, str> {
    fn as_cstr(&self) -> Cow<'_, CStr> {
        self.as_ref().as_cstr()
    }
}

impl<T: AsCStr + ?Sized> AsCStr for &T {
    fn as_cstr(&self) -> Cow<'_, CStr> {
        (*self).as_cstr()
    }
}

pub trait IntoJson {
    type Output: AsCStr;

    fn get_json_string(self) -> Result<Self::Output, ()>;
}

impl<S: AsCStr> IntoJson for S {
    type Output = Self;

    fn get_json_string(self) -> Result<Self::Output, ()> {
        Ok(self)
    }
}
