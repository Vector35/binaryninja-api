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

use crate::rc::*;
use crate::types::QualifiedName;
use std::borrow::Cow;
use std::ffi::{c_char, CStr, CString};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem;
use std::ops::Deref;
use std::path::{Path, PathBuf};

// TODO: Remove or refactor this.
pub(crate) fn raw_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() })
    }
}

// TODO: Make this pass in an iterator over something more generic...
pub(crate) fn strings_to_string_list(strings: &[String]) -> *mut *mut c_char {
    use binaryninjacore_sys::BNAllocStringList;
    let bn_str_list = strings
        .iter()
        .map(|s| BnString::new(s.as_str()))
        .collect::<Vec<_>>();
    let mut raw_str_list = bn_str_list.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
    unsafe { BNAllocStringList(raw_str_list.as_mut_ptr(), raw_str_list.len()) }
}

/// Is the equivalent of `core::ffi::CString` but using the alloc and free from `binaryninjacore-sys`.
#[repr(transparent)]
pub struct BnString {
    raw: *mut c_char,
}

/// A nul-terminated C string allocated by the core.
///
/// Received from a variety of core function calls, and
/// must be used when giving strings to the core from many
/// core-invoked callbacks.
///
/// These are strings we're responsible for freeing, such as
/// strings allocated by the core and given to us through the API
/// and then forgotten about by the core.
impl BnString {
    pub fn new<S: BnStrCompatible>(s: S) -> Self {
        use binaryninjacore_sys::BNAllocString;
        let raw = s.into_bytes_with_nul();
        unsafe {
            let ptr = raw.as_ref().as_ptr() as *mut _;
            Self::from_raw(BNAllocString(ptr))
        }
    }

    /// Construct a BnString from an owned const char* allocated by BNAllocString
    pub(crate) unsafe fn from_raw(raw: *mut c_char) -> Self {
        Self { raw }
    }

    /// Consumes the `BnString`, returning a raw pointer to the string.
    ///
    /// After calling this function, the caller is responsible for the
    /// memory previously managed by the `BnString`.
    ///
    /// This is typically used to pass a string back through the core where the core is expected to free.
    pub fn into_raw(value: Self) -> *mut c_char {
        let res = value.raw;
        // we're surrendering ownership over the *mut c_char to
        // the core, so ensure we don't free it
        mem::forget(value);
        res
    }

    pub fn as_str(&self) -> &str {
        unsafe { CStr::from_ptr(self.raw).to_str().unwrap() }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    pub fn as_bytes_with_null(&self) -> &[u8] {
        self.deref().to_bytes()
    }

    pub fn len(&self) -> usize {
        self.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
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

impl Deref for BnString {
    type Target = CStr;

    fn deref(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.raw) }
    }
}

impl AsRef<[u8]> for BnString {
    fn as_ref(&self) -> &[u8] {
        self.to_bytes_with_nul()
    }
}

impl Hash for BnString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state)
    }
}

impl PartialEq for BnString {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}

impl Eq for BnString {}

impl fmt::Display for BnString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

impl fmt::Debug for BnString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

impl CoreArrayProvider for BnString {
    type Raw = *mut c_char;
    type Context = ();
    type Wrapped<'a> = &'a str;
}

unsafe impl CoreArrayProviderInner for BnString {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        use binaryninjacore_sys::BNFreeStringList;
        BNFreeStringList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        CStr::from_ptr(*raw).to_str().unwrap()
    }
}

pub unsafe trait BnStrCompatible {
    type Result: AsRef<[u8]>;

    fn into_bytes_with_nul(self) -> Self::Result;
}

unsafe impl<'a> BnStrCompatible for &'a CStr {
    type Result = &'a [u8];

    fn into_bytes_with_nul(self) -> Self::Result {
        self.to_bytes_with_nul()
    }
}

unsafe impl BnStrCompatible for BnString {
    type Result = Self;

    fn into_bytes_with_nul(self) -> Self::Result {
        self
    }
}

unsafe impl BnStrCompatible for CString {
    type Result = Vec<u8>;

    fn into_bytes_with_nul(self) -> Self::Result {
        self.into_bytes_with_nul()
    }
}

unsafe impl BnStrCompatible for &str {
    type Result = Vec<u8>;

    fn into_bytes_with_nul(self) -> Self::Result {
        let ret = CString::new(self).expect("can't pass strings with internal nul bytes to core!");
        ret.into_bytes_with_nul()
    }
}

unsafe impl BnStrCompatible for String {
    type Result = Vec<u8>;

    fn into_bytes_with_nul(self) -> Self::Result {
        self.as_str().into_bytes_with_nul()
    }
}

unsafe impl BnStrCompatible for &String {
    type Result = Vec<u8>;

    fn into_bytes_with_nul(self) -> Self::Result {
        self.as_str().into_bytes_with_nul()
    }
}

unsafe impl<'a> BnStrCompatible for &'a Cow<'a, str> {
    type Result = Vec<u8>;

    fn into_bytes_with_nul(self) -> Self::Result {
        self.to_string().into_bytes_with_nul()
    }
}

unsafe impl BnStrCompatible for Cow<'_, str> {
    type Result = Vec<u8>;

    fn into_bytes_with_nul(self) -> Self::Result {
        self.to_string().into_bytes_with_nul()
    }
}

unsafe impl BnStrCompatible for &QualifiedName {
    type Result = Vec<u8>;

    fn into_bytes_with_nul(self) -> Self::Result {
        self.to_string().into_bytes_with_nul()
    }
}

unsafe impl BnStrCompatible for PathBuf {
    type Result = Vec<u8>;

    fn into_bytes_with_nul(self) -> Self::Result {
        self.as_path().into_bytes_with_nul()
    }
}

unsafe impl BnStrCompatible for &Path {
    type Result = Vec<u8>;

    fn into_bytes_with_nul(self) -> Self::Result {
        let ret = CString::new(self.as_os_str().as_encoded_bytes())
            .expect("can't pass paths with internal nul bytes to core!");
        ret.into_bytes_with_nul()
    }
}

pub trait IntoJson {
    type Output: BnStrCompatible;

    fn get_json_string(self) -> Result<Self::Output, ()>;
}

impl<S: BnStrCompatible> IntoJson for S {
    type Output = S;

    fn get_json_string(self) -> Result<Self::Output, ()> {
        Ok(self)
    }
}
