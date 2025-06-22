// Copyright 2021-2025 Vector 35 Inc.
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

use binaryninjacore_sys::*;
use std::borrow::Cow;
use std::ffi::{c_char, CStr, CString};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use crate::rc::*;
use crate::type_archive::TypeArchiveSnapshotId;
use crate::types::QualifiedName;

// TODO: Remove or refactor this.
pub(crate) fn raw_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() })
    }
}

pub fn strings_to_string_list<I, S>(strings: I) -> *mut *mut c_char
where
    I: IntoIterator<Item = S>,
    // TODO make `S: BnStrCompatible,`
    S: AsRef<str>,
{
    use binaryninjacore_sys::BNAllocStringList;
    let bn_str_list = strings
        .into_iter()
        .map(|s| BnString::new(s.as_ref()))
        .collect::<Vec<_>>();
    let mut raw_str_list = bn_str_list.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
    unsafe { BNAllocStringList(raw_str_list.as_mut_ptr(), raw_str_list.len()) }
}

/// A nul-terminated C string allocated by the core.
///
/// Received from a variety of core function calls, and must be used when giving strings to the
/// core from many core-invoked callbacks, or otherwise passing ownership of the string to the core.
///
/// These are strings we're responsible for freeing, such as strings allocated by the core and
/// given to us through the API and then forgotten about by the core.
///
/// When passing to the core, make sure to use [`BnString::to_cstr`] and [`CStr::as_ptr`].
///
/// When giving ownership to the core, make sure to prevent dropping by calling [`BnString::into_raw`].
#[repr(transparent)]
pub struct BnString {
    raw: *mut c_char,
}

impl BnString {
    pub fn new(s: impl IntoCStr) -> Self {
        let raw = s.to_cstr();
        unsafe { Self::from_raw(BNAllocString(raw.as_ptr())) }
    }

    /// Take an owned core string and convert it to [`String`].
    ///
    /// This expects the passed raw string to be owned, as in, freed by us.
    pub unsafe fn into_string(raw: *mut c_char) -> String {
        Self::from_raw(raw).to_string_lossy().to_string()
    }

    /// Construct a BnString from an owned const char* allocated by [`BNAllocString`].
    pub(crate) unsafe fn from_raw(raw: *mut c_char) -> Self {
        Self { raw }
    }

    /// Free a raw string allocated by [`BNAllocString`].
    pub unsafe fn free_raw(raw: *mut c_char) {
        if !raw.is_null() {
            BNFreeString(raw);
        }
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
}

impl Drop for BnString {
    fn drop(&mut self) {
        unsafe { BnString::free_raw(self.raw) };
    }
}

impl Clone for BnString {
    fn clone(&self) -> Self {
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

impl From<String> for BnString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for BnString {
    fn from(s: &str) -> Self {
        Self::new(s)
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

impl fmt::Debug for BnString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string_lossy().fmt(f)
    }
}

impl CoreArrayProvider for BnString {
    type Raw = *mut c_char;
    type Context = ();
    type Wrapped<'a> = &'a str;
}

unsafe impl CoreArrayProviderInner for BnString {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeStringList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        CStr::from_ptr(*raw).to_str().unwrap()
    }
}

pub trait IntoCStr {
    type Result: Deref<Target = CStr>;

    fn to_cstr(self) -> Self::Result;
}

impl IntoCStr for &CStr {
    type Result = Self;

    fn to_cstr(self) -> Self::Result {
        self
    }
}

impl IntoCStr for BnString {
    type Result = Self;

    fn to_cstr(self) -> Self::Result {
        self
    }
}

impl IntoCStr for &BnString {
    type Result = BnString;

    fn to_cstr(self) -> Self::Result {
        self.clone()
    }
}

impl IntoCStr for CString {
    type Result = Self;

    fn to_cstr(self) -> Self::Result {
        self
    }
}

impl IntoCStr for &str {
    type Result = CString;

    fn to_cstr(self) -> Self::Result {
        CString::new(self).expect("can't pass strings with internal nul bytes to core!")
    }
}

impl IntoCStr for String {
    type Result = CString;

    fn to_cstr(self) -> Self::Result {
        CString::new(self).expect("can't pass strings with internal nul bytes to core!")
    }
}

impl IntoCStr for &String {
    type Result = CString;

    fn to_cstr(self) -> Self::Result {
        self.clone().to_cstr()
    }
}

impl<'a> IntoCStr for &'a Cow<'a, str> {
    type Result = CString;

    fn to_cstr(self) -> Self::Result {
        self.to_string().to_cstr()
    }
}

impl IntoCStr for Cow<'_, str> {
    type Result = CString;

    fn to_cstr(self) -> Self::Result {
        self.to_string().to_cstr()
    }
}

impl IntoCStr for &QualifiedName {
    type Result = CString;

    fn to_cstr(self) -> Self::Result {
        self.to_string().to_cstr()
    }
}

impl IntoCStr for PathBuf {
    type Result = CString;

    fn to_cstr(self) -> Self::Result {
        self.as_path().to_cstr()
    }
}

impl IntoCStr for &Path {
    type Result = CString;

    fn to_cstr(self) -> Self::Result {
        CString::new(self.as_os_str().as_encoded_bytes())
            .expect("can't pass paths with internal nul bytes to core!")
    }
}

impl IntoCStr for TypeArchiveSnapshotId {
    type Result = CString;

    fn to_cstr(self) -> Self::Result {
        self.to_string().to_cstr()
    }
}

pub trait IntoJson {
    type Output: IntoCStr;

    fn get_json_string(self) -> Result<Self::Output, ()>;
}

impl<S: IntoCStr> IntoJson for S {
    type Output = S;

    fn get_json_string(self) -> Result<Self::Output, ()> {
        Ok(self)
    }
}
