// Copyright 2021-2022 Vector 35 Inc.
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

use std::borrow::{Borrow, Cow};
use std::ffi::{CStr, CString};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem;
use std::ops::Deref;
use std::os::raw;

use crate::rc::*;
use crate::types::QualifiedName;

pub(crate) fn raw_to_string(ptr: *const raw::c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() })
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(C)]
pub struct BnStr {
    raw: [u8],
}

impl BnStr {
    pub(crate) unsafe fn from_raw<'a>(ptr: *const raw::c_char) -> &'a Self {
        mem::transmute(CStr::from_ptr(ptr).to_bytes_with_nul())
    }

    pub fn as_str(&self) -> &str {
        self.as_cstr().to_str().unwrap()
    }

    pub fn as_cstr(&self) -> &CStr {
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.raw) }
    }
}

impl Deref for BnStr {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for BnStr {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl AsRef<str> for BnStr {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for BnStr {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for BnStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_cstr().to_string_lossy())
    }
}

#[repr(C)]
pub struct BnString {
    raw: *mut raw::c_char,
}

/// A nul-terminated C string allocated by the core.
///
/// Received from a variety of core function calls, and
/// must be used when giving strings to the core from many
/// core-invoked callbacks.
impl BnString {
    pub fn new<S: BnStrCompatible>(s: S) -> Self {
        use binaryninjacore_sys::BNAllocString;

        let raw = s.into_bytes_with_nul();

        unsafe {
            let ptr = raw.as_ref().as_ptr() as *mut _;

            Self {
                raw: BNAllocString(ptr),
            }
        }
    }

    /// Construct a BnString from an owned const char* allocated by BNAllocString
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

    pub fn as_str(&self) -> &str {
        unsafe { BnStr::from_raw(self.raw).as_str() }
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
    type Target = BnStr;

    fn deref(&self) -> &BnStr {
        unsafe { BnStr::from_raw(self.raw) }
    }
}

impl AsRef<[u8]> for BnString {
    fn as_ref(&self) -> &[u8] {
        self.as_cstr().to_bytes_with_nul()
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
        write!(f, "{}", self.as_cstr().to_string_lossy())
    }
}

impl fmt::Debug for BnString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_cstr().to_string_lossy())
    }
}

impl CoreArrayProvider for BnString {
    type Raw = *mut raw::c_char;
    type Context = ();
}

unsafe impl CoreOwnedArrayProvider for BnString {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        use binaryninjacore_sys::BNFreeStringList;
        BNFreeStringList(raw, count);
    }
}

unsafe impl<'a> CoreArrayWrapper<'a> for BnString {
    type Wrapped = &'a BnStr;

    unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
        BnStr::from_raw(*raw)
    }
}

pub unsafe trait BnStrCompatible {
    type Result: AsRef<[u8]>;
    fn into_bytes_with_nul(self) -> Self::Result;
}

unsafe impl<'a> BnStrCompatible for &'a BnStr {
    type Result = &'a [u8];

    fn into_bytes_with_nul(self) -> Self::Result {
        self.as_cstr().to_bytes_with_nul()
    }
}

unsafe impl BnStrCompatible for BnString {
    type Result = Self;

    fn into_bytes_with_nul(self) -> Self::Result {
        self
    }
}

unsafe impl<'a> BnStrCompatible for &'a CStr {
    type Result = &'a [u8];

    fn into_bytes_with_nul(self) -> Self::Result {
        self.to_bytes_with_nul()
    }
}

unsafe impl BnStrCompatible for CString {
    type Result = Vec<u8>;

    fn into_bytes_with_nul(self) -> Self::Result {
        self.into_bytes_with_nul()
    }
}

unsafe impl<'a> BnStrCompatible for &'a str {
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

unsafe impl<'a> BnStrCompatible for &'a String {
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

unsafe impl BnStrCompatible for &QualifiedName {
    type Result = Vec<u8>;

    fn into_bytes_with_nul(self) -> Self::Result {
        self.string().into_bytes_with_nul()
    }
}
