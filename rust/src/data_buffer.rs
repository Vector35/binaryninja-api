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

//! A basic wrapper around an array of binary data

use binaryninjacore_sys::*;

use std::ffi::c_void;
use std::slice;

use crate::string::BnString;

pub struct DataBuffer(*mut BNDataBuffer);

impl DataBuffer {
    pub(crate) fn from_raw(raw: *mut BNDataBuffer) -> Self {
        DataBuffer(raw)
    }

    pub(crate) fn as_raw(&self) -> *mut BNDataBuffer {
        self.0
    }

    pub fn get_data(&self) -> &[u8] {
        let buffer = unsafe { BNGetDataBufferContents(self.0) };
        if buffer.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(buffer as *const _, self.len()) }
        }
    }

    pub fn get_data_at(&self, offset: usize) -> &[u8] {
        let len = self.len();
        if offset > len {
            panic!();
        }
        let slice_len = len - offset;
        let buffer = unsafe { BNGetDataBufferContentsAt(self.0, offset) };
        if buffer.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(buffer as *const _, slice_len) }
        }
    }

    /// Create a copy of a especified part of the data
    pub fn get_slice(&self, start: usize, len: usize) -> Option<Self> {
        if start + len > self.len() {
            return None;
        }
        let ptr = unsafe { BNGetDataBufferSlice(self.0, start, len) };
        (!ptr.is_null()).then(|| Self(ptr))
    }

    /// change the size of the allocated data, if new size is bigger data is
    /// need to be initialized
    pub unsafe fn set_len(&mut self, len: usize) {
        unsafe { BNSetDataBufferLength(self.0, len) }
    }

    /// set the size to 0
    pub fn clear(&self) {
        unsafe { BNClearDataBuffer(self.0) }
    }

    /// Copy the contents of `src` into `dst`
    pub fn assign(dst: &mut Self, src: &Self) {
        unsafe { BNAssignDataBuffer(dst.0, src.0) }
    }

    /// Concat the contents of `src` into `dst`
    pub fn append(dst: &mut Self, src: &Self) {
        unsafe { BNAppendDataBuffer(dst.0, src.0) }
    }

    /// concat the contents of `data` into self
    pub fn append_data(&self, data: &[u8]) {
        unsafe { BNAppendDataBufferContents(self.0, data.as_ptr() as *const c_void, data.len()) }
    }

    /// Return the byte at `offset`
    pub unsafe fn byte_at(&self, offset: usize) -> u8 {
        unsafe { BNGetDataBufferByte(self.0, offset) }
    }

    /// Set the value of the byte at `offset`
    pub unsafe fn set_byte_at(&mut self, offset: usize, byte: u8) {
        unsafe { BNSetDataBufferByte(self.0, offset, byte) }
    }

    pub fn set_data(&mut self, data: &[u8]) {
        unsafe {
            BNSetDataBufferContents(
                self.0,
                data.as_ptr() as *const c_void as *mut c_void,
                data.len(),
            );
        }
    }

    pub fn to_escaped_string(&self, null_terminates: bool, escape_printable: bool) -> BnString {
        unsafe {
            BnString::from_raw(BNDataBufferToEscapedString(
                self.0,
                null_terminates,
                escape_printable,
            ))
        }
    }

    pub fn from_escaped_string(value: &BnString) -> Self {
        Self(unsafe { BNDecodeEscapedString(value.as_ptr()) })
    }

    pub fn to_base64(&self) -> BnString {
        unsafe { BnString::from_raw(BNDataBufferToBase64(self.0)) }
    }

    pub fn from_base64(value: &BnString) -> Self {
        Self(unsafe { BNDecodeBase64(value.as_ptr()) })
    }

    pub fn zlib_compress(&self) -> Self {
        Self(unsafe { BNZlibCompress(self.0) })
    }

    pub fn zlib_decompress(&self) -> Self {
        Self(unsafe { BNZlibDecompress(self.0) })
    }

    pub fn lzma_decompress(&self) -> Self {
        Self(unsafe { BNLzmaDecompress(self.0) })
    }

    pub fn lzma2_decompress(&self) -> Self {
        Self(unsafe { BNLzma2Decompress(self.0) })
    }

    pub fn xz_decompress(&self) -> Self {
        Self(unsafe { BNXzDecompress(self.0) })
    }

    pub fn len(&self) -> usize {
        unsafe { BNGetDataBufferLength(self.0) }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn new(data: &[u8]) -> Result<Self, ()> {
        let buffer = unsafe { BNCreateDataBuffer(data.as_ptr() as *const c_void, data.len()) };
        if buffer.is_null() {
            Err(())
        } else {
            Ok(DataBuffer::from_raw(buffer))
        }
    }
}

impl Default for DataBuffer {
    fn default() -> Self {
        Self(unsafe { BNCreateDataBuffer([].as_ptr(), 0) })
    }
}

impl Drop for DataBuffer {
    fn drop(&mut self) {
        unsafe {
            BNFreeDataBuffer(self.0);
        }
    }
}

impl Clone for DataBuffer {
    fn clone(&self) -> Self {
        Self::from_raw(unsafe { BNDuplicateDataBuffer(self.0) })
    }
}

impl TryFrom<&[u8]> for DataBuffer {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        DataBuffer::new(value)
    }
}

impl AsRef<[u8]> for DataBuffer {
    fn as_ref(&self) -> &[u8] {
        self.get_data()
    }
}

impl std::borrow::Borrow<[u8]> for DataBuffer {
    fn borrow(&self) -> &[u8] {
        self.as_ref()
    }
}

macro_rules! data_buffer_index {
    ($range:ty, $output:ty) => {
        impl std::ops::Index<$range> for DataBuffer {
            type Output = $output;

            fn index(&self, index: $range) -> &Self::Output {
                &self.get_data()[index]
            }
        }
    };
}

data_buffer_index!(usize, u8);
data_buffer_index!(std::ops::Range<usize>, [u8]);
data_buffer_index!(std::ops::RangeInclusive<usize>, [u8]);
data_buffer_index!(std::ops::RangeTo<usize>, [u8]);
data_buffer_index!(std::ops::RangeFull, [u8]);

impl PartialEq for DataBuffer {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}
impl Eq for DataBuffer {}

impl PartialOrd for DataBuffer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.as_ref().cmp(other.as_ref()))
    }
}

impl Ord for DataBuffer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}
