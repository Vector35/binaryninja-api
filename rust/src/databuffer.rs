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
use std::ptr;
use std::slice;

pub struct DataBuffer(*mut BNDataBuffer);

impl DataBuffer {
    pub(crate) fn from_raw(raw: *mut BNDataBuffer) -> Self {
        DataBuffer(raw)
    }
    pub(crate) fn as_raw(&self) -> *mut BNDataBuffer {
        self.0
    }

    pub fn get_data(&self) -> &[u8] {
        if self.0.is_null() {
            // TODO : Change the default value and remove this
            return &[];
        }
        let buffer = unsafe { BNGetDataBufferContents(self.0) };
        if buffer.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(buffer as *const _, self.len()) }
        }
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

    pub fn len(&self) -> usize {
        unsafe { BNGetDataBufferLength(self.0) }
    }

    pub fn is_empty(&self) -> bool {
        unsafe { BNGetDataBufferLength(self.0) == 0 }
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

// TODO : delete this
impl Default for DataBuffer {
    fn default() -> Self {
        DataBuffer::from_raw(ptr::null_mut())
    }
}

impl Drop for DataBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BNFreeDataBuffer(self.0);
            }
        }
    }
}

impl Clone for DataBuffer {
    fn clone(&self) -> Self {
        Self::from_raw(unsafe { BNDuplicateDataBuffer(self.0) })
    }
}
