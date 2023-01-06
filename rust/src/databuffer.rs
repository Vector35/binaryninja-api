// Copyright 2021-2023 Vector 35 Inc.
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

use std::ptr;
use std::slice;

pub struct DataBuffer(*mut BNDataBuffer);

impl DataBuffer {
    pub(crate) fn from_raw(raw: *mut BNDataBuffer) -> Self {
        DataBuffer(raw)
    }

    pub fn get_data(&self) -> &[u8] {
        if self.0 == ptr::null_mut() {
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

    pub fn len(&self) -> usize {
        unsafe { BNGetDataBufferLength(self.0) }
    }

    // pub fn new(data: ?, len: usize) -> Result<Self> {
    //   let read_buffer = unsafe { BNCreateDataBuffer(data, len) };
    //   if read_buffer.is_null() {
    //     Err(())
    //   } else {
    //     Ok(DataBuffer::from_raw(read_buffer))
    //   }
    // }
}

// TODO : delete this
impl Default for DataBuffer {
    fn default() -> Self {
        DataBuffer::from_raw(ptr::null_mut())
    }
}

impl Drop for DataBuffer {
    fn drop(&mut self) {
        if self.0 != ptr::null_mut() {
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
