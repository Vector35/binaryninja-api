// Copyright 2022 Vector 35 Inc.
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

//! A convenience class for writing binary data

use binaryninjacore_sys::*;

use crate::binaryview::BinaryView;
use crate::Endianness;

use std::io::{Seek, SeekFrom, Write};

pub struct BinaryWriter {
    handle: *mut BNBinaryWriter,
}

impl BinaryWriter {
    pub fn new(view: &BinaryView, endian: Endianness) -> Self {
        let handle = unsafe { BNCreateBinaryWriter(view.handle) };
        unsafe {
            BNSetBinaryWriterEndianness(handle, endian);
        }
        Self { handle }
    }

    pub fn endian(&self) -> Endianness {
        unsafe { BNGetBinaryWriterEndianness(self.handle) }
    }

    pub fn set_endian(&self, endian: Endianness) {
        unsafe { BNSetBinaryWriterEndianness(self.handle, endian) }
    }

    pub fn offset(&self) -> u64 {
        unsafe { BNGetWriterPosition(self.handle) }
    }
}

impl Seek for BinaryWriter {
    /// Seek to the specified position.
    ///
    /// # Errors
    /// Seeking relative to [SeekFrom::End] is unsupported and will return an error.
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        unsafe {
            match pos {
                SeekFrom::Current(offset) => BNSeekBinaryWriterRelative(self.handle, offset),
                SeekFrom::Start(offset) => BNSeekBinaryWriter(self.handle, offset),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "Cannot seek end of BinaryWriter",
                    ))
                }
            };
        }

        Ok(self.offset())
    }
}

impl Write for BinaryWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = buf.len();
        let result = unsafe { BNWriteData(self.handle, buf.as_ptr() as *mut _, len) };
        if !result {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "write out of bounds",
            ))
        } else {
            Ok(len)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for BinaryWriter {
    fn drop(&mut self) {
        unsafe { BNFreeBinaryWriter(self.handle) }
    }
}

unsafe impl Sync for BinaryWriter {}
unsafe impl Send for BinaryWriter {}
