// Copyright 2022-2024 Vector 35 Inc.
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
use std::fmt::Debug;

use crate::binary_view::{BinaryView, BinaryViewBase};
use crate::Endianness;

use crate::rc::Ref;
use std::io::{ErrorKind, Seek, SeekFrom, Write};

pub struct BinaryWriter {
    view: Ref<BinaryView>,
    handle: *mut BNBinaryWriter,
}

impl BinaryWriter {
    pub fn new(view: &BinaryView) -> Self {
        let handle = unsafe { BNCreateBinaryWriter(view.handle) };
        Self {
            view: view.to_owned(),
            handle,
        }
    }

    pub fn new_with_opts(view: &BinaryView, options: &BinaryWriterOptions) -> Self {
        let mut writer = Self::new(view);
        if let Some(endianness) = options.endianness {
            writer.set_endianness(endianness);
        }
        if let Some(address) = options.address {
            writer.seek_to_offset(address);
        }
        writer
    }

    pub fn endianness(&self) -> Endianness {
        unsafe { BNGetBinaryWriterEndianness(self.handle) }
    }

    pub fn set_endianness(&mut self, endianness: Endianness) {
        unsafe { BNSetBinaryWriterEndianness(self.handle, endianness) }
    }

    pub fn seek_to_offset(&mut self, offset: u64) {
        unsafe { BNSeekBinaryWriter(self.handle, offset) }
    }

    pub fn seek_to_relative_offset(&mut self, offset: i64) {
        unsafe { BNSeekBinaryWriterRelative(self.handle, offset) }
    }

    pub fn offset(&self) -> u64 {
        unsafe { BNGetWriterPosition(self.handle) }
    }
}

impl Debug for BinaryWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryWriter")
            .field("offset", &self.offset())
            .field("endianness", &self.endianness())
            .finish()
    }
}

impl Seek for BinaryWriter {
    /// Seek to the specified position.
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Current(offset) => self.seek_to_relative_offset(offset),
            SeekFrom::Start(offset) => self.seek_to_offset(offset),
            SeekFrom::End(end_offset) => {
                let offset =
                    self.view
                        .len()
                        .checked_add_signed(end_offset)
                        .ok_or(std::io::Error::new(
                            ErrorKind::Other,
                            "Seeking from end overflowed",
                        ))?;
                self.seek_to_offset(offset);
            }
        };

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BinaryWriterOptions {
    endianness: Option<Endianness>,
    address: Option<u64>,
}

impl BinaryWriterOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_endianness(mut self, endian: Endianness) -> Self {
        self.endianness = Some(endian);
        self
    }

    pub fn with_address(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }
}
