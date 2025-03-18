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

//! A convenience class for reading binary data

use binaryninjacore_sys::*;
use std::fmt::Debug;

use crate::binary_view::{BinaryView, BinaryViewBase};
use crate::Endianness;

use crate::rc::Ref;
use std::io::{ErrorKind, Read, Seek, SeekFrom};

pub struct BinaryReader {
    view: Ref<BinaryView>,
    handle: *mut BNBinaryReader,
}

impl BinaryReader {
    pub fn new(view: &BinaryView) -> Self {
        let handle = unsafe { BNCreateBinaryReader(view.handle) };
        Self {
            view: view.to_owned(),
            handle,
        }
    }

    pub fn new_with_opts(view: &BinaryView, options: &BinaryReaderOptions) -> Self {
        let mut reader = Self::new(view);
        if let Some(endianness) = options.endianness {
            reader.set_endianness(endianness);
        }
        // Set the virtual base before we seek.
        if let Some(virtual_base) = options.virtual_base {
            reader.set_virtual_base(virtual_base);
        }
        if let Some(address) = options.address {
            reader.seek_to_offset(address);
        }
        reader
    }

    pub fn endianness(&self) -> Endianness {
        unsafe { BNGetBinaryReaderEndianness(self.handle) }
    }

    pub fn set_endianness(&mut self, endianness: Endianness) {
        unsafe { BNSetBinaryReaderEndianness(self.handle, endianness) }
    }

    pub fn virtual_base(&self) -> u64 {
        unsafe { BNGetBinaryReaderVirtualBase(self.handle) }
    }

    pub fn set_virtual_base(&mut self, virtual_base_addr: u64) {
        unsafe { BNSetBinaryReaderVirtualBase(self.handle, virtual_base_addr) }
    }

    /// Prefer using [crate::binary_reader::BinaryReader::seek] over this.
    pub fn seek_to_offset(&mut self, offset: u64) {
        unsafe { BNSeekBinaryReader(self.handle, offset) }
    }

    /// Prefer using [crate::binary_reader::BinaryReader::seek] over this.
    pub fn seek_to_relative_offset(&mut self, offset: i64) {
        unsafe { BNSeekBinaryReaderRelative(self.handle, offset) }
    }

    pub fn offset(&self) -> u64 {
        unsafe { BNGetReaderPosition(self.handle) }
    }

    /// Are we at the end of the file?
    pub fn is_eof(&self) -> bool {
        unsafe { BNIsEndOfFile(self.handle) }
    }
}

impl Debug for BinaryReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryReader")
            .field("offset", &self.offset())
            .field("virtual_base", &self.virtual_base())
            .field("endianness", &self.endianness())
            .finish()
    }
}

impl Seek for BinaryReader {
    /// Seek to the specified position.
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Current(offset) => self.seek_to_relative_offset(offset),
            SeekFrom::Start(offset) => self.seek_to_offset(offset),
            SeekFrom::End(end_offset) => {
                // We do NOT need to add the image base here as
                // the reader (unlike the writer) can set the virtual base.
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

impl Read for BinaryReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len();

        let result = unsafe { BNReadData(self.handle, buf.as_mut_ptr() as *mut _, len) };

        if !result {
            Err(std::io::Error::new(ErrorKind::Other, "Read out of bounds"))
        } else {
            Ok(len)
        }
    }
}

impl Drop for BinaryReader {
    fn drop(&mut self) {
        unsafe { BNFreeBinaryReader(self.handle) }
    }
}

unsafe impl Sync for BinaryReader {}
unsafe impl Send for BinaryReader {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BinaryReaderOptions {
    endianness: Option<Endianness>,
    virtual_base: Option<u64>,
    address: Option<u64>,
}

impl BinaryReaderOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_endianness(mut self, endian: Endianness) -> Self {
        self.endianness = Some(endian);
        self
    }

    pub fn with_virtual_base(mut self, virtual_base_addr: u64) -> Self {
        self.virtual_base = Some(virtual_base_addr);
        self
    }

    pub fn with_address(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }
}
