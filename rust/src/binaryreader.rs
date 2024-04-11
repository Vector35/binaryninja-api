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

use crate::binaryview::BinaryView;
use crate::Endianness;

use std::io::{Read, Seek, SeekFrom};

use paste::paste;

pub struct BinaryReader {
    handle: *mut BNBinaryReader,
}

impl BinaryReader {
    pub fn new(view: &BinaryView, endian: Endianness) -> Self {
        let handle = unsafe { BNCreateBinaryReader(view.handle) };
        unsafe {
            BNSetBinaryReaderEndianness(handle, endian);
        }
        Self { handle }
    }

    pub fn endian(&self) -> Endianness {
        unsafe { BNGetBinaryReaderEndianness(self.handle) }
    }

    pub fn set_endian(&self, endian: Endianness) {
        unsafe { BNSetBinaryReaderEndianness(self.handle, endian) }
    }

    pub fn offset(&self) -> u64 {
        unsafe { BNGetReaderPosition(self.handle) }
    }

    pub fn eof(&self) -> bool {
        unsafe { BNIsEndOfFile(self.handle) }
    }
}

macro_rules! read_int_function {
    ($utype:ty, $itype:ty $(,)?) => {
        paste! {
            pub fn [<read_ $utype>](&mut self) -> std::io::Result<$utype> {
                let mut value = [0u8; (<$utype>::BITS / 8) as usize];
                self.read_exact(&mut value)?;
                match self.endian() {
                    Endianness::BigEndian => Ok(<$utype>::from_be_bytes(value)),
                    Endianness::LittleEndian => Ok(<$utype>::from_le_bytes(value)),
                }
            }
            pub fn [<read_ $utype _be>](&mut self) -> std::io::Result<$utype> {
                let mut value = [0u8; (<$utype>::BITS / 8) as usize];
                self.read_exact(&mut value)?;
                Ok(<$utype>::from_be_bytes(value))
            }
            pub fn [<read_ $utype _le>](&mut self) -> std::io::Result<$utype> {
                let mut value = [0u8; (<$utype>::BITS / 8) as usize];
                self.read_exact(&mut value)?;
                Ok(<$utype>::from_le_bytes(value))
            }
            pub fn [<read_ $itype>](&mut self) -> std::io::Result<$itype> {
                self.[<read_ $utype>]().map(|x| x as $itype)
            }
            pub fn [<read_ $itype _be>](&mut self) -> std::io::Result<$itype> {
                self.[<read_ $utype _be>]().map(|x| x as $itype)
            }
            pub fn [<read_ $itype _le>](&mut self) -> std::io::Result<$itype> {
                self.[<read_ $utype _le>]().map(|x| x as $itype)
            }
        }
    };
}

impl BinaryReader {
    read_int_function!(u8, i8);
    read_int_function!(u16, i16);
    read_int_function!(u32, i32);
    read_int_function!(u64, i64);
    read_int_function!(u128, i128);
}

impl Seek for BinaryReader {
    /// Seek to the specified position.
    ///
    /// # Errors
    /// Seeking relative to [SeekFrom::End] is unsupported and will return an error.
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        unsafe {
            match pos {
                SeekFrom::Current(offset) => BNSeekBinaryReaderRelative(self.handle, offset),
                SeekFrom::Start(offset) => BNSeekBinaryReader(self.handle, offset),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "Cannot seek end of BinaryReader",
                    ))
                }
            };
        }

        Ok(self.offset())
    }
}

impl Read for BinaryReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len();

        let result = unsafe { BNReadData(self.handle, buf.as_mut_ptr() as *mut _, len) };

        if !result {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Read out of bounds",
            ))
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
