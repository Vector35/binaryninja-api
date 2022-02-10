use binaryninjacore_sys::*;

use crate::binaryview::BinaryView;
use crate::Endianness;

use std::io::{Read, Seek, SeekFrom};

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
