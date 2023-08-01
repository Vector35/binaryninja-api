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

use gimli::{Endianity, Error, Reader, ReaderOffsetId, RunTimeEndian, SectionId};

use binaryninja::binaryninjacore_sys::*;

use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    databuffer::DataBuffer,
    Endianness,
};

use std::borrow::Cow;
use std::convert::TryInto;
use std::ffi::CString;
use std::{fmt, str};

//////////////////////
// Dwarf Validation

pub fn is_non_dwo_dwarf(view: &BinaryView) -> bool {
    view.section_by_name(".debug_info").is_ok() || view.section_by_name("__debug_info").is_ok()
}

pub fn is_dwo_dwarf(view: &BinaryView) -> bool {
    view.section_by_name(".debug_info.dwo").is_ok()
}

pub fn is_raw_non_dwo_dwarf(view: &BinaryView) -> bool {
    if let Ok(raw_view) = view.raw_view() {
        raw_view.section_by_name(".debug_info").is_ok()
            || view.section_by_name("__debug_info").is_ok()
    } else {
        false
    }
}

pub fn is_raw_dwo_dwarf(view: &BinaryView) -> bool {
    if let Ok(raw_view) = view.raw_view() {
        raw_view.section_by_name(".debug_info.dwo").is_ok()
    } else {
        false
    }
}

pub fn is_valid(view: &BinaryView) -> bool {
    is_non_dwo_dwarf(view)
        || is_raw_non_dwo_dwarf(view)
        || is_dwo_dwarf(view)
        || is_raw_dwo_dwarf(view)
}

pub fn get_endian(view: &BinaryView) -> RunTimeEndian {
    match view.default_endianness() {
        Endianness::LittleEndian => RunTimeEndian::Little,
        Endianness::BigEndian => RunTimeEndian::Big,
    }
}

#[derive(Clone)]
pub struct DWARFReader<Endian: Endianity> {
    data: Vec<u8>,
    endian: Endian,
    data_offset: usize,
    section_offset: usize,
}

impl<Endian: Endianity> DWARFReader<Endian> {
    pub fn new(data: Vec<u8>, endian: Endian) -> Self {
        Self {
            data,
            endian,
            data_offset: 0,
            section_offset: 0,
        }
    }
}

impl<Endian: Endianity> fmt::Debug for DWARFReader<Endian> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data = if self.data.len() < 6 {
            self.data.clone()
        } else {
            let mut vec = vec![0; 6];
            vec.clone_from_slice(&self.data[0..6]);
            vec
        };
        f.debug_struct("DWARFReader")
            .field("data", &data)
            .field("endian", &self.endian)
            .field("data_offset", &self.data_offset)
            .field("section_offset", &self.section_offset)
            .finish()
    }
}

impl<Endian: Endianity> Reader for DWARFReader<Endian> {
    type Endian = Endian;
    type Offset = usize;

    fn endian(&self) -> Endian {
        self.endian
    }

    fn len(&self) -> usize {
        self.data.len() - self.data_offset
    }

    fn empty(&mut self) {
        self.data.clear();
        self.data_offset = 0;
    }

    fn truncate(&mut self, len: usize) -> Result<(), Error> {
        self.data.truncate(self.data_offset + len);
        Ok(())
    }

    fn offset_from(&self, base: &Self) -> usize {
        (self.section_offset + self.data_offset) - (base.section_offset + base.data_offset)
    }

    fn offset_id(&self) -> ReaderOffsetId {
        ReaderOffsetId(self.data_offset.try_into().unwrap())
    }

    fn lookup_offset_id(&self, id: ReaderOffsetId) -> Option<usize> {
        Some(id.0.try_into().unwrap())
    }

    fn find(&self, byte: u8) -> Result<usize, Error> {
        match self
            .data
            .iter()
            .skip(self.data_offset)
            .position(|&b| b == byte)
        {
            Some(value) => Ok(value),
            _ => Err(Error::UnexpectedEof(self.offset_id())),
        }
    }

    fn skip(&mut self, len: usize) -> Result<(), Error> {
        if self.data.len() < self.data_offset + len {
            Err(Error::UnexpectedEof(self.offset_id()))
        } else {
            self.data_offset += len;
            Ok(())
        }
    }

    fn split(&mut self, len: usize) -> Result<Self, Error> {
        if self.data.len() < self.data_offset + len {
            unreachable!();
            // Err(Error::UnexpectedEof(self.offset_id()))
        } else {
            self.data_offset += len;

            Ok(Self {
                data: self.data[(self.data_offset - len)..self.data_offset].to_vec(),
                endian: self.endian,
                data_offset: 0,
                section_offset: self.section_offset + self.data_offset - len,
            })
        }
    }

    fn to_slice(&self) -> Result<Cow<'_, [u8]>, Error> {
        Ok(self.data[self.data_offset..].into())
    }

    fn to_string(&self) -> Result<Cow<'_, str>, Error> {
        Ok(str::from_utf8(&self.data[self.data_offset..])
            .unwrap()
            .into())
    }

    fn to_string_lossy(&self) -> Result<Cow<'_, str>, Error> {
        Ok(str::from_utf8(&self.data[self.data_offset..])
            .unwrap()
            .into())
    }

    fn read_slice(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        if self.len() >= 4 {
            let mut vec = vec![0; 4];
            vec.clone_from_slice(&self.data[self.data_offset..self.data_offset + 4]);
        }

        if self.data.len() < self.data_offset + buf.len() {
            Err(Error::UnexpectedEof(self.offset_id()))
        } else {
            for b in buf {
                *b = self.data[self.data_offset];
                self.data_offset += 1;
            }

            Ok(())
        }
    }
}

pub fn create_section_reader<'a, Endian: 'a + Endianity>(
    view: &'a BinaryView,
    endian: Endian,
    dwo_file: bool,
) -> Box<dyn Fn(SectionId) -> Result<DWARFReader<Endian>, Error> + 'a> {
    Box::new(move |section_id: SectionId| {
        let section_name = if dwo_file && section_id.dwo_name().is_some() {
            section_id.dwo_name().unwrap()
        } else {
            section_id.name()
        };

        if let Ok(section) = view.section_by_name(section_name) {
            // TODO : This is kinda broke....should add rust wrappers for some of this
            if let Some(symbol) = view
                .symbols()
                .iter()
                .find(|symbol| symbol.full_name().as_str() == "__elf_section_headers")
            {
                if let Some(data_var) = view
                    .data_variables()
                    .iter()
                    .find(|var| var.address == symbol.address())
                {
                    // TODO : This should eventually be wrapped by some DataView sorta thingy thing, like how python does it
                    let data_type = data_var.type_with_confidence().contents;
                    let data = view.read_vec(data_var.address, data_type.width() as usize);
                    let element_type = data_type.element_type().unwrap().contents;

                    // TODO : broke af?
                    if let Some(current_section_header) = data
                        .chunks(element_type.width() as usize)
                        .find(|section_header| {
                            endian.read_u64(&section_header[24..32]) == section.start()
                        })
                    {
                        if (endian.read_u64(&current_section_header[8..16]) & 2048) != 0 {
                            // Get section, trim header, decompress, return
                            let offset = section.start() + 24; // TODO : Super broke AF
                            let len = section.len() - 24;

                            if let Ok(buffer) = view.read_buffer(offset, len) {
                                // Incredibly broke as fuck
                                use std::ptr;
                                let transform_name =
                                    CString::new("Zlib").unwrap().into_bytes_with_nul();
                                let transform = unsafe {
                                    BNGetTransformByName(transform_name.as_ptr() as *mut _)
                                };

                                // Omega broke
                                let raw_buf: *mut BNDataBuffer =
                                    unsafe { BNCreateDataBuffer(ptr::null_mut(), 0) };
                                if unsafe {
                                    BNDecode(
                                        transform,
                                        std::mem::transmute(buffer),
                                        raw_buf,
                                        ptr::null_mut(),
                                        0,
                                    )
                                } {
                                    let output_buffer: DataBuffer =
                                        unsafe { std::mem::transmute(raw_buf) };

                                    return Ok(DWARFReader::new(
                                        output_buffer.get_data().into(),
                                        endian,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            let offset = section.start();
            let len = section.len();
            if len == 0 {
                Ok(DWARFReader::new(vec![], endian))
            } else {
                Ok(DWARFReader::new(view.read_vec(offset, len), endian))
            }
        } else if let Ok(section) = view.section_by_name("__".to_string() + &section_name[1..]) {
            Ok(DWARFReader::new(
                view.read_vec(section.start(), section.len()),
                endian,
            ))
        } else {
            Ok(DWARFReader::new(vec![], endian))
        }
    })
}
