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

use binaryninja::rc::ArrayProvider;
use gimli::{EndianRcSlice, Endianity, Error, RunTimeEndian, SectionId};

use binaryninja::binaryninjacore_sys::*;

use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    databuffer::DataBuffer,
    Endianness,
};

use std::{ffi::CString, rc::Rc};

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

pub fn create_section_reader<'a, Endian: 'a + Endianity>(
    section_id: SectionId,
    view: &'a BinaryView,
    endian: Endian,
    dwo_file: bool,
) -> Result<EndianRcSlice<Endian>, Error> {
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

                if let Some(current_section_header) = data
                    .chunks(element_type.width() as usize)
                    .find(|section_header| {
                        endian.read_u64(&section_header[24..32]) == section.start()
                    })
                {
                    if (endian.read_u64(&current_section_header[8..16]) & 2048) != 0 {
                        // Get section, trim header, decompress, return
                        let offset = section.start() + 24;
                        let len = section.len() - 24;

                        if let Ok(buffer) = view.read_buffer(offset, len) {
                            use std::ptr;
                            let transform_name =
                                CString::new("Zlib").unwrap().into_bytes_with_nul();
                            let transform =
                                unsafe { BNGetTransformByName(transform_name.as_ptr() as *mut _) };

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

                                return Ok(EndianRcSlice::new(
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
            Ok(EndianRcSlice::new(Rc::from([]), endian))
        } else {
            Ok(EndianRcSlice::new(
                Rc::from(view.read_vec(offset, len).as_slice()),
                endian,
            ))
        }
    } else if let Ok(section) = view.section_by_name("__".to_string() + &section_name[1..]) {
        Ok(EndianRcSlice::new(
            Rc::from(view.read_vec(section.start(), section.len()).as_slice()),
            endian,
        ))
    } else {
        Ok(EndianRcSlice::new(Rc::from([]), endian))
    }
}
