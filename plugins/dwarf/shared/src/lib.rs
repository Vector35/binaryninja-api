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

use gimli::{EndianRcSlice, Endianity, RunTimeEndian, SectionId};

use binaryninja::{
    binary_view::{BinaryView, BinaryViewBase, BinaryViewExt},
    settings::Settings,
    Endianness,
};

use binaryninja::settings::QueryOptions;
use std::rc::Rc;
//////////////////////
// Dwarf Validation

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unknown section compression method {0:#x}")]
    UnknownCompressionMethod(u32),

    #[error("{0}")]
    GimliError(#[from] gimli::Error),

    #[error("{0}")]
    IoError(#[from] std::io::Error),
}

pub fn is_non_dwo_dwarf(view: &BinaryView) -> bool {
    view.section_by_name(".debug_info").is_some() || view.section_by_name("__debug_info").is_some()
}

pub fn is_dwo_dwarf(view: &BinaryView) -> bool {
    view.section_by_name(".debug_info.dwo").is_some()
}

pub fn is_raw_non_dwo_dwarf(view: &BinaryView) -> bool {
    if let Some(raw_view) = view.raw_view() {
        raw_view.section_by_name(".debug_info").is_some()
            || view.section_by_name("__debug_info").is_some()
    } else {
        false
    }
}

pub fn is_raw_dwo_dwarf(view: &BinaryView) -> bool {
    if let Some(raw_view) = view.raw_view() {
        raw_view.section_by_name(".debug_info.dwo").is_some()
    } else {
        false
    }
}

pub fn can_use_debuginfod(view: &BinaryView) -> bool {
    let mut query_options = QueryOptions::new_with_view(view);
    has_build_id_section(view)
        && Settings::new().get_bool_with_opts("network.enableDebuginfod", &mut query_options)
}

pub fn has_build_id_section(view: &BinaryView) -> bool {
    if let Some(raw_view) = view.raw_view() {
        return raw_view.section_by_name(".note.gnu.build-id").is_some();
    }
    false
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

    if let Some(section) = view.section_by_name(section_name) {
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
                let data_type = &data_var.ty.contents;
                let data = view.read_vec(data_var.address, data_type.width() as usize);
                let element_type = data_type.element_type().unwrap().contents;

                if let Some(current_section_header) = data
                    .chunks(element_type.width() as usize)
                    .find(|section_header| {
                        if view.address_size() == 4 {
                            endian.read_u32(&section_header[16..20]) as u64 == section.start()
                        } else {
                            endian.read_u64(&section_header[24..32]) == section.start()
                        }
                    })
                {
                    let section_flags = if view.address_size() == 4 {
                        endian.read_u32(&current_section_header[8..12]) as u64
                    } else {
                        endian.read_u64(&current_section_header[8..16])
                    };
                    // If the section has the compressed bit set
                    if (section_flags & 2048) != 0 {
                        // Get section, trim header, decompress, return
                        let compressed_header_size = view.address_size() * 3;

                        let offset = section.start() + compressed_header_size as u64;
                        let len = section.len() - compressed_header_size;

                        let ch_type_vec = view.read_vec(section.start(), 4);
                        let ch_type = endian.read_u32(&ch_type_vec);

                        if let Ok(buffer) = view.read_buffer(offset, len) {
                            match ch_type {
                                1 => {
                                    return Ok(EndianRcSlice::new(
                                        buffer.zlib_decompress().get_data().into(),
                                        endian,
                                    ));
                                }
                                2 => {
                                    return Ok(EndianRcSlice::new(
                                        zstd::decode_all(buffer.get_data())?.as_slice().into(),
                                        endian,
                                    ));
                                }
                                x => {
                                    return Err(Error::UnknownCompressionMethod(x));
                                }
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
    } else if let Some(section) = view.section_by_name("__".to_string() + &section_name[1..]) {
        Ok(EndianRcSlice::new(
            Rc::from(view.read_vec(section.start(), section.len()).as_slice()),
            endian,
        ))
    } else {
        Ok(EndianRcSlice::new(Rc::from([]), endian))
    }
}
