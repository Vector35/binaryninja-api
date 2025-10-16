// Copyright 2021-2025 Vector 35 Inc.
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
use object::{Object, ObjectSection, ObjectSymbol};

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
            .find(|symbol| symbol.full_name().to_string_lossy() == "__elf_section_headers")
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
                        // Get section, trim header, decompress, and apply relocations before returning
                        let compressed_header_size = view.address_size() * 3;

                        let offset = section.start() + compressed_header_size as u64;
                        let len = section.len() - compressed_header_size;

                        let ch_type_vec = view.read_vec(section.start(), 4);
                        let ch_type = endian.read_u32(&ch_type_vec);

                        if let Ok(buffer) = view.read_buffer(offset, len) {
                            let mut decompressed = match ch_type {
                                1 => buffer.zlib_decompress().get_data().to_vec(),
                                2 => zstd::decode_all(buffer.get_data())?,
                                x => return Err(Error::UnknownCompressionMethod(x)),
                            };

                            let section_name_owned = section.name().to_string_lossy().into_owned();
                            let is_little =
                                matches!(view.default_endianness(), Endianness::LittleEndian);
                            apply_relocations_with_object(
                                view,
                                &section_name_owned,
                                &mut decompressed,
                                is_little,
                            );

                            return Ok(EndianRcSlice::new(
                                Rc::from(decompressed.into_boxed_slice()),
                                endian,
                            ));
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
            let mut data = view.read_vec(offset, len);
            let section_name_owned = section.name().to_string_lossy().into_owned();
            let is_little = matches!(view.default_endianness(), Endianness::LittleEndian);
            apply_relocations_with_object(view, &section_name_owned, &mut data, is_little);
            Ok(EndianRcSlice::new(
                Rc::from(data.into_boxed_slice()),
                endian,
            ))
        }
    }
    // Truncate Mach-O section names to 16 bytes
    else if let Some(section) = view.section_by_name(&format!(
        "__{}",
        &section_name[1..section_name.len().min(15)]
    )) {
        let mut data = view.read_vec(section.start(), section.len());
        apply_relocations_with_object(
            view,
            section.name().to_string_lossy().as_ref(),
            &mut data,
            matches!(view.default_endianness(), Endianness::LittleEndian),
        );
        Ok(EndianRcSlice::new(
            Rc::from(data.into_boxed_slice()),
            endian,
        ))
    } else {
        Ok(EndianRcSlice::new(Rc::from([]), endian))
    }
}

fn read_int(bytes: &[u8], is_little_endian: bool) -> u64 {
    let mut value = 0u64;
    if is_little_endian {
        for (i, byte) in bytes.iter().enumerate() {
            value |= (*byte as u64) << (i * 8);
        }
    } else {
        for (i, byte) in bytes.iter().enumerate() {
            value |= (*byte as u64) << (8 * (bytes.len() - 1 - i));
        }
    }
    value
}

fn write_int(bytes: &mut [u8], value: u64, is_little_endian: bool) {
    if is_little_endian {
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (value >> (i * 8)) as u8;
        }
    } else {
        let len = bytes.len();
        for (i, byte) in bytes.iter_mut().enumerate() {
            let shift = 8 * (len - 1 - i);
            *byte = (value >> shift) as u8;
        }
    }
}

fn apply_relocations_with_object(
    view: &BinaryView,
    section_name: &str,
    data: &mut [u8],
    is_little_endian: bool,
) -> bool {
    let Some(file_bytes) = read_entire_view(view) else {
        return false;
    };

    let Ok(file) = object::File::parse(&*file_bytes) else {
        return false;
    };

    let Some(obj_section) = file.section_by_name(section_name) else {
        return false;
    };

    let mut applied = false;

    for (offset, relocation) in obj_section.relocations() {
        let size_bits = relocation.size();
        if size_bits == 0 {
            continue;
        }
        let size = (size_bits / 8) as usize;
        if size == 0 || size > 8 {
            continue;
        }

        let offset = offset as usize;
        if offset + size > data.len() {
            continue;
        }

        let mut base = 0i128;
        let mut target_section_name: Option<&str> = None;

        match relocation.target() {
            object::RelocationTarget::Symbol(symbol_index) => {
                let Ok(symbol) = file.symbol_by_index(symbol_index) else {
                    continue;
                };
                if let Some(section_index) = symbol.section_index() {
                    let Ok(target_section) = file.section_by_index(section_index) else {
                        continue;
                    };
                    if let Ok(name) = target_section.name() {
                        target_section_name = Some(name);
                    }
                    base += target_section.address() as i128;
                }
                base += symbol.address() as i128;
            }
            object::RelocationTarget::Section(section_index) => {
                let Ok(target_section) = file.section_by_index(section_index) else {
                    continue;
                };
                if let Ok(name) = target_section.name() {
                    target_section_name = Some(name);
                }
                base += target_section.address() as i128;
            }
            _ => {}
        }

        if let Some(name) = target_section_name {
            if !is_debug_related_section(name) {
                continue;
            }
        } else {
            continue;
        }

        if relocation.kind() != object::RelocationKind::Absolute {
            continue;
        }

        let _existing = read_int(&data[offset..offset + size], is_little_endian) as i128;
        let addend = relocation.addend() as i128;
        let value = base.wrapping_add(addend) as u64;
        write_int(&mut data[offset..offset + size], value, is_little_endian);
        applied = true;
    }

    applied
}

fn read_entire_view(view: &BinaryView) -> Option<Vec<u8>> {
    let len = view.len();
    if len == 0 || len > usize::MAX as u64 {
        return None;
    }
    let data = view.read_vec(0, len as usize);
    if data.len() as u64 != len {
        return None;
    }
    Some(data)
}

fn is_debug_related_section(name: &str) -> bool {
    name.starts_with(".debug") || name.starts_with(".zdebug")
}
