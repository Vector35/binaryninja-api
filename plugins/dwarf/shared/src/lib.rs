// Copyright 2021-2026 Vector 35 Inc.
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
use object::{Object, ObjectSection};

use binaryninja::{
    binary_view::{BinaryView, BinaryViewBase},
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

    #[error("{0}")]
    ObjectError(#[from] object::Error),
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

pub fn create_section_reader<Endian: Endianity>(
    section_id: SectionId,
    view: &BinaryView,
    endian: Endian,
    is_dwo: bool,
) -> Result<RelocateOwned<gimli::EndianRcSlice<Endian>>, Error> {
    let raw_view = view.raw_view().unwrap();
    let view_data = raw_view.read_vec(0, raw_view.len() as usize);
    let file = object::File::parse(&*view_data)?;
    create_section_reader_object(section_id, &file, endian, is_dwo)
}

#[derive(Debug, Clone)]
pub struct RelocationMap(Rc<object::read::RelocationMap>);

impl Default for RelocationMap {
    fn default() -> Self {
        Self(Rc::new(object::read::RelocationMap::default()))
    }
}

impl RelocationMap {
    fn add(&mut self, file: &object::File, section: &object::Section) -> Result<(), Error> {
        let map =
            Rc::get_mut(&mut self.0).expect("Failed to get mutable reference to RelocationMap");
        for (offset, relocation) in section.relocations() {
            map.add(file, offset, relocation)?
        }
        Ok(())
    }
}

impl gimli::read::Relocate for RelocationMap {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.0.relocate(offset as u64, value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        <usize as gimli::ReaderOffset>::from_u64(self.0.relocate(offset as u64, value as u64))
    }
}

type RelocateOwned<R> = gimli::RelocateReader<R, RelocationMap>;

pub fn create_section_reader_object<Endian: gimli::Endianity>(
    id: gimli::SectionId,
    file: &object::File,
    endian: Endian,
    is_dwo: bool,
) -> Result<RelocateOwned<gimli::EndianRcSlice<Endian>>, Error> {
    let mut relocations = RelocationMap::default();
    let name = if is_dwo {
        id.dwo_name()
    } else if file.format() == object::BinaryFormat::Xcoff {
        id.xcoff_name()
    } else {
        Some(id.name())
    };
    let data = match name.and_then(|name| file.section_by_name(name)) {
        Some(ref section) => {
            // DWO sections never have relocations, so don't bother.
            if !is_dwo {
                relocations.add(file, section)?;
            }
            section.uncompressed_data()?.into_owned()
        }
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Vec::with_capacity(1),
    };
    let section = EndianRcSlice::new(Rc::from(data.into_boxed_slice()), endian);
    Ok(gimli::RelocateReader::new(section, relocations))
}
