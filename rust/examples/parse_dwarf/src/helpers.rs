// Copyright 2021 Vector 35 Inc.
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

use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::databuffer::DataBuffer;
use binaryninja::Endianness;

use gimli::{
    constants, Attribute, AttributeValue::UnitRef, DebuggingInformationEntry, Dwarf, EndianReader,
    Endianity, Error, Reader, RunTimeEndian, SectionId, Unit, UnitOffset,
};

use std::{
    fmt,
    fmt::{Debug, Formatter},
    ops::Deref,
    sync::Arc,
};

//////////////////////
// Dwarf Validation

pub(crate) fn is_non_dwo_dwarf(view: &BinaryView) -> bool {
    view.section_by_name(".debug_info").is_ok()
}

pub(crate) fn is_dwo_dwarf(view: &BinaryView) -> bool {
    view.section_by_name(".debug_info.dwo").is_ok()
}

pub(crate) fn is_parent_non_dwo_dwarf(view: &BinaryView) -> bool {
    if let Ok(parent_view) = view.parent_view() {
        parent_view.section_by_name(".debug_info").is_ok()
    } else {
        false
    }
}

pub(crate) fn is_parent_dwo_dwarf(view: &BinaryView) -> bool {
    if let Ok(parent_view) = view.parent_view() {
        parent_view.section_by_name(".debug_info").is_ok()
    } else {
        false
    }
}

////////////////////////
// DataBuffer Wrapper

// gimli::read::load only takes structures containing &[u8]'s, but we need to keep the data buffer alive until it's done using that
//   I don't think that the `Arc` is needed, but I couldn't figure out how else to implement the traits properly without it
#[derive(Clone)]
pub(crate) struct DataBufferWrapper(Arc<DataBuffer>);
impl DataBufferWrapper {
    pub(crate) fn new(buf: DataBuffer) -> Self {
        DataBufferWrapper(Arc::new(buf))
    }
}
impl Deref for DataBufferWrapper {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.get_data()
    }
}
impl Debug for DataBufferWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataBufferWrapper")
            .field("0", &"I'm too lazy to do this right")
            .finish()
    }
}
unsafe impl gimli::StableDeref for DataBufferWrapper {}
unsafe impl gimli::CloneStableDeref for DataBufferWrapper {}

/////////////////////
// Reader Wrappers

pub(crate) fn get_endian(view: &BinaryView) -> RunTimeEndian {
    match view.default_endianness() {
        Endianness::LittleEndian => RunTimeEndian::Little,
        Endianness::BigEndian => RunTimeEndian::Big,
    }
}

pub(crate) fn create_section_reader<'a, Endian: 'a + Endianity>(
    view: &'a BinaryView,
    endian: Endian,
    dwo_file: bool,
) -> Box<dyn Fn(SectionId) -> Result<EndianReader<Endian, DataBufferWrapper>, Error> + 'a> {
    Box::new(move |section_id: SectionId| {
        let section_name;
        if dwo_file && section_id.dwo_name().is_some() {
            section_name = section_id.dwo_name().unwrap();
        } else if dwo_file {
            return Ok(EndianReader::new(
                DataBufferWrapper::new(DataBuffer::default()),
                endian,
            ));
        } else {
            section_name = section_id.name();
        }

        if let Ok(section) = view.section_by_name(section_name) {
            let offset = section.start();
            let len = section.len();
            if len == 0 {
                return Ok(EndianReader::new(
                    DataBufferWrapper::new(DataBuffer::default()),
                    endian,
                ));
            }

            if let Ok(read_buffer) = view.read_buffer(offset, len as usize) {
                return Ok(EndianReader::new(
                    DataBufferWrapper::new(read_buffer),
                    endian,
                ));
            }
            return Err(Error::Io);
        } else {
            return Ok(EndianReader::new(
                DataBufferWrapper::new(DataBuffer::default()),
                endian,
            ));
        }
    })
}

pub(crate) fn create_empty_reader<'a, Endian: 'a + Endianity>(
    endian: Endian,
) -> Box<dyn Fn(SectionId) -> Result<EndianReader<Endian, DataBufferWrapper>, Error> + 'a> {
    Box::new(move |_| {
        Ok(EndianReader::new(
            DataBufferWrapper::new(DataBuffer::default()),
            endian,
        ))
    })
}

////////////////////////////////////
// DIE attr convenience functions

// TODO : This only gets one kind of base entry (for...functions?), we should check for overlap and whatnot to parse specific types of base entries
pub(crate) fn get_base_entry<R: Reader>(
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> UnitOffset<<R as Reader>::Offset> {
    if let Ok(Some(UnitRef(offset))) = entry.attr_value(constants::DW_AT_specification) {
        let entry = unit.entry(offset).unwrap();
        get_base_entry(unit, &entry)
    } else if let Ok(Some(UnitRef(offset))) = entry.attr_value(constants::DW_AT_abstract_origin) {
        let entry = unit.entry(offset).unwrap();
        get_base_entry(unit, &entry)
    } else {
        entry.offset()
    }
}

pub(crate) fn get_name<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Option<String> {
    if let Ok(Some(attr_val)) = entry.attr_value(constants::DW_AT_name) {
        if let Ok(attr_string) = dwarf.attr_string(&unit, attr_val) {
            if let Ok(attr_string) = attr_string.to_string() {
                Some(attr_string.to_string())
            } else {
                None
            }
        } else {
            None
        }
    } else if let Ok(Some(UnitRef(offset))) = entry.attr_value(constants::DW_AT_specification) {
        let entry = unit.entry(offset).unwrap();
        get_name(dwarf, unit, &entry)
    } else if let Ok(Some(UnitRef(offset))) = entry.attr_value(constants::DW_AT_abstract_origin) {
        let entry = unit.entry(offset).unwrap();
        get_name(dwarf, unit, &entry)
    } else {
        None
    }
}

pub(crate) fn get_raw_name<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Option<String> {
    if let Ok(Some(attr_val)) = entry.attr_value(constants::DW_AT_linkage_name) {
        if let Ok(attr_string) = dwarf.attr_string(&unit, attr_val) {
            if let Ok(attr_string) = attr_string.to_string() {
                Some(attr_string.to_string())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

pub(crate) fn recover_full_name(
    short_name: &Option<String>,
    namespace_qualifiers: &Vec<(isize, String)>,
) -> Option<String> {
    // The DIE does not contain any namespace information, so we track the namespaces and build the symbol ourselves
    if let Some(function_name) = short_name {
        let mut full_name_builder = "".to_string();
        for (_, namespace) in namespace_qualifiers {
            full_name_builder = format!("{}{}::", full_name_builder, namespace);
        }
        Some(format!("{}{}", full_name_builder, function_name))
    } else {
        None
    }
}

pub(crate) fn get_start_address<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Option<u64> {
    // TODO : Need to cover more address DIE address representations:
    //   DW_AT_ranges
    if let Ok(Some(attr_val)) = entry.attr_value(constants::DW_AT_low_pc) {
        Some(dwarf.attr_address(&unit, attr_val).unwrap().unwrap())
    } else if let Ok(Some(attr_val)) = entry.attr_value(constants::DW_AT_entry_pc) {
        Some(dwarf.attr_address(&unit, attr_val).unwrap().unwrap())
    } else {
        None
    }
}

pub(crate) fn get_attr_as_u64<R: Reader>(attr: Attribute<R>) -> Option<u64> {
    if let Some(value) = attr.u8_value() {
        Some(value.into())
    } else if let Some(value) = attr.u16_value() {
        Some(value.into())
    } else if let Some(value) = attr.udata_value() {
        Some(value.into())
    } else if let Some(value) = attr.sdata_value() {
        Some(value as u64)
    } else {
        None
    }
}

pub(crate) fn get_attr_as_usize<R: Reader>(attr: Attribute<R>) -> Option<usize> {
    if let Some(value) = attr.u8_value() {
        Some(value.into())
    } else if let Some(value) = attr.u16_value() {
        Some(value.into())
    } else if let Some(value) = attr.udata_value() {
        Some(value as usize)
    } else if let Some(value) = attr.sdata_value() {
        Some(value as usize)
    } else {
        None
    }
}

// TODO : Make this non-copy
pub(crate) fn get_attr_string<'a, R: 'a + Reader>(
    dwarf: &'a Dwarf<R>,
    unit: &'a Unit<R>,
    entry: &'a DebuggingInformationEntry<R>,
) -> String {
    // TODO : This shouldn't need a else case, since I should never be calling this on a DIE without this attribute
    // TODO : Also, rename the variables here
    if let Ok(Some(thing)) = entry.attr_value(constants::DW_AT_name) {
        let attr_name: R = dwarf.attr_string(&unit, thing).unwrap();
        let thing = attr_name.to_string().unwrap_or_default(); // TODO : remove or_default
        String::from(thing.as_ref())
    } else {
        "".to_string()
    }
}
