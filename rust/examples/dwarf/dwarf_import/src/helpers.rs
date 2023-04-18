// Copyright 2021-2023 Vector 35 Inc.
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

use gimli::{
    constants, Attribute, AttributeValue, AttributeValue::UnitRef, DebuggingInformationEntry,
    Dwarf, Operation, Reader, Unit, UnitOffset, UnitSectionOffset,
};

use std::ffi::CString;

pub(crate) fn get_uid<R: Reader<Offset = usize>>(
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> usize {
    match entry.offset().to_unit_section_offset(unit) {
        UnitSectionOffset::DebugInfoOffset(o) => o.0,
        UnitSectionOffset::DebugTypesOffset(o) => o.0,
    }
}

////////////////////////////////////
// DIE attr convenience functions

pub fn resolve_specification<R: Reader<Offset = usize>>(
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> UnitOffset {
    if let Ok(Some(UnitRef(offset))) = entry.attr_value(constants::DW_AT_specification) {
        resolve_specification(unit, &unit.entry(offset).unwrap())
    } else if let Ok(Some(UnitRef(offset))) = entry.attr_value(constants::DW_AT_abstract_origin) {
        resolve_specification(unit, &unit.entry(offset).unwrap())
    } else {
        entry.offset()
    }
}

// Get name from DIE, or referenced dependencies
pub(crate) fn get_name<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Option<CString> {
    let entry = unit.entry(resolve_specification(unit, entry)).unwrap();

    if let Ok(Some(attr_val)) = entry.attr_value(constants::DW_AT_name) {
        if let Ok(attr_string) = dwarf.attr_string(unit, attr_val) {
            if let Ok(attr_string) = attr_string.to_string() {
                return Some(CString::new(attr_string.to_string()).unwrap());
            }
        }
    }
    None
}

// Get raw name from DIE, or referenced dependencies
pub(crate) fn get_raw_name<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Option<CString> {
    if let Ok(Some(attr_val)) = entry.attr_value(constants::DW_AT_linkage_name) {
        if let Ok(attr_string) = dwarf.attr_string(unit, attr_val) {
            if let Ok(attr_string) = attr_string.to_string() {
                Some(CString::new(attr_string.to_string()).unwrap())
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

// Get the size of an object as a usize
pub(crate) fn get_size_as_usize<R: Reader>(entry: &DebuggingInformationEntry<R>) -> Option<usize> {
    if let Ok(Some(attr)) = entry.attr(constants::DW_AT_byte_size) {
        get_attr_as_usize(attr)
    } else if let Ok(Some(attr)) = entry.attr(constants::DW_AT_bit_size) {
        get_attr_as_usize(attr).map(|attr_value| attr_value / 8)
    } else {
        None
    }
}

// Get the size of an object as a u64
pub(crate) fn get_size_as_u64<R: Reader>(entry: &DebuggingInformationEntry<R>) -> Option<u64> {
    if let Ok(Some(attr)) = entry.attr(constants::DW_AT_byte_size) {
        get_attr_as_u64(&attr)
    } else if let Ok(Some(attr)) = entry.attr(constants::DW_AT_bit_size) {
        get_attr_as_u64(&attr).map(|attr_value| attr_value / 8)
    } else {
        None
    }
}

// Get the size of a subrange as a u64
pub(crate) fn get_subrange_size<R: Reader>(entry: &DebuggingInformationEntry<R>) -> u64 {
    if let Ok(Some(attr)) = entry.attr(constants::DW_AT_upper_bound) {
        get_attr_as_u64(&attr).map_or(0, |v| v + 1)
    } else if let Ok(Some(attr)) = entry.attr(constants::DW_AT_count) {
        get_attr_as_u64(&attr).unwrap_or(0)
    } else if let Ok(Some(attr)) = entry.attr(constants::DW_AT_lower_bound) {
        get_attr_as_u64(&attr).map_or(0, |v| v + 1)
    } else {
        0
    }
}

// Get the start address of a function
pub(crate) fn get_start_address<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Option<u64> {
    if let Ok(Some(attr_val)) = entry.attr_value(constants::DW_AT_low_pc) {
        match dwarf.attr_address(unit, attr_val) {
            Ok(Some(val)) => Some(val),
            _ => None,
        }
    } else if let Ok(Some(attr_val)) = entry.attr_value(constants::DW_AT_entry_pc) {
        match dwarf.attr_address(unit, attr_val) {
            Ok(Some(val)) => Some(val),
            _ => None,
        }
    } else if let Ok(Some(attr_value)) = entry.attr_value(constants::DW_AT_ranges) {
        if let Ok(Some(ranges_offset)) = dwarf.attr_ranges_offset(unit, attr_value) {
            if let Ok(mut ranges) = dwarf.ranges(unit, ranges_offset) {
                if let Ok(Some(range)) = ranges.next() {
                    return Some(range.begin);
                }
            }
        }
        return None;
    } else {
        None
    }
}

// Get an attribute value as a u64 if it can be coerced
pub(crate) fn get_attr_as_u64<R: Reader>(attr: &Attribute<R>) -> Option<u64> {
    if let Some(value) = attr.u8_value() {
        Some(value.into())
    } else if let Some(value) = attr.u16_value() {
        Some(value.into())
    } else if let Some(value) = attr.udata_value() {
        Some(value)
    } else {
        attr.sdata_value().map(|value| value as u64)
    }
}

// Get an attribute value as a usize if it can be coerced
pub(crate) fn get_attr_as_usize<R: Reader>(attr: Attribute<R>) -> Option<usize> {
    if let Some(value) = attr.u8_value() {
        Some(value.into())
    } else if let Some(value) = attr.u16_value() {
        Some(value.into())
    } else if let Some(value) = attr.udata_value() {
        Some(value as usize)
    } else {
        attr.sdata_value().map(|value| value as usize)
    }
}

// Get an attribute value as a usize if it can be coerced
// Parses DW_OP_address, DW_OP_const
pub(crate) fn get_expr_value<R: Reader>(unit: &Unit<R>, attr: Attribute<R>) -> Option<u64> {
    if let AttributeValue::Exprloc(mut expression) = attr.value() {
        match Operation::parse(&mut expression.0, unit.encoding()).unwrap() {
            Operation::PlusConstant { value } => Some(value),
            Operation::UnsignedConstant { value } => Some(value),
            Operation::Address { address: 0 } => None,
            Operation::Address { address } => Some(address),
            _ => None,
        }
    } else {
        None
    }
}
