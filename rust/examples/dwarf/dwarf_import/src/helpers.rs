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

use crate::DebugInfoBuilderContext;

use gimli::{
    constants, Attribute, AttributeValue,
    AttributeValue::{DebugInfoRef, UnitRef},
    DebuggingInformationEntry, Operation, Reader, Unit, UnitOffset, UnitSectionOffset,
};

use log::warn;

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

pub(crate) enum DieReference<'a, R: Reader<Offset = usize>> {
    UnitAndOffset((&'a Unit<R>, UnitOffset)),
    Err,
}

pub(crate) fn get_attr_die<'a, R: Reader<Offset = usize>>(
    unit: &'a Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &'a DebugInfoBuilderContext<R>,
    attr: constants::DwAt,
) -> Option<DieReference<'a, R>> {
    match entry.attr_value(attr) {
        Ok(Some(UnitRef(offset))) => Some(DieReference::UnitAndOffset((unit, offset))),
        Ok(Some(DebugInfoRef(offset))) => {
            for source_unit in debug_info_builder_context.units() {
                if let Some(new_offset) = offset.to_unit_offset(&source_unit.header) {
                    return Some(DieReference::UnitAndOffset((source_unit, new_offset)));
                }
            }
            warn!("Failed to fetch DIE. Debug information may be incomplete.");
            None
        }
        // Ok(Some(DebugInfoRefSup(offset))) TODO - dwarf 5 stuff
        _ => None,
    }
}

pub(crate) fn resolve_specification<'a, R: Reader<Offset = usize>>(
    unit: &'a Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &'a DebugInfoBuilderContext<R>,
) -> DieReference<'a, R> {
    if let Some(die_reference) = get_attr_die(
        unit,
        entry,
        debug_info_builder_context,
        constants::DW_AT_specification,
    ) {
        match die_reference {
            DieReference::UnitAndOffset((entry_unit, entry_offset)) => {
                if let Ok(entry) = entry_unit.entry(entry_offset) {
                    resolve_specification(entry_unit, &entry, debug_info_builder_context)
                } else {
                    warn!("Failed to fetch DIE. Debug information may be incomplete.");
                    DieReference::Err
                }
            }
            DieReference::Err => DieReference::Err,
        }
    } else if let Some(die_reference) = get_attr_die(
        unit,
        entry,
        debug_info_builder_context,
        constants::DW_AT_abstract_origin,
    ) {
        match die_reference {
            DieReference::UnitAndOffset((entry_unit, entry_offset)) => {
                if entry_offset == entry.offset() {
                    warn!("DWARF information is invalid (infinite abstract origin reference cycle). Debug information may be incomplete.");
                    DieReference::Err
                } else if let Ok(new_entry) = entry_unit.entry(entry_offset) {
                    resolve_specification(entry_unit, &new_entry, debug_info_builder_context)
                } else {
                    warn!("Failed to fetch DIE. Debug information may be incomplete.");
                    DieReference::Err
                }
            }
            DieReference::Err => DieReference::Err,
        }
    } else {
        DieReference::UnitAndOffset((unit, entry.offset()))
    }
}

// Get name from DIE, or referenced dependencies
pub(crate) fn get_name<R: Reader<Offset = usize>>(
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
) -> Option<String> {
    match resolve_specification(unit, entry, debug_info_builder_context) {
        DieReference::UnitAndOffset((entry_unit, entry_offset)) => {
            if let Ok(Some(attr_val)) = entry_unit
                .entry(entry_offset)
                .unwrap()
                .attr_value(constants::DW_AT_name)
            {
                if let Ok(attr_string) = debug_info_builder_context
                    .dwarf()
                    .attr_string(entry_unit, attr_val)
                {
                    if let Ok(attr_string) = attr_string.to_string() {
                        return Some(attr_string.to_string());
                    }
                }
            }

            // if let Some(raw_name) = get_raw_name(unit, entry, debug_info_builder_context) {
            //     if let Some(arch) = debug_info_builder_context.default_architecture() {
            //         if let Ok((_, names)) = demangle_gnu3(&arch, raw_name, true) {
            //             return Some(names.join("::"));
            //         }
            //     }
            // }
            None
        }
        DieReference::Err => None,
    }
}

// Get raw name from DIE, or referenced dependencies
pub(crate) fn get_raw_name<R: Reader<Offset = usize>>(
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
) -> Option<String> {
    if let Ok(Some(attr_val)) = entry.attr_value(constants::DW_AT_linkage_name) {
        if let Ok(attr_string) = debug_info_builder_context
            .dwarf()
            .attr_string(unit, attr_val)
        {
            if let Ok(attr_string) = attr_string.to_string() {
                return Some(attr_string.to_string());
            }
        }
    }
    None
}

// Get the size of an object as a usize
pub(crate) fn get_size_as_usize<R: Reader<Offset = usize>>(
    entry: &DebuggingInformationEntry<R>,
) -> Option<usize> {
    if let Ok(Some(attr)) = entry.attr(constants::DW_AT_byte_size) {
        get_attr_as_usize(attr)
    } else if let Ok(Some(attr)) = entry.attr(constants::DW_AT_bit_size) {
        get_attr_as_usize(attr).map(|attr_value| attr_value / 8)
    } else {
        None
    }
}

// Get the size of an object as a u64
pub(crate) fn get_size_as_u64<R: Reader<Offset = usize>>(
    entry: &DebuggingInformationEntry<R>,
) -> Option<u64> {
    if let Ok(Some(attr)) = entry.attr(constants::DW_AT_byte_size) {
        get_attr_as_u64(&attr)
    } else if let Ok(Some(attr)) = entry.attr(constants::DW_AT_bit_size) {
        get_attr_as_u64(&attr).map(|attr_value| attr_value / 8)
    } else {
        None
    }
}

// Get the size of a subrange as a u64
pub(crate) fn get_subrange_size<R: Reader<Offset = usize>>(
    entry: &DebuggingInformationEntry<R>,
) -> u64 {
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
pub(crate) fn get_start_address<R: Reader<Offset = usize>>(
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
) -> Option<u64> {
    if let Ok(Some(attr_val)) = entry.attr_value(constants::DW_AT_low_pc) {
        match debug_info_builder_context
            .dwarf()
            .attr_address(unit, attr_val)
        {
            Ok(Some(val)) => Some(val),
            _ => None,
        }
    } else if let Ok(Some(attr_val)) = entry.attr_value(constants::DW_AT_entry_pc) {
        match debug_info_builder_context
            .dwarf()
            .attr_address(unit, attr_val)
        {
            Ok(Some(val)) => Some(val),
            _ => None,
        }
    } else if let Ok(Some(attr_value)) = entry.attr_value(constants::DW_AT_ranges) {
        if let Ok(Some(ranges_offset)) = debug_info_builder_context
            .dwarf()
            .attr_ranges_offset(unit, attr_value)
        {
            if let Ok(mut ranges) = debug_info_builder_context
                .dwarf()
                .ranges(unit, ranges_offset)
            {
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
pub(crate) fn get_attr_as_u64<R: Reader<Offset = usize>>(attr: &Attribute<R>) -> Option<u64> {
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
pub(crate) fn get_attr_as_usize<R: Reader<Offset = usize>>(attr: Attribute<R>) -> Option<usize> {
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
pub(crate) fn get_expr_value<R: Reader<Offset = usize>>(
    unit: &Unit<R>,
    attr: Attribute<R>,
) -> Option<u64> {
    if let AttributeValue::Exprloc(mut expression) = attr.value() {
        match Operation::parse(&mut expression.0, unit.encoding()) {
            Ok(Operation::PlusConstant { value }) => Some(value),
            Ok(Operation::UnsignedConstant { value }) => Some(value),
            Ok(Operation::Address { address: 0 }) => None,
            Ok(Operation::Address { address }) => Some(address),
            _ => None,
        }
    } else {
        None
    }
}
