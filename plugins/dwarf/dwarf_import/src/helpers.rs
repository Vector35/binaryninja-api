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

use std::path::PathBuf;
use std::{str::FromStr, sync::mpsc};

use crate::{DebugInfoBuilderContext, ReaderType};
use binaryninja::binary_view::BinaryViewBase;
use binaryninja::Endianness;
use binaryninja::{
    binary_view::{BinaryView, BinaryViewExt},
    download::{DownloadInstanceInputOutputCallbacks, DownloadProvider},
    settings::Settings,
};
use gimli::Dwarf;
use gimli::{
    constants, Attribute, AttributeValue,
    AttributeValue::{DebugInfoRef, DebugInfoRefSup, UnitRef},
    DebuggingInformationEntry, Operation, Unit, UnitOffset, UnitSectionOffset,
};

use binaryninja::settings::QueryOptions;

pub(crate) fn get_uid<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> usize {
    // We set a large gap between supplementary and main entries
    let adj = dwarf.sup().map_or(0, |_| 0x1000000000000000);
    let entry_offset = match entry.offset().to_unit_section_offset(unit) {
        UnitSectionOffset::DebugInfoOffset(o) => o.0,
        UnitSectionOffset::DebugTypesOffset(o) => o.0,
    };
    entry_offset + adj
}

////////////////////////////////////
// DIE attr convenience functions

pub(crate) enum DieReference<'a, R: ReaderType> {
    UnitAndOffset((&'a Dwarf<R>, &'a Unit<R>, UnitOffset)),
    Err,
}

pub(crate) fn get_attr_die<'a, R: ReaderType>(
    dwarf: &'a Dwarf<R>,
    unit: &'a Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &'a DebugInfoBuilderContext<R>,
    attr: constants::DwAt,
) -> Option<DieReference<'a, R>> {
    match entry.attr_value(attr) {
        Ok(Some(UnitRef(offset))) => Some(DieReference::UnitAndOffset((dwarf, unit, offset))),
        Ok(Some(DebugInfoRef(offset))) => {
            if dwarf.sup().is_some() {
                for source_unit in debug_info_builder_context.units() {
                    if let Some(new_offset) = offset.to_unit_offset(&source_unit.header) {
                        return Some(DieReference::UnitAndOffset((
                            dwarf,
                            source_unit,
                            new_offset,
                        )));
                    }
                }
            } else {
                // This could either have no supplementary file because it is one or because it just doesn't have one
                // operate on supplementary file if dwarf is a supplementary file, else self

                // It's possible this is a reference in the supplementary file to itself
                for source_unit in debug_info_builder_context.sup_units() {
                    if let Some(new_offset) = offset.to_unit_offset(&source_unit.header) {
                        return Some(DieReference::UnitAndOffset((
                            dwarf,
                            source_unit,
                            new_offset,
                        )));
                    }
                }

                // ... or it just doesn't have a supplementary file
                for source_unit in debug_info_builder_context.units() {
                    if let Some(new_offset) = offset.to_unit_offset(&source_unit.header) {
                        return Some(DieReference::UnitAndOffset((
                            dwarf,
                            source_unit,
                            new_offset,
                        )));
                    }
                }
            }

            None
        }
        Ok(Some(DebugInfoRefSup(offset))) => {
            for source_unit in debug_info_builder_context.sup_units() {
                if let Some(new_offset) = offset.to_unit_offset(&source_unit.header) {
                    let sup: &Dwarf<R> = match dwarf.sup() {
                        Some(x) => x,
                        None => {
                            tracing::error!("Trying to get offset in supplmentary dwarf info, but none is present");
                            return None;
                        }
                    };
                    return Some(DieReference::UnitAndOffset((sup, source_unit, new_offset)));
                }
            }
            tracing::warn!(
                "Failed to fetch DIE. Supplementary debug information may be incomplete."
            );
            None
        }
        _ => None,
    }
}

pub(crate) fn resolve_specification<'a, R: ReaderType>(
    dwarf: &'a Dwarf<R>,
    unit: &'a Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &'a DebugInfoBuilderContext<R>,
) -> DieReference<'a, R> {
    if let Some(die_reference) = get_attr_die(
        dwarf,
        unit,
        entry,
        debug_info_builder_context,
        constants::DW_AT_specification,
    ) {
        match die_reference {
            DieReference::UnitAndOffset((dwarf, entry_unit, entry_offset)) => {
                if let Ok(entry) = entry_unit.entry(entry_offset) {
                    resolve_specification(dwarf, entry_unit, &entry, debug_info_builder_context)
                } else {
                    tracing::warn!("Failed to fetch DIE for attr DW_AT_specification. Debug information may be incomplete.");
                    DieReference::Err
                }
            }
            DieReference::Err => DieReference::Err,
        }
    } else if let Some(die_reference) = get_attr_die(
        dwarf,
        unit,
        entry,
        debug_info_builder_context,
        constants::DW_AT_abstract_origin,
    ) {
        match die_reference {
            DieReference::UnitAndOffset((dwarf, entry_unit, entry_offset)) => {
                if entry_offset == entry.offset()
                    && unit.header.offset() == entry_unit.header.offset()
                {
                    tracing::warn!("DWARF information is invalid (infinite abstract origin reference cycle). Debug information may be incomplete.");
                    DieReference::Err
                } else if let Ok(new_entry) = entry_unit.entry(entry_offset) {
                    resolve_specification(dwarf, entry_unit, &new_entry, debug_info_builder_context)
                } else {
                    tracing::warn!("Failed to fetch DIE for attr DW_AT_abstract_origin. Debug information may be incomplete.");
                    DieReference::Err
                }
            }
            DieReference::Err => DieReference::Err,
        }
    } else {
        DieReference::UnitAndOffset((dwarf, unit, entry.offset()))
    }
}

// Get name from DIE, or referenced dependencies
pub(crate) fn get_name<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
) -> Option<String> {
    match resolve_specification(dwarf, unit, entry, debug_info_builder_context) {
        DieReference::UnitAndOffset((dwarf, entry_unit, entry_offset)) => {
            let resolved_entry = match entry_unit.entry(entry_offset) {
                Ok(x) => x,
                Err(_) => {
                    tracing::error!(
                        "Failed to get entry in unit at {:?} at offset {:#x} (get_name)",
                        entry_unit.header.offset(),
                        entry_offset.0
                    );
                    return None;
                }
            };
            if let Ok(Some(attr_val)) = resolved_entry.attr_value(constants::DW_AT_name) {
                if let Ok(attr_string) = dwarf.attr_string(entry_unit, attr_val.clone()) {
                    if let Ok(attr_string) = attr_string.to_string() {
                        return Some(attr_string.to_string());
                    }
                } else if let Some(dwarf) = &dwarf.sup {
                    if let Ok(attr_string) = dwarf.attr_string(entry_unit, attr_val) {
                        if let Ok(attr_string) = attr_string.to_string() {
                            return Some(attr_string.to_string());
                        }
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
pub(crate) fn get_raw_name<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
) -> Option<String> {
    match resolve_specification(dwarf, unit, entry, debug_info_builder_context) {
        DieReference::UnitAndOffset((dwarf, entry_unit, entry_offset)) => {
            let resolved_entry = match entry_unit.entry(entry_offset) {
                Ok(x) => x,
                Err(_) => {
                    tracing::error!(
                        "Failed to get entry in unit at {:?} at offset {:#x} (get_raw_name)",
                        entry_unit.header.offset(),
                        entry_offset.0
                    );
                    return None;
                }
            };

            if let Ok(Some(attr_val)) = resolved_entry.attr_value(constants::DW_AT_linkage_name) {
                if let Ok(attr_string) = dwarf.attr_string(entry_unit, attr_val.clone()) {
                    if let Ok(attr_string) = attr_string.to_string() {
                        return Some(attr_string.to_string());
                    }
                } else if let Some(dwarf) = &dwarf.sup {
                    if let Ok(attr_string) = dwarf.attr_string(entry_unit, attr_val) {
                        if let Ok(attr_string) = attr_string.to_string() {
                            return Some(attr_string.to_string());
                        }
                    }
                }
            }
            None
        }
        DieReference::Err => None,
    }
}

// Get the size of an object as a usize
pub(crate) fn get_size_as_usize<R: ReaderType>(
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
pub(crate) fn get_size_as_u64<R: ReaderType>(entry: &DebuggingInformationEntry<R>) -> Option<u64> {
    if let Ok(Some(attr)) = entry.attr(constants::DW_AT_byte_size) {
        get_attr_as_u64(&attr)
    } else if let Ok(Some(attr)) = entry.attr(constants::DW_AT_bit_size) {
        get_attr_as_u64(&attr).map(|attr_value| attr_value / 8)
    } else {
        None
    }
}

// Get the size of a subrange as a u64
pub(crate) fn get_subrange_size<R: ReaderType>(entry: &DebuggingInformationEntry<R>) -> u64 {
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
pub(crate) fn get_start_address<R: ReaderType>(
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
pub(crate) fn get_attr_as_u64<R: ReaderType>(attr: &Attribute<R>) -> Option<u64> {
    if let Some(value) = attr.udata_value() {
        Some(value)
    } else if let Some(value) = attr.sdata_value() {
        Some(value as u64)
    } else if let AttributeValue::Block(mut data) = attr.value() {
        match data.len() {
            1 => data.read_u8().map(u64::from).ok(),
            2 => data.read_u16().map(u64::from).ok(),
            4 => data.read_u32().map(u64::from).ok(),
            8 => data.read_u64().ok(),
            _ => None,
        }
    } else {
        None
    }
}

// Get an attribute value as a usize if it can be coerced
pub(crate) fn get_attr_as_usize<R: ReaderType>(attr: Attribute<R>) -> Option<usize> {
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
pub(crate) fn get_expr_value<R: ReaderType>(unit: &Unit<R>, attr: Attribute<R>) -> Option<u64> {
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

pub(crate) fn get_build_id(view: &BinaryView) -> Result<Option<Vec<u8>>, String> {
    let mut build_id: Option<Vec<u8>> = None;

    if let Some(raw_view) = view.raw_view() {
        if let Some(build_id_section) = raw_view.section_by_name(".note.gnu.build-id") {
            // Name size - 4 bytes
            // Desc size - 4 bytes
            // Type - 4 bytes
            // Name - n bytes
            // Desc - n bytes
            let build_id_bytes =
                raw_view.read_vec(build_id_section.start(), build_id_section.len());
            if build_id_bytes.len() < 12 {
                return Err("Build id section must be at least 12 bytes".to_string());
            }

            let conversion_func = match raw_view.default_endianness() {
                Endianness::LittleEndian => u32::from_le_bytes,
                Endianness::BigEndian => u32::from_be_bytes,
            };

            let name_len = build_id_bytes[0..4]
                .try_into()
                .map_err(|e| format!("Failed to get name length: {}", e))
                .map(|byte_val| conversion_func(byte_val))?;

            let desc_len = build_id_bytes[4..8]
                .try_into()
                .map_err(|e| format!("Failed to get desc length: {}", e))
                .map(|byte_val| conversion_func(byte_val))?;

            let note_type = build_id_bytes[8..12]
                .try_into()
                .map_err(|e| format!("Failed to get note type: {}", e))
                .map(|byte_val| conversion_func(byte_val))?;

            if note_type != 3 {
                return Err(format!("Build id section has wrong type: {}", note_type));
            }

            let expected_len = (12 + name_len + desc_len) as usize;

            if build_id_bytes.len() < expected_len {
                return Err(format!(
                    "Build id section not expected length: expected {}, got {}",
                    expected_len,
                    build_id_bytes.len()
                ));
            }

            let desc: &[u8] = &build_id_bytes[(12 + name_len as usize)..expected_len];
            build_id = Some(desc.to_vec());
        }
    }

    Ok(build_id)
}

pub(crate) fn download_debug_info(
    build_id: &[u8],
    view: &BinaryView,
) -> Result<Option<Vec<u8>>, String> {
    let build_id_hex: String = build_id.iter().map(|x| format!("{:02x}", x)).collect();
    let mut settings_query_opts = QueryOptions::new_with_view(view);
    let settings = Settings::new();
    let debug_server_urls =
        settings.get_string_list_with_opts("network.debuginfodServers", &mut settings_query_opts);

    for debug_server_url in debug_server_urls.iter() {
        let artifact_url = format!(
            "{}/buildid/{}/debuginfo",
            debug_server_url.trim_end_matches("/"),
            build_id_hex
        );

        // Download from remote
        let (tx, rx) = mpsc::channel();
        let write = move |data: &[u8]| -> usize {
            if tx.send(Vec::from(data)).is_ok() {
                data.len()
            } else {
                0
            }
        };

        let dp = DownloadProvider::try_default().map_err(|_| "No default download provider")?;
        let mut inst = dp
            .create_instance()
            .map_err(|_| "Couldn't create download instance")?;
        let result = inst
            .perform_custom_request(
                "GET",
                &artifact_url,
                vec![],
                &DownloadInstanceInputOutputCallbacks {
                    read: None,
                    write: Some(Box::new(write)),
                    progress: None,
                },
            )
            .map_err(|e| e.to_string())?;
        if result.status_code != 200 {
            continue;
        }

        let mut expected_length = None;
        for (k, v) in result.headers.iter() {
            if k.to_lowercase() == "content-length" {
                expected_length = Some(usize::from_str(v).map_err(|e| e.to_string())?);
            }
        }

        let mut data = vec![];
        while let Ok(packet) = rx.try_recv() {
            data.extend(packet.into_iter());
        }

        if let Some(length) = expected_length {
            if data.len() != length {
                return Err(format!(
                    "Bad length: expected {} got {}",
                    length,
                    data.len()
                ));
            }
        }
        return Ok(Some(data));
    }
    Ok(None)
}

pub(crate) fn find_local_debug_file_from_path(path: &PathBuf, view: &BinaryView) -> Option<String> {
    // Search debug directories for path (or None if setting disabled/empty), return the first one that exists
    // TODO: put absolute paths behind setting?
    if path.is_absolute() {
        if !path.exists() {
            return None;
        }
        return path.to_str().map(|s| s.to_string());
    }

    let mut settings_query_opts = QueryOptions::new_with_view(view);
    let settings = Settings::new();
    let debug_dirs_enabled = settings.get_bool_with_opts(
        "analysis.debugInfo.enableDebugDirectories",
        &mut settings_query_opts,
    );

    if !debug_dirs_enabled {
        return None;
    }

    let debug_info_paths = settings.get_string_list_with_opts(
        "analysis.debugInfo.debugDirectories",
        &mut settings_query_opts,
    );

    for debug_info_path in debug_info_paths.into_iter() {
        let final_path = PathBuf::from(debug_info_path).join(path);
        if final_path.exists() {
            return final_path.to_str().map(|s| s.to_string());
        }
    }
    None
}

pub(crate) fn find_local_debug_file_for_build_id(
    build_id: &[u8],
    view: &BinaryView,
) -> Option<String> {
    let build_id_hex: String = build_id.iter().map(|x| format!("{:02x}", x)).collect();
    let debug_ext_path =
        PathBuf::from(&build_id_hex[..2]).join(format!("{}.debug", &build_id_hex[2..]));

    let elf_path = PathBuf::from(&build_id_hex[..2])
        .join(&build_id_hex[2..])
        .join("elf");

    find_local_debug_file_from_path(&debug_ext_path, view)
        .or_else(|| find_local_debug_file_from_path(&elf_path, view))
}

pub(crate) fn load_debug_info_for_build_id(
    build_id: &[u8],
    view: &BinaryView,
) -> Result<Option<Vec<u8>>, String> {
    let mut settings_query_opts = QueryOptions::new_with_view(view);
    let settings = Settings::new();
    if let Some(debug_file_path) = find_local_debug_file_for_build_id(build_id, view) {
        return std::fs::read(&debug_file_path)
            .map(|x| Some(x))
            .map_err(|e| format!("Failed to read local debug file {}: {}", debug_file_path, e));
    } else if settings.get_bool_with_opts("network.enableDebuginfod", &mut settings_query_opts) {
        return download_debug_info(build_id, view);
    }
    Ok(None)
}

pub(crate) fn find_sibling_debug_file(view: &BinaryView) -> Option<String> {
    let mut settings_query_opts = QueryOptions::new_with_view(view);
    let settings = Settings::new();
    let load_sibling_debug = settings.get_bool_with_opts(
        "analysis.debugInfo.loadSiblingDebugFiles",
        &mut settings_query_opts,
    );

    if !load_sibling_debug {
        return None;
    }

    let debug_file = view.file().file_path().with_extension("debug");
    let dsym_folder = view.file().file_path().with_extension("dSYM");

    // Find sibling debug file
    if debug_file.exists() && debug_file.is_file() {
        return Some(debug_file.to_string_lossy().to_string());
    }

    // Find sibling debug file in project
    if let Some(debug_file_name) = debug_file.file_name() {
        if let Some(project_file) = view.file().project_file() {
            let project_file_folder_id = project_file.folder().map(|x| x.id());
            for file in project_file.project().files().iter() {
                if !file.exists_on_disk() {
                    // If the file doesn't exist, don't consider it
                    // TODO: if we're connected to a remote project, offer to download the file
                    continue;
                }

                let file_folder_id = file.folder().map(|x| x.id());
                if *file.name() == *debug_file_name && file_folder_id == project_file_folder_id {
                    if let Some(path_on_disk) = file.path_on_disk() {
                        return path_on_disk.to_str().map(|x| x.to_string());
                    }
                }
            }
        }
    }

    // Look for dSYM
    // TODO: look for dSYM in project
    if dsym_folder.exists() && dsym_folder.is_dir() {
        if let Some(filename) = view.file().file_path().file_name() {
            // TODO: should this just pull any file out? Can there be multiple files?
            let dsym_file = dsym_folder.join("Contents/Resources/DWARF/").join(filename);
            if dsym_file.exists() {
                return Some(dsym_file.to_string_lossy().to_string());
            }
        }
    }

    None
}

pub(crate) fn load_sibling_debug_file(view: &BinaryView) -> Result<Option<Vec<u8>>, String> {
    let Some(debug_file) = find_sibling_debug_file(view) else {
        return Ok(None);
    };

    std::fs::read(&debug_file)
        .map(|x| Some(x))
        .map_err(|e| format!("Failed to read sibling debug file {}: {}", debug_file, e))
}
