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

mod die_handlers;
mod dwarfdebuginfo;
mod functions;
mod helpers;
mod types;

use crate::dwarfdebuginfo::DebugInfoBuilder;
use crate::functions::parse_function_entry;
use crate::helpers::{get_name, get_uid};
use crate::types::parse_data_variable;

use binaryninja::{
    binaryview::{BinaryView, BinaryViewExt},
    debuginfo::{CustomDebugInfoParser, DebugInfo, DebugInfoParser},
    logger,
    templatesimplifier::simplify_str_to_str,
};
use dwarfreader::{
    create_section_reader, get_endian, is_dwo_dwarf, is_non_dwo_dwarf, is_raw_dwo_dwarf,
};

use gimli::{
    constants, AttributeValue::UnitRef, DebuggingInformationEntry, Dwarf, DwarfFileType, Reader,
    Unit,
};

use log::LevelFilter;
use std::ffi::CString;

fn recover_names<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    debug_info_builder: &mut DebugInfoBuilder,
) -> usize {
    let mut total_die_count = 0;
    let mut iter = dwarf.units();
    while let Some(header) = iter.next().unwrap() {
        let unit = dwarf.unit(header).unwrap();
        let mut namespace_qualifiers: Vec<(isize, CString)> = vec![];
        let mut entries = unit.entries();
        let mut depth = 0;

        // The first entry in the unit is the header for the unit
        if let Ok(Some((delta_depth, _))) = entries.next_dfs() {
            depth += delta_depth;
            total_die_count += 1;
        }

        while let Ok(Some((delta_depth, entry))) = entries.next_dfs() {
            total_die_count += 1;
            depth += delta_depth;
            assert!(depth >= 0);

            // TODO : Better module/component support
            namespace_qualifiers.retain(|&(entry_depth, _)| entry_depth < depth);

            match entry.tag() {
                constants::DW_TAG_namespace => {
                    fn resolve_namespace_name<R: Reader<Offset = usize>>(
                        dwarf: &Dwarf<R>,
                        unit: &Unit<R>,
                        entry: &DebuggingInformationEntry<R>,
                        namespace_qualifiers: &mut Vec<(isize, CString)>,
                        depth: isize,
                    ) {
                        if let Some(namespace_qualifier) = get_name(dwarf, unit, entry) {
                            namespace_qualifiers.push((depth, namespace_qualifier));
                        } else if let Ok(Some(UnitRef(offset))) =
                            entry.attr_value(constants::DW_AT_extension)
                        {
                            resolve_namespace_name(
                                dwarf,
                                unit,
                                &unit.entry(offset).unwrap(),
                                namespace_qualifiers,
                                depth,
                            );
                        } else {
                            namespace_qualifiers
                                .push((depth, CString::new("anonymous_namespace").unwrap()));
                        }
                    }

                    resolve_namespace_name(dwarf, &unit, entry, &mut namespace_qualifiers, depth);
                }
                constants::DW_TAG_class_type => {
                    let class_name = get_name(dwarf, &unit, entry).unwrap();
                    namespace_qualifiers.push((depth, class_name));

                    debug_info_builder.set_name(
                        get_uid(&unit, entry),
                        CString::new(
                            simplify_str_to_str(
                                namespace_qualifiers
                                    .iter()
                                    .map(|(_, namespace)| namespace.to_string_lossy().to_string())
                                    .collect::<Vec<String>>()
                                    .join("::"),
                            )
                            .as_str(),
                        )
                        .unwrap(),
                    );
                }
                constants::DW_TAG_structure_type => {
                    if let Some(name) = get_name(dwarf, &unit, entry) {
                        namespace_qualifiers.push((depth, name))
                    } else {
                        namespace_qualifiers
                            .push((depth, CString::new("anonymous_structure").unwrap()))
                    }
                    debug_info_builder.set_name(
                        get_uid(&unit, entry),
                        CString::new(
                            simplify_str_to_str(
                                namespace_qualifiers
                                    .iter()
                                    .map(|(_, namespace)| namespace.to_string_lossy().to_string())
                                    .collect::<Vec<String>>()
                                    .join("::"),
                            )
                            .as_str(),
                        )
                        .unwrap(),
                    );
                }
                _ => {
                    if let Some(name) = get_name(dwarf, &unit, entry) {
                        debug_info_builder.set_name(
                            get_uid(&unit, entry),
                            CString::new(
                                simplify_str_to_str(
                                    namespace_qualifiers
                                        .iter()
                                        .chain(vec![&(-1, name)].into_iter())
                                        .map(|(_, namespace)| {
                                            namespace.to_string_lossy().to_string()
                                        })
                                        .collect::<Vec<String>>()
                                        .join("::"),
                                )
                                .as_str(),
                            )
                            .unwrap(),
                        );
                    }
                }
            }
        }
    }

    total_die_count
}

fn parse_unit<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    debug_info_builder: &mut DebugInfoBuilder,
    progress: &Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    total_die_count: usize,
) {
    let mut entries = unit.entries();

    // Really all we care about as we iterate the entries in a given unit is how they modify state (our perception of the file)
    // There's a lot of junk we don't care about in DWARF info, so we choose a couple DIEs and mutate state (add functions (which adds the types it uses) and keep track of what namespace we're in)
    let mut current_die_number = 0;
    while let Ok(Some((_, entry))) = entries.next_dfs() {
        current_die_number += 1;
        if current_die_number % 1000 == 0
            && (*progress)(current_die_number, total_die_count).is_err()
        {
            return; // Parsing canceled
        }

        match entry.tag() {
            constants::DW_TAG_subprogram => {
                parse_function_entry(dwarf, unit, entry, debug_info_builder)
            }
            constants::DW_TAG_variable => {
                parse_data_variable(dwarf, unit, entry, debug_info_builder)
            }
            _ => (),
        }
    }
}

fn parse_dwarf(
    view: &BinaryView,
    progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
) -> DebugInfoBuilder {
    // Determine if this is a DWO
    // TODO : Make this more robust...some DWOs follow non-DWO conventions
    let dwo_file = is_dwo_dwarf(view) || is_raw_dwo_dwarf(view);

    // Figure out if it's the given view or the raw view that has the dwarf info in it
    let raw_view = &view.raw_view().unwrap();
    let view = if is_dwo_dwarf(view) || is_non_dwo_dwarf(view) {
        view
    } else {
        raw_view
    };

    // gimli setup
    let endian = get_endian(view);
    let section_reader = create_section_reader(view, endian, dwo_file);
    let mut dwarf = Dwarf::load(&section_reader).unwrap();
    if dwo_file {
        dwarf.file_type = DwarfFileType::Dwo;
    }

    // Create debug info builder and recover name mapping first
    //  Since DWARF is stored as a tree with arbitrary implicit edges among leaves,
    //   it is not possible to correctly track namespaces while you're parsing "in order" without backtracking,
    //   so we just do it up front
    let mut debug_info_builder = DebugInfoBuilder::new();
    if (*progress)(0, 1).is_err() {
        return debug_info_builder; // Parsing canceled
    };
    let total_die_count = recover_names(&dwarf, &mut debug_info_builder);

    // Parse all the compilation units
    let mut iter = dwarf.units();
    while let Some(header) = iter.next().unwrap() {
        parse_unit(
            &dwarf,
            &dwarf.unit(header).unwrap(),
            &mut debug_info_builder,
            &progress,
            total_die_count,
        );
    }

    debug_info_builder
}

struct DWARFParser;

impl CustomDebugInfoParser for DWARFParser {
    fn is_valid(&self, view: &BinaryView) -> bool {
        dwarfreader::is_valid(view)
    }

    fn parse_info(
        &self,
        debug_info: &mut DebugInfo,
        _: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        // Parse dwarf info in raw view or from a separate file
        parse_dwarf(debug_file, progress).commit_info(debug_info);
        true
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    logger::init(LevelFilter::Debug).unwrap();

    DebugInfoParser::register("DWARF", DWARFParser {});
    true
}
