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

mod die_handlers;
mod dwarfdebuginfo;
mod functions;
mod helpers;
mod types;

use crate::dwarfdebuginfo::{DebugInfoBuilder, DebugInfoBuilderContext};
use crate::functions::parse_function_entry;
use crate::helpers::{get_attr_die, get_name, get_uid, DieReference};
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

use gimli::{constants, DebuggingInformationEntry, Dwarf, DwarfFileType, Reader, SectionId, Unit};

use log::{error, warn, LevelFilter};

fn recover_names<R: Reader<Offset = usize>>(
    debug_info_builder_context: &mut DebugInfoBuilderContext<R>,
    progress: &dyn Fn(usize, usize) -> Result<(), ()>,
) -> bool {
    let mut iter = debug_info_builder_context.dwarf().units();
    while let Ok(Some(header)) = iter.next() {
        let unit = debug_info_builder_context.dwarf().unit(header).unwrap();
        let mut namespace_qualifiers: Vec<(isize, String)> = vec![];
        let mut entries = unit.entries();
        let mut depth = 0;

        // The first entry in the unit is the header for the unit
        if let Ok(Some((delta_depth, _))) = entries.next_dfs() {
            depth += delta_depth;
            debug_info_builder_context.total_die_count += 1;
        }

        while let Ok(Some((delta_depth, entry))) = entries.next_dfs() {
            debug_info_builder_context.total_die_count += 1;

            if (*progress)(0, debug_info_builder_context.total_die_count).is_err() {
                return false; // Parsing canceled
            };

            depth += delta_depth;
            if depth < 0 {
                error!("DWARF information is seriously malformed. Aborting parsing.");
                return false;
            }

            // TODO : Better module/component support
            namespace_qualifiers.retain(|&(entry_depth, _)| entry_depth < depth);

            match entry.tag() {
                constants::DW_TAG_namespace => {
                    fn resolve_namespace_name<R: Reader<Offset = usize>>(
                        unit: &Unit<R>,
                        entry: &DebuggingInformationEntry<R>,
                        debug_info_builder_context: &DebugInfoBuilderContext<R>,
                        namespace_qualifiers: &mut Vec<(isize, String)>,
                        depth: isize,
                    ) {
                        if let Some(namespace_qualifier) =
                            get_name(unit, entry, debug_info_builder_context)
                        {
                            namespace_qualifiers.push((depth, namespace_qualifier));
                        } else if let Some(die_reference) = get_attr_die(
                            unit,
                            entry,
                            debug_info_builder_context,
                            constants::DW_AT_extension,
                        ) {
                            match die_reference {
                                DieReference::UnitAndOffset((entry_unit, entry_offset)) => {
                                    resolve_namespace_name(
                                        entry_unit,
                                        &entry_unit.entry(entry_offset).unwrap(),
                                        debug_info_builder_context,
                                        namespace_qualifiers,
                                        depth,
                                    )
                                }
                                DieReference::Err => {
                                    warn!(
                                        "Failed to fetch DIE. Debug information may be incomplete."
                                    );
                                }
                            }
                        } else {
                            namespace_qualifiers
                                .push((depth, "anonymous_namespace".to_string()));
                        }
                    }

                    resolve_namespace_name(
                        &unit,
                        entry,
                        debug_info_builder_context,
                        &mut namespace_qualifiers,
                        depth,
                    );
                }
                constants::DW_TAG_class_type
                | constants::DW_TAG_structure_type
                | constants::DW_TAG_union_type => {
                    if let Some(name) = get_name(&unit, entry, debug_info_builder_context) {
                        namespace_qualifiers.push((depth, name))
                    } else {
                        namespace_qualifiers.push((
                            depth,
                            match entry.tag() {
                                constants::DW_TAG_class_type => "anonymous_class".to_string(),
                                constants::DW_TAG_structure_type => "anonymous_structure".to_string(),
                                constants::DW_TAG_union_type => "anonymous_union".to_string(),
                                _ => unreachable!(),
                            }
                        ))
                    }
                    debug_info_builder_context.set_name(
                        get_uid(&unit, entry),
                            simplify_str_to_str(
                                namespace_qualifiers
                                    .iter()
                                    .map(|(_, namespace)| namespace.to_owned())
                                    .collect::<Vec<String>>()
                                    .join("::"),
                            )
                            .to_string(),
                    );
                }
                constants::DW_TAG_typedef
                | constants::DW_TAG_subprogram
                | constants::DW_TAG_enumeration_type => {
                    if let Some(name) = get_name(&unit, entry, debug_info_builder_context) {
                        debug_info_builder_context.set_name(
                            get_uid(&unit, entry),
                                simplify_str_to_str(
                                    namespace_qualifiers
                                        .iter()
                                        .chain(vec![&(-1, name)].into_iter())
                                        .map(|(_, namespace)| {
                                            namespace.to_owned()
                                        })
                                        .collect::<Vec<String>>()
                                        .join("::"),
                                )
                                .to_string(),
                        );
                    }
                }
                _ => {
                    if let Some(name) = get_name(&unit, entry, debug_info_builder_context) {
                        debug_info_builder_context.set_name(get_uid(&unit, entry), name);
                    }
                }
            }
        }
    }

    true
}

fn parse_unit<R: Reader<Offset = usize>>(
    unit: &Unit<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
    progress: &dyn Fn(usize, usize) -> Result<(), ()>,
    current_die_number: &mut usize,
) {
    let mut entries = unit.entries();

    // Really all we care about as we iterate the entries in a given unit is how they modify state (our perception of the file)
    // There's a lot of junk we don't care about in DWARF info, so we choose a couple DIEs and mutate state (add functions (which adds the types it uses) and keep track of what namespace we're in)
    while let Ok(Some((_, entry))) = entries.next_dfs() {
        *current_die_number += 1;
        if (*progress)(
            *current_die_number,
            debug_info_builder_context.total_die_count,
        )
        .is_err()
        {
            return; // Parsing canceled
        }

        match entry.tag() {
            constants::DW_TAG_subprogram => {
                parse_function_entry(unit, entry, debug_info_builder_context, debug_info_builder)
            }
            constants::DW_TAG_variable => {
                parse_data_variable(unit, entry, debug_info_builder_context, debug_info_builder)
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
    let mut section_reader =
        |section_id: SectionId| -> _ { create_section_reader(section_id, view, endian, dwo_file) };
    let mut dwarf = Dwarf::load(&mut section_reader).unwrap();
    if dwo_file {
        dwarf.file_type = DwarfFileType::Dwo;
    }

    // Create debug info builder and recover name mapping first
    //  Since DWARF is stored as a tree with arbitrary implicit edges among leaves,
    //   it is not possible to correctly track namespaces while you're parsing "in order" without backtracking,
    //   so we just do it up front
    let mut debug_info_builder = DebugInfoBuilder::new();
    if let Some(mut debug_info_builder_context) = DebugInfoBuilderContext::new(view, dwarf) {
        if !recover_names(&mut debug_info_builder_context, &progress)
            || debug_info_builder_context.total_die_count == 0
        {
            return debug_info_builder;
        }

        // Parse all the compilation units
        let mut current_die_number = 0;
        for unit in debug_info_builder_context.units() {
            parse_unit(
                unit,
                &debug_info_builder_context,
                &mut debug_info_builder,
                &progress,
                &mut current_die_number,
            );
        }
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
        bv: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        parse_dwarf(debug_file, progress)
            .post_process(bv, debug_info)
            .commit_info(debug_info);
        true
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    logger::init(LevelFilter::Debug).unwrap();

    DebugInfoParser::register("DWARF", DWARFParser {});
    true
}
