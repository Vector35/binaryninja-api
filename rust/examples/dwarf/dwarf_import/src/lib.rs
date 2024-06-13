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

use std::collections::HashMap;

use crate::dwarfdebuginfo::{DebugInfoBuilder, DebugInfoBuilderContext};
use crate::functions::parse_function_entry;
use crate::helpers::{get_attr_die, get_name, get_uid, DieReference};
use crate::types::parse_variable;

use binaryninja::binaryview::BinaryViewBase;
use binaryninja::{
    binaryview::{BinaryView, BinaryViewExt},
    debuginfo::{CustomDebugInfoParser, DebugInfo, DebugInfoParser},
    logger,
    settings::Settings,
    templatesimplifier::simplify_str_to_str,
};
use dwarfreader::{
    create_section_reader, get_endian, is_dwo_dwarf, is_non_dwo_dwarf, is_raw_dwo_dwarf,
};

use gimli::{constants, DebuggingInformationEntry, Dwarf, DwarfFileType, Reader, Section, SectionId, Unit, UnwindSection};

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
                            namespace_qualifiers.push((depth, "anonymous_namespace".to_string()));
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
                                constants::DW_TAG_structure_type => {
                                    "anonymous_structure".to_string()
                                }
                                constants::DW_TAG_union_type => "anonymous_union".to_string(),
                                _ => unreachable!(),
                            },
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
                                    .map(|(_, namespace)| namespace.to_owned())
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

    let mut current_depth: isize = 0;
    let mut functions_by_depth: Vec<(Option<usize>, isize)> = vec![];

    // Really all we care about as we iterate the entries in a given unit is how they modify state (our perception of the file)
    // There's a lot of junk we don't care about in DWARF info, so we choose a couple DIEs and mutate state (add functions (which adds the types it uses) and keep track of what namespace we're in)
    while let Ok(Some((depth_delta, entry))) = entries.next_dfs() {
        *current_die_number += 1;
        if (*progress)(
            *current_die_number,
            debug_info_builder_context.total_die_count,
        )
        .is_err()
        {
            return; // Parsing canceled
        }

        current_depth = current_depth.saturating_add(depth_delta);

        loop {
            if let Some((_fn_idx, depth)) = functions_by_depth.last() {
                if current_depth <= *depth {
                    functions_by_depth.pop();
                }
                else {
                    break
                }
            }
            else {
                break;
            }
        }

        match entry.tag() {
            constants::DW_TAG_subprogram => {
                let fn_idx = parse_function_entry(unit, entry, debug_info_builder_context, debug_info_builder);
                functions_by_depth.push((fn_idx, current_depth));
            }
            constants::DW_TAG_variable => {
                let current_fn_idx = functions_by_depth.last().and_then(|x| x.0);
                parse_variable(unit, entry, debug_info_builder_context, debug_info_builder, current_fn_idx)
            }
            _ => (),
        }
    }
}

fn parse_eh_frame<R: Reader>(
    view: &BinaryView,
    mut eh_frame: gimli::EhFrame<R>,
) -> gimli::Result<iset::IntervalMap<u64, i64>> {
    eh_frame.set_address_size(view.address_size() as u8);

    let mut bases = gimli::BaseAddresses::default();
    if let Ok(section) = view.section_by_name(".eh_frame_hdr").or(view.section_by_name("__eh_frame_hdr")) {
        bases = bases.set_eh_frame_hdr(section.start());
    }
    if let Ok(section) = view.section_by_name(".eh_frame").or(view.section_by_name("__eh_frame")) {
        bases = bases.set_eh_frame(section.start());
    }
    if let Ok(section) = view.section_by_name(".text").or(view.section_by_name("__text")) {
        bases = bases.set_text(section.start());
    }
    if let Ok(section) = view.section_by_name(".got").or(view.section_by_name("__got")) {
        bases = bases.set_got(section.start());
    }

    let mut cies = HashMap::new();
    let mut cie_data_offsets = iset::IntervalMap::new();

    let mut entries = eh_frame.entries(&bases);
    loop {
        match entries.next()? {
            None => return Ok(cie_data_offsets),
            Some(gimli::CieOrFde::Cie(_cie)) => {
                // TODO: do we want to do anything with standalone CIEs?
            }
            Some(gimli::CieOrFde::Fde(partial)) => {
                let fde = match partial.parse(|_, bases, o| {
                    cies.entry(o)
                        .or_insert_with(|| eh_frame.cie_from_offset(bases, o))
                        .clone()
                }) {
                    Ok(fde) => fde,
                    Err(e) => {
                        error!("Failed to parse FDE: {}", e);
                        continue;
                    }
                };
                // Store CIE offset for FDE range
                cie_data_offsets.insert(
                    fde.initial_address()..fde.initial_address()+fde.len(),
                    fde.cie().data_alignment_factor()
                );
            }
        }
    }
}

fn parse_dwarf(
    bv: &BinaryView,
    debug_bv: &BinaryView,
    progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
) -> Result<DebugInfoBuilder, ()> {
    // Determine if this is a DWO
    // TODO : Make this more robust...some DWOs follow non-DWO conventions

    // Figure out if it's the given view or the raw view that has the dwarf info in it
    let raw_view = &debug_bv.raw_view().unwrap();
    let view = if is_dwo_dwarf(debug_bv) || is_non_dwo_dwarf(debug_bv) {
        debug_bv
    } else {
        raw_view
    };

    let dwo_file = is_dwo_dwarf(view) || is_raw_dwo_dwarf(view);

    // gimli setup
    let endian = get_endian(view);
    let mut section_reader =
        |section_id: SectionId| -> _ { create_section_reader(section_id, view, endian, dwo_file) };
    let mut dwarf = Dwarf::load(&mut section_reader).unwrap();
    if dwo_file {
        dwarf.file_type = DwarfFileType::Dwo;
    }

    let eh_frame_endian = get_endian(bv);
    let mut eh_frame_section_reader =
        |section_id: SectionId| -> _ { create_section_reader(section_id, bv, eh_frame_endian, dwo_file) };
    let eh_frame = gimli::EhFrame::load(&mut eh_frame_section_reader).unwrap();

    let range_data_offsets = parse_eh_frame(bv, eh_frame)
        .map_err(|e| println!("Error parsing .eh_frame: {}", e))?;

    // Create debug info builder and recover name mapping first
    //  Since DWARF is stored as a tree with arbitrary implicit edges among leaves,
    //   it is not possible to correctly track namespaces while you're parsing "in order" without backtracking,
    //   so we just do it up front
    let mut debug_info_builder = DebugInfoBuilder::new();
    debug_info_builder.set_range_data_offsets(range_data_offsets);
    if let Some(mut debug_info_builder_context) = DebugInfoBuilderContext::new(view, dwarf) {
        if !recover_names(&mut debug_info_builder_context, &progress)
            || debug_info_builder_context.total_die_count == 0
        {
            return Ok(debug_info_builder);
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
    Ok(debug_info_builder)
}

struct DWARFParser;

impl CustomDebugInfoParser for DWARFParser {
    fn is_valid(&self, view: &BinaryView) -> bool {
        dwarfreader::is_valid(view) ||
        dwarfreader::can_use_debuginfod(view) ||
        (dwarfreader::has_build_id_section(view) && helpers::find_local_debug_file(view).is_some())
    }

    fn parse_info(
        &self,
        debug_info: &mut DebugInfo,
        bv: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        let external_file = if !dwarfreader::is_valid(bv) {
            if dwarfreader::has_build_id_section(bv) {
                if let Ok(Some(debug_view)) = helpers::load_debug_info_for_build_id(bv) {
                    Some(debug_view)
                }
                else {
                    if dwarfreader::can_use_debuginfod(bv) {
                        if let Ok(debug_view) = helpers::download_debug_info(bv) {
                            Some(debug_view)
                        } else {
                            None
                        }
                    }
                    else {
                        None
                    }
                }
            }
            else {
                None
            }
        }
        else {
            None
        };

        match parse_dwarf(bv, external_file.as_deref().unwrap_or(debug_file), progress) {
            Ok(mut builder) => {
                builder
                .post_process(bv, debug_info)
                .commit_info(debug_info);
                true
            },
            Err(_) => {
                false
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    logger::init(LevelFilter::Debug).unwrap();

    let settings = Settings::new("");

    settings.register_setting_json(
        "network.enableDebuginfod",
        r#"{
            "title" : "Enable Debuginfod Support",
            "type" : "boolean",
            "default" : false,
            "description" : "Enable using debuginfod servers to fetch debug info for files with a .note.gnu.build-id section.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "network.debuginfodServers",
        r#"{
            "title" : "Debuginfod Server URLs",
            "type" : "array",
			"elementType" : "string",
			"default" : [],
            "description" : "Servers to use for fetching debug info for files with a .note.gnu.build-id section.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "analysis.debugInfo.debugDirectories",
        r#"{
            "title" : "Debug File Directories",
            "type" : "array",
			"elementType" : "string",
            "default" : [],
            "description" : "Paths to folder containing debug info stored by build id.",
            "ignore" : []
        }"#,
    );

    DebugInfoParser::register("DWARF", DWARFParser {});
    true
}
