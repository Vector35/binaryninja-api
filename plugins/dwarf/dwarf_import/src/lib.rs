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

use binaryninja::binary_view::BinaryViewBase;
use binaryninja::{
    binary_view::{BinaryView, BinaryViewExt},
    debuginfo::{CustomDebugInfoParser, DebugInfo, DebugInfoParser},
    settings::Settings,
    template_simplifier::simplify_str_to_str,
};
use dwarfreader::{
    create_section_reader, get_endian, is_dwo_dwarf, is_non_dwo_dwarf, is_raw_dwo_dwarf,
};

use functions::parse_lexical_block;
use gimli::{
    constants, CfaRule, DebuggingInformationEntry, Dwarf, DwarfFileType, Reader, Section,
    SectionId, Unit, UnwindContext, UnwindSection,
};

use binaryninja::logger::Logger;
use helpers::{get_build_id, load_debug_info_for_build_id};
use log::{debug, error, warn};

trait ReaderType: Reader<Offset = usize> {}
impl<T: Reader<Offset = usize>> ReaderType for T {}

pub(crate) fn split_progress<'b, F: Fn(usize, usize) -> Result<(), ()> + 'b>(
    original_fn: F,
    subpart: usize,
    subpart_weights: &[f64],
) -> Box<dyn Fn(usize, usize) -> Result<(), ()> + 'b> {
    // Normalize weights
    let weight_sum: f64 = subpart_weights.iter().sum();
    if weight_sum < 0.0001 {
        return Box::new(|_, _| Ok(()));
    }

    // Keep a running count of weights for the start
    let mut subpart_starts = vec![];
    let mut start = 0f64;
    for w in subpart_weights {
        subpart_starts.push(start);
        start += *w;
    }

    let subpart_start = subpart_starts[subpart] / weight_sum;
    let weight = subpart_weights[subpart] / weight_sum;

    Box::new(move |cur: usize, max: usize| {
        // Just use a large number for easy divisibility
        let steps = 1000000f64;
        let subpart_size = steps * weight;
        let subpart_progress = ((cur as f64) / (max as f64)) * subpart_size;

        original_fn(
            (subpart_start * steps + subpart_progress) as usize,
            steps as usize,
        )
    })
}

fn calculate_total_unit_bytes<R: ReaderType>(
    dwarf: &Dwarf<R>,
    debug_info_builder_context: &mut DebugInfoBuilderContext<R>,
) {
    let mut iter = dwarf.units();
    let mut total_size: usize = 0;
    while let Ok(Some(header)) = iter.next() {
        total_size += header.length_including_self();
    }
    debug_info_builder_context.total_unit_size_bytes = total_size;
}

fn recover_names<R: ReaderType>(
    dwarf: &Dwarf<R>,
    debug_info_builder_context: &mut DebugInfoBuilderContext<R>,
    progress: &dyn Fn(usize, usize) -> Result<(), ()>,
) -> bool {
    let mut res = true;
    if let Some(sup_dwarf) = dwarf.sup() {
        res = recover_names_internal(sup_dwarf, debug_info_builder_context, progress);
    }

    if res {
        res = recover_names_internal(dwarf, debug_info_builder_context, progress);
    }
    res
}

fn recover_names_internal<R: ReaderType>(
    dwarf: &Dwarf<R>,
    debug_info_builder_context: &mut DebugInfoBuilderContext<R>,
    progress: &dyn Fn(usize, usize) -> Result<(), ()>,
) -> bool {
    let mut iter = dwarf.units();
    let mut current_byte_offset: usize = 0;
    while let Ok(Some(header)) = iter.next() {
        let unit_offset = header.offset().as_debug_info_offset().unwrap().0;
        let unit = dwarf.unit(header).unwrap();
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

            if (*progress)(
                current_byte_offset,
                debug_info_builder_context.total_unit_size_bytes,
            )
            .is_err()
            {
                return false; // Parsing canceled
            };
            current_byte_offset = unit_offset + entry.offset().0;

            depth += delta_depth;
            if depth < 0 {
                error!("DWARF information is seriously malformed. Aborting parsing.");
                return false;
            }

            // TODO : Better module/component support
            namespace_qualifiers.retain(|&(entry_depth, _)| entry_depth < depth);

            match entry.tag() {
                constants::DW_TAG_namespace => {
                    fn resolve_namespace_name<R: ReaderType>(
                        dwarf: &Dwarf<R>,
                        unit: &Unit<R>,
                        entry: &DebuggingInformationEntry<R>,
                        debug_info_builder_context: &DebugInfoBuilderContext<R>,
                        namespace_qualifiers: &mut Vec<(isize, String)>,
                        depth: isize,
                    ) {
                        if let Some(namespace_qualifier) =
                            get_name(dwarf, unit, entry, debug_info_builder_context)
                        {
                            namespace_qualifiers.push((depth, namespace_qualifier));
                        } else if let Some(die_reference) = get_attr_die(
                            dwarf,
                            unit,
                            entry,
                            debug_info_builder_context,
                            constants::DW_AT_extension,
                        ) {
                            match die_reference {
                                DieReference::UnitAndOffset((dwarf, entry_unit, entry_offset)) => {
                                    resolve_namespace_name(
                                        dwarf,
                                        entry_unit,
                                        &entry_unit.entry(entry_offset).unwrap(),
                                        debug_info_builder_context,
                                        namespace_qualifiers,
                                        depth,
                                    )
                                }
                                DieReference::Err => {
                                    warn!(
                                        "Failed to fetch DIE when resolving namespace. Debug information may be incomplete."
                                    );
                                }
                            }
                        } else {
                            namespace_qualifiers.push((depth, "anonymous_namespace".to_string()));
                        }
                    }

                    resolve_namespace_name(
                        dwarf,
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
                    if let Some(name) = get_name(dwarf, &unit, entry, debug_info_builder_context) {
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
                        get_uid(dwarf, &unit, entry),
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
                    if let Some(name) = get_name(dwarf, &unit, entry, debug_info_builder_context) {
                        debug_info_builder_context.set_name(
                            get_uid(dwarf, &unit, entry),
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
                    if let Some(name) = get_name(dwarf, &unit, entry, debug_info_builder_context) {
                        debug_info_builder_context.set_name(get_uid(dwarf, &unit, entry), name);
                    }
                }
            }
        }
    }

    true
}

fn parse_unit<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
    progress: &dyn Fn(usize, usize) -> Result<(), ()>,
    current_die_number: &mut usize,
) {
    let mut entries = unit.entries();

    let mut current_depth: isize = 0;
    let mut functions_by_depth: Vec<(Option<usize>, isize)> = vec![];
    let mut lexical_blocks_by_depth: Vec<(iset::IntervalSet<u64>, isize)> = vec![];

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
                } else {
                    break;
                }
            } else {
                break;
            }

            if let Some((_lexical_block, depth)) = lexical_blocks_by_depth.last() {
                if current_depth <= *depth {
                    lexical_blocks_by_depth.pop();
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        match entry.tag() {
            constants::DW_TAG_subprogram => {
                let fn_idx = parse_function_entry(
                    dwarf,
                    unit,
                    entry,
                    debug_info_builder_context,
                    debug_info_builder,
                );
                functions_by_depth.push((fn_idx, current_depth));
            }
            constants::DW_TAG_lexical_block => {
                if let Some(block_ranges) = parse_lexical_block(dwarf, unit, entry) {
                    lexical_blocks_by_depth.push((block_ranges, current_depth));
                }
            }
            constants::DW_TAG_variable => {
                let current_fn_idx = functions_by_depth.last().and_then(|x| x.0);
                let current_lexical_block = lexical_blocks_by_depth.last().and_then(|x| Some(&x.0));
                parse_variable(
                    dwarf,
                    unit,
                    entry,
                    debug_info_builder_context,
                    debug_info_builder,
                    current_fn_idx,
                    current_lexical_block,
                )
            }
            constants::DW_TAG_class_type
            | constants::DW_TAG_enumeration_type
            | constants::DW_TAG_structure_type
            | constants::DW_TAG_union_type
            | constants::DW_TAG_typedef => {
                // Ensure types are loaded even if they're unused
                types::get_type(
                    dwarf,
                    unit,
                    entry,
                    debug_info_builder_context,
                    debug_info_builder,
                );
            }
            _ => (),
        }
    }
}

fn parse_unwind_section<R: Reader, U: UnwindSection<R>>(
    view: &BinaryView,
    unwind_section: U,
) -> gimli::Result<iset::IntervalMap<u64, i64>>
where
    <U as UnwindSection<R>>::Offset: std::hash::Hash,
{
    let mut bases = gimli::BaseAddresses::default();

    if let Some(section) = view
        .section_by_name(".eh_frame_hdr")
        .or(view.section_by_name("__eh_frame_hdr"))
    {
        bases = bases.set_eh_frame_hdr(section.start());
    }

    if let Some(section) = view
        .section_by_name(".eh_frame")
        .or(view.section_by_name("__eh_frame"))
    {
        bases = bases.set_eh_frame(section.start());
    } else if let Some(section) = view
        .section_by_name(".debug_frame")
        .or(view.section_by_name("__debug_frame"))
    {
        bases = bases.set_eh_frame(section.start());
    }

    if let Some(section) = view
        .section_by_name(".text")
        .or(view.section_by_name("__text"))
    {
        bases = bases.set_text(section.start());
    }

    if let Some(section) = view
        .section_by_name(".got")
        .or(view.section_by_name("__got"))
    {
        bases = bases.set_got(section.start());
    }

    let mut cies = HashMap::new();
    let mut cfa_offsets = iset::IntervalMap::new();

    let mut entries = unwind_section.entries(&bases);
    let mut unwind_context = UnwindContext::new();
    loop {
        match entries.next()? {
            None => return Ok(cfa_offsets),
            Some(gimli::CieOrFde::Cie(_cie)) => {
                // TODO: do we want to do anything with standalone CIEs?
            }
            Some(gimli::CieOrFde::Fde(partial)) => {
                let fde = match partial.parse(|_, bases, o| {
                    cies.entry(o)
                        .or_insert_with(|| unwind_section.cie_from_offset(bases, o))
                        .clone()
                }) {
                    Ok(fde) => fde,
                    Err(e) => {
                        error!("Failed to parse FDE: {}", e);
                        continue;
                    }
                };

                if fde.len() == 0 {
                    // This FDE is a terminator
                    return Ok(cfa_offsets);
                }

                if fde.initial_address().overflowing_add(fde.len()).1 {
                    warn!(
                        "FDE at offset {:?} exceeds bounds of memory space! {:#x} + length {:#x}",
                        fde.offset(),
                        fde.initial_address(),
                        fde.len()
                    );
                } else {
                    // Walk the FDE table rows and store their CFA
                    let mut fde_table = fde.rows(&unwind_section, &bases, &mut unwind_context)?;

                    while let Some(row) = fde_table.next_row()? {
                        match row.cfa() {
                            CfaRule::RegisterAndOffset {
                                register: _,
                                offset,
                            } => {
                                // TODO: we should store offsets by register
                                if row.start_address() < row.end_address() {
                                    cfa_offsets
                                        .insert(row.start_address()..row.end_address(), *offset);
                                } else {
                                    debug!(
                                        "Invalid FDE table row addresses: {:#x}..{:#x}",
                                        row.start_address(),
                                        row.end_address()
                                    );
                                }
                            }
                            CfaRule::Expression(_) => {
                                debug!("Unhandled CFA expression when determining offset");
                            }
                        };
                    }
                }
            }
        }
    }
}

fn get_supplementary_build_id(bv: &BinaryView) -> Option<String> {
    let raw_view = bv.raw_view()?;
    if let Some(section) = raw_view.section_by_name(".gnu_debugaltlink") {
        let start = section.start();
        let len = section.len();

        if len < 20 {
            // Not large enough to hold a build id
            return None;
        }

        raw_view
            .read_vec(start, len)
            .splitn(2, |x| *x == 0)
            .last()
            .map(|a| a.iter().map(|b| format!("{:02x}", b)).collect())
    } else {
        None
    }
}

fn parse_dwarf(
    _bv: &BinaryView,
    debug_bv: &BinaryView,
    supplementary_bv: Option<&BinaryView>,
    progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
) -> Result<DebugInfoBuilder, ()> {
    // TODO: warn if no supplementary file and .gnu_debugaltlink section present

    // Determine if this is a DWO
    // TODO : Make this more robust...some DWOs follow non-DWO conventions

    // Figure out if it's the given view or the raw view that has the dwarf info in it
    let raw_view = &debug_bv.raw_view().ok_or(())?;
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

    let mut dwarf = match Dwarf::load(&mut section_reader) {
        Ok(x) => x,
        Err(e) => {
            error!("Failed to load DWARF info: {}", e);
            return Err(());
        }
    };

    if dwo_file {
        dwarf.file_type = DwarfFileType::Dwo;
    } else {
        dwarf.file_type = DwarfFileType::Main;
    }

    if let Some(sup_bv) = supplementary_bv {
        let sup_endian = get_endian(sup_bv);
        let sup_dwo_file = is_dwo_dwarf(sup_bv) || is_raw_dwo_dwarf(sup_bv);
        let sup_section_reader = |section_id: SectionId| -> _ {
            create_section_reader(section_id, sup_bv, sup_endian, sup_dwo_file)
        };
        if let Err(e) = dwarf.load_sup(sup_section_reader) {
            error!("Failed to load supplementary file: {}", e);
        }
    }

    let range_data_offsets;
    if view.section_by_name(".eh_frame").is_some() || view.section_by_name("__eh_frame").is_some() {
        let eh_frame_endian = get_endian(view);
        let eh_frame_section_reader = |section_id: SectionId| -> _ {
            create_section_reader(section_id, view, eh_frame_endian, dwo_file)
        };
        let mut eh_frame = gimli::EhFrame::load(eh_frame_section_reader).unwrap();
        eh_frame.set_address_size(view.address_size() as u8);
        range_data_offsets = parse_unwind_section(view, eh_frame)
            .map_err(|e| error!("Error parsing .eh_frame: {}", e))?;
    } else if view.section_by_name(".debug_frame").is_some()
        || view.section_by_name("__debug_frame").is_some()
    {
        let debug_frame_endian = get_endian(view);
        let debug_frame_section_reader = |section_id: SectionId| -> _ {
            create_section_reader(section_id, view, debug_frame_endian, dwo_file)
        };
        let mut debug_frame = gimli::DebugFrame::load(debug_frame_section_reader).unwrap();
        debug_frame.set_address_size(view.address_size() as u8);
        range_data_offsets = parse_unwind_section(view, debug_frame)
            .map_err(|e| error!("Error parsing .debug_frame: {}", e))?;
    } else {
        range_data_offsets = Default::default();
    }

    // Create debug info builder and recover name mapping first
    //  Since DWARF is stored as a tree with arbitrary implicit edges among leaves,
    //   it is not possible to correctly track namespaces while you're parsing "in order" without backtracking,
    //   so we just do it up front
    let mut debug_info_builder = DebugInfoBuilder::new();
    debug_info_builder.set_range_data_offsets(range_data_offsets);

    if let Some(mut debug_info_builder_context) = DebugInfoBuilderContext::new(view, &dwarf) {
        calculate_total_unit_bytes(&dwarf, &mut debug_info_builder_context);

        let progress_weights = [0.5, 0.5];
        let name_progress = split_progress(&progress, 0, &progress_weights);
        let parse_progress = split_progress(&progress, 1, &progress_weights);

        if !recover_names(&dwarf, &mut debug_info_builder_context, &name_progress)
            || debug_info_builder_context.total_die_count == 0
        {
            return Ok(debug_info_builder);
        }

        // Parse all the compilation units
        let mut current_die_number = 0;

        for unit in debug_info_builder_context.sup_units() {
            parse_unit(
                dwarf.sup().unwrap(),
                unit,
                &debug_info_builder_context,
                &mut debug_info_builder,
                &parse_progress,
                &mut current_die_number,
            );
        }

        for unit in debug_info_builder_context.units() {
            parse_unit(
                &dwarf,
                unit,
                &debug_info_builder_context,
                &mut debug_info_builder,
                &parse_progress,
                &mut current_die_number,
            );
        }
    }

    Ok(debug_info_builder)
}

struct DWARFParser;

impl CustomDebugInfoParser for DWARFParser {
    fn is_valid(&self, view: &BinaryView) -> bool {
        if dwarfreader::is_valid(view) || dwarfreader::can_use_debuginfod(view) {
            return true;
        }
        if dwarfreader::has_build_id_section(view) {
            if let Ok(build_id) = get_build_id(view) {
                if helpers::find_local_debug_file_for_build_id(&build_id, view).is_some() {
                    return true;
                }
            }
        }
        if helpers::find_sibling_debug_file(view).is_some() {
            return true;
        }
        false
    }

    fn parse_info(
        &self,
        debug_info: &mut DebugInfo,
        bv: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        let (external_file, close_external) = if !dwarfreader::is_valid(bv) {
            if let (Some(debug_view), x) = helpers::load_sibling_debug_file(bv) {
                (Some(debug_view), x)
            } else if let Ok(build_id) = get_build_id(bv) {
                load_debug_info_for_build_id(&build_id, bv)
            } else {
                (None, false)
            }
        } else {
            (None, false)
        };

        let sup_bv = get_supplementary_build_id(external_file.as_deref().unwrap_or(debug_file))
            .and_then(|build_id| {
                load_debug_info_for_build_id(&build_id, bv)
                    .0
                    .map(|x| x.raw_view().unwrap())
            });

        let result = match parse_dwarf(
            bv,
            external_file.as_deref().unwrap_or(debug_file),
            sup_bv.as_deref(),
            progress,
        ) {
            Ok(mut builder) => {
                builder.post_process(bv, debug_info).commit_info(debug_info);
                true
            }
            Err(_) => false,
        };

        if let (Some(ext), true) = (external_file, close_external) {
            ext.file().close();
        }

        result
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("DWARF").init();

    let settings = Settings::new();

    settings.register_setting_json(
        "network.enableDebuginfod",
        r#"{
            "title" : "Enable Debuginfod Support",
            "type" : "boolean",
            "default" : false,
            "description" : "Enable using Debuginfod servers to fetch DWARF debug info for files with a .note.gnu.build-id section.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "network.debuginfodServers",
        r#"{
            "title" : "Debuginfod Server URLs",
            "type" : "array",
            "sorted" : true,
            "default" : [],
            "description" : "Servers to use for fetching DWARF debug info for files with a .note.gnu.build-id section.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "analysis.debugInfo.enableDebugDirectories",
        r#"{
            "title" : "Enable Debug File Directories",
            "type" : "boolean",
            "default" : true,
            "description" : "Enable searching local debug directories for DWARF debug info.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "analysis.debugInfo.debugDirectories",
        r#"{
            "title" : "Debug File Directories",
            "type" : "array",
            "sorted" : true,
            "default" : [],
            "description" : "Paths to folder containing DWARF debug info stored by build id.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "analysis.debugInfo.loadSiblingDebugFiles",
        r#"{
            "title" : "Enable Loading of Sibling Debug Files",
            "type" : "boolean",
            "default" : true,
            "description" : "Enable automatic loading of X.debug and X.dSYM files next to a file named X.",
            "ignore" : []
        }"#,
    );

    DebugInfoParser::register("DWARF", DWARFParser {});
    true
}
