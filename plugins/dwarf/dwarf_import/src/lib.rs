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

mod die_handlers;
mod dwarfdebuginfo;
mod functions;
mod helpers;
mod types;

use std::collections::HashMap;
use std::path::PathBuf;

use crate::dwarfdebuginfo::{DebugInfoBuilder, DebugInfoBuilderContext};
use crate::functions::parse_function_entry;
use crate::helpers::{
    find_local_debug_file_from_path, get_attr_die, get_name, get_uid, DieReference,
};
use crate::types::parse_variable;

use binaryninja::binary_view::BinaryViewBase;
use binaryninja::{
    binary_view::{BinaryView, BinaryViewExt},
    debuginfo::{CustomDebugInfoParser, DebugInfo, DebugInfoParser},
    settings::Settings,
    template_simplifier::simplify_str_to_str,
};
use dwarfreader::create_section_reader_object;

use functions::parse_lexical_block;
use gimli::{
    constants, CfaRule, DebuggingInformationEntry, Dwarf, DwarfFileType, Reader, Section,
    SectionId, Unit, UnwindContext, UnwindSection,
};

use helpers::{get_build_id, load_debug_info_for_build_id};
use iset::IntervalMap;
use object::read::macho::FatArch;
use object::{Object, ObjectSection};

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
        let unit_offset = header.offset().as_debug_info_offset().map_or_else(
            || {
                tracing::warn!("Failed to get debug info offset for {:?}", header.offset());
                0
            },
            |x| x.0,
        );
        let unit = match dwarf.unit(header) {
            Ok(x) => x,
            Err(e) => {
                tracing::error!("Failed to get unit at {:#x}: {}", unit_offset, e);
                continue;
            }
        };
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
                tracing::error!("DWARF information is seriously malformed. Aborting parsing.");
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
                                    let resolved_entry = match entry_unit.entry(entry_offset) {
                                        Ok(x) => x,
                                        Err(e) => {
                                            tracing::error!("Failed to resolve entry in unit {:?} at offset {:#x} (resolve_namespace_name): {}", entry_unit.header.offset(), entry_offset.0, e);
                                            return;
                                        }
                                    };
                                    resolve_namespace_name(
                                        dwarf,
                                        entry_unit,
                                        &resolved_entry,
                                        debug_info_builder_context,
                                        namespace_qualifiers,
                                        depth,
                                    )
                                }
                                DieReference::Err => {
                                    tracing::warn!(
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
                        .to_string_lossy()
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
                            .to_string_lossy()
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
    file: &object::File,
    unwind_section: U,
) -> gimli::Result<iset::IntervalMap<u64, i64>>
where
    <U as UnwindSection<R>>::Offset: std::hash::Hash,
{
    let mut bases = gimli::BaseAddresses::default();

    if let Some(section) = file.section_by_name(".eh_frame_hdr") {
        bases = bases.set_eh_frame_hdr(section.address());
    }

    if let Some(section) = file.section_by_name(".eh_frame") {
        bases = bases.set_eh_frame(section.address());
    } else if let Some(section) = file.section_by_name(".debug_frame") {
        bases = bases.set_eh_frame(section.address());
    }

    if let Some(section) = file.section_by_name(".text") {
        bases = bases.set_text(section.address());
    }

    if let Some(section) = file.section_by_name(".got") {
        bases = bases.set_got(section.address());
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
                        tracing::error!("Failed to parse FDE: {}", e);
                        continue;
                    }
                };

                if fde.len() == 0 {
                    // This FDE is a terminator
                    return Ok(cfa_offsets);
                }

                if fde.initial_address().overflowing_add(fde.len()).1 {
                    tracing::warn!(
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
                                //TODO: can we normalize this to be sp-based?
                                /*
                                Switching to RBP from RSP in this example breaks things, and we should know that RBP = RSP - 8
                                    65   │   0x1139: CFA=RSP+8: RIP=[CFA-8]
                                    66   │   0x113a: CFA=RSP+16: RBP=[CFA-16], RIP=[CFA-8]
                                    67   │   0x113d: CFA=RBP+16: RBP=[CFA-16], RIP=[CFA-8]
                                    68   │   0x1162: CFA=RSP+8: RBP=[CFA-16], RIP=[CFA-8]

                                    can we
                                    know that CFA=RSP+8 at the beginning
                                    in the next instruction (66) we know RBP=[CFA-16]=[RSP-8]
                                    and do something with that?
                                */
                                // TODO: we should store offsets by register
                                if row.start_address() < row.end_address() {
                                    cfa_offsets
                                        .insert(row.start_address()..row.end_address(), *offset);
                                } else {
                                    tracing::debug!(
                                        "Invalid FDE table row addresses: {:#x}..{:#x}",
                                        row.start_address(),
                                        row.end_address()
                                    );
                                }
                            }
                            CfaRule::Expression(_) => {
                                tracing::debug!("Unhandled CFA expression when determining offset");
                            }
                        };
                    }
                }
            }
        }
    }
}

fn parse_range_data_offsets(file: &object::File) -> Result<IntervalMap<u64, i64>, String> {
    let dwo_file = file.section_by_name(".debug_info.dwo").is_some();
    let endian = match file.endianness() {
        object::Endianness::Little => gimli::RunTimeEndian::Little,
        object::Endianness::Big => gimli::RunTimeEndian::Big,
    };

    let section_reader = |section_id: SectionId| -> _ {
        create_section_reader_object(section_id, &file, endian, dwo_file)
    };

    if file.section_by_name(".eh_frame").is_some() {
        let mut eh_frame = gimli::EhFrame::load(section_reader)
            .map_err(|e| format!("Failed to load EH frame: {}", e))?;

        if file.architecture() == object::Architecture::Aarch64 {
            eh_frame.set_vendor(gimli::Vendor::AArch64);
        }

        if let Some(address_size) = file.architecture().address_size() {
            eh_frame.set_address_size(address_size.bytes());
        }

        parse_unwind_section(&file, eh_frame).map_err(|e| format!("Error parsing .eh_frame: {}", e))
    } else if file.section_by_name(".debug_frame").is_some() {
        let mut debug_frame = gimli::DebugFrame::load(section_reader)
            .map_err(|e| format!("Failed to load debug frame: {}", e))?;

        if file.architecture() == object::Architecture::Aarch64 {
            debug_frame.set_vendor(gimli::Vendor::AArch64);
        }

        if let Some(address_size) = file.architecture().address_size() {
            debug_frame.set_address_size(address_size.bytes());
        }
        parse_unwind_section(&file, debug_frame)
            .map_err(|e| format!("Error parsing .debug_frame: {}", e))
    } else {
        Ok(Default::default())
    }
}

fn parse_dwarf(
    bv: &BinaryView,
    debug_file: &object::File,
    supplementary_data: Option<&object::File>,
    progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
) -> Result<DebugInfoBuilder, String> {
    if debug_file.section_by_name(".gnu_debugaltlink").is_some() && supplementary_data.is_none() {
        tracing::warn!(".gnu_debugaltlink section present but no supplementary data provided. DWARF parsing may fail.")
    }

    let address_size = match debug_file.architecture().address_size() {
        Some(x) => x.bytes() as usize,
        None => bv.address_size(),
    };

    let range_data_offsets = parse_range_data_offsets(debug_file).unwrap_or_default();

    let dwo_file = debug_file.section_by_name(".debug_info.dwo").is_some();
    let endian = match debug_file.endianness() {
        object::Endianness::Little => gimli::RunTimeEndian::Little,
        object::Endianness::Big => gimli::RunTimeEndian::Big,
    };

    let mut section_reader = |section_id: SectionId| -> _ {
        create_section_reader_object(section_id, &debug_file, endian, dwo_file)
    };

    let mut dwarf = Dwarf::load(&mut section_reader)
        .map_err(|e| format!("Failed to load DWARF info: {}", e))?;

    if dwo_file {
        dwarf.file_type = DwarfFileType::Dwo;
    } else {
        dwarf.file_type = DwarfFileType::Main;
    }

    if let Some(sup_file) = supplementary_data {
        let sup_endian = match sup_file.endianness() {
            object::Endianness::Little => gimli::RunTimeEndian::Little,
            object::Endianness::Big => gimli::RunTimeEndian::Big,
        };

        let sup_dwo_file = sup_file.section_by_name(".debug_info.dwo").is_some();
        let sup_section_reader = |section_id: SectionId| -> _ {
            create_section_reader_object(section_id, &sup_file, sup_endian, sup_dwo_file)
        };
        if let Err(e) = dwarf.load_sup(sup_section_reader) {
            tracing::error!("Failed to load supplementary file: {}", e);
        }
    }

    // Create debug info builder and recover name mapping first
    //  Since DWARF is stored as a tree with arbitrary implicit edges among leaves,
    //   it is not possible to correctly track namespaces while you're parsing "in order" without backtracking,
    //   so we just do it up front
    let mut debug_info_builder = DebugInfoBuilder::new();
    debug_info_builder.set_range_data_offsets(range_data_offsets);

    if let Some(mut debug_info_builder_context) = DebugInfoBuilderContext::new(address_size, &dwarf)
    {
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
            let sup = match dwarf.sup() {
                Some(x) => x,
                None => {
                    tracing::error!(
                        "Supplemental units found but no supplementary DWARF info available"
                    );
                    break;
                }
            };
            parse_unit(
                sup,
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

fn parse_data_to_object<'a>(
    data: &'a [u8],
    target_bv: &BinaryView,
) -> Result<object::File<'a>, String> {
    // Try to parse as normal file, fall back to parsing as fat macho and selecting the right arch from the target bv
    if let Ok(o) = object::File::parse(data) {
        return Ok(o);
    }

    if let Some(bv_arch) = target_bv.default_arch() {
        let target_obj_arch = match bv_arch.name().as_str() {
            "x86" => object::Architecture::I386,
            "x86_64" => object::Architecture::X86_64,
            "aarch64" => object::Architecture::Aarch64,
            "armv7" | "thumb2" => object::Architecture::Arm,
            "mips32" => object::Architecture::Mips,
            "mips64" => object::Architecture::Mips64,
            "ppc" => object::Architecture::PowerPc,
            "ppc64" => object::Architecture::PowerPc64,
            _ => {
                return Err(format!(
                    "Unable to determine architecture to load from \"{}\"",
                    bv_arch.name()
                ));
            }
        };
        if let Ok(o) = object::read::macho::MachOFatFile32::parse(data) {
            for arch in o.arches() {
                if arch.architecture() == target_obj_arch {
                    let arch_data = arch
                        .data(data)
                        .map_err(|e| format!("Failed to read FatArch32: {}", e))?;
                    return object::File::parse(arch_data)
                        .map_err(|e| format!("Failed to parse object from FatArch32 data: {}", e));
                }
            }
        }

        if let Ok(o) = object::read::macho::MachOFatFile64::parse(data) {
            for arch in o.arches() {
                if arch.architecture() == target_obj_arch {
                    let arch_data = arch
                        .data(data)
                        .map_err(|e| format!("Failed to read FatArch64: {}", e))?;
                    return object::File::parse(arch_data)
                        .map_err(|e| format!("Failed to parse object from FatArch64 data: {}", e));
                }
            }
        }
    }

    Err("Unable to load object from data".to_string())
}

struct DWARFParser;

impl CustomDebugInfoParser for DWARFParser {
    fn is_valid(&self, view: &BinaryView) -> bool {
        if dwarfreader::is_valid(view) || dwarfreader::can_use_debuginfod(view) {
            return true;
        }
        if dwarfreader::has_build_id_section(view) {
            if let Ok(Some(build_id)) = get_build_id(view) {
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
        debug_bv: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        let Some(debug_data_vec) = dwarfreader::is_valid(debug_bv)
            .then(|| {
                // Load the raw view of the debug bv passed in if it has valid debug info
                let raw_view = debug_bv.raw_view().expect("Failed to get raw view");
                raw_view.read_vec(0, raw_view.len() as usize)
            })
            .or_else(|| {
                // Try loading sibling debug files
                match helpers::load_sibling_debug_file(bv) {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::error!("Failed loading sibling debug file: {}", e);
                        None
                    }
                }
            })
            .or_else(|| {
                // Try loading from the file's build id
                if let Ok(Some(build_id)) = get_build_id(bv) {
                    match load_debug_info_for_build_id(&build_id, bv) {
                        Ok(x) => x,
                        Err(e) => {
                            tracing::error!("Failed loading debug info from build id: {}", e);
                            None
                        }
                    }
                } else {
                    // No build id found
                    None
                }
            })
        else {
            // There isn't any dwarf info available to load
            return false;
        };

        let debug_file = match parse_data_to_object(debug_data_vec.as_slice(), bv) {
            Ok(x) => x,
            Err(e) => {
                tracing::error!("Failed to parse debug data: {}", e);
                return false;
            }
        };

        // TODO: allow passing a supplementary file path as a setting?
        // Try to load supplementary file from build id, falling back to file path
        let sup_view_data = debug_file.gnu_debugaltlink().ok().flatten().and_then(
            |(sup_filename, sup_build_id)| {
                // Try loading from build id
                let sup_data = match load_debug_info_for_build_id(sup_build_id, bv) {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::error!("Failed to load supplementary debug file: {}", e);
                        None
                    }
                };

                // Try loading from file path if build id loading didn't work
                sup_data.or_else(|| match std::str::from_utf8(sup_filename) {
                    Ok(x) => find_local_debug_file_from_path(&PathBuf::from(x), bv).and_then(
                        |sup_file_path| match std::fs::read(sup_file_path) {
                            Ok(sup_data) => Some(sup_data),
                            Err(e) => {
                                tracing::error!("Failed reading supplementary file {}: {}", x, e);
                                None
                            }
                        },
                    ),
                    Err(e) => {
                        tracing::error!("Supplementary file path is invalid utf8: {}", e);
                        None
                    }
                })
            },
        );

        let sup_file = sup_view_data.as_ref().and_then(|data| {
            match parse_data_to_object(data.as_slice(), bv) {
                Ok(x) => Some(x),
                Err(e) => {
                    tracing::error!("Failed to parse supplementary debug data: {}", e);
                    None
                }
            }
        });

        // If we have a sup file, verify its build id with the expected build id, else warn
        if let Some(sup_file) = &sup_file {
            if let Ok(Some((_, expected_build_id))) = debug_file.gnu_debugaltlink() {
                if let Ok(Some(loaded_sup_build_id)) = sup_file.build_id() {
                    if loaded_sup_build_id != expected_build_id {
                        tracing::warn!(
                            "Supplementary debug info build id ({}) does not match expected ({})",
                            loaded_sup_build_id
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<String>(),
                            expected_build_id
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<String>()
                        );
                    }
                }
            }
        }

        let result = match parse_dwarf(bv, &debug_file, sup_file.as_ref(), progress) {
            Ok(mut builder) => {
                builder.post_process(bv, debug_info).commit_info(debug_info);
                true
            }
            Err(e) => {
                tracing::error!("Failed to parse DWARF: {}", e);
                false
            }
        };

        result
    }
}

fn plugin_init() {
    binaryninja::tracing_init!("DWARF Import");

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
            "description" : "Paths to search for DWARF debug info.",
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
}

#[no_mangle]
#[allow(non_snake_case)]
#[cfg(not(feature = "demo"))]
pub extern "C" fn CorePluginInit() -> bool {
    plugin_init();
    true
}

#[no_mangle]
#[allow(non_snake_case)]
#[cfg(feature = "demo")]
pub extern "C" fn DwarfImportPluginInit() -> bool {
    plugin_init();
    true
}
