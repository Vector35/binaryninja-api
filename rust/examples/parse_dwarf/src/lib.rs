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

mod types;
use crate::types::get_type;

mod helpers;
use crate::helpers::*;

mod dwarfdebuginfo;
use crate::dwarfdebuginfo::DebugInfoBuilder;

use binaryninja::{
    binaryview::{BinaryView, BinaryViewExt},
    debuginfo::{CustomDebugInfoParser, DebugFunctionInfo, DebugInfo, DebugInfoParser},
    types::Type,
};

use gimli::{constants, DebuggingInformationEntry, Dwarf, DwarfFileType, Reader, Unit, UnitOffset};

fn get_parameters<'a, R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    mut debug_info_builder: &mut DebugInfoBuilder<UnitOffset>,
) -> Option<Vec<(String, UnitOffset)>> {
    // TODO : Get tree for entry
    // TODO : (Might need to flip the last two things)
    // TODO : Collect the formal parameters and unspecified's as well

    if !entry.has_children() {
        None
    } else {
        // We make a new tree from the current entry to iterate over its children
        // TODO : We could instead pass the `entries` object down from parse_dwarf to avoid parsing the same object multiple times
        let mut sub_die_tree = unit.entries_tree(Some(entry.offset())).unwrap();
        let root = sub_die_tree.root().unwrap();

        let mut result = vec![];
        let mut children = root.children();
        while let Some(child) = children.next().unwrap() {
            match child.entry().tag() {
                constants::DW_TAG_formal_parameter => {
                    // TODO : Remove the safety-rails; when this plugin is complete, it'll always be safe to unwrap()
                    if let (Some(parameter_name), Some(parameter_type)) = (
                        get_name(&dwarf, &unit, &child.entry()),
                        get_type(&dwarf, &unit, &child.entry(), &mut debug_info_builder),
                    ) {
                        result.push((parameter_name, parameter_type));
                    }
                    // let parameter_name = get_name(&dwarf, &unit, &child.entry()).unwrap();
                    // let parameter_type =
                    //     get_type(&dwarf, &unit, &child.entry(), &mut debug_info_builder).unwrap();
                    // result.push((parameter_name, parameter_type));
                }
                constants::DW_TAG_unspecified_parameters => (),
                _ => (),
            }
        }
        Some(result)
    }
}

#[inline]
fn parse_function_entry<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    namespace_qualifiers: &mut Vec<(isize, String)>,
    mut debug_info_builder: &mut DebugInfoBuilder<UnitOffset>,
) {
    // TODO : Handle OOT, stubs/trampolines

    // Collect function properties (if they exist in this DIE)
    let raw_name = get_raw_name(&dwarf, &unit, &entry);
    let short_name = get_name(&dwarf, &unit, &entry);
    let full_name = recover_full_name(&short_name, namespace_qualifiers); // TODO : This function call might be expensive, and can be done fewer times in an outer loop instead
    let return_type = get_type(&dwarf, &unit, &entry, &mut debug_info_builder);
    let address = get_start_address(&dwarf, &unit, &entry);
    let parameters = get_parameters(&dwarf, &unit, &entry, &mut debug_info_builder);

    // Functions can be declared and defined in different parts of the tree, and decls and defs can hold different parts of the information we need
    //   But there /should/ (TODO : Verify) be only one unique "base" DIE for each function
    let base_entry = get_base_entry(&unit, &entry);

    debug_info_builder.insert_function(
        base_entry,
        full_name,
        raw_name,
        short_name,
        return_type,
        address,
        parameters,
    );
}

fn parse_unit<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    mut debug_info_builder: &mut DebugInfoBuilder<UnitOffset>,
) {
    let mut namespace_qualifiers: Vec<(isize, String)> = vec![];
    let mut entries = unit.entries();
    let mut depth = 0;

    // The first entry in the unit is the header for the unit
    // TODO : Support compilation units/modules/components
    if let Ok(Some((delta_depth, _))) = entries.next_dfs() {
        depth += delta_depth;
    }

    // Really all we care about as we iterate the entries in a given unit is how they modify state (our perception of the file)
    //  There's a lot of junk we don't care about in DWARF info, so we choose a couple DIEs and mutate state (add functions (which adds the types it uses) and keep track of what namespace we're in)
    while let Ok(Some((delta_depth, entry))) = entries.next_dfs() {
        depth += delta_depth;
        assert!(depth >= 0); // TODO : Properly handle this

        // TODO : Better module/component support
        namespace_qualifiers.retain(|&(entry_depth, _)| entry_depth < depth);

        match entry.tag() {
            constants::DW_TAG_namespace => {
                namespace_qualifiers.push((depth, get_name(&dwarf, &unit, &entry).unwrap()))
            }
            constants::DW_TAG_class_type => {
                namespace_qualifiers.push((depth, get_name(&dwarf, &unit, &entry).unwrap()))
            }
            constants::DW_TAG_structure_type => {
                // TODO : Is this necessary?
                if let Some(name) = get_name(&dwarf, &unit, &entry) {
                    namespace_qualifiers.push((depth, name))
                } else {
                    println!("Couldn't get name for structure_type");
                }
            }
            constants::DW_TAG_subprogram => parse_function_entry(
                &dwarf,
                &unit,
                &entry,
                &mut namespace_qualifiers,
                &mut debug_info_builder,
            ),
            _ => (),
            // TODO : Parse and add all types in a program, not just
        }
    }
}

fn parse_dwarf(
    mut debug_info_builder: &mut DebugInfoBuilder<UnitOffset>,
    view: &BinaryView,
    dwo_file: bool,
) {
    // TODO : This only works for non-DWO files, but it should be able to work for both (there's some function call to set GIMLI into DWO mode)
    // TODO : Function names have disappeared?

    let endian = get_endian(view);
    let section_reader = create_section_reader(view, endian, dwo_file);
    let empty_reader = create_empty_reader(endian);
    let mut dwarf = Dwarf::load(&section_reader, &empty_reader).unwrap();
    if dwo_file {
        dwarf.file_type = DwarfFileType::Dwo;
    }

    let mut iter = dwarf.units();
    while let Some(header) = iter.next().unwrap() {
        let unit = dwarf.unit(header).unwrap();
        parse_unit(&dwarf, &unit, &mut debug_info_builder);
    }
}

struct DWARFParser;

impl CustomDebugInfoParser for DWARFParser {
    fn is_valid(&self, view: &BinaryView) -> bool {
        is_non_dwo_dwarf(view)
            || is_parent_non_dwo_dwarf(view)
            || is_dwo_dwarf(view)
            || is_parent_dwo_dwarf(view)
    }

    fn parse_info(&self, debug_info: &mut DebugInfo, view: &BinaryView) {
        let mut dwarf_debug_info = DebugInfoBuilder::new();

        if is_non_dwo_dwarf(view) {
            parse_dwarf(&mut dwarf_debug_info, &view, false);
        } else if is_parent_non_dwo_dwarf(view) {
            parse_dwarf(&mut dwarf_debug_info, &view.parent_view().unwrap(), false);
        } else if is_dwo_dwarf(view) {
            parse_dwarf(&mut dwarf_debug_info, &view, true);
        } else if is_parent_dwo_dwarf(view) {
            parse_dwarf(&mut dwarf_debug_info, &view.parent_view().unwrap(), true);
        }

        // Much of the data we collected is likely incomplete, so we need to filter those away
        // TODO : For functions with valid, partial info we should allow their addition with more APIs (eg, no return type, no name)
        for function in dwarf_debug_info.get_functions() {
            if let Some(address) = function.address {
                let full_name: String;
                if let Some(name) = &function.full_name {
                    full_name = name.to_string();
                } else {
                    full_name = "".to_string();
                }
                let raw_name: String;
                if let Some(name) = &function.raw_name {
                    raw_name = name.to_string();
                } else {
                    raw_name = "".to_string();
                }
                let short_name: String;
                if let Some(name) = &function.short_name {
                    short_name = name.to_string();
                } else {
                    short_name = "".to_string();
                }

                let return_type;
                if let Some(return_type_id) = function.return_type {
                    return_type = dwarf_debug_info.get_type(return_type_id).unwrap().clone();
                } else {
                    return_type = Type::void();
                }

                debug_info.add_function(DebugFunctionInfo::new(
                    full_name,
                    raw_name,
                    short_name,
                    return_type,
                    address,
                    function
                        .parameters
                        .iter()
                        .map(|(s, uid)| {
                            (s.clone(), dwarf_debug_info.get_type(*uid).unwrap().clone())
                        })
                        .collect(),
                ));
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    DebugInfoParser::register("DWARF", DWARFParser {});
    true
}
