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

use crate::dwarfdebuginfo::{DebugInfoBuilder, DebugInfoBuilderContext, TypeUID};
use crate::helpers::*;
use crate::types::get_type;

use gimli::{constants, DebuggingInformationEntry, Reader, Unit};

fn get_parameters<R: Reader<Offset = usize>>(
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
) -> Vec<Option<(String, TypeUID)>> {
    if !entry.has_children() {
        vec![]
    } else {
        // We make a new tree from the current entry to iterate over its children
        let mut sub_die_tree = unit.entries_tree(Some(entry.offset())).unwrap();
        let root = sub_die_tree.root().unwrap();

        let mut result = vec![];
        let mut children = root.children();
        while let Some(child) = children.next().unwrap() {
            match child.entry().tag() {
                constants::DW_TAG_formal_parameter => {
                    let name = debug_info_builder_context.get_name(unit, child.entry());
                    let type_ = get_type(
                        unit,
                        child.entry(),
                        debug_info_builder_context,
                        debug_info_builder,
                    );
                    if let Some(parameter_name) = name {
                        if let Some(parameter_type) = type_ {
                            result.push(Some((parameter_name, parameter_type)));
                        } else {
                            result.push(Some((parameter_name, 0)))
                        }
                    } else {
                        result.push(None)
                    }
                }
                constants::DW_TAG_unspecified_parameters => (),
                _ => (),
            }
        }
        result
    }
}

pub(crate) fn parse_function_entry<R: Reader<Offset = usize>>(
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
) {
    // Collect function properties (if they exist in this DIE)
    let full_name = debug_info_builder_context.get_name(unit, entry);
    let raw_name = get_raw_name(unit, entry, debug_info_builder_context);
    let return_type = get_type(unit, entry, debug_info_builder_context, debug_info_builder);
    let address = get_start_address(unit, entry, debug_info_builder_context);
    let parameters = get_parameters(unit, entry, debug_info_builder_context, debug_info_builder);

    debug_info_builder.insert_function(full_name, raw_name, return_type, address, parameters);
}
