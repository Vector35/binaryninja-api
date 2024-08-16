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

use std::sync::OnceLock;

use crate::dwarfdebuginfo::{DebugInfoBuilder, DebugInfoBuilderContext, TypeUID};
use crate::{helpers::*, ReaderType};
use crate::types::get_type;

use binaryninja::templatesimplifier::simplify_str_to_str;
use cpp_demangle::DemangleOptions;
use gimli::{constants, DebuggingInformationEntry, Dwarf, Unit};
use log::debug;
use regex::Regex;

fn get_parameters<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
) -> (Vec<Option<(String, TypeUID)>>, bool) {
    if !entry.has_children() {
        return (vec![], false);
    }

    // We make a new tree from the current entry to iterate over its children
    let mut sub_die_tree = unit.entries_tree(Some(entry.offset())).unwrap();
    let root = sub_die_tree.root().unwrap();

    let mut variable_arguments = false;
    let mut result = vec![];
    let mut children = root.children();
    while let Some(child) = children.next().unwrap() {
        match child.entry().tag() {
            constants::DW_TAG_formal_parameter => {
                //TODO: if the param type is a typedef to an anonymous struct (typedef struct {...} foo) then this is reoslved to an anonymous struct instead of foo
                //  We should still recurse to make sure we load all types this param type depends on, but
                let name = debug_info_builder_context.get_name(dwarf, unit, child.entry());

                let type_ = get_type(
                    dwarf,
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
            constants::DW_TAG_unspecified_parameters => variable_arguments = true,
            _ => (),
        }
    }
    (result, variable_arguments)
}

pub(crate) fn parse_function_entry<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
) -> Option<usize> {
    // Collect function properties (if they exist in this DIE)
    let raw_name = get_raw_name(dwarf, unit, entry);
    let return_type = get_type(dwarf, unit, entry, debug_info_builder_context, debug_info_builder);
    let address = get_start_address(dwarf, unit, entry);
    let (parameters, variable_arguments) = get_parameters(dwarf, unit, entry, debug_info_builder_context, debug_info_builder);

    // If we have a raw name, it might be mangled, see if we can demangle it into full_name
    //  raw_name should contain a superset of the info we have in full_name
    let mut full_name = None;
    if let Some(possibly_mangled_name) = &raw_name {
        if possibly_mangled_name.starts_with('_') {
            static OPTIONS_MEM: OnceLock<DemangleOptions> = OnceLock::new();
            let demangle_options = OPTIONS_MEM.get_or_init(|| {
                DemangleOptions::new()
                    .no_return_type()
                    .hide_expression_literal_types()
                    .no_params()
            });

            static ABI_REGEX_MEM: OnceLock<Regex> = OnceLock::new();
            let abi_regex = ABI_REGEX_MEM.get_or_init(|| {
                Regex::new(r"\[abi:v\d+\]").unwrap()
            });
            if let Ok(sym) = cpp_demangle::Symbol::new(possibly_mangled_name) {
                if let Ok(demangled) = sym.demangle(demangle_options) {
                    let cleaned = abi_regex.replace_all(&demangled, "");
                    let simplified = simplify_str_to_str(&cleaned);
                    full_name = Some(simplified.to_string());
                }
            }
        }
    }

    // If we didn't demangle the raw name, fetch the name given
    if full_name.is_none() {
        full_name = debug_info_builder_context.get_name(dwarf, unit, entry)
    }

    if raw_name.is_none() && full_name.is_none() {
        debug!(
            "Function entry in DWARF without full or raw name: .debug_info offset {:?}",
            entry.offset().to_debug_info_offset(&unit.header)
        );
        return None;
    }

    debug_info_builder.insert_function(full_name, raw_name, return_type, address, &parameters, variable_arguments)
}
