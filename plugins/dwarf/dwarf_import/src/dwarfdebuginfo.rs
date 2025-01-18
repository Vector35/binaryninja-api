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

use crate::{
    helpers::{get_uid, resolve_specification, DieReference},
    ReaderType,
};

use binaryninja::{
    binary_view::{BinaryView, BinaryViewBase, BinaryViewExt},
    debuginfo::{DebugFunctionInfo, DebugInfo},
    platform::Platform,
    rc::*,
    symbol::SymbolType,
    template_simplifier::simplify_str_to_fqn,
    types::{FunctionParameter, Type},
    variable::NamedVariableWithType,
};

use gimli::{DebuggingInformationEntry, Dwarf, Unit};

use binaryninja::confidence::Conf;
use binaryninja::variable::{Variable, VariableSourceType};
use indexmap::{map::Values, IndexMap};
use log::{debug, error, warn};
use std::{cmp::Ordering, collections::HashMap, hash::Hash};

pub(crate) type TypeUID = usize;

/////////////////////////
// FunctionInfoBuilder

// TODO : Function local variables
#[derive(PartialEq, Eq, Hash)]
pub(crate) struct FunctionInfoBuilder {
    pub(crate) full_name: Option<String>,
    pub(crate) raw_name: Option<String>,
    pub(crate) return_type: Option<TypeUID>,
    pub(crate) address: Option<u64>,
    pub(crate) parameters: Vec<Option<(String, TypeUID)>>,
    pub(crate) platform: Option<Ref<Platform>>,
    pub(crate) variable_arguments: bool,
    pub(crate) stack_variables: Vec<NamedVariableWithType>,
    pub(crate) use_cfa: bool, //TODO actually store more info about the frame base
}

impl FunctionInfoBuilder {
    pub(crate) fn update(
        &mut self,
        full_name: Option<String>,
        raw_name: Option<String>,
        return_type: Option<TypeUID>,
        address: Option<u64>,
        parameters: &Vec<Option<(String, TypeUID)>>,
    ) {
        if full_name.is_some() {
            self.full_name = full_name;
        }

        if raw_name.is_some() {
            self.raw_name = raw_name;
        }

        if return_type.is_some() {
            self.return_type = return_type;
        }

        if address.is_some() {
            self.address = address;
        }

        for (i, new_parameter) in parameters.iter().enumerate() {
            match self.parameters.get(i) {
                Some(None) => self.parameters[i] = new_parameter.clone(),
                Some(Some(_)) => (),
                // Some(Some((name, _))) if name.as_bytes().is_empty() => {
                //     self.parameters[i] = new_parameter
                // }
                // Some(Some((_, uid))) if *uid == 0 => self.parameters[i] = new_parameter, // TODO : This is a placebo....void types aren't actually UID 0
                _ => self.parameters.push(new_parameter.clone()),
            }
        }
    }
}

//////////////////////
// DebugInfoBuilder

// TODO : Don't make this pub...fix the value thing
pub(crate) struct DebugType {
    pub name: String,
    pub ty: Ref<Type>,
    pub commit: bool,
}

impl DebugType {
    pub fn get_type(&self) -> Ref<Type> {
        self.ty.clone()
    }
}

pub(crate) struct DebugInfoBuilderContext<R: ReaderType> {
    units: Vec<Unit<R>>,
    sup_units: Vec<Unit<R>>,
    names: HashMap<TypeUID, String>,
    default_address_size: usize,
    pub(crate) total_die_count: usize,
    pub(crate) total_unit_size_bytes: usize,
}

impl<R: ReaderType> DebugInfoBuilderContext<R> {
    pub(crate) fn new(view: &BinaryView, dwarf: &Dwarf<R>) -> Option<Self> {
        let mut units = vec![];
        let mut iter = dwarf.units();
        while let Ok(Some(header)) = iter.next() {
            if let Ok(unit) = dwarf.unit(header) {
                units.push(unit);
            } else {
                error!("Unable to read DWARF information. File may be malformed or corrupted. Not applying debug info.");
                return None;
            }
        }

        let mut sup_units = vec![];
        if let Some(sup_dwarf) = dwarf.sup() {
            let mut sup_iter = sup_dwarf.units();
            while let Ok(Some(header)) = sup_iter.next() {
                if let Ok(unit) = sup_dwarf.unit(header) {
                    sup_units.push(unit);
                } else {
                    error!("Unable to read supplementary DWARF information. File may be malformed or corrupted. Not applying debug info.");
                    return None;
                }
            }
        }

        Some(Self {
            units,
            sup_units,
            names: HashMap::new(),
            default_address_size: view.address_size(),
            total_die_count: 0,
            total_unit_size_bytes: 0,
        })
    }

    pub(crate) fn units(&self) -> &[Unit<R>] {
        &self.units
    }

    pub(crate) fn sup_units(&self) -> &[Unit<R>] {
        &self.sup_units
    }

    pub(crate) fn default_address_size(&self) -> usize {
        self.default_address_size
    }

    pub(crate) fn set_name(&mut self, die_uid: TypeUID, name: String) {
        // die_uids need to be unique here
        assert!(self.names.insert(die_uid, name).is_none());
    }

    pub(crate) fn get_name(
        &self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Option<String> {
        match resolve_specification(dwarf, unit, entry, self) {
            DieReference::UnitAndOffset((dwarf, entry_unit, entry_offset)) => self
                .names
                .get(&get_uid(
                    dwarf,
                    entry_unit,
                    &entry_unit.entry(entry_offset).unwrap(),
                ))
                .cloned(),
            DieReference::Err => None,
        }
    }
}

// DWARF info is stored and displayed in a tree, but is really a graph
//  The purpose of this builder is to help resolve those graph edges by mapping partial function
//  info and types to one DIE's UID (T) before adding the completed info to BN's debug info
pub(crate) struct DebugInfoBuilder {
    functions: Vec<FunctionInfoBuilder>,
    raw_function_name_indices: HashMap<String, usize>,
    full_function_name_indices: HashMap<String, usize>,
    types: IndexMap<TypeUID, DebugType>,
    data_variables: HashMap<u64, (Option<String>, TypeUID)>,
    range_data_offsets: iset::IntervalMap<u64, i64>,
}

impl DebugInfoBuilder {
    pub(crate) fn new() -> Self {
        Self {
            functions: vec![],
            raw_function_name_indices: HashMap::new(),
            full_function_name_indices: HashMap::new(),
            types: IndexMap::new(),
            data_variables: HashMap::new(),
            range_data_offsets: iset::IntervalMap::new(),
        }
    }

    pub(crate) fn set_range_data_offsets(&mut self, offsets: iset::IntervalMap<u64, i64>) {
        self.range_data_offsets = offsets
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert_function(
        &mut self,
        full_name: Option<String>,
        raw_name: Option<String>,
        return_type: Option<TypeUID>,
        address: Option<u64>,
        parameters: &Vec<Option<(String, TypeUID)>>,
        variable_arguments: bool,
        use_cfa: bool,
    ) -> Option<usize> {
        // Returns the index of the function
        // Raw names should be the primary key, but if they don't exist, use the full name
        // TODO : Consider further falling back on address/architecture

        /*
           If it has a raw_name and we know it, update it and return
           Else if it has a full_name and we know it, update it and return
           Else Add a new entry if we don't know the full_name or raw_name
        */

        if let Some(ident) = &raw_name {
            // check if we already know about this raw name's index
            // if we do, and the full name will change, remove the known full index if it exists
            // update the function
            // if the full name exists, update the stored index for the full name
            if let Some(idx) = self.raw_function_name_indices.get(ident) {
                let function = self.functions.get_mut(*idx).unwrap();

                if function.full_name.is_some() && function.full_name != full_name {
                    self.full_function_name_indices
                        .remove(function.full_name.as_ref().unwrap());
                }

                function.update(full_name, raw_name, return_type, address, parameters);

                if function.full_name.is_some() {
                    self.full_function_name_indices
                        .insert(function.full_name.clone().unwrap(), *idx);
                }

                return Some(*idx);
            }
        } else if let Some(ident) = &full_name {
            // check if we already know about this full name's index
            // if we do, and the raw name will change, remove the known raw index if it exists
            // update the function
            // if the raw name exists, update the stored index for the raw name
            if let Some(idx) = self.full_function_name_indices.get(ident) {
                let function = self.functions.get_mut(*idx).unwrap();

                if function.raw_name.is_some() && function.raw_name != raw_name {
                    self.raw_function_name_indices
                        .remove(function.raw_name.as_ref().unwrap());
                }

                function.update(full_name, raw_name, return_type, address, parameters);

                if function.raw_name.is_some() {
                    self.raw_function_name_indices
                        .insert(function.raw_name.clone().unwrap(), *idx);
                }

                return Some(*idx);
            }
        } else {
            debug!("Function entry in DWARF without full or raw name.");
            return None;
        }

        let function = FunctionInfoBuilder {
            full_name,
            raw_name,
            return_type,
            address,
            parameters: parameters.clone(),
            platform: None,
            variable_arguments,
            stack_variables: vec![],
            use_cfa,
        };

        if let Some(n) = &function.full_name {
            self.full_function_name_indices
                .insert(n.clone(), self.functions.len());
        }

        if let Some(n) = &function.raw_name {
            self.raw_function_name_indices
                .insert(n.clone(), self.functions.len());
        }

        self.functions.push(function);
        Some(self.functions.len() - 1)
    }

    pub(crate) fn functions(&self) -> &[FunctionInfoBuilder] {
        &self.functions
    }

    #[allow(dead_code)]
    pub(crate) fn types(&self) -> Values<'_, TypeUID, DebugType> {
        self.types.values()
    }

    pub(crate) fn add_type(&mut self, type_uid: TypeUID, name: String, t: Ref<Type>, commit: bool) {
        if let Some(DebugType {
            name: existing_name,
            ty: existing_type,
            commit: _,
        }) = self.types.insert(
            type_uid,
            DebugType {
                name: name.clone(),
                ty: t.clone(),
                commit,
            },
        ) {
            if existing_type != t && commit {
                warn!("DWARF info contains duplicate type definition. Overwriting type `{}` (named `{:?}`) with `{}` (named `{:?}`)",
                    existing_type,
                    existing_name,
                    t,
                    name
                );
            }
        }
    }

    pub(crate) fn remove_type(&mut self, type_uid: TypeUID) {
        self.types.swap_remove(&type_uid);
    }

    pub(crate) fn get_type(&self, type_uid: TypeUID) -> Option<&DebugType> {
        self.types.get(&type_uid)
    }

    pub(crate) fn contains_type(&self, type_uid: TypeUID) -> bool {
        self.types.contains_key(&type_uid)
    }

    pub(crate) fn add_stack_variable(
        &mut self,
        fn_idx: Option<usize>,
        offset: i64,
        name: Option<String>,
        type_uid: Option<TypeUID>,
        lexical_block: Option<&iset::IntervalSet<u64>>,
    ) {
        let name = match name {
            Some(x) => {
                if x.len() == 1 && x.chars().next() == Some('\x00') {
                    // Anonymous variable, generate name
                    format!("debug_var_{}", offset)
                } else {
                    x
                }
            }
            None => {
                // Anonymous variable, generate name
                format!("debug_var_{}", offset)
            }
        };

        let Some(function_index) = fn_idx else {
            // If we somehow lost track of what subprogram we're in or we're not actually in a subprogram
            error!(
                "Trying to add a local variable outside of a subprogram. Please report this issue."
            );
            return;
        };

        // Either get the known type or use a 0 confidence void type so we at least get the name applied
        let ty = match type_uid {
            Some(uid) => Conf::new(self.get_type(uid).unwrap().ty.clone(), 128),
            None => Conf::new(Type::void(), 0),
        };
        let function = &mut self.functions[function_index];

        // TODO: If we can't find a known offset can we try to guess somehow?

        let Some(func_addr) = function.address else {
            // If we somehow are processing a function's variables before the function is created
            error!("Trying to add a local variable without a known function start. Please report this issue.");
            return;
        };

        let Some(adjustment_at_variable_lifetime_start) = lexical_block
            .and_then(|block_ranges| {
                block_ranges
                    .unsorted_iter()
                    .find_map(|x| self.range_data_offsets.values_overlap(x.start).next())
            })
            .or_else(|| {
                // Try using the offset at the adjustment 4 bytes after the function start, in case the function starts with a stack adjustment
                // TODO: This is a decent heuristic but not perfect, since further adjustments could still be made
                self.range_data_offsets.values_overlap(func_addr + 4).next()
            })
            .or_else(|| {
                // If all else fails, use the function start address
                self.range_data_offsets.values_overlap(func_addr).next()
            })
        else {
            // Unknown why, but this is happening with MachO + external dSYM
            debug!("Refusing to add a local variable ({}@{}) to function at {} without a known CIE offset.", name, offset, func_addr);
            return;
        };

        // TODO: handle non-sp frame bases
        // TODO: if not in a lexical block these can be wrong, see https://github.com/Vector35/binaryninja-api/issues/5882#issuecomment-2406065057
        let adjusted_offset = if function.use_cfa {
            // Apply CFA offset to variable storage offset if DW_AT_frame_base is frame base is CFA
            offset + adjustment_at_variable_lifetime_start
        } else {
            // If it's using SP, we know the SP offset is <SP offset> + (<entry SP CFA offset> - <SP CFA offset>)
            let Some(adjustment_at_entry) =
                self.range_data_offsets.values_overlap(func_addr).next()
            else {
                // Unknown why, but this is happening with MachO + external dSYM
                debug!("Refusing to add a local variable ({}@{}) to function at {} without a known CIE offset for function start.", name, offset, func_addr);
                return;
            };

            offset + (adjustment_at_entry - adjustment_at_variable_lifetime_start)
        };

        if adjusted_offset > 0 {
            // If we somehow end up with a positive sp offset
            error!("Trying to add a local variable \"{}\" in function at {:#x} at positive storage offset {}. Please report this issue.", name, func_addr, adjusted_offset);
            return;
        }

        let var = Variable::new(
            VariableSourceType::StackVariableSourceType,
            0,
            adjusted_offset,
        );
        function
            .stack_variables
            .push(NamedVariableWithType::new(var, ty, name, false));
    }

    pub(crate) fn add_data_variable(
        &mut self,
        address: u64,
        name: Option<String>,
        type_uid: TypeUID,
    ) {
        if let Some((_existing_name, existing_type_uid)) =
            self.data_variables.insert(address, (name, type_uid))
        {
            let existing_type = self.get_type(existing_type_uid).unwrap().ty.as_ref();
            let new_type = self.get_type(type_uid).unwrap().ty.as_ref();

            if existing_type_uid != type_uid || existing_type != new_type {
                warn!("DWARF info contains duplicate data variable definition. Overwriting data variable at 0x{:08x} (`{}`) with `{}`",
                    address,
                    existing_type,
                    new_type
                );
            }
        }
    }

    fn commit_types(&self, debug_info: &mut DebugInfo) {
        let mut type_uids_by_name: HashMap<String, TypeUID> = HashMap::new();

        for (debug_type_uid, debug_type) in self.types.iter() {
            if !debug_type.commit {
                continue;
            }

            let mut debug_type_name = debug_type.name.clone();

            // Prevent storing two types with the same name and differing definitions
            if let Some(stored_uid) = type_uids_by_name.get(&debug_type_name) {
                let Some(stored_debug_type) = self.types.get(stored_uid) else {
                    error!("Stored type name without storing a type! Please report this error. UID: {}, name: {}", stored_uid, debug_type_name);
                    continue;
                };

                let mut skip_adding_type = false;
                if stored_debug_type.ty != debug_type.ty {
                    // We already stored a type with this name and it's a different type, deconflict the name and try again
                    let mut i = 1;
                    loop {
                        if let Some(stored_uid) = type_uids_by_name.get(&debug_type_name) {
                            if debug_type_uid == stored_uid {
                                // We already have a type with this name but it's the same type so we're ok
                                skip_adding_type = true;
                                break;
                            }
                            if let Some(stored_debug_type) = self.types.get(stored_uid) {
                                if stored_debug_type.ty == debug_type.ty {
                                    // We already have a type with this name but it's the same type so we're ok
                                    skip_adding_type = true;
                                    break;
                                }
                            }

                            debug_type_name = format!("{}_{}", debug_type.name, i);
                            i += 1;
                        } else {
                            // We found a unique name
                            break;
                        }
                    }
                }

                if skip_adding_type {
                    continue;
                }
            };

            // TODO : Components
            debug_info.add_type(&debug_type_name, &debug_type.ty, &[]);
            type_uids_by_name.insert(debug_type_name, *debug_type_uid);
        }
    }

    // TODO : Consume data?
    fn commit_data_variables(&self, debug_info: &mut DebugInfo) {
        for (&address, (name, type_uid)) in &self.data_variables {
            assert!(debug_info.add_data_variable(
                address,
                &self.get_type(*type_uid).unwrap().ty,
                name.clone(),
                &[] // TODO : Components
            ));
        }
    }

    fn get_function_type(&self, function: &FunctionInfoBuilder) -> Ref<Type> {
        let return_type = match function.return_type {
            Some(return_type_id) => {
                Conf::new(self.get_type(return_type_id).unwrap().ty.clone(), 128)
            }
            _ => Conf::new(Type::void(), 0),
        };

        let parameters: Vec<FunctionParameter> = function
            .parameters
            .iter()
            .filter_map(|parameter| match parameter {
                Some((name, 0)) => Some(FunctionParameter::new(Type::void(), name.clone(), None)),
                Some((name, uid)) => Some(FunctionParameter::new(
                    self.get_type(*uid).unwrap().ty.clone(),
                    name.clone(),
                    None,
                )),
                _ => None,
            })
            .collect();

        Type::function(&return_type, parameters, function.variable_arguments)
    }

    fn commit_functions(&self, debug_info: &mut DebugInfo) {
        for function in self.functions() {
            // let calling_convention: Option<Ref<CallingConvention<CoreArchitecture>>> = None;

            debug_info.add_function(DebugFunctionInfo::new(
                function.full_name.clone(),
                function.full_name.clone(), // TODO : This should eventually be changed, but the "full_name" should probably be the unsimplified version, and the "short_name" should be the simplified version...currently the symbols view shows the full version, so changing it here too makes it look bad in the UI
                function.raw_name.clone(),
                Some(self.get_function_type(function)),
                function.address,
                function.platform.clone(),
                vec![],                           // TODO : Components
                function.stack_variables.clone(), // TODO: local non-stack variables
            ));
        }
    }

    pub(crate) fn post_process(&mut self, bv: &BinaryView, _debug_info: &mut DebugInfo) -> &Self {
        //   When originally resolving names, we need to check:
        //     If there's already a name from binja that's "more correct" than what we found (has more namespaces)
        //     If there's no name for the DIE, but there's a linkage name that's resolved in binja to a usable name
        // This is no longer true, because DWARF doesn't provide platform information for functions, so we at least need to post-process thumb functions

        for func in &mut self.functions {
            // If the function's raw name already exists in the binary...
            if let Some(raw_name) = &func.raw_name {
                if let Some(symbol) = bv.symbol_by_raw_name(raw_name) {
                    // Link mangled names without addresses to existing symbols in the binary
                    if func.address.is_none() && func.raw_name.is_some() {
                        // DWARF doesn't contain GOT info, so remove any entries there...they will be wrong (relying on Binja's mechanisms for the GOT is good )
                        if symbol.sym_type() != SymbolType::ImportAddress {
                            func.address = Some(symbol.address());
                        }
                    }

                    if let Some(full_name) = &func.full_name {
                        let func_full_name = full_name;
                        let symbol_full_name = symbol.full_name();

                        // If our name has fewer namespaces than the existing name, assume we lost the namespace info
                        if simplify_str_to_fqn(func_full_name, true).items.len()
                            < simplify_str_to_fqn(symbol_full_name.clone(), true)
                                .items
                                .len()
                        {
                            func.full_name = Some(symbol_full_name.to_string());
                        }
                    }
                }
            }

            if let Some(address) = func.address.as_mut() {
                let (diff, overflowed) = bv.start().overflowing_sub(bv.original_image_base());
                if !overflowed {
                    *address = (*address).overflowing_add(diff).0; // rebase the address
                    let existing_functions = bv.functions_at(*address);
                    match existing_functions.len().cmp(&1) {
                        Ordering::Greater => {
                            warn!("Multiple existing functions at address {address:08x}. One or more functions at this address may have the wrong platform information. Please report this binary.");
                        }
                        Ordering::Equal => {
                            func.platform = Some(existing_functions.get(0).platform())
                        }
                        Ordering::Less => {}
                    }
                }
            }
        }

        self
    }

    pub(crate) fn commit_info(&self, debug_info: &mut DebugInfo) {
        self.commit_types(debug_info);
        self.commit_data_variables(debug_info);
        self.commit_functions(debug_info);
    }
}
