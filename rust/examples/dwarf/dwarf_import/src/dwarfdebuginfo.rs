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

use crate::helpers::{get_uid, resolve_specification, DieReference};

use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    debuginfo::{DebugFunctionInfo, DebugInfo},
    platform::Platform,
    rc::*,
    symbol::SymbolType,
    templatesimplifier::simplify_str_to_fqn,
    types::{Conf, FunctionParameter, Type},
};

use gimli::{DebuggingInformationEntry, Dwarf, Reader, Unit};

use log::{error, warn};
use std::{
    collections::{hash_map::Values, HashMap},
    hash::Hash,
};

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
}

impl FunctionInfoBuilder {
    pub(crate) fn update(
        &mut self,
        full_name: Option<String>,
        raw_name: Option<String>,
        return_type: Option<TypeUID>,
        address: Option<u64>,
        parameters: Vec<Option<(String, TypeUID)>>,
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

        for (i, new_parameter) in parameters.into_iter().enumerate() {
            match self.parameters.get(i) {
                Some(None) => self.parameters[i] = new_parameter,
                Some(Some(_)) => (),
                // Some(Some((name, _))) if name.as_bytes().is_empty() => {
                //     self.parameters[i] = new_parameter
                // }
                // Some(Some((_, uid))) if *uid == 0 => self.parameters[i] = new_parameter, // TODO : This is a placebo....void types aren't actually UID 0
                _ => self.parameters.push(new_parameter),
            }
        }
    }
}

//////////////////////
// DebugInfoBuilder

// TODO : Don't make this pub...fix the value thing
pub(crate) struct DebugType {
    name: String,
    t: Ref<Type>,
    commit: bool,
}

pub(crate) struct DebugInfoBuilderContext<R: Reader<Offset = usize>> {
    dwarf: Dwarf<R>,
    units: Vec<Unit<R>>,
    names: HashMap<TypeUID, String>,
    default_address_size: usize,
    pub(crate) total_die_count: usize,
}

impl<R: Reader<Offset = usize>> DebugInfoBuilderContext<R> {
    pub(crate) fn new(view: &BinaryView, dwarf: Dwarf<R>) -> Option<Self> {
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

        Some(Self {
            dwarf,
            units,
            names: HashMap::new(),
            default_address_size: view.address_size(),
            total_die_count: 0,
        })
    }

    pub(crate) fn dwarf(&self) -> &Dwarf<R> {
        &self.dwarf
    }

    pub(crate) fn units(&self) -> &[Unit<R>] {
        &self.units
    }

    pub(crate) fn default_address_size(&self) -> usize {
        self.default_address_size
    }

    pub(crate) fn set_name(&mut self, die_uid: TypeUID, name: String) {
        assert!(self.names.insert(die_uid, name).is_none());
    }

    pub(crate) fn get_name(
        &self,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Option<String> {
        match resolve_specification(unit, entry, self) {
            DieReference::UnitAndOffset((entry_unit, entry_offset)) => self
                .names
                .get(&get_uid(
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
    types: HashMap<TypeUID, DebugType>,
    data_variables: HashMap<u64, (Option<String>, TypeUID)>,
}

impl DebugInfoBuilder {
    pub(crate) fn new() -> Self {
        Self {
            functions: vec![],
            types: HashMap::new(),
            data_variables: HashMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert_function(
        &mut self,
        full_name: Option<String>,
        raw_name: Option<String>,
        return_type: Option<TypeUID>,
        address: Option<u64>,
        parameters: Vec<Option<(String, TypeUID)>>,
    ) {
        // Raw names should be the primary key, but if they don't exist, use the full name
        // TODO : Consider further falling back on address/architecture
        if let Some(function) = self
            .functions
            .iter_mut()
            .find(|func| func.raw_name.is_some() && func.raw_name == raw_name)
        {
            function.update(full_name, raw_name, return_type, address, parameters);
        } else if let Some(function) = self.functions.iter_mut().find(|func| {
            (func.raw_name.is_none() || raw_name.is_none())
                && func.full_name.is_some()
                && func.full_name == full_name
        }) {
            function.update(full_name, raw_name, return_type, address, parameters);
        } else {
            self.functions.push(FunctionInfoBuilder {
                full_name,
                raw_name,
                return_type,
                address,
                parameters,
                platform: None,
            });
        }
    }

    pub(crate) fn functions(&self) -> &[FunctionInfoBuilder] {
        &self.functions
    }

    pub(crate) fn types(&self) -> Values<'_, TypeUID, DebugType> {
        self.types.values()
    }

    pub(crate) fn add_type(
        &mut self,
        type_uid: TypeUID,
        name: String,
        t: Ref<Type>,
        commit: bool,
    ) {
        if let Some(DebugType {
            name: existing_name,
            t: existing_type,
            commit: _,
        }) = self.types.insert(
            type_uid,
            DebugType {
                name: name.clone(),
                t: t.clone(),
                commit,
            },
        ) {
            if existing_type != t && commit {
                error!("DWARF info contains duplicate type definition. Overwriting type `{}` (named `{:?}`) with `{}` (named `{:?}`)",
                    existing_type,
                    existing_name,
                    t,
                    name
                );
            }
        }
    }

    pub(crate) fn remove_type(&mut self, type_uid: TypeUID) {
        self.types.remove(&type_uid);
    }

    // TODO : Non-copy?
    pub(crate) fn get_type(&self, type_uid: TypeUID) -> Option<(String, Ref<Type>)> {
        self.types
            .get(&type_uid)
            .map(|type_ref_ref| (type_ref_ref.name.clone(), type_ref_ref.t.clone()))
    }

    pub(crate) fn contains_type(&self, type_uid: TypeUID) -> bool {
        self.types.get(&type_uid).is_some()
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
            let existing_type = self.get_type(existing_type_uid).unwrap().1;
            let new_type = self.get_type(type_uid).unwrap().1;

            if existing_type_uid != type_uid || existing_type != new_type {
                error!("DWARF info contains duplicate data variable definition. Overwriting data variable at 0x{:08x} (`{}`) with `{}`",
                    address,
                    self.get_type(existing_type_uid).unwrap().1,
                    self.get_type(type_uid).unwrap().1
                );
            }
        }
    }

    fn commit_types(&self, debug_info: &mut DebugInfo) {
        for debug_type in self.types() {
            if debug_type.commit {
                debug_info.add_type(debug_type.name.clone(), debug_type.t.as_ref(), &[]);
                // TODO : Components
            }
        }
    }

    // TODO : Consume data?
    fn commit_data_variables(&self, debug_info: &mut DebugInfo) {
        for (&address, (name, type_uid)) in &self.data_variables {
            assert!(debug_info.add_data_variable(
                address,
                &self.get_type(*type_uid).unwrap().1,
                name.clone(),
                &[] // TODO : Components
            ));
        }
    }

    fn get_function_type(&self, function: &FunctionInfoBuilder) -> Ref<Type> {
        let return_type = match function.return_type {
            Some(return_type_id) => Conf::new(self.get_type(return_type_id).unwrap().1.clone(), 0),
            _ => Conf::new(binaryninja::types::Type::void(), 0),
        };

        let parameters: Vec<FunctionParameter<String>> = function
            .parameters
            .iter()
            .filter_map(|parameter| match parameter {
                Some((name, 0)) => Some(FunctionParameter::new(Type::void(), name.clone(), None)),
                Some((name, uid)) => Some(FunctionParameter::new(
                    self.get_type(*uid).unwrap().1,
                    name.clone(),
                    None,
                )),
                _ => None,
            })
            .collect();

        // TODO : Handle
        let variable_parameters = false;

        binaryninja::types::Type::function(&return_type, &parameters, variable_parameters)
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
                vec![], // TODO : Components
            ));
        }
    }

    pub(crate) fn post_process(&mut self, bv: &BinaryView, _debug_info: &mut DebugInfo) -> &Self {
        // TODO : We don't need post-processing if we process correctly the first time....
        //   When originally resolving names, we need to check:
        //     If there's already a name from binja that's "more correct" than what we found (has more namespaces)
        //     If there's no name for the DIE, but there's a linkage name that's resolved in binja to a usable name
        // This is no longer true, because DWARF doesn't provide platform information for functions, so we at least need to post-process thumb functions

        for func in &mut self.functions {
            // If the function's raw name already exists in the binary...
            if let Some(raw_name) = &func.raw_name {
                if let Ok(symbol) = bv.symbol_by_raw_name(raw_name) {
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
                        if simplify_str_to_fqn(func_full_name, true).len()
                            < simplify_str_to_fqn(symbol_full_name.clone(), true).len()
                        {
                            func.full_name =
                                Some(symbol_full_name.to_string());
                        }
                    }
                }
            }

            if let Some(address) = func.address {
                let existing_functions = bv.functions_at(address);
                if existing_functions.len() > 1 {
                    warn!("Multiple existing functions at address {address:08x}. One or more functions at this address may have the wrong platform information. Please report this binary.");
                } else if existing_functions.len() == 1 {
                    func.platform = Some(existing_functions.get(0).platform());
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
