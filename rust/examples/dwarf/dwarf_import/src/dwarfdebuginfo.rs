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

use crate::helpers::{get_uid, resolve_specification, DieReference};

use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase},
    debuginfo::{DebugFunctionInfo, DebugInfo},
    rc::*,
    templatesimplifier::simplify_str_to_str,
    types::{Conf, FunctionParameter, Type},
};

use gimli::{DebuggingInformationEntry, Dwarf, Reader, Unit};

use log::error;
use std::{
    collections::{hash_map::Values, HashMap},
    ffi::CString,
    hash::Hash,
};

pub(crate) type TypeUID = usize;

/////////////////////////
// FunctionInfoBuilder

// TODO : Function local variables
#[derive(PartialEq, Eq, Hash)]
pub struct FunctionInfoBuilder {
    pub full_name: Option<CString>,
    pub raw_name: Option<CString>,
    pub return_type: Option<TypeUID>,
    pub address: Option<u64>,
    pub parameters: Vec<Option<(CString, TypeUID)>>,
}

impl FunctionInfoBuilder {
    pub fn update(
        &mut self,
        full_name: Option<CString>,
        raw_name: Option<CString>,
        return_type: Option<TypeUID>,
        address: Option<u64>,
        parameters: Vec<Option<(CString, TypeUID)>>,
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
            if let Some(old_parameter) = self.parameters.get(i) {
                if old_parameter.is_none() {
                    self.parameters[i] = new_parameter;
                }
            } else {
                self.parameters.push(new_parameter);
            }
        }
    }
}

//////////////////////
// DebugInfoBuilder

// TODO : Don't make this pub...fix the value thing
pub(crate) struct DebugType {
    name: CString,
    t: Ref<Type>,
    commit: bool,
}

// DWARF info is stored and displayed in a tree, but is really a graph
//  The purpose of this builder is to help resolve those graph edges by mapping partial function
//  info and types to one DIE's UID (T) before adding the completed info to BN's debug info
pub struct DebugInfoBuilder {
    functions: Vec<FunctionInfoBuilder>,
    types: HashMap<TypeUID, DebugType>,
    data_variables: HashMap<u64, (Option<CString>, TypeUID)>,
    names: HashMap<TypeUID, CString>,
    default_address_size: usize,
}

impl DebugInfoBuilder {
    pub fn new(view: &BinaryView) -> Self {
        DebugInfoBuilder {
            functions: vec![],
            types: HashMap::new(),
            data_variables: HashMap::new(),
            names: HashMap::new(),
            default_address_size: view.address_size(),
        }
    }

    pub fn default_address_size(&self) -> usize {
        self.default_address_size
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_function(
        &mut self,
        full_name: Option<CString>,
        raw_name: Option<CString>,
        return_type: Option<TypeUID>,
        address: Option<u64>,
        parameters: Vec<Option<(CString, TypeUID)>>,
    ) {
        if let Some(function) = self.functions.iter_mut().find(|func| {
            (func.raw_name.is_some() && func.raw_name == raw_name)
                || (func.full_name.is_some() && func.full_name == full_name)
        }) {
            function.update(full_name, raw_name, return_type, address, parameters);
        } else {
            self.functions.push(FunctionInfoBuilder {
                full_name,
                raw_name,
                return_type,
                address,
                parameters,
            });
        }
    }

    pub fn functions(&self) -> &[FunctionInfoBuilder] {
        &self.functions
    }

    pub(crate) fn types(&self) -> Values<'_, TypeUID, DebugType> {
        self.types.values()
    }

    pub fn add_type(&mut self, type_uid: TypeUID, name: CString, t: Ref<Type>, commit: bool) {
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
            if existing_type != t {
                error!("DWARF info contains duplicate type definition. Overwriting type `{}` (named `{:?}`) with `{}` (named `{:?}`)",
                    existing_type,
                    existing_name,
                    t,
                    name
                );
            }
        }
    }

    pub fn remove_type(&mut self, type_uid: TypeUID) {
        self.types.remove(&type_uid);
    }

    // TODO : Non-copy?
    pub fn get_type(&self, type_uid: TypeUID) -> Option<(CString, Ref<Type>)> {
        self.types
            .get(&type_uid)
            .map(|type_ref_ref| (type_ref_ref.name.clone(), type_ref_ref.t.clone()))
    }

    pub fn contains_type(&self, type_uid: TypeUID) -> bool {
        self.types.get(&type_uid).is_some()
    }

    pub fn add_data_variable(&mut self, address: u64, name: Option<CString>, type_uid: TypeUID) {
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

    pub fn set_name(&mut self, die_uid: TypeUID, name: CString) {
        assert!(self.names.insert(die_uid, name).is_none());
    }

    pub fn get_name<R: Reader<Offset = usize>>(
        &self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Option<CString> {
        match resolve_specification(dwarf, unit, entry) {
            DieReference::Offset(entry_offset) => self
                .names
                .get(&get_uid(unit, &unit.entry(entry_offset).unwrap()))
                .cloned(),
            DieReference::UnitAndOffset((entry_unit, entry_offset)) => self
                .names
                .get(&get_uid(
                    &entry_unit,
                    &entry_unit.entry(entry_offset).unwrap(),
                ))
                .cloned(),
        }
    }

    fn commit_types(&self, debug_info: &mut DebugInfo) {
        for debug_type in self.types() {
            if debug_type.commit {
                debug_info.add_type(debug_type.name.clone(), debug_type.t.as_ref());
            }
        }
    }

    // TODO : Consume data?
    fn commit_data_variables(&self, debug_info: &mut DebugInfo) {
        for (&address, (name, type_uid)) in &self.data_variables {
            assert!(debug_info.add_data_variable(
                address,
                &self.get_type(*type_uid).unwrap().1,
                name.clone()
            ));
        }
    }

    fn commit_functions(&self, debug_info: &mut DebugInfo) {
        for function in self.functions() {
            let return_type = match function.return_type {
                Some(return_type_id) => {
                    Conf::new(self.get_type(return_type_id).unwrap().1.clone(), 0)
                }
                _ => Conf::new(binaryninja::types::Type::void(), 0),
            };

            let parameters: Vec<FunctionParameter<CString>> = function
                .parameters
                .iter()
                .filter_map(|parameter| match parameter {
                    Some((name, 0)) => {
                        Some(FunctionParameter::new(Type::void(), name.clone(), None))
                    }
                    Some((name, uid)) => Some(FunctionParameter::new(
                        self.get_type(*uid).unwrap().1,
                        name.clone(),
                        None,
                    )),
                    _ => None,
                })
                .collect();

            // TODO : Handle
            let platform = None;
            let variable_parameters = false;
            // let calling_convention: Option<Ref<CallingConvention<CoreArchitecture>>> = None;

            let function_type =
                binaryninja::types::Type::function(&return_type, &parameters, variable_parameters);

            let simplified_full_name = function
                .full_name
                .as_ref()
                .map(|name| simplify_str_to_str(name.as_ref()).as_str().to_owned())
                .map(|simp| CString::new(simp).unwrap());

            debug_info.add_function(DebugFunctionInfo::new(
                simplified_full_name.clone(),
                simplified_full_name, // TODO : This should eventually be changed, but the "full_name" should probably be the unsimplified version, and the "short_name" should be the simplified version...currently the symbols view shows the full version, so changing it here too makes it look bad in the UI
                function.raw_name.clone(),
                Some(function_type),
                function.address,
                platform,
            ));
        }
    }

    pub fn commit_info(&self, debug_info: &mut DebugInfo) {
        self.commit_types(debug_info);
        self.commit_data_variables(debug_info);
        self.commit_functions(debug_info);
    }
}
