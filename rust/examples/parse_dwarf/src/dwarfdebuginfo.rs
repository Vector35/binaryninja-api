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

use binaryninja::rc::*;
use binaryninja::types::Type;

use std::collections::{hash_map::Values, HashMap};
use std::hash::Hash;

/////////////////////////
// FunctionInfoBuilder

// TODO : Function local variables
#[derive(PartialEq, Eq, Hash)]
pub struct FunctionInfoBuilder<T: Eq + Hash + Copy> {
    pub full_name: Option<String>,
    pub raw_name: Option<String>,
    pub short_name: Option<String>,
    pub return_type: Option<T>,
    pub address: Option<u64>,
    pub parameters: Vec<(String, T)>,
}

impl<T: Eq + Hash + Copy> FunctionInfoBuilder<T> {
    pub fn update(
        &mut self,
        short_name: Option<String>,
        full_name: Option<String>,
        raw_name: Option<String>,
        return_type: Option<T>,
        address: Option<u64>,
        parameters: Option<Vec<(String, T)>>,
    ) {
        if full_name.is_some() {
            self.full_name = full_name;
        }

        if short_name.is_some() {
            self.short_name = short_name;
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

        if let Some(parameters) = parameters {
            self.parameters = parameters;
        }
    }
}

//////////////////////
// DebugInfoBuilder

// DWARF info is stored and displayed in a tree, but is really a graph
//  The purpose of this builder is to help resolve those graph edges by mapping partial function info and types to one DIE's UID (T) before adding the completed info to BN's debug info
pub struct DebugInfoBuilder<T: Eq + Hash + Copy> {
    functions: HashMap<T, FunctionInfoBuilder<T>>,
    types: HashMap<T, Ref<Type>>,
}

impl<T: Eq + Hash + Copy> DebugInfoBuilder<T> {
    pub fn new() -> Self {
        DebugInfoBuilder {
            functions: HashMap::new(),
            types: HashMap::new(),
        }
    }

    pub fn insert_function(
        &mut self,
        function_uid: T,
        short_name: Option<String>,
        full_name: Option<String>,
        raw_name: Option<String>,
        return_type: Option<T>,
        address: Option<u64>,
        parameters: Option<Vec<(String, T)>>,
    ) {
        if let Some(function) = self.functions.get_mut(&function_uid) {
            function.update(
                full_name,
                raw_name,
                short_name,
                return_type,
                address,
                parameters,
            );
        } else {
            self.functions.insert(
                function_uid,
                FunctionInfoBuilder {
                    full_name,
                    raw_name,
                    short_name,
                    return_type,
                    address,
                    parameters: parameters.unwrap_or_default(),
                },
            );
        }
    }

    pub fn get_functions(&self) -> Values<'_, T, FunctionInfoBuilder<T>> {
        self.functions.values()
    }

    pub fn add_type(&mut self, type_uid: T, t: Ref<Type>) {
        assert!(self.types.insert(type_uid, t).is_none());
    }

    pub fn get_type(&self, type_uid: T) -> Option<Ref<Type>> {
        match self.types.get(&type_uid) {
            Some(type_ref_ref) => Some((*type_ref_ref).clone()),
            None => None,
        }
    }

    pub fn remove_type(&mut self, type_uid: T) {
        self.types.remove(&type_uid);
    }

    pub fn contains_type(&self, type_uid: T) -> bool {
        self.types.get(&type_uid).is_some()
    }
}
