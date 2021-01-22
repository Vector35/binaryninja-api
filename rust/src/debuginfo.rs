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

use binaryninjacore_sys::*;

// TODO : Documentation
//   Types need to be created in a specific order; if you have a pointer to a struct, you need to define that struct and all its fields before you can define what a pointer to that struct is
//   Though in reality we might need to forward declare all structs and classes and come back later to populate them
//   Either way, this being the case, you're required to give each type a UID for all your types with which Binary Ninja can track dependencies efficiently
//   The intended workflow of using DebugInfo is to first create `FunctionInfoBuilder`s, iterating your debug info and gathering whatever information you can about your functions (creating types for return values and parameters along the way and adding them to the DebugInfo, but not registering them with the BV)
//   Then destill that information into `FunctionInfo` and adding those to the DebugInfo,
// TODO : Move the code that converts FunctionInfoBuilder's into TypeInfo from the module into the core library
// TODO : Or move all the FunctionInfoBuilder stuff out
//   Then you're done and BN will take your DebugInfo and apply it to the binary best we can

use crate::binaryview::BinaryView;
use crate::rc::*;
use crate::string::BnStrCompatible;
use crate::string::BnString;
use crate::types::Type;

use std::hash::Hash;
use std::mem;
use std::os::raw::{c_char, c_void};

//////////////////////
//  DebugInfoParser

#[derive(PartialEq, Eq, Hash)]
pub struct DebugInfoParser {
    pub(crate) handle: *mut BNDebugInfoParser,
}

impl DebugInfoParser {
    pub(crate) unsafe fn from_raw(handle: *mut BNDebugInfoParser) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    // TODO : do I need to "init plugins?"
    pub fn list() -> Array<DebugInfoParser> {
        let mut count: usize = unsafe { mem::zeroed() };
        let raw_parsers = unsafe { BNGetDebugInfoParsers(&mut count as *mut _) };
        unsafe { Array::new(raw_parsers, count, ()) }
    }

    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetDebugInfoParserName(self.handle)) }
    }

    pub fn is_valid_for_view(&self, view: BinaryView) -> bool {
        unsafe { BNIsDebugInfoParserValidForView(self.handle, view.handle) }
    }

    pub fn register<S, C>(name: S, parser_callbacks: C) -> Self
    where
        S: BnStrCompatible,
        C: CustomDebugInfoParser,
    {
        extern "C" fn cb_is_valid<C>(ctxt: *mut c_void, view: *mut BNBinaryView) -> bool
        where
            C: CustomDebugInfoParser,
        {
            ffi_wrap!("CustomDebugInfoParser::is_valid", unsafe {
                let cmd = &*(ctxt as *const C);
                let view = BinaryView::from_raw(view);

                cmd.is_valid(&view)
            })
        }

        extern "C" fn cb_parse_info<C>(
            ctxt: *mut c_void,
            debug_info: *mut BNDebugInfo,
            view: *mut BNBinaryView,
        ) where
            C: CustomDebugInfoParser,
        {
            ffi_wrap!("CustomDebugInfoParser::parse_info", unsafe {
                let cmd = &*(ctxt as *const C);
                let view = BinaryView::from_raw(view);
                let mut debug_info = DebugInfo::from_raw(debug_info);

                cmd.parse_info(&mut debug_info, &view);
            })
        }

        let name = name.as_bytes_with_nul();
        let name_ptr = name.as_ref().as_ptr() as *mut _;
        let ctxt = Box::into_raw(Box::new(parser_callbacks));

        unsafe {
            DebugInfoParser::from_raw(BNRegisterDebugInfoParser(
                name_ptr,
                Some(cb_is_valid::<C>),
                Some(cb_parse_info::<C>),
                ctxt as *mut _,
            ))
        }
    }
}

unsafe impl CoreOwnedArrayProvider for DebugInfoParser {
    type Raw = *mut BNDebugInfoParser;
    type Context = ();

    unsafe fn free(raw: *mut Self::Raw, count: usize, _: &Self::Context) {
        BNFreeDebugInfoParserList(raw, count);
    }
}

// TODO : Ref to DebugParsers?
// // TODO : Need "real iterators" to do this
// impl Iterator for DebugInfoParser {
//     fn next(&mut self) -> Option<DebugInfoParser> {
//         let new_next = self.curr + self.next;

//         self.curr = self.next;
//         self.next = new_next;

//         Some(self.curr)
//     }
// }

///////////////////////
// DebugFunctionInfo

pub struct DebugFunctionInfo<S1: BnStrCompatible, S2: BnStrCompatible> {
    short_name: S1,
    full_name: S1,
    raw_name: S1,
    return_type: Ref<Type>,
    address: u64,
    parameters: Vec<(S2, Ref<Type>)>,
}

impl<S1: BnStrCompatible, S2: BnStrCompatible> DebugFunctionInfo<S1, S2> {
    pub fn new(
        short_name: S1,
        full_name: S1,
        raw_name: S1,
        return_type: Ref<Type>,
        address: u64,
        parameters: Vec<(S2, Ref<Type>)>,
    ) -> Self {
        Self {
            short_name,
            full_name,
            raw_name,
            return_type,
            address,
            parameters,
        }
    }
}

///////////////
// DebugInfo

#[derive(PartialEq, Eq, Hash)]
pub struct DebugInfo {
    pub(crate) handle: *mut BNDebugInfo,
}

impl DebugInfo {
    pub(crate) unsafe fn from_raw(handle: *mut BNDebugInfo) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    // TODO : Return the type that was added instead of whether or not the type was added (type wasn't previously added)?
    pub fn add_type<S: BnStrCompatible>(&mut self, name: S, new_type: &Type) -> bool {
        let name = name.as_bytes_with_nul();
        unsafe {
            BNAddDebugType(
                self.handle,
                name.as_ref().as_ptr() as *mut _,
                new_type.handle,
            )
        }
    }

    pub fn add_function<S1: BnStrCompatible, S2: BnStrCompatible>(
        &mut self,
        new_func: DebugFunctionInfo<S1, S2>,
    ) -> bool {
        let parameter_count: usize = new_func.parameters.len();

        let short_name = new_func.short_name.as_bytes_with_nul();
        let full_name = new_func.full_name.as_bytes_with_nul();
        let raw_name = new_func.raw_name.as_bytes_with_nul();

        // let (parameter_names, mut parameter_types): (Vec<S2>, Vec<*mut BNType>) =
        let (mut parameter_names, mut parameter_types): (Vec<*mut c_char>, Vec<*mut BNType>) =
            new_func.parameters.into_iter().fold(
                (
                    Vec::with_capacity(parameter_count),
                    Vec::with_capacity(parameter_count),
                ),
                |(mut parameter_names, mut parameter_types), (n, t)| {
                    parameter_names.push(n.as_bytes_with_nul().as_ref().as_ptr() as *mut c_char);
                    parameter_types.push(t.handle);
                    (parameter_names, parameter_types)
                },
            );

        // let mut parameter_names: Vec<*mut c_char> = parameter_names
        //     .into_iter()
        //     .map(|n| n.as_bytes_with_nul().as_ref().as_ptr() as *mut c_char)
        //     .collect();

        let mut func = BNDebugFunctionInfo {
            shortName: short_name.as_ref().as_ptr() as *mut _,
            fullName: full_name.as_ref().as_ptr() as *mut _,
            rawName: raw_name.as_ref().as_ptr() as *mut _,
            address: new_func.address,
            returnType: new_func.return_type.handle,
            parameterNames: parameter_names.as_mut_ptr(),
            parameterTypes: parameter_types.as_mut_ptr(),
            parameterCount: parameter_count as u64,
        };

        unsafe { BNAddDebugFunction(self.handle, &mut func as *mut _) }
    }
}

////////////////////////////
//  CustomDebugInfoParser

// TODO : Make the names/traits impls creative so it's pretty to implement

pub trait CustomDebugInfoParser: 'static + Sync {
    fn is_valid(&self, view: &BinaryView) -> bool;
    fn parse_info(&self, debug_info: &mut DebugInfo, view: &BinaryView);
}
