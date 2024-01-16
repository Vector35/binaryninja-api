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

// TODO : These docs are here, but could afford to be cleaned up

//! Parsers and providers of debug information to Binary Ninja.
//!
//! The debug information is used by Binary Ninja as ground-truth information about the attributes of functions,
//! types, and variables that Binary Ninja's analysis pipeline would otherwise work to deduce. By providing
//! debug info, Binary Ninja's output can be generated quicker, more accurately, and more completely.
//!
//! A DebugInfoParser consists of:
//!     1. A name
//!     2. An `is_valid` function which takes a BV and returns a bool
//!     3. A `parse` function which takes a `DebugInfo` object and uses the member functions `add_type`, `add_function`, and `add_data_variable` to populate all the info it can.
//! And finally calling `binaryninja::debuginfo::DebugInfoParser::register` to register it with the core.
//!
//! Here's a minimal, complete example boilerplate-plugin:
//! ```
//! use binaryninja::{
//!     binaryview::BinaryView,
//!     debuginfo::{CustomDebugInfoParser, DebugInfo, DebugInfoParser},
//! };
//!
//! struct ExampleDebugInfoParser;
//!
//! impl CustomDebugInfoParser for ExampleDebugInfoParser {
//!     fn is_valid(&self, _view: &BinaryView) -> bool {
//!         true
//!     }
//!
//!     fn parse_info(&self, _debug_info: &mut DebugInfo, _view: &BinaryView, _debug_file: &BinaryView, _progress: Box<dyn Fn(usize, usize) -> bool>) {
//!         println!("Parsing info");
//!     }
//! }
//!
//! #[no_mangle]
//! pub extern "C" fn CorePluginInit() -> bool {
//!     DebugInfoParser::register("example debug info parser", ExampleDebugInfoParser {});
//!     true
//! }
//! ```
//!
//! `DebugInfo` will then be automatically applied to binary views that contain debug information (via the setting `analysis.debugInfo.internal`), binary views that provide valid external debug info files (`analysis.debugInfo.external`), or manually fetched/applied as below:
//! ```
//! let valid_parsers = DebugInfoParser::parsers_for_view(bv);
//! let parser = valid_parsers[0];
//! let debug_info = parser.parse_debug_info(bv);
//! bv.apply_debug_info(debug_info);
//! ```
//!
//! Multiple debug-info parsers can manually contribute debug info for a binary view by simply calling `parse_debug_info` with the
//! `DebugInfo` object just returned. This is automatic when opening a binary view with multiple valid debug info parsers. If you
//! wish to set the debug info for a binary view without applying it as well, you can call `binaryninja::binaryview::BinaryView::set_debug_info`.

use binaryninjacore_sys::*;

use crate::{
    binaryview::BinaryView,
    platform::Platform,
    rc::*,
    string::{raw_to_string, BnStrCompatible, BnString},
    types::{DataVariableAndName, NameAndType, Type},
};

use std::{hash::Hash, mem, os::raw::c_void, ptr, slice};

struct ProgressContext(Option<Box<dyn Fn(usize, usize) -> Result<(), ()>>>);

//////////////////////
//  DebugInfoParser

/// Represents the registered parsers and providers of debug information to Binary Ninja.
/// See `binaryninja::debuginfo` for more information
#[derive(PartialEq, Eq, Hash)]
pub struct DebugInfoParser {
    pub(crate) handle: *mut BNDebugInfoParser,
}

impl DebugInfoParser {
    pub(crate) unsafe fn from_raw(handle: *mut BNDebugInfoParser) -> Ref<Self> {
        debug_assert!(!handle.is_null());

        Ref::new(Self { handle })
    }

    /// Returns debug info parser of the given name, if it exists
    pub fn from_name<S: BnStrCompatible>(name: S) -> Result<Ref<Self>, ()> {
        let name = name.into_bytes_with_nul();
        let parser = unsafe { BNGetDebugInfoParserByName(name.as_ref().as_ptr() as *mut _) };

        if parser.is_null() {
            Err(())
        } else {
            unsafe { Ok(Self::from_raw(parser)) }
        }
    }

    /// List all debug-info parsers
    pub fn list() -> Array<DebugInfoParser> {
        let mut count: usize = unsafe { mem::zeroed() };
        let raw_parsers = unsafe { BNGetDebugInfoParsers(&mut count as *mut _) };
        unsafe { Array::new(raw_parsers, count, ()) }
    }

    /// Returns a list of debug-info parsers that are valid for the provided binary view
    pub fn parsers_for_view(bv: &BinaryView) -> Array<DebugInfoParser> {
        let mut count: usize = unsafe { mem::zeroed() };
        let raw_parsers = unsafe { BNGetDebugInfoParsersForView(bv.handle, &mut count as *mut _) };
        unsafe { Array::new(raw_parsers, count, ()) }
    }

    /// Returns the name of the current parser
    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetDebugInfoParserName(self.handle)) }
    }

    /// Returns whether this debug-info parser is valid for the provided binary view
    pub fn is_valid_for_view(&self, view: &BinaryView) -> bool {
        unsafe { BNIsDebugInfoParserValidForView(self.handle, view.handle) }
    }

    extern "C" fn cb_progress(ctxt: *mut c_void, cur: usize, max: usize) -> bool {
        ffi_wrap!("DebugInfoParser::cb_progress", unsafe {
            let progress = ctxt as *mut ProgressContext;
            match &(*progress).0 {
                Some(func) => (func)(cur, max).is_ok(),
                None => true,
            }
        })
    }

    /// Returns a `DebugInfo` object populated with debug info by this debug-info parser. Only provide a `DebugInfo` object if you wish to append to the existing debug info
    pub fn parse_debug_info(
        &self,
        view: &BinaryView,
        debug_file: &BinaryView,
        existing_debug_info: Option<&DebugInfo>,
        progress: Option<Box<dyn Fn(usize, usize) -> Result<(), ()>>>,
    ) -> Option<Ref<DebugInfo>> {
        let mut progress_raw = ProgressContext(progress);
        let info: *mut BNDebugInfo = match existing_debug_info {
            Some(debug_info) => unsafe {
                BNParseDebugInfo(
                    self.handle,
                    view.handle,
                    debug_file.handle,
                    debug_info.handle,
                    Some(Self::cb_progress),
                    &mut progress_raw as *mut _ as *mut c_void,
                )
            },
            None => unsafe {
                BNParseDebugInfo(
                    self.handle,
                    view.handle,
                    debug_file.handle,
                    ptr::null_mut(),
                    Some(Self::cb_progress),
                    &mut progress_raw as *mut _ as *mut c_void,
                )
            },
        };
        if info.is_null() {
            return None;
        }
        Some(unsafe { DebugInfo::from_raw(info) })
    }

    // Registers a DebugInfoParser. See `binaryninja::debuginfo::DebugInfoParser` for more details.
    pub fn register<S, C>(name: S, parser_callbacks: C) -> Ref<Self>
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
            debug_file: *mut BNBinaryView,
            progress: Option<unsafe extern "C" fn(*mut c_void, usize, usize) -> bool>,
            progress_ctxt: *mut c_void,
        ) -> bool
        where
            C: CustomDebugInfoParser,
        {
            ffi_wrap!("CustomDebugInfoParser::parse_info", unsafe {
                let cmd = &*(ctxt as *const C);
                let view = BinaryView::from_raw(view);
                let debug_file = BinaryView::from_raw(debug_file);
                let mut debug_info = DebugInfo::from_raw(debug_info);

                cmd.parse_info(
                    &mut debug_info,
                    &view,
                    &debug_file,
                    Box::new(move |cur: usize, max: usize| match progress {
                        Some(func) => {
                            if func(progress_ctxt, cur, max) {
                                Ok(())
                            } else {
                                Err(())
                            }
                        }
                        _ => Ok(()),
                    }),
                )
            })
        }

        let name = name.into_bytes_with_nul();
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

unsafe impl RefCountable for DebugInfoParser {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewDebugInfoParserReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeDebugInfoParserReference(handle.handle);
    }
}

impl ToOwned for DebugInfoParser {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

impl CoreArrayProvider for DebugInfoParser {
    type Raw = *mut BNDebugInfoParser;
    type Context = ();
}

unsafe impl CoreOwnedArrayProvider for DebugInfoParser {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _: &Self::Context) {
        BNFreeDebugInfoParserList(raw, count);
    }
}

///////////////////////
// DebugFunctionInfo

/// Collates ground-truth function-external attributes for use in BinaryNinja's internal analysis.
///
/// When contributing function info, provide only what you know - BinaryNinja will figure out everything else that it can, as it usually does.
///
/// Functions will not be created if an address is not provided, but will be able to be queried from debug info for later user analysis.
pub struct DebugFunctionInfo {
    short_name: Option<String>,
    full_name: Option<String>,
    raw_name: Option<String>,
    type_: Option<Ref<Type>>,
    address: u64,
    platform: Option<Ref<Platform>>,
    components: Vec<String>,
}

impl From<&BNDebugFunctionInfo> for DebugFunctionInfo {
    fn from(raw: &BNDebugFunctionInfo) -> Self {
        let components = unsafe { slice::from_raw_parts(raw.components, raw.componentN) }
            .iter()
            .map(|component| raw_to_string(*component as *const _).unwrap())
            .collect();

        Self {
            short_name: raw_to_string(raw.shortName),
            full_name: raw_to_string(raw.fullName),
            raw_name: raw_to_string(raw.rawName),
            type_: if raw.type_.is_null() {
                None
            } else {
                Some(unsafe { Type::ref_from_raw(raw.type_) })
            },
            address: raw.address,
            platform: if raw.platform.is_null() {
                None
            } else {
                Some(unsafe { Platform::ref_from_raw(raw.platform) })
            },
            components,
        }
    }
}

impl DebugFunctionInfo {
    pub fn new(
        short_name: Option<String>,
        full_name: Option<String>,
        raw_name: Option<String>,
        type_: Option<Ref<Type>>,
        address: Option<u64>,
        platform: Option<Ref<Platform>>,
        components: Vec<String>,
    ) -> Self {
        Self {
            short_name,
            full_name,
            raw_name,
            type_,
            address: match address {
                Some(address) => address,
                _ => 0,
            },
            platform,
            components,
        }
    }
}

///////////////
// DebugInfo

/// Provides an interface to both provide and query debug info. The DebugInfo object is used
/// internally by the binary view to which it is applied to determine the attributes of functions, types, and variables
/// that would otherwise be costly to deduce.
///
/// DebugInfo objects themselves are independent of binary views; their data can be sourced from any arbitrary binary
/// views and be applied to any other arbitrary binary view. A DebugInfo object can also contain debug info from multiple
/// DebugInfoParsers. This makes it possible to gather debug info that may be distributed across several different
/// formats and files.
///
/// DebugInfo cannot be instantiated by the user, instead get it from either the binary view (see `binaryninja::binaryview::BinaryView::debug_info`)
/// or a debug-info parser (see `binaryninja::debuginfo::DebugInfoParser::parse_debug_info`).
///
/// Please note that calling one of `add_*` functions will not work outside of a debuginfo plugin.
#[derive(PartialEq, Eq, Hash)]
pub struct DebugInfo {
    pub(crate) handle: *mut BNDebugInfo,
}

impl DebugInfo {
    pub(crate) unsafe fn from_raw(handle: *mut BNDebugInfo) -> Ref<Self> {
        debug_assert!(!handle.is_null());

        Ref::new(Self { handle })
    }

    /// Returns a generator of all types provided by a named DebugInfoParser
    pub fn types_by_name<S: BnStrCompatible>(&self, parser_name: S) -> Vec<NameAndType<String>> {
        let parser_name = parser_name.into_bytes_with_nul();

        let mut count: usize = 0;
        let debug_types_ptr = unsafe {
            BNGetDebugTypes(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                &mut count,
            )
        };
        let result: Vec<NameAndType<String>> = unsafe {
            slice::from_raw_parts_mut(debug_types_ptr, count)
                .iter()
                .map(NameAndType::<String>::from_raw)
                .collect()
        };

        unsafe { BNFreeDebugTypes(debug_types_ptr, count) };
        result
    }

    /// A generator of all types provided by DebugInfoParsers
    pub fn types(&self) -> Vec<NameAndType<String>> {
        let mut count: usize = 0;
        let debug_types_ptr = unsafe { BNGetDebugTypes(self.handle, ptr::null_mut(), &mut count) };
        let result: Vec<NameAndType<String>> = unsafe {
            slice::from_raw_parts_mut(debug_types_ptr, count)
                .iter()
                .map(NameAndType::<String>::from_raw)
                .collect()
        };

        unsafe { BNFreeDebugTypes(debug_types_ptr, count) };
        result
    }

    /// Returns a generator of all functions provided by a named DebugInfoParser
    pub fn functions_by_name<S: BnStrCompatible>(
        &self,
        parser_name: S,
    ) -> Vec<DebugFunctionInfo> {
        let parser_name = parser_name.into_bytes_with_nul();

        let mut count: usize = 0;
        let functions_ptr = unsafe {
            BNGetDebugFunctions(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                &mut count,
            )
        };

        let result: Vec<DebugFunctionInfo> = unsafe {
            slice::from_raw_parts_mut(functions_ptr, count)
                .iter()
                .map(DebugFunctionInfo::from)
                .collect()
        };

        unsafe { BNFreeDebugFunctions(functions_ptr, count) };
        result
    }

    /// A generator of all functions provided by DebugInfoParsers
    pub fn functions(&self) -> Vec<DebugFunctionInfo> {
        let mut count: usize = 0;
        let functions_ptr =
            unsafe { BNGetDebugFunctions(self.handle, ptr::null_mut(), &mut count) };

        let result: Vec<DebugFunctionInfo> = unsafe {
            slice::from_raw_parts_mut(functions_ptr, count)
                .iter()
                .map(DebugFunctionInfo::from)
                .collect()
        };

        unsafe { BNFreeDebugFunctions(functions_ptr, count) };
        result
    }

    /// Returns a generator of all data variables provided by a named DebugInfoParser
    pub fn data_variables_by_name<S: BnStrCompatible>(
        &self,
        parser_name: S,
    ) -> Vec<DataVariableAndName<String>> {
        let parser_name = parser_name.into_bytes_with_nul();

        let mut count: usize = 0;
        let data_variables_ptr = unsafe {
            BNGetDebugDataVariables(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                &mut count,
            )
        };

        let result: Vec<DataVariableAndName<String>> = unsafe {
            slice::from_raw_parts_mut(data_variables_ptr, count)
                .iter()
                .map(DataVariableAndName::<String>::from_raw)
                .collect()
        };

        unsafe { BNFreeDataVariablesAndName(data_variables_ptr, count) };
        result
    }

    /// A generator of all data variables provided by DebugInfoParsers
    pub fn data_variables(&self) -> Vec<DataVariableAndName<String>> {
        let mut count: usize = 0;
        let data_variables_ptr =
            unsafe { BNGetDebugDataVariables(self.handle, ptr::null_mut(), &mut count) };

        let result: Vec<DataVariableAndName<String>> = unsafe {
            slice::from_raw_parts_mut(data_variables_ptr, count)
                .iter()
                .map(DataVariableAndName::<String>::from_raw)
                .collect()
        };

        unsafe { BNFreeDataVariablesAndName(data_variables_ptr, count) };
        result
    }

    /// May return nullptr
    pub fn type_by_name<S: BnStrCompatible>(&self, parser_name: S, name: S) -> Option<Ref<Type>> {
        let parser_name = parser_name.into_bytes_with_nul();
        let name = name.into_bytes_with_nul();

        let result = unsafe {
            BNGetDebugTypeByName(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                name.as_ref().as_ptr() as *mut _,
            )
        };
        if !result.is_null() {
            Some(unsafe { Type::ref_from_raw(result) })
        } else {
            None
        }
    }

    pub fn get_data_variable_by_name<S: BnStrCompatible>(
        &self,
        parser_name: S,
        name: S,
    ) -> Option<(u64, Ref<Type>)> {
        let parser_name = parser_name.into_bytes_with_nul();
        let name = name.into_bytes_with_nul();

        let result = unsafe {
            BNGetDebugDataVariableByName(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                name.as_ref().as_ptr() as *mut _,
            )
        };

        if !result.is_null() {
            unsafe { BNFreeString((*result).name) };
            Some(unsafe { ((*result).address, Type::ref_from_raw((*result).type_)) })
        } else {
            None
        }
    }

    pub fn get_data_variable_by_address<S: BnStrCompatible>(
        &self,
        parser_name: S,
        address: u64,
    ) -> Option<(String, Ref<Type>)> {
        let parser_name = parser_name.into_bytes_with_nul();
        let name_and_var = unsafe {
            BNGetDebugDataVariableByAddress(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                address,
            )
        };

        if !name_and_var.is_null() {
            let result = unsafe {
                (
                    raw_to_string((*name_and_var).name).unwrap(),
                    Type::ref_from_raw((*name_and_var).type_),
                )
            };
            unsafe { BNFreeString((*name_and_var).name) };
            Some(result)
        } else {
            None
        }
    }

    // The tuple is (DebugInfoParserName, type)
    pub fn get_types_by_name<S: BnStrCompatible>(&self, name: S) -> Vec<(String, Ref<Type>)> {
        let name = name.into_bytes_with_nul();

        let mut count: usize = 0;
        let raw_names_and_types = unsafe {
            BNGetDebugTypesByName(self.handle, name.as_ref().as_ptr() as *mut _, &mut count)
        };

        let names_and_types: &[*mut BNNameAndType] =
            unsafe { slice::from_raw_parts(raw_names_and_types as *mut _, count) };

        let result = names_and_types
            .iter()
            .take(count)
            .map(|&name_and_type| unsafe {
                (
                    raw_to_string((*name_and_type).name).unwrap(),
                    Type::ref_from_raw(BNNewTypeReference((*name_and_type).type_)),
                )
            })
            .collect();

        unsafe { BNFreeNameAndTypeList(raw_names_and_types, count) };
        result
    }

    // The tuple is (DebugInfoParserName, address, type)
    pub fn get_data_variables_by_name<S: BnStrCompatible>(
        &self,
        name: S,
    ) -> Vec<(String, u64, Ref<Type>)> {
        let name = name.into_bytes_with_nul();

        let mut count: usize = 0;
        let raw_variables_and_names = unsafe {
            BNGetDebugDataVariablesByName(self.handle, name.as_ref().as_ptr() as *mut _, &mut count)
        };

        let variables_and_names: &[*mut BNDataVariableAndName] =
            unsafe { slice::from_raw_parts(raw_variables_and_names as *mut _, count) };

        let result = variables_and_names
            .iter()
            .take(count)
            .map(|&variable_and_name| unsafe {
                (
                    raw_to_string((*variable_and_name).name).unwrap(),
                    (*variable_and_name).address,
                    Type::ref_from_raw(BNNewTypeReference((*variable_and_name).type_)),
                )
            })
            .collect();

        unsafe { BNFreeDataVariablesAndName(raw_variables_and_names, count) };
        result
    }

    /// The tuple is (DebugInfoParserName, TypeName, type)
    pub fn get_data_variables_by_address(&self, address: u64) -> Vec<(String, String, Ref<Type>)> {
        let mut count: usize = 0;
        let raw_variables_and_names =
            unsafe { BNGetDebugDataVariablesByAddress(self.handle, address, &mut count) };

        let variables_and_names: &[*mut BNDataVariableAndNameAndDebugParser] =
            unsafe { slice::from_raw_parts(raw_variables_and_names as *mut _, count) };

        let result = variables_and_names
            .iter()
            .take(count)
            .map(|&variable_and_name| unsafe {
                (
                    raw_to_string((*variable_and_name).parser).unwrap(),
                    raw_to_string((*variable_and_name).name).unwrap(),
                    Type::ref_from_raw(BNNewTypeReference((*variable_and_name).type_)),
                )
            })
            .collect();

        unsafe { BNFreeDataVariableAndNameAndDebugParserList(raw_variables_and_names, count) };
        result
    }

    pub fn remove_parser_info<S: BnStrCompatible>(&self, parser_name: S) -> bool {
        let parser_name = parser_name.into_bytes_with_nul();

        unsafe { BNRemoveDebugParserInfo(self.handle, parser_name.as_ref().as_ptr() as *mut _) }
    }

    pub fn remove_parser_types<S: BnStrCompatible>(&self, parser_name: S) -> bool {
        let parser_name = parser_name.into_bytes_with_nul();

        unsafe { BNRemoveDebugParserTypes(self.handle, parser_name.as_ref().as_ptr() as *mut _) }
    }

    pub fn remove_parser_functions<S: BnStrCompatible>(&self, parser_name: S) -> bool {
        let parser_name = parser_name.into_bytes_with_nul();

        unsafe {
            BNRemoveDebugParserFunctions(self.handle, parser_name.as_ref().as_ptr() as *mut _)
        }
    }

    pub fn remove_parser_data_variables<S: BnStrCompatible>(&self, parser_name: S) -> bool {
        let parser_name = parser_name.into_bytes_with_nul();

        unsafe {
            BNRemoveDebugParserDataVariables(self.handle, parser_name.as_ref().as_ptr() as *mut _)
        }
    }

    pub fn remove_type_by_name<S: BnStrCompatible>(&self, parser_name: S, name: S) -> bool {
        let parser_name = parser_name.into_bytes_with_nul();
        let name = name.into_bytes_with_nul();

        unsafe {
            BNRemoveDebugTypeByName(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                name.as_ref().as_ptr() as *mut _,
            )
        }
    }

    pub fn remove_function_by_index<S: BnStrCompatible>(
        &self,
        parser_name: S,
        index: usize,
    ) -> bool {
        let parser_name = parser_name.into_bytes_with_nul();

        unsafe {
            BNRemoveDebugFunctionByIndex(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                index,
            )
        }
    }

    pub fn remove_data_variable_by_address<S: BnStrCompatible>(
        &self,
        parser_name: S,
        address: u64,
    ) -> bool {
        let parser_name = parser_name.into_bytes_with_nul();

        unsafe {
            BNRemoveDebugDataVariableByAddress(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                address,
            )
        }
    }

    /// Adds a type scoped under the current parser's name to the debug info
    pub fn add_type<S: BnStrCompatible>(
        &self,
        name: S,
        new_type: &Type,
        components: &[&str],
    ) -> bool {
        let mut components_array: Vec<*const ::std::os::raw::c_char> =
            Vec::with_capacity(components.len());
        for component in components {
            components_array.push(component.as_ptr() as _);
        }

        let name = name.into_bytes_with_nul();
        unsafe {
            BNAddDebugType(
                self.handle,
                name.as_ref().as_ptr() as *mut _,
                new_type.handle,
                components_array.as_ptr() as _,
                components.len(),
            )
        }
    }

    /// Adds a function scoped under the current parser's name to the debug info
    pub fn add_function(&self, new_func: DebugFunctionInfo) -> bool {
        let short_name_bytes = new_func.short_name.map(|name| name.into_bytes_with_nul());
        let short_name = short_name_bytes
            .as_ref()
            .map_or(ptr::null_mut() as *mut _, |name| {
                name.as_ptr() as _
            });
        let full_name_bytes = new_func.full_name.map(|name| name.into_bytes_with_nul());
        let full_name = full_name_bytes
            .as_ref()
            .map_or(ptr::null_mut() as *mut _, |name| {
                name.as_ptr() as _
            });
        let raw_name_bytes = new_func.raw_name.map(|name| name.into_bytes_with_nul());
        let raw_name = raw_name_bytes
            .as_ref()
            .map_or(ptr::null_mut() as *mut _, |name| {
                name.as_ptr() as _
            });

        let mut components_array: Vec<*const ::std::os::raw::c_char> =
            Vec::with_capacity(new_func.components.len());
        for component in &new_func.components {
            components_array.push(component.as_ptr() as _);
        }

        unsafe {
            BNAddDebugFunction(
                self.handle,
                &mut BNDebugFunctionInfo {
                    shortName: short_name,
                    fullName: full_name,
                    rawName: raw_name,
                    address: new_func.address,
                    type_: match new_func.type_ {
                        Some(type_) => type_.handle,
                        _ => ptr::null_mut(),
                    },
                    platform: match new_func.platform {
                        Some(platform) => platform.handle,
                        _ => ptr::null_mut(),
                    },
                    components: components_array.as_ptr() as _,
                    componentN: new_func.components.len(),
                },
            )
        }
    }

    /// Adds a data variable scoped under the current parser's name to the debug info
    pub fn add_data_variable<S: BnStrCompatible>(
        &self,
        address: u64,
        t: &Type,
        name: Option<S>,
        components: &[&str],
    ) -> bool {
        let mut components_array: Vec<*const ::std::os::raw::c_char> =
            Vec::with_capacity(components.len());
        for component in components {
            components_array.push(component.as_ptr() as _);
        }

        match name {
            Some(name) => {
                let name = name.into_bytes_with_nul();
                unsafe {
                    BNAddDebugDataVariable(
                        self.handle,
                        address,
                        t.handle,
                        name.as_ref().as_ptr() as *mut _,
                        components.as_ptr() as _,
                        components.len(),
                    )
                }
            }
            None => unsafe {
                BNAddDebugDataVariable(
                    self.handle,
                    address,
                    t.handle,
                    ptr::null_mut(),
                    components.as_ptr() as _,
                    components.len(),
                )
            },
        }
    }

    pub fn add_data_variable_info<S: BnStrCompatible>(&self, var: DataVariableAndName<S>) -> bool {
        let name = var.name.into_bytes_with_nul();
        unsafe {
            BNAddDebugDataVariableInfo(
                self.handle,
                &BNDataVariableAndName {
                    address: var.address,
                    type_: var.t.contents.handle,
                    name: name.as_ref().as_ptr() as *mut _,
                    autoDiscovered: var.auto_discovered,
                    typeConfidence: var.t.confidence,
                },
            )
        }
    }
}

unsafe impl RefCountable for DebugInfo {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewDebugInfoReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeDebugInfoReference(handle.handle);
    }
}

impl ToOwned for DebugInfo {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

////////////////////////////
//  CustomDebugInfoParser

/// Implement this trait to implement a debug info parser.  See `DebugInfoParser` for more details.
pub trait CustomDebugInfoParser: 'static + Sync {
    fn is_valid(&self, view: &BinaryView) -> bool;
    fn parse_info(
        &self,
        debug_info: &mut DebugInfo,
        view: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool;
}
