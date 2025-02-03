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
//! ```no_run
//! use binaryninja::{
//!     binary_view::BinaryView,
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
//!     fn parse_info(
//!         &self,
//!         _debug_info: &mut DebugInfo,
//!         _view: &BinaryView,
//!         _debug_file: &BinaryView,
//!         _progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
//!     ) -> bool {
//!         println!("Parsing info");
//!         true
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
//! ```no_run
//! # use binaryninja::debuginfo::DebugInfoParser;
//! # use binaryninja::binary_view::BinaryViewExt;
//! let bv = binaryninja::load("example").unwrap();
//! let valid_parsers = DebugInfoParser::parsers_for_view(&bv);
//! let parser = valid_parsers.get(0);
//! let debug_info = parser.parse_debug_info(&bv, &bv, None).unwrap();
//! bv.apply_debug_info(&debug_info);
//! ```
//!
//! Multiple debug-info parsers can manually contribute debug info for a binary view by simply calling `parse_debug_info` with the
//! `DebugInfo` object just returned. This is automatic when opening a binary view with multiple valid debug info parsers. If you
//! wish to set the debug info for a binary view without applying it as well, you can call `binaryninja::binaryview::BinaryView::set_debug_info`.

use binaryninjacore_sys::*;
use std::ffi::c_void;

use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::variable::{NamedDataVariableWithType, NamedVariableWithType};
use crate::{
    binary_view::BinaryView,
    platform::Platform,
    rc::*,
    string::{raw_to_string, BnStrCompatible, BnString},
    types::{NameAndType, Type},
};

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
        let mut count = 0;
        let raw_parsers = unsafe { BNGetDebugInfoParsers(&mut count as *mut _) };
        unsafe { Array::new(raw_parsers, count, ()) }
    }

    /// Returns a list of debug-info parsers that are valid for the provided binary view
    pub fn parsers_for_view(bv: &BinaryView) -> Array<DebugInfoParser> {
        let mut count = 0;
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

    /// Returns [`DebugInfo`] populated with debug info by this debug-info parser.
    ///
    /// Only provide a `DebugInfo` object if you wish to append to the existing debug info
    pub fn parse_debug_info(
        &self,
        view: &BinaryView,
        debug_file: &BinaryView,
        existing_debug_info: Option<&DebugInfo>,
    ) -> Option<Ref<DebugInfo>> {
        self.parse_debug_info_with_progress(
            view,
            debug_file,
            existing_debug_info,
            NoProgressCallback,
        )
    }

    /// Returns [`DebugInfo`] populated with debug info by this debug-info parser.
    ///
    /// Only provide a `DebugInfo` object if you wish to append to the existing debug info
    pub fn parse_debug_info_with_progress<P: ProgressCallback>(
        &self,
        view: &BinaryView,
        debug_file: &BinaryView,
        existing_debug_info: Option<&DebugInfo>,
        mut progress: P,
    ) -> Option<Ref<DebugInfo>> {
        let info: *mut BNDebugInfo = match existing_debug_info {
            Some(debug_info) => unsafe {
                BNParseDebugInfo(
                    self.handle,
                    view.handle,
                    debug_file.handle,
                    debug_info.handle,
                    Some(P::cb_progress_callback),
                    &mut progress as *mut P as *mut c_void,
                )
            },
            None => unsafe {
                BNParseDebugInfo(
                    self.handle,
                    view.handle,
                    debug_file.handle,
                    std::ptr::null_mut(),
                    Some(P::cb_progress_callback),
                    &mut progress as *mut P as *mut c_void,
                )
            },
        };

        if info.is_null() {
            return None;
        }
        Some(unsafe { DebugInfo::ref_from_raw(info) })
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
                let view = BinaryView::ref_from_raw(view);

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
                let view = BinaryView::ref_from_raw(view);
                let debug_file = BinaryView::ref_from_raw(debug_file);
                let mut debug_info = DebugInfo::ref_from_raw(debug_info);

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
    type Wrapped<'a> = Guard<'a, DebugInfoParser>;
}

unsafe impl CoreArrayProviderInner for DebugInfoParser {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _: &Self::Context) {
        BNFreeDebugInfoParserList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self { handle: *raw }, context)
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
    local_variables: Vec<NamedVariableWithType>,
}

impl DebugFunctionInfo {
    pub(crate) fn from_raw(value: &BNDebugFunctionInfo) -> Self {
        let raw_components =
            unsafe { std::slice::from_raw_parts(value.components, value.componentN) };
        let components = raw_components
            .iter()
            .filter_map(|&c| raw_to_string(c))
            .collect();
        let raw_local_variables =
            unsafe { std::slice::from_raw_parts(value.localVariables, value.localVariableN) };
        let local_variables = raw_local_variables
            .iter()
            .map(NamedVariableWithType::from_raw)
            .collect();
        Self {
            short_name: raw_to_string(value.shortName),
            full_name: raw_to_string(value.fullName),
            raw_name: raw_to_string(value.rawName),
            type_: if value.type_.is_null() {
                None
            } else {
                Some(unsafe { Type::from_raw(value.type_) }.to_owned())
            },
            address: value.address,
            platform: if value.platform.is_null() {
                None
            } else {
                Some(unsafe { Platform::from_raw(value.platform) }.to_owned())
            },
            components,
            local_variables,
        }
    }
}

impl DebugFunctionInfo {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        short_name: Option<String>,
        full_name: Option<String>,
        raw_name: Option<String>,
        type_: Option<Ref<Type>>,
        address: Option<u64>,
        platform: Option<Ref<Platform>>,
        components: Vec<String>,
        local_variables: Vec<NamedVariableWithType>,
    ) -> Self {
        Self {
            short_name,
            full_name,
            raw_name,
            type_,
            address: address.unwrap_or(0),
            platform,
            components,
            local_variables,
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
    pub(crate) unsafe fn ref_from_raw(handle: *mut BNDebugInfo) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    /// Returns all types within the parser
    pub fn types_by_name<S: BnStrCompatible>(&self, parser_name: S) -> Vec<NameAndType> {
        let parser_name = parser_name.into_bytes_with_nul();

        let mut count: usize = 0;
        let debug_types_ptr = unsafe {
            BNGetDebugTypes(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                &mut count,
            )
        };
        let result: Vec<_> = unsafe {
            std::slice::from_raw_parts_mut(debug_types_ptr, count)
                .iter()
                .map(NameAndType::from_raw)
                .collect()
        };

        unsafe { BNFreeDebugTypes(debug_types_ptr, count) };
        result
    }

    pub fn types(&self) -> Vec<NameAndType> {
        let mut count: usize = 0;
        let debug_types_ptr =
            unsafe { BNGetDebugTypes(self.handle, std::ptr::null_mut(), &mut count) };
        let result: Vec<_> = unsafe {
            std::slice::from_raw_parts_mut(debug_types_ptr, count)
                .iter()
                .map(NameAndType::from_raw)
                .collect()
        };

        unsafe { BNFreeDebugTypes(debug_types_ptr, count) };
        result
    }

    /// Returns all functions within the parser
    pub fn functions_by_name<S: BnStrCompatible>(&self, parser_name: S) -> Vec<DebugFunctionInfo> {
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
            std::slice::from_raw_parts_mut(functions_ptr, count)
                .iter()
                .map(DebugFunctionInfo::from_raw)
                .collect()
        };

        unsafe { BNFreeDebugFunctions(functions_ptr, count) };
        result
    }

    pub fn functions(&self) -> Vec<DebugFunctionInfo> {
        let mut count: usize = 0;
        let functions_ptr =
            unsafe { BNGetDebugFunctions(self.handle, std::ptr::null_mut(), &mut count) };

        let result: Vec<DebugFunctionInfo> = unsafe {
            std::slice::from_raw_parts_mut(functions_ptr, count)
                .iter()
                .map(DebugFunctionInfo::from_raw)
                .collect()
        };

        unsafe { BNFreeDebugFunctions(functions_ptr, count) };
        result
    }

    /// Returns all data variables within the parser
    pub fn data_variables_by_name<S: BnStrCompatible>(
        &self,
        parser_name: S,
    ) -> Vec<NamedDataVariableWithType> {
        let parser_name = parser_name.into_bytes_with_nul();

        let mut count: usize = 0;
        let data_variables_ptr = unsafe {
            BNGetDebugDataVariables(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                &mut count,
            )
        };

        let result: Vec<NamedDataVariableWithType> = unsafe {
            std::slice::from_raw_parts_mut(data_variables_ptr, count)
                .iter()
                .map(NamedDataVariableWithType::from_raw)
                .collect()
        };

        unsafe { BNFreeDataVariablesAndName(data_variables_ptr, count) };
        result
    }

    pub fn data_variables(&self) -> Vec<NamedDataVariableWithType> {
        let mut count: usize = 0;
        let data_variables_ptr =
            unsafe { BNGetDebugDataVariables(self.handle, std::ptr::null_mut(), &mut count) };

        let result: Vec<NamedDataVariableWithType> = unsafe {
            std::slice::from_raw_parts_mut(data_variables_ptr, count)
                .iter()
                .map(NamedDataVariableWithType::from_raw)
                .collect()
        };

        unsafe { BNFreeDataVariablesAndName(data_variables_ptr, count) };
        result
    }

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
    ) -> Option<NamedDataVariableWithType> {
        let parser_name = parser_name.into_bytes_with_nul();
        let name = name.into_bytes_with_nul();
        let mut dv = BNDataVariableAndName::default();
        unsafe {
            if BNGetDebugDataVariableByName(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                name.as_ref().as_ptr() as *mut _,
                &mut dv,
            ) {
                Some(NamedDataVariableWithType::from_owned_raw(dv))
            } else {
                None
            }
        }
    }

    pub fn get_data_variable_by_address<S: BnStrCompatible>(
        &self,
        parser_name: S,
        address: u64,
    ) -> Option<NamedDataVariableWithType> {
        let parser_name = parser_name.into_bytes_with_nul();
        let mut dv = BNDataVariableAndName::default();
        unsafe {
            if BNGetDebugDataVariableByAddress(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                address,
                &mut dv,
            ) {
                Some(NamedDataVariableWithType::from_owned_raw(dv))
            } else {
                None
            }
        }
    }

    /// Returns a list of [`NameAndType`] where the `name` is the parser the type originates from.
    pub fn get_types_by_name<S: BnStrCompatible>(&self, name: S) -> Vec<NameAndType> {
        let mut count: usize = 0;
        let name = name.into_bytes_with_nul();
        let raw_names_and_types_ptr = unsafe {
            BNGetDebugTypesByName(self.handle, name.as_ref().as_ptr() as *mut _, &mut count)
        };

        let raw_names_and_types: &[BNNameAndType] =
            unsafe { std::slice::from_raw_parts(raw_names_and_types_ptr, count) };

        let names_and_types = raw_names_and_types
            .iter()
            .map(NameAndType::from_raw)
            .collect();

        unsafe { BNFreeNameAndTypeList(raw_names_and_types_ptr, count) };
        names_and_types
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
            unsafe { std::slice::from_raw_parts(raw_variables_and_names as *mut _, count) };

        let result = variables_and_names
            .iter()
            .take(count)
            .map(|&variable_and_name| unsafe {
                (
                    raw_to_string((*variable_and_name).name).unwrap(),
                    (*variable_and_name).address,
                    Type::from_raw((*variable_and_name).type_).to_owned(),
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
            unsafe { std::slice::from_raw_parts(raw_variables_and_names as *mut _, count) };

        let result = variables_and_names
            .iter()
            .take(count)
            .map(|&variable_and_name| unsafe {
                (
                    raw_to_string((*variable_and_name).parser).unwrap(),
                    raw_to_string((*variable_and_name).name).unwrap(),
                    Type::from_raw((*variable_and_name).type_).to_owned(),
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
        // SAFETY: Lifetime of `components` will live long enough, so passing as_ptr is safe.
        let raw_components: Vec<_> = components.iter().map(|&c| c.as_ptr()).collect();

        let name = name.into_bytes_with_nul();
        unsafe {
            BNAddDebugType(
                self.handle,
                name.as_ref().as_ptr() as *mut _,
                new_type.handle,
                raw_components.as_ptr() as *mut _,
                components.len(),
            )
        }
    }

    /// Adds a function scoped under the current parser's name to the debug info
    pub fn add_function(&self, new_func: DebugFunctionInfo) -> bool {
        let short_name_bytes = new_func.short_name.map(|name| name.into_bytes_with_nul());
        let short_name = short_name_bytes
            .as_ref()
            .map_or(std::ptr::null_mut() as *mut _, |name| name.as_ptr() as _);
        let full_name_bytes = new_func.full_name.map(|name| name.into_bytes_with_nul());
        let full_name = full_name_bytes
            .as_ref()
            .map_or(std::ptr::null_mut() as *mut _, |name| name.as_ptr() as _);
        let raw_name_bytes = new_func.raw_name.map(|name| name.into_bytes_with_nul());
        let raw_name = raw_name_bytes
            .as_ref()
            .map_or(std::ptr::null_mut() as *mut _, |name| name.as_ptr() as _);

        let mut components_array: Vec<*mut ::std::os::raw::c_char> =
            Vec::with_capacity(new_func.components.len());

        let mut local_variables_array: Vec<BNVariableNameAndType> =
            Vec::with_capacity(new_func.local_variables.len());

        unsafe {
            for component in &new_func.components {
                components_array.push(BNAllocString(
                    component.clone().into_bytes_with_nul().as_ptr() as _,
                ));
            }

            for local_variable in &new_func.local_variables {
                local_variables_array.push(BNVariableNameAndType {
                    var: local_variable.variable.into(),
                    autoDefined: local_variable.auto_defined,
                    typeConfidence: local_variable.ty.confidence,
                    name: BNAllocString(
                        local_variable.name.clone().into_bytes_with_nul().as_ptr() as _
                    ),
                    type_: local_variable.ty.contents.handle,
                });
            }

            let result = BNAddDebugFunction(
                self.handle,
                &mut BNDebugFunctionInfo {
                    shortName: short_name,
                    fullName: full_name,
                    rawName: raw_name,
                    address: new_func.address,
                    type_: match new_func.type_ {
                        Some(type_) => type_.handle,
                        _ => std::ptr::null_mut(),
                    },
                    platform: match new_func.platform {
                        Some(platform) => platform.handle,
                        _ => std::ptr::null_mut(),
                    },
                    components: components_array.as_ptr() as _,
                    componentN: new_func.components.len(),
                    localVariables: local_variables_array.as_ptr() as _,
                    localVariableN: local_variables_array.len(),
                },
            );

            for i in components_array {
                BNFreeString(i);
            }

            for i in &local_variables_array {
                BNFreeString(i.name);
            }
            result
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
                    std::ptr::null_mut(),
                    components.as_ptr() as _,
                    components.len(),
                )
            },
        }
    }

    pub fn add_data_variable_info(&self, var: NamedDataVariableWithType) -> bool {
        let raw_data_var = NamedDataVariableWithType::into_raw(var);
        let success = unsafe { BNAddDebugDataVariableInfo(self.handle, &raw_data_var) };
        NamedDataVariableWithType::free_raw(raw_data_var);
        success
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
