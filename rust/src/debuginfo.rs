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
//!     fn parse_info(&self, _debug_info: &mut DebugInfo, _view: &BinaryView) {
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
//! `DebugInfo` can then be automatically applied to valid binary views (via the "Parse and Apply Debug Info" setting), or manually fetched/applied as bellow:
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
    architecture::{Architecture, CoreArchitecture},
    binaryview::BinaryView,
    callingconvention::CallingConvention,
    platform::Platform,
    rc::*,
    string::{raw_to_string, BnStrCompatible, BnString},
    types::{DataVariableAndName, NameAndType, Type},
};

use std::{
    hash::Hash,
    mem,
    os::raw::{c_char, c_void},
    ptr, slice,
};

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
        let name = name.as_bytes_with_nul();
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

    /// Returns a `DebugInfo` object populated with debug info by this debug-info parser. Only provide a `DebugInfo` object if you wish to append to the existing debug info
    pub fn parse_debug_info(
        &self,
        view: &BinaryView,
        existing_debug_info: Option<&DebugInfo>,
    ) -> Ref<DebugInfo> {
        match existing_debug_info {
            Some(debug_info) => unsafe {
                DebugInfo::from_raw(BNParseDebugInfo(
                    self.handle,
                    view.handle,
                    debug_info.handle,
                ))
            },
            None => unsafe {
                DebugInfo::from_raw(BNParseDebugInfo(self.handle, view.handle, ptr::null_mut()))
            },
        }
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

impl AsRef<DebugInfoParser> for DebugInfoParser {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl ToOwned for DebugInfoParser {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl CoreOwnedArrayProvider for DebugInfoParser {
    type Raw = *mut BNDebugInfoParser;
    type Context = ();

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
pub struct DebugFunctionInfo<A: Architecture, S1: BnStrCompatible, S2: BnStrCompatible> {
    short_name: Option<S1>,
    full_name: Option<S1>,
    raw_name: Option<S1>,
    return_type: Option<Ref<Type>>,
    address: u64,
    parameters: Vec<(S2, Ref<Type>)>,
    variable_parameters: bool,
    calling_convention: Option<Ref<CallingConvention<A>>>,
    platform: Option<Ref<Platform>>,
}

impl From<&BNDebugFunctionInfo> for DebugFunctionInfo<CoreArchitecture, String, String> {
    fn from(raw: &BNDebugFunctionInfo) -> Self {
        let raw_parameter_names: &[*mut ::std::os::raw::c_char] =
            unsafe { slice::from_raw_parts(raw.parameterNames as *mut _, raw.parameterCount) };
        let raw_parameter_types: &[*mut BNType] =
            unsafe { slice::from_raw_parts(raw.parameterTypes as *mut _, raw.parameterCount) };

        let parameters: Vec<(String, Ref<Type>)> = (0..raw.parameterCount)
            .map(|i| {
                (raw_to_string(raw_parameter_names[i]).unwrap(), unsafe {
                    Type::ref_from_raw(raw_parameter_types[i])
                })
            })
            .collect();

        Self {
            short_name: raw_to_string(raw.shortName),
            full_name: raw_to_string(raw.fullName),
            raw_name: raw_to_string(raw.rawName),
            return_type: if raw.returnType.is_null() {
                None
            } else {
                Some(unsafe { Type::ref_from_raw(raw.returnType) })
            },
            address: raw.address,
            parameters,
            variable_parameters: raw.variableParameters,
            calling_convention: if raw.callingConvention.is_null() {
                None
            } else {
                Some(unsafe {
                    CallingConvention::ref_from_raw(
                        raw.callingConvention,
                        CoreArchitecture::from_raw(BNGetCallingConventionArchitecture(
                            raw.callingConvention,
                        )),
                    )
                })
            },
            platform: if raw.returnType.is_null() {
                None
            } else {
                Some(unsafe { Platform::ref_from_raw(raw.platform) })
            },
        }
    }
}

impl<A: Architecture, S1: BnStrCompatible, S2: BnStrCompatible> Into<BNDebugFunctionInfo>
    for DebugFunctionInfo<A, S1, S2>
{
    fn into(self) -> BNDebugFunctionInfo {
        let parameter_count: usize = self.parameters.len();

        let (short_name, _short_name_ref) = match self.short_name {
            Some(name) => {
                let temp = Box::new(name.as_bytes_with_nul());
                ((*temp).as_ref().as_ptr() as *mut _, Some(temp))
            }
            _ => (ptr::null_mut() as *mut _, None),
        };
        let (full_name, _full_name_ref) = match self.full_name {
            Some(name) => {
                let temp = Box::new(name.as_bytes_with_nul());
                ((*temp).as_ref().as_ptr() as *mut _, Some(temp))
            }
            _ => (ptr::null_mut() as *mut _, None),
        };
        let (raw_name, _raw_name_ref) = match self.raw_name {
            Some(name) => {
                let temp = Box::new(name.as_bytes_with_nul());
                ((*temp).as_ref().as_ptr() as *mut _, Some(temp))
            }
            _ => (ptr::null_mut() as *mut _, None),
        };

        let (_parameter_name_bytes, mut parameter_names, mut parameter_types): (
            Vec<S2::Result>,
            Vec<*mut c_char>,
            Vec<*mut BNType>,
        ) = self.parameters.into_iter().fold(
            (
                Vec::with_capacity(parameter_count),
                Vec::with_capacity(parameter_count),
                Vec::with_capacity(parameter_count),
            ),
            |(mut parameter_name_bytes, mut parameter_names, mut parameter_types), (n, t)| {
                parameter_name_bytes.push(n.as_bytes_with_nul());
                parameter_names
                    .push(parameter_name_bytes.last().unwrap().as_ref().as_ptr() as *mut c_char);
                parameter_types.push(t.handle);
                (parameter_name_bytes, parameter_names, parameter_types)
            },
        );

        BNDebugFunctionInfo {
            shortName: short_name,
            fullName: full_name,
            rawName: raw_name,
            address: self.address,
            returnType: match self.return_type {
                Some(return_type) => return_type.handle,
                _ => ptr::null_mut(),
            },
            parameterNames: match parameter_count {
                0 => ptr::null_mut(),
                _ => parameter_names.as_mut_ptr(),
            },
            parameterTypes: match parameter_count {
                0 => ptr::null_mut(),
                _ => parameter_types.as_mut_ptr(),
            },
            parameterCount: parameter_count,
            variableParameters: self.variable_parameters,
            callingConvention: match self.calling_convention {
                Some(calling_convention) => calling_convention.handle,
                _ => ptr::null_mut(),
            },
            platform: match self.platform {
                Some(platform) => platform.handle,
                _ => ptr::null_mut(),
            },
        }
    }
}

impl<A: Architecture, S1: BnStrCompatible, S2: BnStrCompatible> DebugFunctionInfo<A, S1, S2> {
    pub fn new(
        short_name: Option<S1>,
        full_name: Option<S1>,
        raw_name: Option<S1>,
        return_type: Option<Ref<Type>>,
        address: Option<u64>,
        parameters: Option<Vec<(S2, Ref<Type>)>>,
        variable_parameters: Option<bool>,
        calling_convention: Option<Ref<CallingConvention<A>>>,
        platform: Option<Ref<Platform>>,
    ) -> Self {
        Self {
            short_name,
            full_name,
            raw_name,
            return_type,
            address: match address {
                Some(address) => address,
                _ => 0,
            },
            parameters: match parameters {
                Some(parameters) => parameters,
                _ => vec![],
            },
            variable_parameters: match variable_parameters {
                Some(variable_parameters) => variable_parameters,
                _ => false,
            },
            calling_convention,
            platform,
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
        let parser_name = parser_name.as_bytes_with_nul();

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
    ) -> Vec<DebugFunctionInfo<CoreArchitecture, String, String>> {
        let parser_name = parser_name.as_bytes_with_nul();

        let mut count: usize = 0;
        let functions_ptr = unsafe {
            BNGetDebugFunctions(
                self.handle,
                parser_name.as_ref().as_ptr() as *mut _,
                &mut count,
            )
        };

        let result: Vec<DebugFunctionInfo<CoreArchitecture, String, String>> = unsafe {
            slice::from_raw_parts_mut(functions_ptr, count)
                .iter()
                .map(DebugFunctionInfo::<CoreArchitecture, String, String>::from)
                .collect()
        };

        unsafe { BNFreeDebugFunctions(functions_ptr, count) };
        result
    }

    /// A generator of all functions provided by DebugInfoParsers
    pub fn functions(&self) -> Vec<DebugFunctionInfo<CoreArchitecture, String, String>> {
        let mut count: usize = 0;
        let functions_ptr =
            unsafe { BNGetDebugFunctions(self.handle, ptr::null_mut(), &mut count) };

        let result: Vec<DebugFunctionInfo<CoreArchitecture, String, String>> = unsafe {
            slice::from_raw_parts_mut(functions_ptr, count)
                .iter()
                .map(DebugFunctionInfo::<CoreArchitecture, String, String>::from)
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
        let parser_name = parser_name.as_bytes_with_nul();

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

    /// Adds a type scoped under the current parser's name to the debug info
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

    /// Adds a function scoped under the current parser's name to the debug info
    pub fn add_function<A: Architecture, S1: BnStrCompatible, S2: BnStrCompatible>(
        &mut self,
        new_func: DebugFunctionInfo<A, S1, S2>,
    ) -> bool {
        unsafe { BNAddDebugFunction(self.handle, &mut new_func.into() as *mut _) }
    }

    /// Adds a data variable scoped under the current parser's name to the debug info
    pub fn add_data_variable<S: BnStrCompatible>(
        &self,
        address: u64,
        t: &Type,
        name: Option<S>,
    ) -> bool {
        match name {
            Some(name) => {
                let name = name.as_bytes_with_nul();
                unsafe {
                    BNAddDebugDataVariable(
                        self.handle,
                        address,
                        t.handle,
                        name.as_ref().as_ptr() as *mut _,
                    )
                }
            }
            None => unsafe {
                BNAddDebugDataVariable(self.handle, address, t.handle, ptr::null_mut())
            },
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

impl AsRef<DebugInfo> for DebugInfo {
    fn as_ref(&self) -> &Self {
        self
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
    fn parse_info(&self, debug_info: &mut DebugInfo, view: &BinaryView);
}
