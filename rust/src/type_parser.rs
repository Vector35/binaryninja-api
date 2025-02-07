#![allow(unused)]
use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void};
use std::fmt::Debug;
use std::ptr::NonNull;

use crate::platform::Platform;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{raw_to_string, BnStrCompatible, BnString};
use crate::type_container::TypeContainer;
use crate::types::{QualifiedName, QualifiedNameAndType, Type};

pub type TypeParserErrorSeverity = BNTypeParserErrorSeverity;
pub type TypeParserOption = BNTypeParserOption;

/// Register a custom parser with the API
pub fn register_type_parser<S: BnStrCompatible, T: TypeParser>(
    name: S,
    parser: T,
) -> (&'static mut T, CoreTypeParser) {
    let parser = Box::leak(Box::new(parser));
    let mut callback = BNTypeParserCallbacks {
        context: parser as *mut _ as *mut c_void,
        getOptionText: Some(cb_get_option_text::<T>),
        preprocessSource: Some(cb_preprocess_source::<T>),
        parseTypesFromSource: Some(cb_parse_types_from_source::<T>),
        parseTypeString: Some(cb_parse_type_string::<T>),
        freeString: Some(cb_free_string),
        freeResult: Some(cb_free_result),
        freeErrorList: Some(cb_free_error_list),
    };
    let result = unsafe {
        BNRegisterTypeParser(
            name.into_bytes_with_nul().as_ref().as_ptr() as *const _,
            &mut callback,
        )
    };
    let core = unsafe { CoreTypeParser::from_raw(NonNull::new(result).unwrap()) };
    (parser, core)
}

#[repr(transparent)]
pub struct CoreTypeParser {
    handle: NonNull<BNTypeParser>,
}

impl CoreTypeParser {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNTypeParser>) -> Self {
        Self { handle }
    }

    pub fn parsers() -> Array<CoreTypeParser> {
        let mut count = 0;
        let result = unsafe { BNGetTypeParserList(&mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn parser_by_name<S: BnStrCompatible>(name: S) -> Option<CoreTypeParser> {
        let name_raw = name.into_bytes_with_nul();
        let result = unsafe { BNGetTypeParserByName(name_raw.as_ref().as_ptr() as *const c_char) };
        NonNull::new(result).map(|x| unsafe { Self::from_raw(x) })
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNGetTypeParserName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }
}

impl TypeParser for CoreTypeParser {
    fn get_option_text(&self, option: TypeParserOption, value: &str) -> Option<String> {
        let mut output = std::ptr::null_mut();
        let value_cstr = BnString::new(value);
        let result = unsafe {
            BNGetTypeParserOptionText(
                self.handle.as_ptr(),
                option,
                value_cstr.as_ptr(),
                &mut output,
            )
        };
        result.then(|| {
            assert!(!output.is_null());
            value_cstr.to_string()
        })
    }

    fn preprocess_source(
        &self,
        source: &str,
        file_name: &str,
        platform: &Platform,
        existing_types: &TypeContainer,
        options: &[String],
        include_dirs: &[String],
    ) -> Result<String, Vec<TypeParserError>> {
        let source_cstr = BnString::new(source);
        let file_name_cstr = BnString::new(file_name);
        let mut result = std::ptr::null_mut();
        let mut errors = std::ptr::null_mut();
        let mut error_count = 0;
        let success = unsafe {
            BNTypeParserPreprocessSource(
                self.handle.as_ptr(),
                source_cstr.as_ptr(),
                file_name_cstr.as_ptr(),
                platform.handle,
                existing_types.handle.as_ptr(),
                options.as_ptr() as *const *const c_char,
                options.len(),
                include_dirs.as_ptr() as *const *const c_char,
                include_dirs.len(),
                &mut result,
                &mut errors,
                &mut error_count,
            )
        };
        if success {
            assert!(!result.is_null());
            let bn_result = unsafe { BnString::from_raw(result) };
            Ok(bn_result.to_string())
        } else {
            let errors: Array<TypeParserError> = unsafe { Array::new(errors, error_count, ()) };
            Err(errors.to_vec())
        }
    }

    fn parse_types_from_source(
        &self,
        source: &str,
        file_name: &str,
        platform: &Platform,
        existing_types: &TypeContainer,
        options: &[String],
        include_dirs: &[String],
        auto_type_source: &str,
    ) -> Result<TypeParserResult, Vec<TypeParserError>> {
        let source_cstr = BnString::new(source);
        let file_name_cstr = BnString::new(file_name);
        let auto_type_source = BnString::new(auto_type_source);
        let mut raw_result = BNTypeParserResult::default();
        let mut errors = std::ptr::null_mut();
        let mut error_count = 0;
        let success = unsafe {
            BNTypeParserParseTypesFromSource(
                self.handle.as_ptr(),
                source_cstr.as_ptr(),
                file_name_cstr.as_ptr(),
                platform.handle,
                existing_types.handle.as_ptr(),
                options.as_ptr() as *const *const c_char,
                options.len(),
                include_dirs.as_ptr() as *const *const c_char,
                include_dirs.len(),
                auto_type_source.as_ptr(),
                &mut raw_result,
                &mut errors,
                &mut error_count,
            )
        };
        if success {
            let result = TypeParserResult::from_raw(&raw_result);
            // NOTE: This is safe because the core allocated the TypeParserResult
            TypeParserResult::free_raw(raw_result);
            Ok(result)
        } else {
            let errors: Array<TypeParserError> = unsafe { Array::new(errors, error_count, ()) };
            Err(errors.to_vec())
        }
    }

    fn parse_type_string(
        &self,
        source: &str,
        platform: &Platform,
        existing_types: &TypeContainer,
    ) -> Result<QualifiedNameAndType, Vec<TypeParserError>> {
        let source_cstr = BnString::new(source);
        let mut output = BNQualifiedNameAndType::default();
        let mut errors = std::ptr::null_mut();
        let mut error_count = 0;
        let result = unsafe {
            BNTypeParserParseTypeString(
                self.handle.as_ptr(),
                source_cstr.as_ptr(),
                platform.handle,
                existing_types.handle.as_ptr(),
                &mut output,
                &mut errors,
                &mut error_count,
            )
        };
        if result {
            Ok(QualifiedNameAndType::from_owned_raw(output))
        } else {
            let errors: Array<TypeParserError> = unsafe { Array::new(errors, error_count, ()) };
            Err(errors.to_vec())
        }
    }
}

impl Default for CoreTypeParser {
    fn default() -> Self {
        // TODO: This should return a ref
        unsafe { Self::from_raw(NonNull::new(BNGetDefaultTypeParser()).unwrap()) }
    }
}

// TODO: Impl this on platform.
pub trait TypeParser {
    /// Get the string representation of an option for passing to parse_type_*.
    /// Returns a string representing the option if the parser supports it,
    /// otherwise None
    ///
    /// * `option` - Option type
    /// * `value` - Option value
    fn get_option_text(&self, option: TypeParserOption, value: &str) -> Option<String>;

    /// Preprocess a block of source, returning the source that would be parsed
    ///
    /// * `source` - Source code to process
    /// * `file_name` - Name of the file containing the source (does not need to exist on disk)
    /// * `platform` - Platform to assume the source is relevant to
    /// * `existing_types` - Optional collection of all existing types to use for parsing context
    /// * `options` - Optional string arguments to pass as options, e.g. command line arguments
    /// * `include_dirs` - Optional list of directories to include in the header search path
    fn preprocess_source(
        &self,
        source: &str,
        file_name: &str,
        platform: &Platform,
        existing_types: &TypeContainer,
        options: &[String],
        include_dirs: &[String],
    ) -> Result<String, Vec<TypeParserError>>;

    /// Parse an entire block of source into types, variables, and functions
    ///
    /// * `source` - Source code to parse
    /// * `file_name` - Name of the file containing the source (optional: exists on disk)
    /// * `platform` - Platform to assume the types are relevant to
    /// * `existing_types` - Optional container of all existing types to use for parsing context
    /// * `options` - Optional string arguments to pass as options, e.g. command line arguments
    /// * `include_dirs` - Optional list of directories to include in the header search path
    /// * `auto_type_source` - Optional source of types if used for automatically generated types
    fn parse_types_from_source(
        &self,
        source: &str,
        file_name: &str,
        platform: &Platform,
        existing_types: &TypeContainer,
        options: &[String],
        include_dirs: &[String],
        auto_type_source: &str,
    ) -> Result<TypeParserResult, Vec<TypeParserError>>;

    /// Parse a single type and name from a string containing their definition.
    ///
    /// * `source` - Source code to parse
    /// * `platform` - Platform to assume the types are relevant to
    /// * `existing_types` - Optional container of all existing types to use for parsing context
    fn parse_type_string(
        &self,
        source: &str,
        platform: &Platform,
        existing_types: &TypeContainer,
    ) -> Result<QualifiedNameAndType, Vec<TypeParserError>>;
}

impl CoreArrayProvider for CoreTypeParser {
    type Raw = *mut BNTypeParser;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CoreTypeParser {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeTypeParserList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // TODO: Because handle is a NonNull we should prob make Self::Raw that as well...
        let handle = NonNull::new(*raw).unwrap();
        CoreTypeParser::from_raw(handle)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeParserError {
    pub severity: TypeParserErrorSeverity,
    pub message: String,
    pub file_name: String,
    pub line: u64,
    pub column: u64,
}

impl TypeParserError {
    pub(crate) fn from_raw(value: &BNTypeParserError) -> Self {
        Self {
            severity: value.severity,
            message: raw_to_string(value.message).unwrap(),
            file_name: raw_to_string(value.fileName).unwrap(),
            line: value.line,
            column: value.column,
        }
    }

    pub(crate) fn from_owned_raw(value: BNTypeParserError) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNTypeParserError {
        BNTypeParserError {
            severity: value.severity,
            message: BnString::into_raw(BnString::new(value.message)),
            fileName: BnString::into_raw(BnString::new(value.file_name)),
            line: value.line,
            column: value.column,
        }
    }

    pub(crate) fn free_raw(value: BNTypeParserError) {
        let _ = unsafe { BnString::from_raw(value.message) };
        let _ = unsafe { BnString::from_raw(value.fileName) };
    }

    pub fn new(
        severity: TypeParserErrorSeverity,
        message: String,
        file_name: String,
        line: u64,
        column: u64,
    ) -> Self {
        Self {
            severity,
            message,
            file_name,
            line,
            column,
        }
    }
}

impl CoreArrayProvider for TypeParserError {
    type Raw = BNTypeParserError;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for TypeParserError {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        unsafe { BNFreeTypeParserErrors(raw, count) }
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(raw)
    }
}

#[derive(Debug, Eq, PartialEq, Default)]
pub struct TypeParserResult {
    pub types: Vec<ParsedType>,
    pub variables: Vec<ParsedType>,
    pub functions: Vec<ParsedType>,
}

impl TypeParserResult {
    pub(crate) fn from_raw(value: &BNTypeParserResult) -> Self {
        let raw_types = unsafe { std::slice::from_raw_parts(value.types, value.typeCount) };
        let types = raw_types.iter().map(ParsedType::from_raw).collect();
        let raw_variables =
            unsafe { std::slice::from_raw_parts(value.variables, value.variableCount) };
        let variables = raw_variables.iter().map(ParsedType::from_raw).collect();
        let raw_functions =
            unsafe { std::slice::from_raw_parts(value.functions, value.functionCount) };
        let functions = raw_functions.iter().map(ParsedType::from_raw).collect();
        TypeParserResult {
            types,
            variables,
            functions,
        }
    }

    /// Return a rust allocated type parser result, free using [`Self::free_owned_raw`].
    ///
    /// Under no circumstance should you call [`Self::free_raw`] on the returned result.
    pub(crate) fn into_raw(value: Self) -> BNTypeParserResult {
        let boxed_raw_types: Box<[BNParsedType]> = value
            .types
            .into_iter()
            // NOTE: Freed with [`Self::free_owned_raw`].
            .map(ParsedType::into_raw)
            .collect();
        let boxed_raw_variables: Box<[BNParsedType]> = value
            .variables
            .into_iter()
            // NOTE: Freed with [`Self::free_owned_raw`].
            .map(ParsedType::into_raw)
            .collect();
        let boxed_raw_functions: Box<[BNParsedType]> = value
            .functions
            .into_iter()
            // NOTE: Freed with [`Self::free_owned_raw`].
            .map(ParsedType::into_raw)
            .collect();
        BNTypeParserResult {
            typeCount: boxed_raw_types.len(),
            // NOTE: Freed with [`Self::free_owned_raw`].
            types: Box::leak(boxed_raw_types).as_mut_ptr(),
            variableCount: boxed_raw_variables.len(),
            // NOTE: Freed with [`Self::free_owned_raw`].
            variables: Box::leak(boxed_raw_variables).as_mut_ptr(),
            functionCount: boxed_raw_functions.len(),
            // NOTE: Freed with [`Self::free_owned_raw`].
            functions: Box::leak(boxed_raw_functions).as_mut_ptr(),
        }
    }

    pub(crate) fn free_raw(mut value: BNTypeParserResult) {
        // SAFETY: `value` must be a properly initialized BNTypeParserResult.
        // SAFETY: `value` must be core allocated.
        unsafe { BNFreeTypeParserResult(&mut value) };
    }

    pub(crate) fn free_owned_raw(value: BNTypeParserResult) {
        let raw_types = std::ptr::slice_from_raw_parts_mut(value.types, value.typeCount);
        // Free the rust allocated types list
        let boxed_types = unsafe { Box::from_raw(raw_types) };
        for parsed_type in boxed_types {
            ParsedType::free_raw(parsed_type);
        }
        let raw_variables =
            std::ptr::slice_from_raw_parts_mut(value.variables, value.variableCount);
        // Free the rust allocated variables list
        let boxed_variables = unsafe { Box::from_raw(raw_variables) };
        for parsed_type in boxed_variables {
            ParsedType::free_raw(parsed_type);
        }
        let raw_functions =
            std::ptr::slice_from_raw_parts_mut(value.functions, value.functionCount);
        // Free the rust allocated functions list
        let boxed_functions = unsafe { Box::from_raw(raw_functions) };
        for parsed_type in boxed_functions {
            ParsedType::free_raw(parsed_type);
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedType {
    name: QualifiedName,
    ty: Ref<Type>,
    user: bool,
}

impl ParsedType {
    pub(crate) fn from_raw(value: &BNParsedType) -> Self {
        Self {
            name: QualifiedName::from_raw(&value.name),
            ty: unsafe { Type::from_raw(value.type_).to_owned() },
            user: value.isUser,
        }
    }

    pub(crate) fn from_owned_raw(value: BNParsedType) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNParsedType {
        BNParsedType {
            name: QualifiedName::into_raw(value.name),
            type_: unsafe { Ref::into_raw(value.ty) }.handle,
            isUser: value.user,
        }
    }

    pub(crate) fn free_raw(value: BNParsedType) {
        QualifiedName::free_raw(value.name);
        let _ = unsafe { Type::ref_from_raw(value.type_) };
    }

    pub fn new(name: QualifiedName, ty: Ref<Type>, user: bool) -> Self {
        Self { name, ty, user }
    }
}

impl CoreArrayProvider for ParsedType {
    type Raw = BNParsedType;
    type Context = ();
    type Wrapped<'b> = Self;
}

unsafe impl CoreArrayProviderInner for ParsedType {
    unsafe fn free(_raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        // Expected to be freed with BNFreeTypeParserResult
        // TODO ^ because of the above, we should not provide an array provider for this
    }

    unsafe fn wrap_raw<'b>(raw: &'b Self::Raw, _context: &'b Self::Context) -> Self::Wrapped<'b> {
        ParsedType::from_raw(raw)
    }
}

unsafe extern "C" fn cb_get_option_text<T: TypeParser>(
    ctxt: *mut ::std::os::raw::c_void,
    option: BNTypeParserOption,
    value: *const c_char,
    result: *mut *mut c_char,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    if let Some(inner_result) = ctxt.get_option_text(option, &raw_to_string(value).unwrap()) {
        let bn_inner_result = BnString::new(inner_result);
        // NOTE: Dropped by `cb_free_string`
        *result = BnString::into_raw(bn_inner_result);
        true
    } else {
        *result = std::ptr::null_mut();
        false
    }
}

unsafe extern "C" fn cb_preprocess_source<T: TypeParser>(
    ctxt: *mut c_void,
    source: *const c_char,
    file_name: *const c_char,
    platform: *mut BNPlatform,
    existing_types: *mut BNTypeContainer,
    options: *const *const c_char,
    option_count: usize,
    include_dirs: *const *const c_char,
    include_dir_count: usize,
    result: *mut *mut c_char,
    errors: *mut *mut BNTypeParserError,
    error_count: *mut usize,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let platform = Platform { handle: platform };
    let existing_types_ptr = NonNull::new(existing_types).unwrap();
    let existing_types = TypeContainer::from_raw(existing_types_ptr);
    let options_raw = unsafe { std::slice::from_raw_parts(options, option_count) };
    let options: Vec<_> = options_raw
        .iter()
        .filter_map(|&r| raw_to_string(r))
        .collect();
    let includes_raw = unsafe { std::slice::from_raw_parts(include_dirs, include_dir_count) };
    let includes: Vec<_> = includes_raw
        .iter()
        .filter_map(|&r| raw_to_string(r))
        .collect();
    match ctxt.preprocess_source(
        &raw_to_string(source).unwrap(),
        &raw_to_string(file_name).unwrap(),
        &platform,
        &existing_types,
        &options,
        &includes,
    ) {
        Ok(inner_result) => {
            let bn_inner_result = BnString::new(inner_result);
            // NOTE: Dropped by `cb_free_string`
            *result = BnString::into_raw(bn_inner_result);
            *errors = std::ptr::null_mut();
            *error_count = 0;
            true
        }
        Err(inner_errors) => {
            *result = std::ptr::null_mut();
            *error_count = inner_errors.len();
            // NOTE: Leaking errors here, dropped by `cb_free_error_list`.
            let inner_errors: Box<[_]> = inner_errors
                .into_iter()
                .map(TypeParserError::into_raw)
                .collect();
            // NOTE: Dropped by `cb_free_error_list`
            *errors = Box::leak(inner_errors).as_mut_ptr();
            false
        }
    }
}

unsafe extern "C" fn cb_parse_types_from_source<T: TypeParser>(
    ctxt: *mut c_void,
    source: *const c_char,
    file_name: *const c_char,
    platform: *mut BNPlatform,
    existing_types: *mut BNTypeContainer,
    options: *const *const c_char,
    option_count: usize,
    include_dirs: *const *const c_char,
    include_dir_count: usize,
    auto_type_source: *const c_char,
    result: *mut BNTypeParserResult,
    errors: *mut *mut BNTypeParserError,
    error_count: *mut usize,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let platform = Platform { handle: platform };
    let existing_types_ptr = NonNull::new(existing_types).unwrap();
    let existing_types = TypeContainer::from_raw(existing_types_ptr);
    let options_raw = unsafe { std::slice::from_raw_parts(options, option_count) };
    let options: Vec<_> = options_raw
        .iter()
        .filter_map(|&r| raw_to_string(r))
        .collect();
    let includes_raw = unsafe { std::slice::from_raw_parts(include_dirs, include_dir_count) };
    let includes: Vec<_> = includes_raw
        .iter()
        .filter_map(|&r| raw_to_string(r))
        .collect();
    match ctxt.parse_types_from_source(
        &raw_to_string(source).unwrap(),
        &raw_to_string(file_name).unwrap(),
        &platform,
        &existing_types,
        &options,
        &includes,
        &raw_to_string(auto_type_source).unwrap(),
    ) {
        Ok(type_parser_result) => {
            *result = TypeParserResult::into_raw(type_parser_result);
            *errors = std::ptr::null_mut();
            *error_count = 0;
            true
        }
        Err(inner_errors) => {
            *error_count = inner_errors.len();
            let inner_errors: Box<[_]> = inner_errors
                .into_iter()
                .map(TypeParserError::into_raw)
                .collect();
            *result = Default::default();
            // NOTE: Dropped by cb_free_error_list
            *errors = Box::leak(inner_errors).as_mut_ptr();
            false
        }
    }
}

unsafe extern "C" fn cb_parse_type_string<T: TypeParser>(
    ctxt: *mut c_void,
    source: *const c_char,
    platform: *mut BNPlatform,
    existing_types: *mut BNTypeContainer,
    result: *mut BNQualifiedNameAndType,
    errors: *mut *mut BNTypeParserError,
    error_count: *mut usize,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let platform = Platform { handle: platform };
    let existing_types_ptr = NonNull::new(existing_types).unwrap();
    let existing_types = TypeContainer::from_raw(existing_types_ptr);
    match ctxt.parse_type_string(&raw_to_string(source).unwrap(), &platform, &existing_types) {
        Ok(inner_result) => {
            *result = QualifiedNameAndType::into_raw(inner_result);
            *errors = std::ptr::null_mut();
            *error_count = 0;
            true
        }
        Err(inner_errors) => {
            *error_count = inner_errors.len();
            let inner_errors: Box<[_]> = inner_errors
                .into_iter()
                .map(TypeParserError::into_raw)
                .collect();
            *result = Default::default();
            // NOTE: Dropped by cb_free_error_list
            *errors = Box::leak(inner_errors).as_mut_ptr();
            false
        }
    }
}

unsafe extern "C" fn cb_free_string(_ctxt: *mut c_void, string: *mut c_char) {
    // SAFETY: The returned string is just BnString
    let _ = BnString::from_raw(string);
}

unsafe extern "C" fn cb_free_result(_ctxt: *mut c_void, result: *mut BNTypeParserResult) {
    TypeParserResult::free_owned_raw(*result);
}

unsafe extern "C" fn cb_free_error_list(
    _ctxt: *mut c_void,
    errors: *mut BNTypeParserError,
    error_count: usize,
) {
    let errors = std::ptr::slice_from_raw_parts_mut(errors, error_count);
    let boxed_errors = Box::from_raw(errors);
    for error in boxed_errors {
        TypeParserError::free_raw(error);
    }
}
