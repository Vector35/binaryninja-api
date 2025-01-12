use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void};
use std::fmt::Debug;
use std::ptr::NonNull;

use crate::platform::Platform;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{raw_to_string, BnStrCompatible, BnString};
use crate::typecontainer::TypeContainer;
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
            Ok(raw_result.into())
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
            Ok(QualifiedNameAndType::from(output))
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

impl From<BNTypeParserError> for TypeParserError {
    fn from(value: BNTypeParserError) -> Self {
        Self {
            severity: value.severity,
            message: unsafe { BnString::from_raw(value.message).to_string() },
            file_name: unsafe { BnString::from_raw(value.fileName).to_string() },
            line: value.line,
            column: value.column,
        }
    }
}

impl From<&BNTypeParserError> for TypeParserError {
    fn from(value: &BNTypeParserError) -> Self {
        Self {
            severity: value.severity,
            message: raw_to_string(value.message).unwrap(),
            file_name: raw_to_string(value.fileName).unwrap(),
            line: value.line,
            column: value.column,
        }
    }
}

impl From<TypeParserError> for BNTypeParserError {
    fn from(value: TypeParserError) -> Self {
        Self {
            severity: value.severity,
            message: BnString::new(value.message).into_raw(),
            fileName: BnString::new(value.file_name).into_raw(),
            line: value.line,
            column: value.column,
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
        Self::from(raw)
    }
}

#[derive(Debug, Eq, PartialEq, Default)]
pub struct TypeParserResult {
    pub types: Vec<ParsedType>,
    pub variables: Vec<ParsedType>,
    pub functions: Vec<ParsedType>,
}

impl From<BNTypeParserResult> for TypeParserResult {
    fn from(mut value: BNTypeParserResult) -> Self {
        let raw_types = unsafe { std::slice::from_raw_parts(value.types, value.typeCount) };
        let raw_variables =
            unsafe { std::slice::from_raw_parts(value.variables, value.variableCount) };
        let raw_functions =
            unsafe { std::slice::from_raw_parts(value.functions, value.functionCount) };
        let result = TypeParserResult {
            types: raw_types.iter().map(ParsedType::from).collect(),
            variables: raw_variables.iter().map(ParsedType::from).collect(),
            functions: raw_functions.iter().map(ParsedType::from).collect(),
        };
        // SAFETY: `value` must be a properly initialized BNTypeParserResult.
        unsafe { BNFreeTypeParserResult(&mut value) };
        result
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedType {
    name: QualifiedName,
    ty: Ref<Type>,
    user: bool,
}

impl ParsedType {
    pub fn new(name: QualifiedName, ty: Ref<Type>, user: bool) -> Self {
        Self { name, ty, user }
    }
}

impl From<BNParsedType> for ParsedType {
    fn from(value: BNParsedType) -> Self {
        Self {
            name: value.name.into(),
            ty: unsafe { Type::ref_from_raw(value.type_) },
            user: value.isUser,
        }
    }
}

impl From<&BNParsedType> for ParsedType {
    fn from(value: &BNParsedType) -> Self {
        Self {
            name: QualifiedName::from(&value.name),
            ty: unsafe { Type::from_raw(value.type_).to_owned() },
            user: value.isUser,
        }
    }
}

impl From<ParsedType> for BNParsedType {
    fn from(value: ParsedType) -> Self {
        Self {
            name: value.name.into(),
            type_: value.ty.handle,
            isUser: value.user,
        }
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
        ParsedType::from(raw)
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
        *result = bn_inner_result.into_raw();
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
            *result = bn_inner_result.into_raw();
            *errors = std::ptr::null_mut();
            *error_count = 0;
            true
        }
        Err(inner_errors) => {
            *error_count = inner_errors.len();
            let inner_errors: Box<[_]> = inner_errors.into_iter().map(Into::into).collect();
            *result = std::ptr::null_mut();
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
            let boxed_raw_types: Box<[BNParsedType]> = type_parser_result
                .types
                .into_iter()
                .map(Into::into)
                .collect();
            let boxed_raw_variables: Box<[BNParsedType]> = type_parser_result
                .variables
                .into_iter()
                .map(Into::into)
                .collect();
            let boxed_raw_functions: Box<[BNParsedType]> = type_parser_result
                .functions
                .into_iter()
                .map(Into::into)
                .collect();
            let type_count = boxed_raw_types.len();
            let variable_count = boxed_raw_variables.len();
            let function_count = boxed_raw_functions.len();
            let raw_result = BNTypeParserResult {
                // NOTE: Freed with `cb_free_result`.
                types: Box::leak(boxed_raw_types).as_mut_ptr(),
                // NOTE: Freed with `cb_free_result`.
                variables: Box::leak(boxed_raw_variables).as_mut_ptr(),
                // NOTE: Freed with `cb_free_result`.
                functions: Box::leak(boxed_raw_functions).as_mut_ptr(),
                typeCount: type_count,
                variableCount: variable_count,
                functionCount: function_count,
            };
            *result = raw_result;
            *errors = std::ptr::null_mut();
            *error_count = 0;
            true
        }
        Err(inner_errors) => {
            *error_count = inner_errors.len();
            let inner_errors: Box<[_]> = inner_errors.into_iter().map(Into::into).collect();
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
            *result = inner_result.into();
            *errors = std::ptr::null_mut();
            *error_count = 0;
            true
        }
        Err(inner_errors) => {
            *error_count = inner_errors.len();
            let inner_errors: Box<[_]> = inner_errors.into_iter().map(Into::into).collect();
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
    let _ = Box::from_raw(result);
}

unsafe extern "C" fn cb_free_error_list(
    _ctxt: *mut c_void,
    errors: *mut BNTypeParserError,
    error_count: usize,
) {
    let errors = std::ptr::slice_from_raw_parts_mut(errors, error_count);
    let _ = Box::from_raw(errors);
}
