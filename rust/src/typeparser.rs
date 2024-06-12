use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use crate::binaryview::BinaryView;
use crate::disassembly::InstructionTextToken;
use crate::platform::Platform;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{BnStrCompatible, BnString};
use crate::types::{NamedTypeReference, QualifiedName, QualifiedNameAndType, Type};

pub type TypeParserErrorSeverity = BNTypeParserErrorSeverity;
pub type TypeParserOption = BNTypeParserOption;
pub type TokenEscapingType = BNTokenEscapingType;
pub type TypeDefinitionLineType = BNTypeDefinitionLineType;

#[repr(transparent)]
pub struct CoreTypeParser {
    handle: ptr::NonNull<BNTypeParser>,
}

impl CoreTypeParser {
    #[allow(clippy::mut_from_ref)]
    fn as_raw(&self) -> &mut BNTypeParser {
        unsafe { &mut *self.handle.as_ptr() }
    }

    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNTypeParser>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNTypeParser) -> &Self {
        mem::transmute(handle)
    }

    pub fn parsers() -> Array<CoreTypeParser> {
        let mut count = 0;
        let result = unsafe { BNGetTypeParserList(&mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn parser_by_name<S: BnStrCompatible>(name: S) -> Option<CoreTypeParser> {
        let name_raw = name.into_bytes_with_nul();
        let result =
            unsafe { BNGetTypeParserByName(name_raw.as_ref().as_ptr() as *const ffi::c_char) };
        ptr::NonNull::new(result).map(|x| unsafe { Self::from_raw(x) })
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNGetTypeParserName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn get_option_text(&self, option: TypeParserOption, value: &str) -> Option<BnString> {
        let mut output = ptr::null_mut();
        let value_cstr = BnString::new(value);
        let result = unsafe {
            BNGetTypeParserOptionText(self.as_raw(), option, value_cstr.as_ptr(), &mut output)
        };
        result.then(|| {
            assert!(!output.is_null());
            unsafe { BnString::from_raw(output) }
        })
    }

    pub fn preprocess_source(
        &self,
        source: &str,
        file_name: &str,
        platform: &Platform,
        existing_types: &TypeContainer,
        options: &[BnString],
        include_dirs: &[BnString],
    ) -> Result<BnString, Array<TypeParserError>> {
        let source_cstr = BnString::new(source);
        let file_name_cstr = BnString::new(file_name);
        let mut result = ptr::null_mut();
        let mut errors = ptr::null_mut();
        let mut error_count = 0;
        // SAFETY BnString and *const ffi::c_char are transparent
        let success = unsafe {
            BNTypeParserPreprocessSource(
                self.as_raw(),
                source_cstr.as_ptr(),
                file_name_cstr.as_ptr(),
                platform.handle,
                existing_types.as_raw(),
                options.as_ptr() as *const *const ffi::c_char,
                options.len(),
                include_dirs.as_ptr() as *const *const ffi::c_char,
                include_dirs.len(),
                &mut result,
                &mut errors,
                &mut error_count,
            )
        };
        if success {
            assert!(!result.is_null());
            Ok(unsafe { BnString::from_raw(result) })
        } else {
            Err(unsafe { Array::new(errors, error_count, ()) })
        }
    }

    pub fn parse_types_from_source(
        &self,
        source: &str,
        file_name: &str,
        platform: &Platform,
        existing_types: &TypeContainer,
        options: &[BnString],
        include_dirs: &[BnString],
        auto_type_source: &str,
    ) -> Result<TypeParserResult, Array<TypeParserError>> {
        let source_cstr = BnString::new(source);
        let file_name_cstr = BnString::new(file_name);
        let auto_type_source = BnString::new(auto_type_source);
        let mut result = BNTypeParserResult::default();
        let mut errors = ptr::null_mut();
        let mut error_count = 0;
        // SAFETY BnString and *const ffi::c_char are transparent
        let success = unsafe {
            BNTypeParserParseTypesFromSource(
                self.as_raw(),
                source_cstr.as_ptr(),
                file_name_cstr.as_ptr(),
                platform.handle,
                existing_types.as_raw(),
                options.as_ptr() as *const *const ffi::c_char,
                options.len(),
                include_dirs.as_ptr() as *const *const ffi::c_char,
                include_dirs.len(),
                auto_type_source.as_ptr(),
                &mut result,
                &mut errors,
                &mut error_count,
            )
        };
        if success {
            Ok(unsafe { TypeParserResult::from_raw(result) })
        } else {
            Err(unsafe { Array::new(errors, error_count, ()) })
        }
    }

    pub fn parse_type_string(
        &self,
        source: &str,
        platform: &Platform,
        existing_types: &TypeContainer,
    ) -> Result<QualifiedNameAndType, Array<TypeParserError>> {
        let source_cstr = BnString::new(source);
        let mut output = BNQualifiedNameAndType::default();
        let mut errors = ptr::null_mut();
        let mut error_count = 0;
        let result = unsafe {
            BNTypeParserParseTypeString(
                self.as_raw(),
                source_cstr.as_ptr(),
                platform.handle,
                existing_types.as_raw(),
                &mut output,
                &mut errors,
                &mut error_count,
            )
        };
        if result {
            Ok(QualifiedNameAndType(output))
        } else {
            Err(unsafe { Array::new(errors, error_count, ()) })
        }
    }
}

impl Default for CoreTypeParser {
    fn default() -> Self {
        unsafe { Self::from_raw(ptr::NonNull::new(BNGetDefaultTypeParser()).unwrap()) }
    }
}

pub trait TypeParser {
    /// Get the string representation of an option for passing to parse_type_*.
    /// Returns a string representing the option if the parser supports it,
    /// otherwise None
    ///
    /// * `option` - Option type
    /// * `value` - Option value
    fn get_option_text(&self, option: TypeParserOption, value: &str) -> Option<BnString>;

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
        options: &[BnString],
        include_dirs: &[BnString],
    ) -> Result<BnString, Vec<TypeParserError>>;

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
        options: &[BnString],
        include_dirs: &[BnString],
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

/// Register a custom parser with the API
pub fn register_type_parser<S: BnStrCompatible, T: TypeParser>(
    name: S,
    parser: T,
) -> (&'static mut T, CoreTypeParser) {
    let parser = Box::leak(Box::new(parser));
    let mut callback = BNTypeParserCallbacks {
        context: parser as *mut _ as *mut ffi::c_void,
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
            name.into_bytes_with_nul().as_ref().as_ptr() as *const ffi::c_char,
            &mut callback,
        )
    };
    let core = unsafe { CoreTypeParser::from_raw(ptr::NonNull::new(result).unwrap()) };
    (parser, core)
}

impl CoreArrayProvider for CoreTypeParser {
    type Raw = *mut BNTypeParser;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for CoreTypeParser {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeTypeParserList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        CoreTypeParser::ref_from_raw(raw)
    }
}

#[repr(transparent)]
pub struct TypeContainer {
    handle: ptr::NonNull<BNTypeContainer>,
}

impl TypeContainer {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNTypeContainer>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNTypeContainer) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::ref_as_ptr)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNTypeContainer {
        &mut *self.handle.as_ptr()
    }
}

impl Drop for TypeContainer {
    fn drop(&mut self) {
        unsafe { BNFreeTypeContainer(self.as_raw()) }
    }
}

impl Clone for TypeContainer {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNDuplicateTypeContainer(self.as_raw())).unwrap())
        }
    }
}

#[repr(transparent)]
pub struct CoreTypePrinter {
    handle: ptr::NonNull<BNTypePrinter>,
}

impl CoreTypePrinter {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNTypePrinter>) -> CoreTypePrinter {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNTypePrinter) -> &Self {
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNTypePrinter {
        &mut *self.handle.as_ptr()
    }

    pub fn printers() -> Array<CoreTypePrinter> {
        let mut count = 0;
        let result = unsafe { BNGetTypePrinterList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn printer_by_name<S: BnStrCompatible>(name: S) -> Option<CoreTypePrinter> {
        let name_raw = name.into_bytes_with_nul();
        let result =
            unsafe { BNGetTypePrinterByName(name_raw.as_ref().as_ptr() as *const ffi::c_char) };
        ptr::NonNull::new(result).map(|x| unsafe { Self::from_raw(x) })
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNGetTypePrinterName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn get_type_tokens(
        &self,
        type_: &Type,
        platform: &Platform,
        name: &QualifiedName,
        base_confidence: u8,
        escaping: TokenEscapingType,
    ) -> Option<Array<InstructionTextToken>> {
        let mut result_count = 0;
        let mut result = ptr::null_mut();
        let success = unsafe {
            BNGetTypePrinterTypeTokens(
                self.as_raw(),
                type_.handle,
                platform.handle,
                &name.0 as *const _ as *mut _,
                base_confidence,
                escaping,
                &mut result,
                &mut result_count,
            )
        };
        success.then(|| {
            assert!(!result.is_null());
            unsafe { Array::new(result, result_count, ()) }
        })
    }

    pub fn get_type_tokens_before_name(
        &self,
        type_: &Type,
        platform: &Platform,
        base_confidence: u8,
        parent_type: &Type,
        escaping: TokenEscapingType,
    ) -> Option<Array<InstructionTextToken>> {
        let mut result_count = 0;
        let mut result = ptr::null_mut();
        let success = unsafe {
            BNGetTypePrinterTypeTokensBeforeName(
                self.as_raw(),
                type_.handle,
                platform.handle,
                base_confidence,
                parent_type.handle,
                escaping,
                &mut result,
                &mut result_count,
            )
        };
        success.then(|| {
            assert!(!result.is_null());
            unsafe { Array::new(result, result_count, ()) }
        })
    }

    pub fn get_type_tokens_after_name(
        &self,
        type_: &Type,
        platform: &Platform,
        base_confidence: u8,
        parent_type: &Type,
        escaping: TokenEscapingType,
    ) -> Option<Array<InstructionTextToken>> {
        let mut result_count = 0;
        let mut result = ptr::null_mut();
        let success = unsafe {
            BNGetTypePrinterTypeTokensAfterName(
                self.as_raw(),
                type_.handle,
                platform.handle,
                base_confidence,
                parent_type.handle,
                escaping,
                &mut result,
                &mut result_count,
            )
        };
        success.then(|| {
            assert!(!result.is_null());
            unsafe { Array::new(result, result_count, ()) }
        })
    }

    pub fn get_type_string(
        &self,
        type_: &Type,
        platform: &Platform,
        name: &QualifiedName,
        escaping: TokenEscapingType,
    ) -> Option<BnString> {
        let mut result = ptr::null_mut();
        let success = unsafe {
            BNGetTypePrinterTypeString(
                self.as_raw(),
                type_.handle,
                platform.handle,
                &name.0 as *const _ as *mut _,
                escaping,
                &mut result,
            )
        };
        success.then(|| unsafe {
            assert!(!result.is_null());
            BnString::from_raw(result)
        })
    }

    pub fn get_type_string_before_name(
        &self,
        type_: &Type,
        platform: &Platform,
        escaping: BNTokenEscapingType,
    ) -> Option<BnString> {
        let mut result = ptr::null_mut();
        let success = unsafe {
            BNGetTypePrinterTypeStringAfterName(
                self.as_raw(),
                type_.handle,
                platform.handle,
                escaping,
                &mut result,
            )
        };
        success.then(|| unsafe {
            assert!(!result.is_null());
            BnString::from_raw(result)
        })
    }

    pub fn get_type_string_after_name(
        &self,
        type_: &Type,
        platform: &Platform,
        escaping: TokenEscapingType,
    ) -> Option<BnString> {
        let mut result = ptr::null_mut();
        let success = unsafe {
            BNGetTypePrinterTypeStringBeforeName(
                self.as_raw(),
                type_.handle,
                platform.handle,
                escaping,
                &mut result,
            )
        };
        success.then(|| unsafe {
            assert!(!result.is_null());
            BnString::from_raw(result)
        })
    }

    pub fn get_type_lines(
        &self,
        type_: &Type,
        types: &TypeContainer,
        name: &QualifiedName,
        padding_cols: ffi::c_int,
        collapsed: bool,
        escaping: TokenEscapingType,
    ) -> Option<Array<TypeDefinitionLine>> {
        let mut result_count = 0;
        let mut result = ptr::null_mut();
        let success = unsafe {
            BNGetTypePrinterTypeLines(
                self.as_raw(),
                type_.handle,
                types.as_raw(),
                &name.0 as *const BNQualifiedName as *mut BNQualifiedName,
                padding_cols,
                collapsed,
                escaping,
                &mut result,
                &mut result_count,
            )
        };
        success.then(|| {
            assert!(!result.is_null());
            unsafe { Array::<TypeDefinitionLine>::new(result, result_count, ()) }
        })
    }

    /// Print all types to a single big string, including headers, sections, etc
    ///
    /// * `types` - All types to print
    /// * `data` - Binary View in which all the types are defined
    /// * `padding_cols` - Maximum number of bytes represented by each padding line
    /// * `escaping` - Style of escaping literals which may not be parsable
    pub fn default_print_all_types(
        &self,
        types: &[QualifiedNameAndType],
        data: &BinaryView,
        padding_cols: ffi::c_int,
        escaping: TokenEscapingType,
    ) -> Option<BnString> {
        let mut result = ptr::null_mut();
        let mut types_raw: Vec<*mut BNType> = types
            .iter()
            .map(|t| t.type_object().as_ref().handle)
            .collect();
        let mut names_raw: Vec<BNQualifiedName> = types.iter().map(|t| t.name().0).collect();
        let success = unsafe {
            BNTypePrinterDefaultPrintAllTypes(
                self.as_raw(),
                names_raw.as_mut_ptr(),
                types_raw.as_mut_ptr(),
                types.len(),
                data.handle,
                padding_cols,
                escaping,
                &mut result,
            )
        };
        success.then(|| unsafe {
            assert!(!result.is_null());
            BnString::from_raw(result)
        })
    }

    pub fn print_all_types(
        &self,
        types: &[QualifiedNameAndType],
        data: &BinaryView,
        padding_cols: ffi::c_int,
        escaping: TokenEscapingType,
    ) -> Option<BnString> {
        let mut result = ptr::null_mut();
        let mut types_raw: Vec<*mut BNType> = types
            .iter()
            .map(|t| t.type_object().as_ref().handle)
            .collect();
        let mut names_raw: Vec<BNQualifiedName> = types.iter().map(|t| t.name().0).collect();
        let success = unsafe {
            BNTypePrinterPrintAllTypes(
                self.as_raw(),
                names_raw.as_mut_ptr(),
                types_raw.as_mut_ptr(),
                types.len(),
                data.handle,
                padding_cols,
                escaping,
                &mut result,
            )
        };
        success.then(|| unsafe {
            assert!(!result.is_null());
            BnString::from_raw(result)
        })
    }
}

impl Default for CoreTypePrinter {
    fn default() -> Self {
        let default_settings = crate::settings::Settings::default();
        let name = default_settings.get_string(
            ffi::CStr::from_bytes_with_nul(b"analysis.types.printerName\x00").unwrap(),
            None,
            None,
        );
        Self::printer_by_name(name).unwrap()
    }
}

impl CoreArrayProvider for CoreTypePrinter {
    type Raw = *mut BNTypePrinter;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for CoreTypePrinter {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeTypePrinterList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        CoreTypePrinter::ref_from_raw(raw)
    }
}

pub trait TypePrinter {
    /// Generate a single-line text representation of a type, Returns a List
    /// of text tokens representing the type.
    ///
    /// * `type_` - Type to print
    /// * `platform` - Platform responsible for this type
    /// * `name` - Name of the type
    /// * `base_confidence` - Confidence to use for tokens created for this type
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_tokens(
        &self,
        type_: &Type,
        platform: &Platform,
        name: &QualifiedName,
        base_confidence: u8,
        escaping: TokenEscapingType,
    ) -> Option<Vec<InstructionTextToken>>;

    /// In a single-line text representation of a type, generate the tokens that
    /// should be printed before the type's name. Returns a list of text tokens
    /// representing the type
    ///
    /// * `type_` - Type to print
    /// * `platform` - Platform responsible for this type
    /// * `base_confidence` - Confidence to use for tokens created for this type
    /// * `parent_type` - Type of the parent of this type, or None
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_tokens_before_name(
        &self,
        type_: &Type,
        platform: &Platform,
        base_confidence: u8,
        parent_type: &Type,
        escaping: TokenEscapingType,
    ) -> Option<Vec<InstructionTextToken>>;

    /// In a single-line text representation of a type, generate the tokens
    /// that should be printed after the type's name. Returns a ist of text
    /// tokens representing the type
    ///
    /// * `type_` - Type to print
    /// * `platform` - Platform responsible for this type
    /// * `base_confidence` - Confidence to use for tokens created for this type
    /// * `parent_type` - Type of the parent of this type, or None
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_tokens_after_name(
        &self,
        type_: &Type,
        platform: &Platform,
        base_confidence: u8,
        parent_type: &Type,
        escaping: TokenEscapingType,
    ) -> Option<Vec<InstructionTextToken>>;

    /// Generate a single-line text representation of a type. Returns a string
    /// representing the type
    ///
    /// * `type_` - Type to print
    /// * `platform` - Platform responsible for this type
    /// * `name` - Name of the type
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_string(
        &self,
        type_: &Type,
        platform: &Platform,
        name: &QualifiedName,
        escaping: TokenEscapingType,
    ) -> Option<BnString>;

    /// In a single-line text representation of a type, generate the string that
    /// should be printed before the type's name. Returns a string representing
    /// the type
    ///
    /// * `type_` - Type to print
    /// * `platform` - Platform responsible for this type
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_string_before_name(
        &self,
        type_: &Type,
        platform: &Platform,
        escaping: TokenEscapingType,
    ) -> Option<BnString>;

    /// In a single-line text representation of a type, generate the string that
    /// should be printed after the type's name. Returns a string representing
    /// the type
    ///
    /// * `type_` - Type to print
    /// * `platform` - Platform responsible for this type
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_string_after_name(
        &self,
        type_: &Type,
        platform: &Platform,
        escaping: TokenEscapingType,
    ) -> Option<BnString>;

    /// Generate a multi-line representation of a type. Returns a list of type
    /// definition lines
    ///
    /// * `type_` - Type to print
    /// * `types` - Type Container containing the type and dependencies
    /// * `name` - Name of the type
    /// * `padding_cols` - Maximum number of bytes represented by each padding line
    /// * `collapsed` - Whether to collapse structure/enum blocks
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_lines(
        &self,
        type_: &Type,
        types: &TypeContainer,
        name: &QualifiedName,
        padding_cols: ffi::c_int,
        collapsed: bool,
        escaping: TokenEscapingType,
    ) -> Option<Vec<TypeDefinitionLine>>;

    /// Print all types to a single big string, including headers, sections,
    /// etc.
    ///
    /// * `types` - All types to print
    /// * `data` - Binary View in which all the types are defined
    /// * `padding_cols` - Maximum number of bytes represented by each padding line
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn print_all_types(
        &self,
        names: &QualifiedName,
        types: &[Type],
        data: &BinaryView,
        padding_cols: ffi::c_int,
        escaping: TokenEscapingType,
    ) -> Option<BnString>;
}

/// Register a custom parser with the API
pub fn register_type_printer<S: BnStrCompatible, T: TypePrinter>(
    name: S,
    parser: T,
) -> (&'static mut T, CoreTypePrinter) {
    let parser = Box::leak(Box::new(parser));
    let mut callback = BNTypePrinterCallbacks {
        context: parser as *mut _ as *mut ffi::c_void,
        getTypeTokens: Some(cb_get_type_tokens::<T>),
        getTypeTokensBeforeName: Some(cb_get_type_tokens_before_name::<T>),
        getTypeTokensAfterName: Some(cb_get_type_tokens_after_name::<T>),
        getTypeString: Some(cb_get_type_string::<T>),
        getTypeStringBeforeName: Some(cb_get_type_string_before_name::<T>),
        getTypeStringAfterName: Some(cb_get_type_string_after_name::<T>),
        getTypeLines: Some(cb_get_type_lines::<T>),
        printAllTypes: Some(cb_print_all_types::<T>),
        freeTokens: Some(cb_free_tokens),
        freeString: Some(cb_free_string),
        freeLines: Some(cb_free_lines),
    };
    let result = unsafe {
        BNRegisterTypePrinter(
            name.into_bytes_with_nul().as_ref().as_ptr() as *const ffi::c_char,
            &mut callback,
        )
    };
    let core = unsafe { CoreTypePrinter::from_raw(ptr::NonNull::new(result).unwrap()) };
    (parser, core)
}

#[repr(C)]
#[derive(Clone)]
pub struct TypeParserError {
    pub severity: TypeParserErrorSeverity,
    pub message: BnString,
    pub file_name: BnString,
    pub line: u64,
    pub column: u64,
}

impl TypeParserError {
    pub fn new<M: BnStrCompatible, F: BnStrCompatible>(
        severity: TypeParserErrorSeverity,
        message: M,
        file_name: F,
        line: u64,
        column: u64,
    ) -> Self {
        Self {
            severity,
            message: BnString::new(message),
            file_name: BnString::new(file_name),
            line,
            column,
        }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &BNTypeParserError) -> &Self {
        assert!(!handle.message.is_null());
        assert!(!handle.fileName.is_null());
        mem::transmute(handle)
    }
}

impl core::fmt::Debug for TypeParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let severity = match self.severity {
            BNTypeParserErrorSeverity::IgnoredSeverity => "ignored",
            BNTypeParserErrorSeverity::NoteSeverity => "note",
            BNTypeParserErrorSeverity::RemarkSeverity => "remark",
            BNTypeParserErrorSeverity::WarningSeverity => "warning",
            BNTypeParserErrorSeverity::FatalSeverity | BNTypeParserErrorSeverity::ErrorSeverity => {
                "error"
            }
        };
        let message = if self.file_name.as_str() == "" {
            self.message.as_str().to_owned()
        } else {
            format!(
                "{}: {}:{} {}",
                self.file_name.as_str(),
                self.line,
                self.column,
                self.message
            )
        };
        f.debug_struct("TypeParserError")
            .field("severity", &severity)
            .field("message", &message)
            .finish()
    }
}

impl CoreArrayProvider for TypeParserError {
    type Raw = BNTypeParserError;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for TypeParserError {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        unsafe { BNFreeTypeParserErrors(raw, count) }
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TypeParserResult {
    pub types: Vec<ParsedType>,
    pub variables: Vec<ParsedType>,
    pub functions: Vec<ParsedType>,
}

impl TypeParserResult {
    pub(crate) unsafe fn from_raw(mut value: BNTypeParserResult) -> Self {
        fn from_types(values: *mut BNParsedType, value_len: usize) -> Vec<ParsedType> {
            unsafe { core::slice::from_raw_parts(values, value_len) }
                .iter()
                .map(|t| unsafe { ParsedType::clone_from_raw(t) })
                .collect()
        }
        let output = Self {
            types: from_types(value.types, value.typeCount),
            variables: from_types(value.variables, value.variableCount),
            functions: from_types(value.functions, value.functionCount),
        };
        BNFreeTypeParserResult(&mut value);
        output
    }

    unsafe fn into_raw(self) -> TypeParserResultRaw {
        let Self {
            types,
            variables,
            functions,
        } = self;
        let types: &mut [BNParsedType] =
            Box::leak(types.into_iter().map(|x| x.into_raw()).collect());
        let variables: &mut [BNParsedType] =
            Box::leak(variables.into_iter().map(|x| x.into_raw()).collect());
        let functions: &mut [BNParsedType] =
            Box::leak(functions.into_iter().map(|x| x.into_raw()).collect());
        TypeParserResultRaw(BNTypeParserResult {
            types: types.as_mut_ptr(),
            variables: variables.as_mut_ptr(),
            functions: functions.as_mut_ptr(),
            typeCount: types.len(),
            variableCount: variables.len(),
            functionCount: functions.len(),
        })
    }
}

#[repr(transparent)]
struct TypeParserResultRaw(BNTypeParserResult);

impl TypeParserResultRaw {
    pub(crate) unsafe fn into_raw(self) -> BNTypeParserResult {
        mem::ManuallyDrop::new(self).0
    }
}

impl Drop for TypeParserResultRaw {
    fn drop(&mut self) {
        drop(unsafe {
            Box::from_raw(ptr::slice_from_raw_parts_mut(
                self.0.types,
                self.0.typeCount,
            ))
        });
        drop(unsafe {
            Box::from_raw(ptr::slice_from_raw_parts_mut(
                self.0.variables,
                self.0.variableCount,
            ))
        });
        drop(unsafe {
            Box::from_raw(ptr::slice_from_raw_parts_mut(
                self.0.functions,
                self.0.functionCount,
            ))
        });
    }
}

#[derive(Debug, Clone)]
pub struct ParsedType {
    name: QualifiedName,
    type_: Ref<Type>,
    is_user: bool,
}

impl ParsedType {
    pub fn new(name: QualifiedName, type_: Ref<Type>, is_user: bool) -> Self {
        Self {
            name,
            type_,
            is_user,
        }
    }

    pub(crate) unsafe fn clone_from_raw(parsed: &BNParsedType) -> Self {
        let name = mem::ManuallyDrop::new(QualifiedName(parsed.name));
        let type_ = Type {
            handle: parsed.type_,
        }
        .to_owned();
        let user = parsed.isUser;
        ParsedType::new((&*name).clone(), type_, user)
    }

    pub(crate) unsafe fn into_raw(self) -> BNParsedType {
        let Self {
            name,
            type_,
            is_user,
        } = self;
        BNParsedType {
            name: mem::ManuallyDrop::new(name).0,
            type_: Ref::into_raw(type_).handle,
            isUser: is_user,
        }
    }

    pub fn name(&self) -> &QualifiedName {
        &self.name
    }

    pub fn ty(&self) -> &Type {
        &self.type_
    }

    pub fn is_user(&self) -> bool {
        self.is_user
    }
}

#[derive(Clone)]
pub struct TypeDefinitionLine {
    pub line_type: TypeDefinitionLineType,
    pub tokens: Vec<InstructionTextToken>,
    pub type_: Ref<Type>,
    pub parent_type: Ref<Type>,
    pub root_type: Ref<Type>,
    pub root_type_name: BnString,
    pub base_type: Ref<NamedTypeReference>,
    pub base_offset: u64,
    pub offset: u64,
    pub field_index: usize,
}

impl TypeDefinitionLine {
    pub(crate) unsafe fn clone_from_raw(value: &BNTypeDefinitionLine) -> Self {
        Self {
            line_type: value.lineType,
            tokens: unsafe { core::slice::from_raw_parts(value.tokens, value.count) }
                .iter()
                .map(|i| InstructionTextToken::from_raw(i).to_owned())
                .collect(),
            type_: Type {
                handle: value.type_,
            }
            .to_owned(),
            parent_type: Type {
                handle: value.parentType,
            }
            .to_owned(),
            root_type: Type {
                handle: value.rootType,
            }
            .to_owned(),
            root_type_name: unsafe { BnString::new(ffi::CStr::from_ptr(value.rootTypeName)) },
            base_type: NamedTypeReference::from_raw(value.baseType).to_owned(),
            base_offset: value.baseOffset,
            offset: value.offset,
            field_index: value.fieldIndex,
        }
    }

    fn into_raw(self) -> TypeDefinitionLineRaw {
        let TypeDefinitionLine {
            line_type,
            tokens,
            type_,
            parent_type,
            root_type,
            root_type_name,
            base_type,
            base_offset,
            offset,
            field_index,
        } = self;
        let tokens = Box::leak(tokens.into_boxed_slice());
        // SAFETY BNInstructionTextToken and InstructionTextToken are transparent
        let tokens_ptr = tokens.as_mut_ptr() as *mut BNInstructionTextToken;
        TypeDefinitionLineRaw(BNTypeDefinitionLine {
            lineType: line_type,
            tokens: tokens_ptr,
            count: tokens.len(),
            type_: unsafe { Ref::into_raw(type_) }.handle,
            parentType: unsafe { Ref::into_raw(parent_type) }.handle,
            rootType: unsafe { Ref::into_raw(root_type) }.handle,
            rootTypeName: root_type_name.into_raw(),
            baseType: unsafe { Ref::into_raw(base_type) }.handle,
            baseOffset: base_offset,
            offset: offset,
            fieldIndex: field_index,
        })
    }
}

#[repr(transparent)]
struct TypeDefinitionLineRaw(BNTypeDefinitionLine);

impl Drop for TypeDefinitionLineRaw {
    fn drop(&mut self) {
        let _tokens = unsafe {
            Box::from_raw(ptr::slice_from_raw_parts_mut(
                self.0.tokens as *mut InstructionTextToken,
                self.0.count,
            ))
        };
        let _type = unsafe { Type::ref_from_raw(self.0.type_) };
        let _parent_type = unsafe { Type::ref_from_raw(self.0.parentType) };
        let _root_type = unsafe { Type::ref_from_raw(self.0.rootType) };
        let _root_type_name = unsafe { BnString::from_raw(self.0.rootTypeName) };
        let _base_type = unsafe { NamedTypeReference::ref_from_raw(self.0.baseType) };
    }
}

impl CoreArrayProvider for TypeDefinitionLine {
    type Raw = BNTypeDefinitionLine;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for TypeDefinitionLine {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        unsafe { BNFreeTypeDefinitionLineList(raw, count) };
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::clone_from_raw(raw)
    }
}

pub fn options_text<O: BnStrCompatible>(options: O) -> Array<BnString> {
    let options = options.into_bytes_with_nul();
    let mut count = 0;
    let result = unsafe {
        BNParseTypeParserOptionsText(options.as_ref().as_ptr() as *const ffi::c_char, &mut count)
    };
    assert!(!result.is_null());
    unsafe { Array::new(result, count, ()) }
}

pub fn parser_errors(errors: &[TypeParserError]) -> BnString {
    // SAFETY TypeParserError and BNTypeParserError are transparent
    let errors: &[BNTypeParserError] = unsafe { mem::transmute(errors) };
    let result = unsafe { BNFormatTypeParserParseErrors(errors.as_ptr() as *mut _, errors.len()) };
    assert!(!result.is_null());
    unsafe { BnString::from_raw(result) }
}

unsafe extern "C" fn cb_get_option_text<T: TypeParser>(
    ctxt: *mut ::std::os::raw::c_void,
    option: BNTypeParserOption,
    value: *const ffi::c_char,
    result: *mut *mut ffi::c_char,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let value = ffi::CStr::from_ptr(value);
    let value = value.to_string_lossy();
    if let Some(inner_result) = ctxt.get_option_text(option, &value) {
        // SAFETY dropped by cb_free_string
        *result = inner_result.into_raw();
        true
    } else {
        *result = ptr::null_mut();
        false
    }
}

unsafe extern "C" fn cb_preprocess_source<T: TypeParser>(
    ctxt: *mut ffi::c_void,
    source: *const ffi::c_char,
    file_name: *const ffi::c_char,
    platform: *mut BNPlatform,
    existing_types: *mut BNTypeContainer,
    options: *const *const ffi::c_char,
    option_count: usize,
    include_dirs: *const *const ffi::c_char,
    include_dir_count: usize,
    result: *mut *mut ffi::c_char,
    errors: *mut *mut BNTypeParserError,
    error_count: *mut usize,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let source = ffi::CStr::from_ptr(source);
    let file_name = ffi::CStr::from_ptr(file_name);
    let platform = Platform { handle: platform };
    let existing_types = TypeContainer::ref_from_raw(&existing_types);
    // SAFETY BnString and *ffi::c_char are transparent
    let options: &[BnString] =
        core::slice::from_raw_parts(options as *const BnString, option_count);
    let include_dirs: &[BnString] =
        core::slice::from_raw_parts(include_dirs as *const BnString, include_dir_count);
    match ctxt.preprocess_source(
        &source.to_string_lossy(),
        &file_name.to_string_lossy(),
        &platform,
        existing_types,
        options,
        include_dirs,
    ) {
        Ok(inner_result) => {
            // SAFETY drop by the function cb_free_string
            *result = inner_result.into_raw();
            *errors = ptr::null_mut();
            *error_count = 0;
            true
        }
        Err(inner_erros) => {
            // SAFETY drop by the function cb_free_error_list
            let inner_errors = Box::leak(inner_erros.into_boxed_slice());
            // SAFETY: TypeParserError and BNTypeParserError are transparent
            *result = ptr::null_mut();
            *errors = inner_errors.as_ptr() as *mut BNTypeParserError;
            *error_count = inner_errors.len();
            false
        }
    }
}

unsafe extern "C" fn cb_parse_types_from_source<T: TypeParser>(
    ctxt: *mut ffi::c_void,
    source: *const ffi::c_char,
    file_name: *const ffi::c_char,
    platform: *mut BNPlatform,
    existing_types: *mut BNTypeContainer,
    options: *const *const ffi::c_char,
    option_count: usize,
    include_dirs: *const *const ffi::c_char,
    include_dir_count: usize,
    auto_type_source: *const ffi::c_char,
    result: *mut BNTypeParserResult,
    errors: *mut *mut BNTypeParserError,
    error_count: *mut usize,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let source = ffi::CStr::from_ptr(source);
    let file_name = ffi::CStr::from_ptr(file_name);
    let auto_type_source = ffi::CStr::from_ptr(auto_type_source);
    let platform = Platform { handle: platform };
    let existing_types = TypeContainer::ref_from_raw(&existing_types);
    // SAFETY BnString and *ffi::c_char are transparent
    let options: &[BnString] =
        core::slice::from_raw_parts(options as *const BnString, option_count);
    let include_dirs: &[BnString] =
        core::slice::from_raw_parts(include_dirs as *const BnString, include_dir_count);
    match ctxt.parse_types_from_source(
        &source.to_string_lossy(),
        &file_name.to_string_lossy(),
        &platform,
        existing_types,
        options,
        include_dirs,
        &auto_type_source.to_string_lossy(),
    ) {
        Ok(inner_result) => {
            let inner_result_raw = inner_result.into_raw();
            let inner_result_ffi = inner_result_raw.into_raw();
            // SAFETY drop by the function cb_free_result
            *result = inner_result_ffi;
            *errors = ptr::null_mut();
            *error_count = 0;
            true
        }
        Err(inner_erros) => {
            // SAFETY drop by the function cb_free_error_list
            let inner_errors = Box::leak(inner_erros.into_boxed_slice());
            // SAFETY: TypeParserError and BNTypeParserError are transparent
            *result = Default::default();
            *errors = inner_errors.as_ptr() as *mut BNTypeParserError;
            *error_count = inner_errors.len();
            false
        }
    }
}

unsafe extern "C" fn cb_parse_type_string<T: TypeParser>(
    ctxt: *mut ffi::c_void,
    source: *const ffi::c_char,
    platform: *mut BNPlatform,
    existing_types: *mut BNTypeContainer,
    result: *mut BNQualifiedNameAndType,
    errors: *mut *mut BNTypeParserError,
    error_count: *mut usize,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let source = ffi::CStr::from_ptr(source);
    let platform = Platform { handle: platform };
    let existing_types = TypeContainer::ref_from_raw(&existing_types);
    match ctxt.parse_type_string(&source.to_string_lossy(), &platform, existing_types) {
        Ok(inner_result) => {
            // TODO: SAFETY: dropped by the function ?BNFreeQualifiedNameAndType?
            *result = mem::ManuallyDrop::new(inner_result).0;
            *errors = ptr::null_mut();
            *error_count = 0;
            true
        }
        Err(inner_errors) => {
            // SAFETY drop by the function cb_free_error_list
            let inner_errors = Box::leak(inner_errors.into_boxed_slice());
            // SAFETY: TypeParserError and BNTypeParserError are transparent
            *result = Default::default();
            *errors = inner_errors.as_ptr() as *mut BNTypeParserError;
            *error_count = inner_errors.len();
            false
        }
    }
}

unsafe extern "C" fn cb_free_string(_ctxt: *mut ffi::c_void, string: *mut ffi::c_char) {
    // SAFETY the returned string is just BnString
    drop(BnString::from_raw(string))
}

unsafe extern "C" fn cb_free_result(_ctxt: *mut ffi::c_void, result: *mut BNTypeParserResult) {
    drop(TypeParserResultRaw(*result))
}

unsafe extern "C" fn cb_free_error_list(
    _ctxt: *mut ffi::c_void,
    errors: *mut BNTypeParserError,
    error_count: usize,
) {
    // SAFETY TypeParserError and BNTypeParserError are transparent, and error
    // originally was an TypeParserError transmuted into BNTypeParserError
    let errors =
        core::ptr::slice_from_raw_parts_mut(errors, error_count) as *mut [TypeParserError];
    let errors: Box<[TypeParserError]> = Box::from_raw(errors);
    drop(errors)
}

unsafe extern "C" fn cb_get_type_tokens<T: TypePrinter>(
    ctxt: *mut ::std::os::raw::c_void,
    type_: *mut BNType,
    platform: *mut BNPlatform,
    name: *mut BNQualifiedName,
    base_confidence: u8,
    escaping: BNTokenEscapingType,
    result: *mut *mut BNInstructionTextToken,
    result_count: *mut usize,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let inner_result = ctxt.get_type_tokens(
        &Type { handle: type_ },
        &Platform { handle: platform },
        &*mem::ManuallyDrop::new(QualifiedName(*name)),
        base_confidence,
        escaping,
    );
    if let Some(inner_result) = inner_result {
        // SAFETY dropped by the cb_free_tokens
        let inner_result = Box::leak(inner_result.into_boxed_slice());
        *result_count = inner_result.len();
        // SAFETY InstructionTextToken and BNInstructionTextToken are transparent
        let inner_result_ptr =
            inner_result.as_ptr() as *mut InstructionTextToken as *mut BNInstructionTextToken;
        *result = inner_result_ptr;
        true
    } else {
        *result = ptr::null_mut();
        *result_count = 0;
        false
    }
}

unsafe extern "C" fn cb_get_type_tokens_before_name<T: TypePrinter>(
    ctxt: *mut ::std::os::raw::c_void,
    type_: *mut BNType,
    platform: *mut BNPlatform,
    base_confidence: u8,
    parent_type: *mut BNType,
    escaping: BNTokenEscapingType,
    result: *mut *mut BNInstructionTextToken,
    result_count: *mut usize,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let inner_result = ctxt.get_type_tokens_before_name(
        &Type { handle: type_ },
        &Platform { handle: platform },
        base_confidence,
        &Type {
            handle: parent_type,
        },
        escaping,
    );
    if let Some(inner_result) = inner_result {
        // SAFETY dropped by the cb_free_tokens
        let inner_result = Box::leak(inner_result.into_boxed_slice());
        *result_count = inner_result.len();
        // SAFETY InstructionTextToken and BNInstructionTextToken are transparent
        let inner_result_ptr =
            inner_result.as_ptr() as *mut InstructionTextToken as *mut BNInstructionTextToken;
        *result = inner_result_ptr;
        true
    } else {
        *result = ptr::null_mut();
        *result_count = 0;
        false
    }
}

unsafe extern "C" fn cb_get_type_tokens_after_name<T: TypePrinter>(
    ctxt: *mut ::std::os::raw::c_void,
    type_: *mut BNType,
    platform: *mut BNPlatform,
    base_confidence: u8,
    parent_type: *mut BNType,
    escaping: BNTokenEscapingType,
    result: *mut *mut BNInstructionTextToken,
    result_count: *mut usize,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let inner_result = ctxt.get_type_tokens_after_name(
        &Type { handle: type_ },
        &Platform { handle: platform },
        base_confidence,
        &Type {
            handle: parent_type,
        },
        escaping,
    );
    if let Some(inner_result) = inner_result {
        // SAFETY dropped by the cb_free_tokens
        let inner_result = Box::leak(inner_result.into_boxed_slice());
        *result_count = inner_result.len();
        // SAFETY InstructionTextToken and BNInstructionTextToken are transparent
        let inner_result_ptr =
            inner_result.as_ptr() as *mut InstructionTextToken as *mut BNInstructionTextToken;
        *result = inner_result_ptr;
        true
    } else {
        *result = ptr::null_mut();
        *result_count = 0;
        false
    }
}

unsafe extern "C" fn cb_get_type_string<T: TypePrinter>(
    ctxt: *mut ::std::os::raw::c_void,
    type_: *mut BNType,
    platform: *mut BNPlatform,
    name: *mut BNQualifiedName,
    escaping: BNTokenEscapingType,
    result: *mut *mut ::std::os::raw::c_char,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let inner_result = ctxt.get_type_string(
        &Type { handle: type_ },
        &Platform { handle: platform },
        &*mem::ManuallyDrop::new(QualifiedName(*name)),
        escaping,
    );
    if let Some(inner_result) = inner_result {
        // SAFETY dropped by the cb_free_string
        *result = inner_result.into_raw();
        true
    } else {
        *result = ptr::null_mut();
        false
    }
}

unsafe extern "C" fn cb_get_type_string_before_name<T: TypePrinter>(
    ctxt: *mut ::std::os::raw::c_void,
    type_: *mut BNType,
    platform: *mut BNPlatform,
    escaping: BNTokenEscapingType,
    result: *mut *mut ::std::os::raw::c_char,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let inner_result = ctxt.get_type_string_before_name(
        &Type { handle: type_ },
        &Platform { handle: platform },
        escaping,
    );
    if let Some(inner_result) = inner_result {
        // SAFETY dropped by the cb_free_string
        *result = inner_result.into_raw();
        true
    } else {
        *result = ptr::null_mut();
        false
    }
}

unsafe extern "C" fn cb_get_type_string_after_name<T: TypePrinter>(
    ctxt: *mut ::std::os::raw::c_void,
    type_: *mut BNType,
    platform: *mut BNPlatform,
    escaping: BNTokenEscapingType,
    result: *mut *mut ::std::os::raw::c_char,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let inner_result = ctxt.get_type_string_after_name(
        &Type { handle: type_ },
        &Platform { handle: platform },
        escaping,
    );
    if let Some(inner_result) = inner_result {
        // SAFETY dropped by the cb_free_string
        *result = inner_result.into_raw();
        true
    } else {
        *result = ptr::null_mut();
        false
    }
}

unsafe extern "C" fn cb_get_type_lines<T: TypePrinter>(
    ctxt: *mut ::std::os::raw::c_void,
    type_: *mut BNType,
    types: *mut BNTypeContainer,
    name: *mut BNQualifiedName,
    padding_cols: ::std::os::raw::c_int,
    collapsed: bool,
    escaping: BNTokenEscapingType,
    result: *mut *mut BNTypeDefinitionLine,
    result_count: *mut usize,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let inner_result = ctxt.get_type_lines(
        &Type { handle: type_ },
        TypeContainer::ref_from_raw(&types),
        &*mem::ManuallyDrop::new(QualifiedName(*name)),
        padding_cols,
        collapsed,
        escaping,
    );
    if let Some(inner_result) = inner_result {
        // SAFETY dropped by the cb_free_lines
        let inner_result = Box::leak(inner_result.into_iter().map(|x| x.into_raw()).collect());
        // SAFETY TypeDefinitionLineRaw and BNTypeDefinitionLine are transparent
        *result_count = inner_result.len();
        let inner_result_ptr = inner_result.as_ptr() as *const BNTypeDefinitionLine;
        *result = inner_result_ptr as *mut BNTypeDefinitionLine;
        true
    } else {
        *result = ptr::null_mut();
        *result_count = 0;
        false
    }
}

unsafe extern "C" fn cb_print_all_types<T: TypePrinter>(
    ctxt: *mut ::std::os::raw::c_void,
    names: *mut BNQualifiedName,
    types: *mut *mut BNType,
    type_count: usize,
    data: *mut BNBinaryView,
    padding_cols: ::std::os::raw::c_int,
    escaping: BNTokenEscapingType,
    result: *mut *mut ::std::os::raw::c_char,
) -> bool {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let inner_result = ctxt.print_all_types(
        &*mem::ManuallyDrop::new(QualifiedName(*names)),
        //SAFETY *mut BNType and Type are transparent
        core::slice::from_raw_parts(types as *mut Type, type_count),
        &BinaryView { handle: data },
        padding_cols,
        escaping,
    );
    if let Some(inner_result) = inner_result {
        // SAFETY dropped by the cb_free_string
        *result = inner_result.into_raw();
        true
    } else {
        *result = ptr::null_mut();
        false
    }
}

unsafe extern "C" fn cb_free_tokens(
    _ctxt: *mut ::std::os::raw::c_void,
    tokens: *mut BNInstructionTextToken,
    count: usize,
) {
    drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
        tokens as *mut InstructionTextToken,
        count,
    )));
}

unsafe extern "C" fn cb_free_lines(
    _ctxt: *mut ::std::os::raw::c_void,
    lines: *mut BNTypeDefinitionLine,
    count: usize,
) {
    drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
        lines as *mut TypeDefinitionLineRaw,
        count,
    )));
}
