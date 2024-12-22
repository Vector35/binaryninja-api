#![allow(unused)]

use crate::binary_view::BinaryView;
use crate::disassembly::InstructionTextToken;
use crate::platform::Platform;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{raw_to_string, BnStrCompatible, BnString};
use crate::type_container::TypeContainer;
use crate::types::{NamedTypeReference, QualifiedName, QualifiedNameAndType, Type};
use binaryninjacore_sys::*;
use std::ffi::{c_char, c_int, c_void};
use std::ptr::NonNull;

pub type TokenEscapingType = BNTokenEscapingType;
pub type TypeDefinitionLineType = BNTypeDefinitionLineType;

/// Register a custom parser with the API
pub fn register_type_printer<S: BnStrCompatible, T: TypePrinter>(
    name: S,
    parser: T,
) -> (&'static mut T, CoreTypePrinter) {
    let parser = Box::leak(Box::new(parser));
    let mut callback = BNTypePrinterCallbacks {
        context: parser as *mut _ as *mut c_void,
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
            name.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
            &mut callback,
        )
    };
    let core = unsafe { CoreTypePrinter::from_raw(NonNull::new(result).unwrap()) };
    (parser, core)
}

#[repr(transparent)]
pub struct CoreTypePrinter {
    handle: NonNull<BNTypePrinter>,
}

impl CoreTypePrinter {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNTypePrinter>) -> CoreTypePrinter {
        Self { handle }
    }

    pub fn printers() -> Array<CoreTypePrinter> {
        let mut count = 0;
        let result = unsafe { BNGetTypePrinterList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn printer_by_name<S: BnStrCompatible>(name: S) -> Option<CoreTypePrinter> {
        let name_raw = name.into_bytes_with_nul();
        let result = unsafe { BNGetTypePrinterByName(name_raw.as_ref().as_ptr() as *const c_char) };
        NonNull::new(result).map(|x| unsafe { Self::from_raw(x) })
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNGetTypePrinterName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn get_type_tokens<T: Into<QualifiedName>>(
        &self,
        type_: &Type,
        platform: &Platform,
        name: T,
        base_confidence: u8,
        escaping: TokenEscapingType,
    ) -> Option<Array<InstructionTextToken>> {
        let mut result_count = 0;
        let mut result = std::ptr::null_mut();
        let mut raw_name = QualifiedName::into_raw(name.into());
        let success = unsafe {
            BNGetTypePrinterTypeTokens(
                self.handle.as_ptr(),
                type_.handle,
                platform.handle,
                &mut raw_name,
                base_confidence,
                escaping,
                &mut result,
                &mut result_count,
            )
        };
        QualifiedName::free_raw(raw_name);
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
        let mut result = std::ptr::null_mut();
        let success = unsafe {
            BNGetTypePrinterTypeTokensBeforeName(
                self.handle.as_ptr(),
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
        let mut result = std::ptr::null_mut();
        let success = unsafe {
            BNGetTypePrinterTypeTokensAfterName(
                self.handle.as_ptr(),
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

    pub fn get_type_string<T: Into<QualifiedName>>(
        &self,
        type_: &Type,
        platform: &Platform,
        name: T,
        escaping: TokenEscapingType,
    ) -> Option<BnString> {
        let mut result = std::ptr::null_mut();
        let mut raw_name = QualifiedName::into_raw(name.into());
        let success = unsafe {
            BNGetTypePrinterTypeString(
                self.handle.as_ptr(),
                type_.handle,
                platform.handle,
                &mut raw_name,
                escaping,
                &mut result,
            )
        };
        QualifiedName::free_raw(raw_name);
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
        let mut result = std::ptr::null_mut();
        let success = unsafe {
            BNGetTypePrinterTypeStringAfterName(
                self.handle.as_ptr(),
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
        let mut result = std::ptr::null_mut();
        let success = unsafe {
            BNGetTypePrinterTypeStringBeforeName(
                self.handle.as_ptr(),
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

    pub fn get_type_lines<T: Into<QualifiedName>>(
        &self,
        type_: &Type,
        types: &TypeContainer,
        name: T,
        padding_cols: isize,
        collapsed: bool,
        escaping: TokenEscapingType,
    ) -> Option<Array<TypeDefinitionLine>> {
        let mut result_count = 0;
        let mut result = std::ptr::null_mut();
        let mut raw_name = QualifiedName::into_raw(name.into());
        let success = unsafe {
            BNGetTypePrinterTypeLines(
                self.handle.as_ptr(),
                type_.handle,
                types.handle.as_ptr(),
                &mut raw_name,
                padding_cols as c_int,
                collapsed,
                escaping,
                &mut result,
                &mut result_count,
            )
        };
        QualifiedName::free_raw(raw_name);
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
    pub fn default_print_all_types<T, I>(
        &self,
        types: T,
        data: &BinaryView,
        padding_cols: isize,
        escaping: TokenEscapingType,
    ) -> Option<BnString>
    where
        T: Iterator<Item = I>,
        I: Into<QualifiedNameAndType>,
    {
        let mut result = std::ptr::null_mut();
        let (mut raw_names, mut raw_types): (Vec<BNQualifiedName>, Vec<_>) = types
            .map(|t| {
                let t = t.into();
                // Leak both to the core and then free afterwards.
                (
                    QualifiedName::into_raw(t.name),
                    unsafe { Ref::into_raw(t.ty) }.handle,
                )
            })
            .unzip();
        let success = unsafe {
            BNTypePrinterDefaultPrintAllTypes(
                self.handle.as_ptr(),
                raw_names.as_mut_ptr(),
                raw_types.as_mut_ptr(),
                raw_types.len(),
                data.handle,
                padding_cols as c_int,
                escaping,
                &mut result,
            )
        };
        for raw_name in raw_names {
            QualifiedName::free_raw(raw_name);
        }
        for raw_type in raw_types {
            let _ = unsafe { Type::ref_from_raw(raw_type) };
        }
        success.then(|| unsafe {
            assert!(!result.is_null());
            BnString::from_raw(result)
        })
    }

    pub fn print_all_types<T, I>(
        &self,
        types: T,
        data: &BinaryView,
        padding_cols: isize,
        escaping: TokenEscapingType,
    ) -> Option<BnString>
    where
        T: IntoIterator<Item = I>,
        I: Into<QualifiedNameAndType>,
    {
        let mut result = std::ptr::null_mut();
        // TODO: I dislike how this iter unzip looks like... but its how to avoid allocating again...
        let (mut raw_names, mut raw_types): (Vec<BNQualifiedName>, Vec<_>) = types
            .into_iter()
            .map(|t| {
                let t = t.into();
                // Leak both to the core and then free afterwards.
                (
                    QualifiedName::into_raw(t.name),
                    unsafe { Ref::into_raw(t.ty) }.handle,
                )
            })
            .unzip();
        let success = unsafe {
            BNTypePrinterPrintAllTypes(
                self.handle.as_ptr(),
                raw_names.as_mut_ptr(),
                raw_types.as_mut_ptr(),
                raw_types.len(),
                data.handle,
                padding_cols as c_int,
                escaping,
                &mut result,
            )
        };
        for raw_name in raw_names {
            QualifiedName::free_raw(raw_name);
        }
        for raw_type in raw_types {
            let _ = unsafe { Type::ref_from_raw(raw_type) };
        }
        success.then(|| unsafe {
            assert!(!result.is_null());
            BnString::from_raw(result)
        })
    }
}

impl Default for CoreTypePrinter {
    fn default() -> Self {
        // TODO: Remove this entirely, there is no "default", its view specific lets not make this some defined behavior.
        let default_settings = crate::settings::Settings::new();
        let name = default_settings.get_string("analysis.types.printerName");
        Self::printer_by_name(name).unwrap()
    }
}

impl CoreArrayProvider for CoreTypePrinter {
    type Raw = *mut BNTypePrinter;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CoreTypePrinter {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeTypePrinterList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // TODO: Because handle is a NonNull we should prob make Self::Raw that as well...
        let handle = NonNull::new(*raw).unwrap();
        CoreTypePrinter::from_raw(handle)
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
    fn get_type_tokens<T: Into<QualifiedName>>(
        &self,
        type_: Ref<Type>,
        platform: Option<Ref<Platform>>,
        name: T,
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
        type_: Ref<Type>,
        platform: Option<Ref<Platform>>,
        base_confidence: u8,
        parent_type: Option<Ref<Type>>,
        escaping: TokenEscapingType,
    ) -> Option<Vec<InstructionTextToken>>;

    /// In a single-line text representation of a type, generate the tokens
    /// that should be printed after the type's name. Returns a list of text
    /// tokens representing the type
    ///
    /// * `type_` - Type to print
    /// * `platform` - Platform responsible for this type
    /// * `base_confidence` - Confidence to use for tokens created for this type
    /// * `parent_type` - Type of the parent of this type, or None
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_tokens_after_name(
        &self,
        type_: Ref<Type>,
        platform: Option<Ref<Platform>>,
        base_confidence: u8,
        parent_type: Option<Ref<Type>>,
        escaping: TokenEscapingType,
    ) -> Option<Vec<InstructionTextToken>>;

    /// Generate a single-line text representation of a type. Returns a string
    /// representing the type
    ///
    /// * `type_` - Type to print
    /// * `platform` - Platform responsible for this type
    /// * `name` - Name of the type
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_string<T: Into<QualifiedName>>(
        &self,
        type_: Ref<Type>,
        platform: Option<Ref<Platform>>,
        name: T,
        escaping: TokenEscapingType,
    ) -> Option<String>;

    /// In a single-line text representation of a type, generate the string that
    /// should be printed before the type's name. Returns a string representing
    /// the type
    ///
    /// * `type_` - Type to print
    /// * `platform` - Platform responsible for this type
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_string_before_name(
        &self,
        type_: Ref<Type>,
        platform: Option<Ref<Platform>>,
        escaping: TokenEscapingType,
    ) -> Option<String>;

    /// In a single-line text representation of a type, generate the string that
    /// should be printed after the type's name. Returns a string representing
    /// the type
    ///
    /// * `type_` - Type to print
    /// * `platform` - Platform responsible for this type
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_string_after_name(
        &self,
        type_: Ref<Type>,
        platform: Option<Ref<Platform>>,
        escaping: TokenEscapingType,
    ) -> Option<String>;

    /// Generate a multi-line representation of a type. Returns a list of type
    /// definition lines
    ///
    /// * `type_` - Type to print
    /// * `types` - Type Container containing the type and dependencies
    /// * `name` - Name of the type
    /// * `padding_cols` - Maximum number of bytes represented by each padding line
    /// * `collapsed` - Whether to collapse structure/enum blocks
    /// * `escaping` - Style of escaping literals which may not be parsable
    fn get_type_lines<T: Into<QualifiedName>>(
        &self,
        type_: Ref<Type>,
        types: &TypeContainer,
        name: T,
        padding_cols: isize,
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
        names: Vec<QualifiedName>,
        types: Vec<Ref<Type>>,
        data: Ref<BinaryView>,
        padding_cols: isize,
        escaping: TokenEscapingType,
    ) -> Option<String>;
}

// TODO: This needs an extreme amount of documentation...
#[derive(Clone)]
pub struct TypeDefinitionLine {
    pub line_type: TypeDefinitionLineType,
    pub tokens: Vec<InstructionTextToken>,
    pub ty: Ref<Type>,
    pub parent_type: Option<Ref<Type>>,
    // TODO: Document what the root type is.
    pub root_type: Option<Ref<Type>>,
    pub root_type_name: Option<String>,
    // TODO: Document the base type, and why its a ntr instead of type + name like root type
    pub base_type: Option<Ref<NamedTypeReference>>,
    // TODO: These can also be optional?
    pub base_offset: u64,
    pub offset: u64,
    pub field_index: usize,
}

impl TypeDefinitionLine {
    pub(crate) fn from_raw(value: &BNTypeDefinitionLine) -> Self {
        Self {
            line_type: value.lineType,
            tokens: {
                let raw_tokens = unsafe { std::slice::from_raw_parts(value.tokens, value.count) };
                raw_tokens
                    .iter()
                    .map(InstructionTextToken::from_raw)
                    .collect()
            },
            ty: unsafe { Type::from_raw(value.type_).to_owned() },
            parent_type: match value.parentType.is_null() {
                false => Some(unsafe { Type::from_raw(value.parentType).to_owned() }),
                true => None,
            },
            root_type: match value.rootType.is_null() {
                false => Some(unsafe { Type::from_raw(value.rootType).to_owned() }),
                true => None,
            },
            root_type_name: match value.rootTypeName.is_null() {
                false => Some(raw_to_string(value.rootTypeName).unwrap()),
                true => None,
            },
            base_type: match value.baseType.is_null() {
                false => Some(unsafe { NamedTypeReference::from_raw(value.baseType).to_owned() }),
                true => None,
            },
            base_offset: value.baseOffset,
            offset: value.offset,
            field_index: value.fieldIndex,
        }
    }

    /// The raw value must have been allocated by rust. See [`Self::free_owned_raw`] for details.
    pub(crate) fn from_owned_raw(value: BNTypeDefinitionLine) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_owned_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNTypeDefinitionLine {
        // NOTE: This is leaking [BNInstructionTextToken::text], [BNInstructionTextToken::typeNames].
        let tokens: Box<[BNInstructionTextToken]> = value
            .tokens
            .into_iter()
            .map(InstructionTextToken::into_raw)
            .collect();
        BNTypeDefinitionLine {
            lineType: value.line_type,
            count: tokens.len(),
            // NOTE: This is leaking tokens. Must free with `cb_free_lines`.
            tokens: Box::leak(tokens).as_mut_ptr(),
            // NOTE: This is leaking a ref to ty. Must free with `cb_free_lines`.
            type_: unsafe { Ref::into_raw(value.ty) }.handle,
            // NOTE: This is leaking a ref to parent_type. Must free with `cb_free_lines`.
            parentType: value
                .parent_type
                .map(|t| unsafe { Ref::into_raw(t) }.handle)
                .unwrap_or(std::ptr::null_mut()),
            // NOTE: This is leaking a ref to root_type. Must free with `cb_free_lines`.
            rootType: value
                .root_type
                .map(|t| unsafe { Ref::into_raw(t) }.handle)
                .unwrap_or(std::ptr::null_mut()),
            // NOTE: This is leaking root_type_name. Must free with `cb_free_lines`.
            rootTypeName: value
                .root_type_name
                .map(|s| BnString::into_raw(BnString::new(s)))
                .unwrap_or(std::ptr::null_mut()),
            // NOTE: This is leaking a ref to base_type. Must free with `cb_free_lines`.
            baseType: value
                .base_type
                .map(|t| unsafe { Ref::into_raw(t) }.handle)
                .unwrap_or(std::ptr::null_mut()),
            baseOffset: value.base_offset,
            offset: value.offset,
            fieldIndex: value.field_index,
        }
    }

    /// This is unique from the typical `from_raw` as the allocation of InstructionTextToken requires it be from rust, hence the "owned" free.
    pub(crate) fn free_owned_raw(raw: BNTypeDefinitionLine) {
        if !raw.tokens.is_null() {
            let tokens = std::ptr::slice_from_raw_parts_mut(raw.tokens, raw.count);
            // SAFETY: raw.tokens must have been allocated by rust.
            let boxed_tokens = unsafe { Box::from_raw(tokens) };
            for token in boxed_tokens {
                InstructionTextToken::free_raw(token);
            }
        }
        if !raw.type_.is_null() {
            // SAFETY: raw.type_ must have been ref incremented in conjunction with this free
            let _ = unsafe { Type::ref_from_raw(raw.type_) };
        }
        if !raw.parentType.is_null() {
            // SAFETY: raw.parentType must have been ref incremented in conjunction with this free
            let _ = unsafe { Type::ref_from_raw(raw.parentType) };
        }
        if !raw.rootType.is_null() {
            // SAFETY: raw.rootType must have been ref incremented in conjunction with this free
            let _ = unsafe { Type::ref_from_raw(raw.rootType) };
        }
        if !raw.rootTypeName.is_null() {
            // SAFETY: raw.rootTypeName must have been ref incremented in conjunction with this free
            let _ = unsafe { BnString::from_raw(raw.rootTypeName) };
        }
        if !raw.baseType.is_null() {
            // SAFETY: raw.baseType must have been ref incremented in conjunction with this free
            let _ = unsafe { NamedTypeReference::ref_from_raw(raw.baseType) };
        }
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
        Self::from_raw(raw)
    }
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
    // NOTE: The caller is responsible for freeing name.
    let qualified_name = QualifiedName::from_raw(&*name);
    let inner_result = ctxt.get_type_tokens(
        unsafe { Type::ref_from_raw(type_) },
        match platform.is_null() {
            false => Some(Platform::ref_from_raw(platform)),
            true => None,
        },
        qualified_name,
        base_confidence,
        escaping,
    );
    if let Some(inner_result) = inner_result {
        let raw_text_tokens: Box<[BNInstructionTextToken]> = inner_result
            .into_iter()
            .map(InstructionTextToken::into_raw)
            .collect();
        *result_count = raw_text_tokens.len();
        // NOTE: Dropped by the cb_free_tokens
        *result = Box::leak(raw_text_tokens).as_mut_ptr();
        true
    } else {
        *result = std::ptr::null_mut();
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
        Type::ref_from_raw(type_),
        match platform.is_null() {
            false => Some(Platform::ref_from_raw(platform)),
            true => None,
        },
        base_confidence,
        match parent_type.is_null() {
            false => Some(Type::ref_from_raw(parent_type)),
            true => None,
        },
        escaping,
    );
    if let Some(inner_result) = inner_result {
        let raw_text_tokens: Box<[BNInstructionTextToken]> = inner_result
            .into_iter()
            .map(InstructionTextToken::into_raw)
            .collect();
        *result_count = raw_text_tokens.len();
        // NOTE: Dropped by the cb_free_tokens
        *result = Box::leak(raw_text_tokens).as_mut_ptr();
        true
    } else {
        *result = std::ptr::null_mut();
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
        Type::ref_from_raw(type_),
        match platform.is_null() {
            false => Some(Platform::ref_from_raw(platform)),
            true => None,
        },
        base_confidence,
        match parent_type.is_null() {
            false => Some(Type::ref_from_raw(parent_type)),
            true => None,
        },
        escaping,
    );
    if let Some(inner_result) = inner_result {
        let raw_text_tokens: Box<[BNInstructionTextToken]> = inner_result
            .into_iter()
            .map(InstructionTextToken::into_raw)
            .collect();
        *result_count = raw_text_tokens.len();
        // NOTE: Dropped by the cb_free_tokens
        *result = Box::leak(raw_text_tokens).as_mut_ptr();
        true
    } else {
        *result = std::ptr::null_mut();
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
    // NOTE: The caller is responsible for freeing name.
    let qualified_name = QualifiedName::from_raw(&*name);
    let inner_result = ctxt.get_type_string(
        Type::ref_from_raw(type_),
        match platform.is_null() {
            false => Some(Platform::ref_from_raw(platform)),
            true => None,
        },
        qualified_name,
        escaping,
    );
    if let Some(inner_result) = inner_result {
        let raw_string = BnString::new(inner_result);
        // NOTE: Dropped by `cb_free_string`
        *result = BnString::into_raw(raw_string);
        true
    } else {
        *result = std::ptr::null_mut();
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
        Type::ref_from_raw(type_),
        match platform.is_null() {
            false => Some(Platform::ref_from_raw(platform)),
            true => None,
        },
        escaping,
    );
    if let Some(inner_result) = inner_result {
        // NOTE: Dropped by `cb_free_string`
        let raw_string = BnString::new(inner_result);
        *result = BnString::into_raw(raw_string);
        true
    } else {
        *result = std::ptr::null_mut();
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
        Type::ref_from_raw(type_),
        match platform.is_null() {
            false => Some(Platform::ref_from_raw(platform)),
            true => None,
        },
        escaping,
    );
    if let Some(inner_result) = inner_result {
        let raw_string = BnString::new(inner_result);
        // NOTE: Dropped by `cb_free_string`
        *result = BnString::into_raw(raw_string);
        true
    } else {
        *result = std::ptr::null_mut();
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
    // NOTE: The caller is responsible for freeing name.
    let qualified_name = QualifiedName::from_raw(&*name);
    let types_ptr = NonNull::new(types).unwrap();
    let types = TypeContainer::from_raw(types_ptr);
    let inner_result = ctxt.get_type_lines(
        Type::ref_from_raw(type_),
        &types,
        qualified_name,
        padding_cols as isize,
        collapsed,
        escaping,
    );
    if let Some(inner_result) = inner_result {
        let boxed_raw_lines: Box<[_]> = inner_result
            .into_iter()
            .map(TypeDefinitionLine::into_raw)
            .collect();
        *result_count = boxed_raw_lines.len();
        // NOTE: Dropped by `cb_free_lines`
        *result = Box::leak(boxed_raw_lines).as_mut_ptr();
        true
    } else {
        *result = std::ptr::null_mut();
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
    let raw_names = std::slice::from_raw_parts(names, type_count);
    // NOTE: The caller is responsible for freeing raw_names.
    let names: Vec<_> = raw_names.iter().map(QualifiedName::from_raw).collect();
    let raw_types = std::slice::from_raw_parts(types, type_count);
    // NOTE: The caller is responsible for freeing raw_types.
    let types: Vec<_> = raw_types.iter().map(|&t| Type::ref_from_raw(t)).collect();
    let inner_result = ctxt.print_all_types(
        names,
        types,
        BinaryView::ref_from_raw(data),
        padding_cols as isize,
        escaping,
    );
    if let Some(inner_result) = inner_result {
        let raw_string = BnString::new(inner_result);
        // NOTE: Dropped by `cb_free_string`
        *result = BnString::into_raw(raw_string);
        true
    } else {
        *result = std::ptr::null_mut();
        false
    }
}

unsafe extern "C" fn cb_free_string(_ctxt: *mut c_void, string: *mut c_char) {
    // SAFETY: The returned string is just BnString
    let _ = BnString::from_raw(string);
}

unsafe extern "C" fn cb_free_tokens(
    _ctxt: *mut ::std::os::raw::c_void,
    tokens: *mut BNInstructionTextToken,
    count: usize,
) {
    let tokens = std::ptr::slice_from_raw_parts_mut(tokens, count);
    // SAFETY: tokens must have been allocated by rust.
    let boxed_tokens = Box::from_raw(tokens);
    for token in boxed_tokens {
        InstructionTextToken::free_raw(token);
    }
}

unsafe extern "C" fn cb_free_lines(
    _ctxt: *mut ::std::os::raw::c_void,
    lines: *mut BNTypeDefinitionLine,
    count: usize,
) {
    let lines = std::ptr::slice_from_raw_parts_mut(lines, count);
    // SAFETY: lines must have been allocated by rust.
    let boxes_lines = Box::from_raw(lines);
    for line in boxes_lines {
        TypeDefinitionLine::free_owned_raw(line);
    }
}
