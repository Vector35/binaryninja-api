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

// TODO : More widely enforce the use of ref_from_raw vs just from_raw to simplify internal binding usage?  Perhaps remove from_raw functions?
// TODO : Add documentation and fix examples
// TODO : Test the get_enumeration and get_structure methods

use binaryninjacore_sys::*;

use crate::{
    architecture::{Architecture, CoreArchitecture},
    binaryview::{BinaryView, BinaryViewExt},
    callingconvention::CallingConvention,
    filemetadata::FileMetadata,
    rc::*,
    string::{BnStrCompatible, BnString},
};

use lazy_static::lazy_static;
use std::{
    borrow::Cow,
    collections::HashSet,
    ffi::{CStr, c_char},
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    iter::{IntoIterator},
    sync::Mutex,
};
use std::num::NonZeroUsize;
use crate::confidence::{Conf, MAX_CONFIDENCE, MIN_CONFIDENCE};
use crate::string::raw_to_string;
use crate::variable::{Variable, VariableSourceType};

pub type ReferenceType = BNReferenceType;
pub type TypeClass = BNTypeClass;
pub type NamedTypeReferenceClass = BNNamedTypeReferenceClass;
pub type MemberAccess = BNMemberAccess;
pub type MemberScope = BNMemberScope;
pub type IntegerDisplayType = BNIntegerDisplayType;

#[derive(PartialEq, Eq, Hash)]
pub struct TypeBuilder {
    pub(crate) handle: *mut BNTypeBuilder,
}

impl TypeBuilder {
    pub fn new(t: &Type) -> Self {
        unsafe { Self::from_raw(BNCreateTypeBuilderFromType(t.handle)) }
    }

    pub(crate) unsafe fn from_raw(handle: *mut BNTypeBuilder) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    // Chainable terminal
    pub fn finalize(&self) -> Ref<Type> {
        unsafe { Type::ref_from_raw(BNFinalizeTypeBuilder(self.handle)) }
    }

    // Settable properties

    pub fn set_can_return<T: Into<Conf<bool>>>(&self, value: T) -> &Self {
        let mut bool_with_confidence = value.into().into();
        unsafe { BNSetFunctionTypeBuilderCanReturn(self.handle, &mut bool_with_confidence) };
        self
    }

    pub fn set_pure<T: Into<Conf<bool>>>(&self, value: T) -> &Self {
        let mut bool_with_confidence = value.into().into();
        unsafe { BNSetTypeBuilderPure(self.handle, &mut bool_with_confidence) };
        self
    }

    pub fn set_const<T: Into<Conf<bool>>>(&self, value: T) -> &Self {
        let mut bool_with_confidence = value.into().into();
        unsafe { BNTypeBuilderSetConst(self.handle, &mut bool_with_confidence) };
        self
    }

    pub fn set_volatile<T: Into<Conf<bool>>>(&self, value: T) -> &Self {
        let mut bool_with_confidence = value.into().into();
        unsafe { BNTypeBuilderSetVolatile(self.handle, &mut bool_with_confidence) };
        self
    }

    // Readable properties

    pub fn type_class(&self) -> TypeClass {
        unsafe { BNGetTypeBuilderClass(self.handle) }
    }

    pub fn width(&self) -> u64 {
        unsafe { BNGetTypeBuilderWidth(self.handle) }
    }

    pub fn alignment(&self) -> usize {
        unsafe { BNGetTypeBuilderAlignment(self.handle) }
    }

    pub fn is_signed(&self) -> Conf<bool> {
        unsafe { BNIsTypeBuilderSigned(self.handle).into() }
    }

    pub fn is_const(&self) -> Conf<bool> {
        unsafe { BNIsTypeBuilderConst(self.handle).into() }
    }

    pub fn is_volatile(&self) -> Conf<bool> {
        unsafe { BNIsTypeBuilderVolatile(self.handle).into() }
    }

    pub fn is_floating_point(&self) -> bool {
        unsafe { BNIsTypeBuilderFloatingPoint(self.handle) }
    }
    
    pub fn child_type(&self) -> Option<Conf<Ref<Type>>> {
        let raw_target = unsafe { BNGetTypeBuilderChildType(self.handle) };
        match raw_target.type_.is_null() {
            false => Some(raw_target.into()),
            true => None,
        }
    }

    /// This is an alias for [`Self::child_type`].
    pub fn target(&self) -> Option<Conf<Ref<Type>>> {
        self.child_type()
    }

    /// This is an alias for [`Self::child_type`].
    pub fn element_type(&self) -> Option<Conf<Ref<Type>>> {
        self.child_type()
    }

    /// This is an alias for [`Self::child_type`].
    pub fn return_value(&self) -> Option<Conf<Ref<Type>>> {
        self.child_type()
    }

    pub fn calling_convention(&self) -> Option<Conf<Ref<CallingConvention<CoreArchitecture>>>> {
        let raw_convention_confidence = unsafe { BNGetTypeBuilderCallingConvention(self.handle) };
        match raw_convention_confidence.convention.is_null() {
            false => Some(raw_convention_confidence.into()),
            true => None,
        }
    }

    pub fn parameters(&self) -> Option<Vec<FunctionParameter>> {
        unsafe {
            let mut count = 0;
            let raw_parameters_ptr = BNGetTypeBuilderParameters(self.handle, &mut count);
            match raw_parameters_ptr.is_null() {
                false => {
                    let raw_parameters = std::slice::from_raw_parts(raw_parameters_ptr, count);
                    let parameters = raw_parameters.iter().map(Into::into).collect();
                    BNFreeTypeParameterList(raw_parameters_ptr, count);
                    Some(parameters)
                }
                true => None
            }
        }
    }

    pub fn has_variable_arguments(&self) -> Conf<bool> {
        unsafe { BNTypeBuilderHasVariableArguments(self.handle).into() }
    }

    pub fn can_return(&self) -> Conf<bool> {
        unsafe { BNFunctionTypeBuilderCanReturn(self.handle).into() }
    }

    pub fn pure(&self) -> Conf<bool> {
        unsafe { BNIsTypeBuilderPure(self.handle).into() }
    }

    // TODO: This naming is problematic... rename to `as_structure`?
    // TODO: We wouldn't need these sort of functions if we destructured `Type`...
    pub fn get_structure(&self) -> Option<Ref<Structure>> {
        let raw_struct_ptr = unsafe { BNGetTypeBuilderStructure(self.handle) };
        match raw_struct_ptr.is_null() {
            false => Some(unsafe { Structure::ref_from_raw(raw_struct_ptr) }),
            true => None,
        }
    }

    // TODO: This naming is problematic... rename to `as_enumeration`?
    // TODO: We wouldn't need these sort of functions if we destructured `Type`...
    pub fn get_enumeration(&self) -> Option<Ref<Enumeration>> {
        let raw_enum_ptr = unsafe { BNGetTypeBuilderEnumeration(self.handle) };
        match raw_enum_ptr.is_null() {
            false => Some(unsafe { Enumeration::ref_from_raw(raw_enum_ptr) }),
            true => None,
        }
    }

    // TODO: This naming is problematic... rename to `as_named_type_reference`?
    // TODO: We wouldn't need these sort of functions if we destructured `Type`...
    pub fn get_named_type_reference(&self) -> Option<Ref<NamedTypeReference>> {
        let raw_type_ref_ptr = unsafe { BNGetTypeBuilderNamedTypeReference(self.handle) };
        match raw_type_ref_ptr.is_null() {
            false => Some(unsafe { NamedTypeReference::ref_from_raw(raw_type_ref_ptr) }),
            true => None,
        }
    }

    pub fn count(&self) -> u64 {
        unsafe { BNGetTypeBuilderElementCount(self.handle) }
    }

    pub fn offset(&self) -> u64 {
        unsafe { BNGetTypeBuilderOffset(self.handle) }
    }

    pub fn stack_adjustment(&self) -> Conf<i64> {
        unsafe { BNGetTypeBuilderStackAdjustment(self.handle).into() }
    }

    // TODO : This and properties
    // pub fn tokens(&self) -> ? {}

    pub fn void() -> Self {
        unsafe { Self::from_raw(BNCreateVoidTypeBuilder()) }
    }

    pub fn bool() -> Self {
        unsafe { Self::from_raw(BNCreateBoolTypeBuilder()) }
    }

    pub fn char() -> Self {
        Self::int(1, true)
    }

    pub fn int(width: usize, is_signed: bool) -> Self {
        let mut is_signed = Conf::new(is_signed, MAX_CONFIDENCE).into();

        unsafe {
            Self::from_raw(BNCreateIntegerTypeBuilder(
                width,
                &mut is_signed,
                BnString::new("").as_ptr() as *mut _,
            ))
        }
    }

    pub fn named_int<S: BnStrCompatible>(width: usize, is_signed: bool, alt_name: S) -> Self {
        let mut is_signed = Conf::new(is_signed, MAX_CONFIDENCE).into();
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.into_bytes_with_nul(); // This segfaulted once, so the above version is there if we need to change to it, but in theory this is copied into a `const string&` on the C++ side; I'm just not 100% confident that a constant reference copies data

        unsafe {
            Self::from_raw(BNCreateIntegerTypeBuilder(
                width,
                &mut is_signed,
                alt_name.as_ref().as_ptr() as _,
            ))
        }
    }

    pub fn float(width: usize) -> Self {
        unsafe {
            Self::from_raw(BNCreateFloatTypeBuilder(
                width,
                BnString::new("").as_ptr() as *mut _,
            ))
        }
    }

    pub fn named_float<S: BnStrCompatible>(width: usize, alt_name: S) -> Self {
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.into_bytes_with_nul(); // See same line in `named_int` above

        unsafe {
            Self::from_raw(BNCreateFloatTypeBuilder(
                width,
                alt_name.as_ref().as_ptr() as _,
            ))
        }
    }

    pub fn array<'a, T: Into<Conf<&'a Type>>>(t: T, count: u64) -> Self {
        unsafe { Self::from_raw(BNCreateArrayTypeBuilder(&t.into().into(), count)) }
    }

    /// ## NOTE
    ///
    /// The C/C++ APIs require an associated architecture, but in the core we only query the default_int_size if the given width is 0.
    ///
    /// For simplicity's sake, that convention isn't followed, and you can query [`Architecture::default_integer_size`] if you need to.
    pub fn enumeration<T: Into<Conf<bool>>>(
        enumeration: &Enumeration,
        width: NonZeroUsize,
        is_signed: T,
    ) -> Self {
        unsafe {
            Self::from_raw(BNCreateEnumerationTypeBuilder(
                // TODO: We pass nullptr arch, really we should not even be passing arch.
                std::ptr::null_mut(),
                enumeration.handle,
                width.get(),
                &mut is_signed.into().into(),
            ))
        }
    }

    pub fn structure(structure_type: &Structure) -> Self {
        unsafe { Self::from_raw(BNCreateStructureTypeBuilder(structure_type.handle)) }
    }

    pub fn named_type(type_reference: NamedTypeReference) -> Self {
        let mut is_const = Conf::new(false, MIN_CONFIDENCE).into();
        let mut is_volatile = Conf::new(false, MIN_CONFIDENCE).into();
        unsafe {
            Self::from_raw(BNCreateNamedTypeReferenceBuilder(
                type_reference.handle,
                0,
                1,
                &mut is_const,
                &mut is_volatile,
            ))
        }
    }

    pub fn named_type_from_type<S: BnStrCompatible>(name: S, t: &Type) -> Self {
        let mut name = QualifiedName::from(name);

        unsafe {
            Self::from_raw(BNCreateNamedTypeReferenceBuilderFromTypeAndId(
                BnString::new("").as_ptr() as *mut _,
                &mut name.0,
                t.handle,
            ))
        }
    }

    // TODO : BNCreateFunctionTypeBuilder

    pub fn pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, t: T) -> Self {
        let mut is_const = Conf::new(false, MIN_CONFIDENCE).into();
        let mut is_volatile = Conf::new(false, MIN_CONFIDENCE).into();

        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilder(
                arch.as_ref().handle,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            ))
        }
    }

    pub fn const_pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, t: T) -> Self {
        let mut is_const = Conf::new(true, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(false, MIN_CONFIDENCE).into();

        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilder(
                arch.as_ref().handle,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            ))
        }
    }

    pub fn pointer_of_width<'a, T: Into<Conf<&'a Type>>>(
        t: T,
        size: usize,
        is_const: bool,
        is_volatile: bool,
        ref_type: Option<ReferenceType>,
    ) -> Self {
        let mut is_const = Conf::new(is_const, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(is_volatile, MAX_CONFIDENCE).into();

        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilderOfWidth(
                size,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or(ReferenceType::PointerReferenceType),
            ))
        }
    }

    pub fn pointer_with_options<'a, A: Architecture, T: Into<Conf<&'a Type>>>(
        arch: &A,
        t: T,
        is_const: bool,
        is_volatile: bool,
        ref_type: Option<ReferenceType>,
    ) -> Self {
        let mut is_const = Conf::new(is_const, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(is_volatile, MAX_CONFIDENCE).into();
        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilder(
                arch.as_ref().handle,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or(ReferenceType::PointerReferenceType),
            ))
        }
    }
}

impl Display for TypeBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", unsafe {
            BnString::from_raw(BNGetTypeBuilderString(self.handle, std::ptr::null_mut()))
        })
    }
}

impl Drop for TypeBuilder {
    fn drop(&mut self) {
        unsafe { BNFreeTypeBuilder(self.handle) };
    }
}

#[repr(transparent)]
pub struct Type {
    pub(crate) handle: *mut BNType,
}

/// ```no_run
/// # use crate::binaryninja::binaryview::BinaryViewExt;
/// # use binaryninja::types::Type;
/// let bv = binaryninja::load("example.bin").unwrap();
/// let my_custom_type_1 = Type::named_int(5, false, "my_w");
/// let my_custom_type_2 = Type::int(5, false);
/// bv.define_user_type("int_1", &my_custom_type_1);
/// bv.define_user_type("int_2", &my_custom_type_2);
/// ```
impl Type {
    pub(crate) unsafe fn from_raw(handle: *mut BNType) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNType) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn to_builder(&self) -> TypeBuilder {
        TypeBuilder::new(self)
    }
    
    pub fn type_class(&self) -> TypeClass {
        unsafe { BNGetTypeClass(self.handle) }
    }

    // TODO: We need to decide on a public type to represent type width.
    // TODO: The api uses both `u64` and `usize`, pick one or a new type!
    pub fn width(&self) -> u64 {
        unsafe { BNGetTypeWidth(self.handle) }
    }

    pub fn alignment(&self) -> usize {
        unsafe { BNGetTypeAlignment(self.handle) }
    }

    pub fn is_signed(&self) -> Conf<bool> {
        unsafe { BNIsTypeSigned(self.handle).into() }
    }

    pub fn is_const(&self) -> Conf<bool> {
        unsafe { BNIsTypeConst(self.handle).into() }
    }

    pub fn is_volatile(&self) -> Conf<bool> {
        unsafe { BNIsTypeVolatile(self.handle).into() }
    }

    pub fn is_floating_point(&self) -> bool {
        unsafe { BNIsTypeFloatingPoint(self.handle) }
    }

    pub fn child_type(&self) -> Option<Conf<Ref<Type>>> {
        let raw_target = unsafe { BNGetChildType(self.handle) };
        match raw_target.type_.is_null() {
            false => Some(raw_target.into()),
            true => None,
        }
    }

    /// This is an alias for [`Self::child_type`].
    pub fn target(&self) -> Option<Conf<Ref<Type>>> {
        self.child_type()
    }

    /// This is an alias for [`Self::child_type`].
    pub fn element_type(&self) -> Option<Conf<Ref<Type>>> {
        self.child_type()
    }

    /// This is an alias for [`Self::child_type`].
    pub fn return_value(&self) -> Option<Conf<Ref<Type>>> {
        self.child_type()
    }

    pub fn calling_convention(&self) -> Option<Conf<Ref<CallingConvention<CoreArchitecture>>>> {
        let convention_confidence = unsafe { BNGetTypeCallingConvention(self.handle) };
        match convention_confidence.convention.is_null() {
            false => Some(convention_confidence.into()),
            true => None,
        }
    }

    pub fn parameters(&self) -> Option<Vec<FunctionParameter>> {
        unsafe {
            let mut count = 0;
            let raw_parameters_ptr = BNGetTypeParameters(self.handle, &mut count);
            match raw_parameters_ptr.is_null() {
                false => {
                    let raw_parameters = std::slice::from_raw_parts(raw_parameters_ptr, count);
                    let parameters = raw_parameters.iter().map(Into::into).collect();
                    //BNFreeTypeParameterList(raw_parameters_ptr, count);
                    Some(parameters)
                }
                true => None
            }
        }
    }

    pub fn has_variable_arguments(&self) -> Conf<bool> {
        unsafe { BNTypeHasVariableArguments(self.handle).into() }
    }

    pub fn can_return(&self) -> Conf<bool> {
        unsafe { BNFunctionTypeCanReturn(self.handle).into() }
    }

    pub fn pure(&self) -> Conf<bool> {
        unsafe { BNIsTypePure(self.handle).into() }
    }

    // TODO: This naming is problematic... rename to `as_structure`?
    // TODO: We wouldn't need these sort of functions if we destructured `Type`...
    pub fn get_structure(&self) -> Option<Ref<Structure>> {
        let raw_struct_ptr = unsafe { BNGetTypeStructure(self.handle) };
        match raw_struct_ptr.is_null() {
            false => Some(unsafe { Structure::ref_from_raw(raw_struct_ptr) }),
            true => None,
        }
    }

    // TODO: This naming is problematic... rename to `as_enumeration`?
    // TODO: We wouldn't need these sort of functions if we destructured `Type`...
    pub fn get_enumeration(&self) -> Option<Ref<Enumeration>> {
        let raw_enum_ptr = unsafe { BNGetTypeEnumeration(self.handle) };
        match raw_enum_ptr.is_null() {
            false => Some(unsafe { Enumeration::ref_from_raw(raw_enum_ptr) }),
            true => None,
        }
    }

    // TODO: This naming is problematic... rename to `as_named_type_reference`?
    // TODO: We wouldn't need these sort of functions if we destructured `Type`...
    pub fn get_named_type_reference(&self) -> Option<Ref<NamedTypeReference>> {
        let raw_type_ref_ptr = unsafe { BNGetTypeNamedTypeReference(self.handle) };
        match raw_type_ref_ptr.is_null() {
            false => Some(unsafe { NamedTypeReference::ref_from_raw(raw_type_ref_ptr) }),
            true => None,
        }
    }

    pub fn count(&self) -> u64 {
        unsafe { BNGetTypeElementCount(self.handle) }
    }

    pub fn offset(&self) -> u64 {
        unsafe { BNGetTypeOffset(self.handle) }
    }

    pub fn stack_adjustment(&self) -> Conf<i64> {
        unsafe { BNGetTypeStackAdjustment(self.handle).into() }
    }

    pub fn registered_name(&self) -> Option<Ref<NamedTypeReference>> {
        let raw_type_ref_ptr = unsafe { BNGetRegisteredTypeName(self.handle) };
        match raw_type_ref_ptr.is_null() {
            false => Some(unsafe { NamedTypeReference::ref_from_raw(raw_type_ref_ptr) }),
            true => None,
        }
    }

    // TODO : This and properties
    // pub fn tokens(&self) -> ? {}

    pub fn void() -> Ref<Self> {
        unsafe { Self::ref_from_raw(BNCreateVoidType()) }
    }

    pub fn bool() -> Ref<Self> {
        unsafe { Self::ref_from_raw(BNCreateBoolType()) }
    }

    pub fn char() -> Ref<Self> {
        Self::int(1, true)
    }

    pub fn wide_char(width: usize) -> Ref<Self> {
        unsafe {
            Self::ref_from_raw(BNCreateWideCharType(
                width,
                BnString::new("").as_ptr() as *mut _,
            ))
        }
    }

    pub fn int(width: usize, is_signed: bool) -> Ref<Self> {
        let mut is_signed = Conf::new(is_signed, MAX_CONFIDENCE).into();
        unsafe {
            Self::ref_from_raw(BNCreateIntegerType(
                width,
                &mut is_signed,
                BnString::new("").as_ptr() as *mut _,
            ))
        }
    }

    pub fn named_int<S: BnStrCompatible>(width: usize, is_signed: bool, alt_name: S) -> Ref<Self> {
        let mut is_signed = Conf::new(is_signed, MAX_CONFIDENCE).into();
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.into_bytes_with_nul(); // This segfaulted once, so the above version is there if we need to change to it, but in theory this is copied into a `const string&` on the C++ side; I'm just not 100% confident that a constant reference copies data

        unsafe {
            Self::ref_from_raw(BNCreateIntegerType(
                width,
                &mut is_signed,
                alt_name.as_ref().as_ptr() as _,
            ))
        }
    }

    pub fn float(width: usize) -> Ref<Self> {
        unsafe {
            Self::ref_from_raw(BNCreateFloatType(
                width,
                BnString::new("").as_ptr() as *mut _,
            ))
        }
    }

    pub fn named_float<S: BnStrCompatible>(width: usize, alt_name: S) -> Ref<Self> {
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.into_bytes_with_nul(); // See same line in `named_int` above

        unsafe { Self::ref_from_raw(BNCreateFloatType(width, alt_name.as_ref().as_ptr() as _)) }
    }

    pub fn array<'a, T: Into<Conf<&'a Type>>>(t: T, count: u64) -> Ref<Self> {
        unsafe { Self::ref_from_raw(BNCreateArrayType(&t.into().into(), count)) }
    }

    /// ## NOTE
    /// 
    /// The C/C++ APIs require an associated architecture, but in the core we only query the default_int_size if the given width is 0.
    ///
    /// For simplicity's sake, that convention isn't followed, and you can query [`Architecture::default_integer_size`] if you need to.
    pub fn enumeration<T: Into<Conf<bool>>>(
        enumeration: &Enumeration,
        width: NonZeroUsize,
        is_signed: T,
    ) -> Ref<Self> {
        unsafe {
            Self::ref_from_raw(BNCreateEnumerationType(
                // TODO: We pass nullptr arch, really we should not even be passing arch.
                std::ptr::null_mut(),
                enumeration.handle,
                width.get(),
                &mut is_signed.into().into(),
            ))
        }
    }

    pub fn structure(structure: &Structure) -> Ref<Self> {
        unsafe { Self::ref_from_raw(BNCreateStructureType(structure.handle)) }
    }

    pub fn named_type(type_reference: &NamedTypeReference) -> Ref<Self> {
        let mut is_const = Conf::new(false, MIN_CONFIDENCE).into();
        let mut is_volatile = Conf::new(false, MIN_CONFIDENCE).into();
        unsafe {
            Self::ref_from_raw(BNCreateNamedTypeReference(
                type_reference.handle,
                0,
                1,
                &mut is_const,
                &mut is_volatile,
            ))
        }
    }

    pub fn named_type_from_type<S: BnStrCompatible>(name: S, t: &Type) -> Ref<Self> {
        let mut name = QualifiedName::from(name);

        unsafe {
            Self::ref_from_raw(BNCreateNamedTypeReferenceFromTypeAndId(
                BnString::new("").as_ptr() as *mut _,
                &mut name.0,
                t.handle,
            ))
        }
    }

    // TODO: FunctionBuilder
    pub fn function<'a, T: Into<Conf<&'a Type>>>(
        return_type: T,
        parameters: &[FunctionParameter],
        variable_arguments: bool,
    ) -> Ref<Self> {
        let mut return_type = return_type.into().into();
        let mut variable_arguments = Conf::new(variable_arguments, MAX_CONFIDENCE).into();
        let mut can_return = Conf::new(true, MIN_CONFIDENCE).into();
        let mut pure = Conf::new(false, MIN_CONFIDENCE).into();

        let mut raw_calling_convention: BNCallingConventionWithConfidence =
            BNCallingConventionWithConfidence {
                convention: std::ptr::null_mut(),
                confidence: MIN_CONFIDENCE,
            };

        let mut stack_adjust = Conf::new(0, MIN_CONFIDENCE).into();
        let mut raw_parameters = parameters.iter().cloned().map(Into::into).collect::<Vec<_>>();
        let reg_stack_adjust_regs = std::ptr::null_mut();
        let reg_stack_adjust_values = std::ptr::null_mut();

        let mut return_regs: BNRegisterSetWithConfidence = BNRegisterSetWithConfidence {
            regs: std::ptr::null_mut(),
            count: 0,
            confidence: 0,
        };

        unsafe {
            Self::ref_from_raw(BNNewTypeReference(BNCreateFunctionType(
                &mut return_type,
                &mut raw_calling_convention,
                raw_parameters.as_mut_ptr(),
                raw_parameters.len(),
                &mut variable_arguments,
                &mut can_return,
                &mut stack_adjust,
                reg_stack_adjust_regs,
                reg_stack_adjust_values,
                0,
                &mut return_regs,
                BNNameType::NoNameType,
                &mut pure,
            )))
        }
    }

    // TODO: FunctionBuilder
    pub fn function_with_opts<
        'a,
        A: Architecture,
        T: Into<Conf<&'a Type>>,
        C: Into<Conf<&'a CallingConvention<A>>>,
    >(
        return_type: T,
        parameters: &[FunctionParameter],
        variable_arguments: bool,
        calling_convention: C,
        stack_adjust: Conf<i64>,
    ) -> Ref<Self> {
        let mut return_type = return_type.into().into();
        let mut variable_arguments = Conf::new(variable_arguments, MAX_CONFIDENCE).into();
        let mut can_return = Conf::new(true, MIN_CONFIDENCE).into();
        let mut pure = Conf::new(false, MIN_CONFIDENCE).into();
        
        let mut raw_calling_convention: BNCallingConventionWithConfidence = calling_convention.into().into();
        
        let mut stack_adjust = stack_adjust.into();
        let mut raw_parameters = parameters.iter().cloned().map(Into::into).collect::<Vec<_>>();

        // TODO: Update type signature and include these (will be a breaking change)
        let reg_stack_adjust_regs = std::ptr::null_mut();
        let reg_stack_adjust_values = std::ptr::null_mut();

        let mut return_regs: BNRegisterSetWithConfidence = BNRegisterSetWithConfidence {
            regs: std::ptr::null_mut(),
            count: 0,
            confidence: 0,
        };

        unsafe {
            Self::ref_from_raw(BNCreateFunctionType(
                &mut return_type,
                &mut raw_calling_convention,
                raw_parameters.as_mut_ptr(),
                raw_parameters.len(),
                &mut variable_arguments,
                &mut can_return,
                &mut stack_adjust,
                reg_stack_adjust_regs,
                reg_stack_adjust_values,
                0,
                &mut return_regs,
                BNNameType::NoNameType,
                &mut pure,
            ))
        }
    }

    pub fn pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, t: T) -> Ref<Self> {
        let mut is_const = Conf::new(false, MIN_CONFIDENCE).into();
        let mut is_volatile = Conf::new(false, MIN_CONFIDENCE).into();
        unsafe {
            Self::ref_from_raw(BNCreatePointerType(
                arch.as_ref().handle,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            ))
        }
    }

    pub fn const_pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(
        arch: &A,
        t: T,
    ) -> Ref<Self> {
        let mut is_const = Conf::new(true, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(false, MIN_CONFIDENCE).into();
        unsafe {
            Self::ref_from_raw(BNCreatePointerType(
                arch.as_ref().handle,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            ))
        }
    }

    pub fn pointer_of_width<'a, T: Into<Conf<&'a Type>>>(
        t: T,
        size: usize,
        is_const: bool,
        is_volatile: bool,
        ref_type: Option<ReferenceType>,
    ) -> Ref<Self> {
        let mut is_const = Conf::new(is_const, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(is_volatile, MAX_CONFIDENCE).into();
        unsafe {
            Self::ref_from_raw(BNCreatePointerTypeOfWidth(
                size,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or(ReferenceType::PointerReferenceType),
            ))
        }
    }

    pub fn pointer_with_options<'a, A: Architecture, T: Into<Conf<&'a Type>>>(
        arch: &A,
        t: T,
        is_const: bool,
        is_volatile: bool,
        ref_type: Option<ReferenceType>,
    ) -> Ref<Self> {
        let mut is_const = Conf::new(is_const, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(is_volatile, MAX_CONFIDENCE).into();
        unsafe {
            Self::ref_from_raw(BNCreatePointerType(
                arch.as_ref().handle,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or(ReferenceType::PointerReferenceType),
            ))
        }
    }

    pub fn generate_auto_demangled_type_id<S: BnStrCompatible>(name: S) -> BnString {
        let mut name = QualifiedName::from(name);
        unsafe { BnString::from_raw(BNGenerateAutoDemangledTypeId(&mut name.0)) }
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", unsafe {
            BnString::from_raw(BNGetTypeString(
                self.handle,
                std::ptr::null_mut(),
                BNTokenEscapingType::NoTokenEscapingType,
            ))
        })
    }
}

lazy_static! {
    static ref TYPE_DEBUG_BV: Mutex<Option<Ref<BinaryView>>> =
        Mutex::new(BinaryView::from_data(&FileMetadata::new(), &[]).ok());
}

impl Debug for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Ok(lock) = TYPE_DEBUG_BV.lock() {
            if let Some(bv) = &*lock {
                let container = unsafe { BNGetAnalysisTypeContainer(bv.handle) };

                let printer = if f.alternate() {
                    unsafe { BNGetTypePrinterByName(c"_DebugTypePrinter".as_ptr()) }
                } else {
                    unsafe { BNGetTypePrinterByName(c"CoreTypePrinter".as_ptr()) }
                };
                if printer.is_null() {
                    return Err(std::fmt::Error);
                }

                let mut name = QualifiedName::from("");

                let mut lines: *mut BNTypeDefinitionLine = std::ptr::null_mut();
                let mut count: usize = 0;

                unsafe {
                    BNGetTypePrinterTypeLines(
                        printer,
                        self.handle,
                        container,
                        &mut name.0,
                        64,
                        false,
                        BNTokenEscapingType::NoTokenEscapingType,
                        &mut lines,
                        &mut count,
                    )
                };
                unsafe {
                    BNFreeTypeContainer(container);
                }

                if lines.is_null() {
                    return Err(std::fmt::Error);
                }

                let line_slice: &[BNTypeDefinitionLine] =
                    unsafe { std::slice::from_raw_parts(lines, count) };

                for (i, line) in line_slice.iter().enumerate() {
                    if i > 0 {
                        writeln!(f)?;
                    }

                    let tokens: &[BNInstructionTextToken] =
                        unsafe { std::slice::from_raw_parts(line.tokens, line.count) };

                    for token in tokens {
                        let text: *const c_char = token.text;
                        let str = unsafe { CStr::from_ptr(text) };
                        write!(f, "{}", str.to_string_lossy())?;
                    }
                }

                unsafe {
                    BNFreeTypeDefinitionLineList(lines, count);
                }
                return Ok(());
            }
        }
        Err(std::fmt::Error)
    }
}

impl PartialEq for Type {
    fn eq(&self, other: &Self) -> bool {
        unsafe { BNTypesEqual(self.handle, other.handle) }
    }
}

impl Eq for Type {}

impl Hash for Type {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

unsafe impl Send for Type {}
unsafe impl Sync for Type {}

unsafe impl RefCountable for Type {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(BNNewTypeReference(handle.handle))
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeType(handle.handle);
    }
}

impl ToOwned for Type {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

// TODO: Remove this struct, or make it not a ZST with a terrible array provider.
/// ZST used only for `Array<ComponentReferencedType>`.
pub struct ComponentReferencedType;

impl CoreArrayProvider for ComponentReferencedType {
    type Raw = *mut BNType;
    type Context = ();
    type Wrapped<'a> = &'a Type;
}

unsafe impl CoreArrayProviderInner for ComponentReferencedType {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNComponentFreeReferencedTypes(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // SAFETY: &*mut BNType == &Type (*mut BNType == Type)
        std::mem::transmute(raw)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FunctionParameter {
    pub ty: Conf<Ref<Type>>,
    pub name: String,
    pub location: Option<Variable>,
}

impl FunctionParameter {
    pub fn new<T: Into<Conf<Ref<Type>>>>(ty: T, name: String, location: Option<Variable>) -> Self {
        Self {
            ty: ty.into(),
            name,
            location,
        }
    }
}

impl From<BNFunctionParameter> for FunctionParameter {
    fn from(value: BNFunctionParameter) -> Self {
        // TODO: I copied this from the original `from_raw` function.
        // TODO: So this actually needs to be audited later.
        let name = if value.name.is_null() {
            if value.location.type_ == VariableSourceType::RegisterVariableSourceType {
                format!("reg_{}", value.location.storage)
            } else if value.location.type_ == VariableSourceType::StackVariableSourceType {
                format!("arg_{}", value.location.storage)
            } else {
                String::new()
            }
        } else {
            unsafe { BnString::from_raw(value.name) }.to_string()
        };
        
        Self {
            ty: Conf::new(
                unsafe { Type::ref_from_raw(value.type_) },
                value.typeConfidence,
            ),
            name,
            location: match value.defaultLocation {
                false => Some(Variable::from(value.location)),
                true => None,
            },
        }
    }
}

impl From<&BNFunctionParameter> for FunctionParameter {
    fn from(value: &BNFunctionParameter) -> Self {
        // TODO: I copied this from the original `from_raw` function.
        // TODO: So this actually needs to be audited later.
        let name = if value.name.is_null() {
            if value.location.type_ == VariableSourceType::RegisterVariableSourceType {
                format!("reg_{}", value.location.storage)
            } else if value.location.type_ == VariableSourceType::StackVariableSourceType {
                format!("arg_{}", value.location.storage)
            } else {
                String::new()
            }
        } else {
            raw_to_string(value.name as *const _).unwrap()
        };

        Self {
            ty: Conf::new(
                unsafe { Type::from_raw(value.type_).to_owned() },
                value.typeConfidence,
            ),
            name,
            location: match value.defaultLocation {
                false => Some(Variable::from(value.location)),
                true => None,
            },
        }
    }
}

impl From<FunctionParameter> for BNFunctionParameter {
    fn from(value: FunctionParameter) -> Self {
        let bn_name = BnString::new(value.name);
        Self {
            name: bn_name.into_raw(),
            type_: value.ty.contents.handle,
            typeConfidence: value.ty.confidence,
            defaultLocation: value.location.is_none(),
            location: value.location.map(Into::into).unwrap_or_default(),
        }
    }
}

// Name, Variable and Type
impl CoreArrayProvider for (&str, Variable, &Type) {
    type Raw = BNVariableNameAndType;
    type Context = ();
    type Wrapped<'a> = (&'a str, Variable, &'a Type) where Self: 'a;
}

unsafe impl CoreArrayProviderInner for (&str, Variable, &Type) {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeVariableNameAndTypeList(raw, count)
    }
    
    unsafe fn wrap_raw<'a>(
        raw: &'a Self::Raw,
        _context: &'a Self::Context,
    ) -> (&'a str, Variable, &'a Type) {
        let name = CStr::from_ptr(raw.name).to_str().unwrap();
        let var = Variable::from(raw.var);
        let var_type = std::mem::transmute(&raw.type_);
        (name, var, var_type)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EnumerationMember {
    pub name: String,
    /// The associated constant value for the member.
    pub value: u64,
    /// Whether this is the default member for the associated [`Enumeration`].
    pub default: bool,
}

impl EnumerationMember {
    pub fn new(name: String, value: u64, default: bool) -> Self {
        Self {
            name,
            value,
            default,
        }
    }
}

impl From<BNEnumerationMember> for EnumerationMember {
    fn from(value: BNEnumerationMember) -> Self {
        Self {
            name: unsafe { BnString::from_raw(value.name).to_string() },
            value: value.value,
            default: value.isDefault,
        }
    }
}

impl From<EnumerationMember> for BNEnumerationMember {
    fn from(value: EnumerationMember) -> Self {
        let bn_name = BnString::new(value.name);
        Self {
            name: bn_name.into_raw(),
            value: value.value,
            isDefault: value.default,
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct EnumerationBuilder {
    pub(crate) handle: *mut BNEnumerationBuilder,
}

impl EnumerationBuilder {
    pub fn new() -> Self {
        Self {
            handle: unsafe { BNCreateEnumerationBuilder() },
        }
    }

    pub(crate) unsafe fn from_raw(handle: *mut BNEnumerationBuilder) -> Self {
        Self { handle }
    }

    pub fn finalize(&self) -> Ref<Enumeration> {
        unsafe { Enumeration::ref_from_raw(BNFinalizeEnumerationBuilder(self.handle)) }
    }

    pub fn append<S: BnStrCompatible>(&self, name: S) -> &Self {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNAddEnumerationBuilderMember(self.handle, name.as_ref().as_ptr() as _);
        }
        self
    }

    pub fn insert<S: BnStrCompatible>(&self, name: S, value: u64) -> &Self {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNAddEnumerationBuilderMemberWithValue(self.handle, name.as_ref().as_ptr() as _, value);
        }
        self
    }

    pub fn replace<S: BnStrCompatible>(&self, id: usize, name: S, value: u64) -> &Self {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNReplaceEnumerationBuilderMember(self.handle, id, name.as_ref().as_ptr() as _, value);
        }
        self
    }

    pub fn remove(&self, id: usize) -> &Self {
        unsafe {
            BNRemoveEnumerationBuilderMember(self.handle, id);
        }

        self
    }

    pub fn members(&self) -> Vec<EnumerationMember> {
        unsafe {
            let mut count = 0;
            let members_raw_ptr = BNGetEnumerationBuilderMembers(self.handle, &mut count);
            let members_raw: &[BNEnumerationMember] = std::slice::from_raw_parts(members_raw_ptr, count);
            let members = members_raw.iter().copied().map(Into::into).collect();
            BNFreeEnumerationMemberList(members_raw_ptr, count);
            members
        }
    }
}

impl Default for EnumerationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&Enumeration> for EnumerationBuilder {
    fn from(enumeration: &Enumeration) -> Self {
        unsafe {
            Self::from_raw(BNCreateEnumerationBuilderFromEnumeration(
                enumeration.handle,
            ))
        }
    }
}

impl Drop for EnumerationBuilder {
    fn drop(&mut self) {
        unsafe { BNFreeEnumerationBuilder(self.handle) };
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct Enumeration {
    pub(crate) handle: *mut BNEnumeration,
}

impl Enumeration {
    pub(crate) unsafe fn ref_from_raw(handle: *mut BNEnumeration) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn builder() -> EnumerationBuilder {
        EnumerationBuilder::new()
    }

    pub fn members(&self) -> Vec<EnumerationMember> {
        unsafe {
            let mut count = 0;
            let members_raw_ptr = BNGetEnumerationMembers(self.handle, &mut count);
            let members_raw: &[BNEnumerationMember] = std::slice::from_raw_parts(members_raw_ptr, count);
            let members = members_raw.iter().copied().map(Into::into).collect();
            BNFreeEnumerationMemberList(members_raw_ptr, count);
            members
        }
    }
}

unsafe impl RefCountable for Enumeration {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(BNNewEnumerationReference(handle.handle))
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeEnumeration(handle.handle);
    }
}

impl ToOwned for Enumeration {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

pub type StructureType = BNStructureVariant;

#[derive(PartialEq, Eq, Hash)]
pub struct StructureBuilder {
    pub(crate) handle: *mut BNStructureBuilder,
}

/// ```no_run
/// // Includes
/// # use binaryninja::binaryview::BinaryViewExt;
/// use binaryninja::types::{Structure, StructureBuilder, Type, MemberAccess, MemberScope};
///
/// // Define struct, set size (in bytes)
/// let mut my_custom_struct = StructureBuilder::new();
/// let field_1 = Type::named_int(5, false, "my_weird_int_type");
/// let field_2 = Type::int(4, false);
/// let field_3 = Type::int(8, false);
///
/// // Assign those fields
/// my_custom_struct.insert(&field_1, "field_1", 0, false, MemberAccess::PublicAccess, MemberScope::NoScope);
/// my_custom_struct.insert(&field_2, "field_2", 5, false, MemberAccess::PublicAccess, MemberScope::NoScope);
/// my_custom_struct.insert(&field_3, "field_3", 9, false, MemberAccess::PublicAccess, MemberScope::NoScope);
/// my_custom_struct.append(&field_1, "field_4", MemberAccess::PublicAccess, MemberScope::NoScope);
///
/// // Convert structure to type
/// let my_custom_structure_type = Type::structure(&my_custom_struct.finalize());
///
/// // Add the struct to the binary view to use in analysis
/// let bv = binaryninja::load("example").unwrap();
/// bv.define_user_type("my_custom_struct", &my_custom_structure_type);
/// ```
impl StructureBuilder {
    pub fn new() -> Self {
        Self {
            handle: unsafe { BNCreateStructureBuilder() },
        }
    }

    pub(crate) unsafe fn from_raw(handle: *mut BNStructureBuilder) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }
    
    pub fn finalize(&self) -> Ref<Structure> {
        unsafe { Structure::ref_from_raw(BNFinalizeStructureBuilder(self.handle)) }
    }

    pub fn set_width(&self, width: u64) -> &Self {
        unsafe {
            BNSetStructureBuilderWidth(self.handle, width);
        }

        self
    }

    pub fn set_alignment(&self, alignment: usize) -> &Self {
        unsafe {
            BNSetStructureBuilderAlignment(self.handle, alignment);
        }

        self
    }

    pub fn set_packed(&self, packed: bool) -> &Self {
        unsafe {
            BNSetStructureBuilderPacked(self.handle, packed);
        }

        self
    }

    pub fn set_structure_type(&self, t: StructureType) -> &Self {
        unsafe { BNSetStructureBuilderType(self.handle, t) };
        self
    }

    pub fn set_pointer_offset(&self, offset: i64) -> &Self {
        unsafe { BNSetStructureBuilderPointerOffset(self.handle, offset) };
        self
    }

    pub fn set_propagates_data_var_refs(&self, does: bool) -> &Self {
        unsafe { BNSetStructureBuilderPropagatesDataVariableReferences(self.handle, does) };
        self
    }

    pub fn set_base_structures(&self, bases: &[BaseStructure]) -> &Self {
        let raw_base_structs: Vec<BNBaseStructure> = bases.iter().map(Into::into).collect();

        unsafe {
            BNSetBaseStructuresForStructureBuilder(
                self.handle,
                raw_base_structs.as_ptr() as *mut _,
                raw_base_structs.len(),
            )
        };

        self
    }

    pub fn append<'a, S: BnStrCompatible, T: Into<Conf<&'a Type>>>(
        &self,
        t: T,
        name: S,
        access: MemberAccess,
        scope: MemberScope,
    ) -> &Self {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNAddStructureBuilderMember(
                self.handle,
                &t.into().into(),
                name.as_ref().as_ptr() as _,
                access,
                scope,
            );
        }

        self
    }

    pub fn insert_member(&self, member: &StructureMember, overwrite_existing: bool) -> &Self {
        self.insert(
            &member.ty,
            member.name.clone(),
            member.offset,
            overwrite_existing,
            member.access,
            member.scope,
        );
        self
    }

    pub fn insert<'a, S: BnStrCompatible, T: Into<Conf<&'a Type>>>(
        &self,
        t: T,
        name: S,
        offset: u64,
        overwrite_existing: bool,
        access: MemberAccess,
        scope: MemberScope,
    ) -> &Self {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNAddStructureBuilderMemberAtOffset(
                self.handle,
                &t.into().into(),
                name.as_ref().as_ptr() as _,
                offset,
                overwrite_existing,
                access,
                scope,
            );
        }

        self
    }

    pub fn with_members<'a, S: BnStrCompatible, T: Into<Conf<&'a Type>>>(
        &self,
        members: impl IntoIterator<Item = (T, S)>,
    ) -> &Self {
        for (t, name) in members {
            self.append(t, name, MemberAccess::NoAccess, MemberScope::NoScope);
        }
        self
    }
    
    pub fn width(&self) -> u64 {
        unsafe { BNGetStructureBuilderWidth(self.handle) }
    }

    pub fn alignment(&self) -> usize {
        unsafe { BNGetStructureBuilderAlignment(self.handle) }
    }

    pub fn packed(&self) -> bool {
        unsafe { BNIsStructureBuilderPacked(self.handle) }
    }

    pub fn structure_type(&self) -> StructureType {
        unsafe { BNGetStructureBuilderType(self.handle) }
    }

    pub fn pointer_offset(&self) -> i64 {
        unsafe { BNGetStructureBuilderPointerOffset(self.handle) }
    }

    pub fn propagates_data_var_refs(&self) -> bool {
        unsafe { BNStructureBuilderPropagatesDataVariableReferences(self.handle) }
    }

    pub fn base_structures(&self) -> Option<Vec<BaseStructure>> {
        let mut count = 0usize;
        let bases_raw_ptr = unsafe { BNGetBaseStructuresForStructureBuilder(self.handle, &mut count) };
        match bases_raw_ptr.is_null() {
            false => {
                let bases_raw = unsafe { std::slice::from_raw_parts(bases_raw_ptr, count) };
                let bases = bases_raw.iter().copied().map(Into::into).collect();
                unsafe { BNFreeBaseStructureList(bases_raw_ptr, count) };
                Some(bases)
            },
            true => None,
        }
    }

    pub fn members(&self) -> Array<StructureMember> {
        let mut count = 0;
        let members_raw = unsafe { BNGetStructureBuilderMembers(self.handle, &mut count) };
        unsafe { Array::new(members_raw, count, ()) }
    }

    pub fn index_by_name(&self, name: &str) -> Option<usize> {
        self.members().iter().position(|member| member.name == name)
    }

    pub fn index_by_offset(&self, offset: u64) -> Option<usize> {
        self.members()
            .iter()
            .position(|member| member.offset == offset)
    }
    
    pub fn clear_members(&self) {
        let len = self.members().len();
        for idx in (0..len).rev() {
            self.remove(idx)
        }
    }

    pub fn add_members<'a>(&self, members: impl IntoIterator<Item = &'a StructureMember>) {
        for member in members {
            self.append(&member.ty, &member.name, member.access, member.scope);
        }
    }

    pub fn set_members<'a>(&self, members: impl IntoIterator<Item = &'a StructureMember>) {
        self.clear_members();
        self.add_members(members);
    }

    pub fn remove(&self, index: usize) {
        unsafe { BNRemoveStructureBuilderMember(self.handle, index) }
    }

    pub fn replace(&self, index: usize, type_: Conf<&Type>, name: &str, overwrite: bool) {
        let name = name.into_bytes_with_nul();
        let name_ptr = name.as_ptr() as *const _;

        let raw_type_ = BNTypeWithConfidence {
            type_: type_.contents as *const Type as *mut _,
            confidence: type_.confidence,
        };
        unsafe {
            BNReplaceStructureBuilderMember(self.handle, index, &raw_type_, name_ptr, overwrite)
        }
    }
}

impl From<&Structure> for StructureBuilder {
    fn from(structure: &Structure) -> StructureBuilder {
        unsafe { Self::from_raw(BNCreateStructureBuilderFromStructure(structure.handle)) }
    }
}

impl From<Vec<StructureMember>> for StructureBuilder {
    fn from(members: Vec<StructureMember>) -> StructureBuilder {
        let builder = StructureBuilder::new();
        for m in members {
            builder.insert_member(&m, false);
        }
        builder
    }
}

impl Debug for StructureBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "StructureBuilder {{ ... }}")
    }
}

impl Drop for StructureBuilder {
    fn drop(&mut self) {
        unsafe { BNFreeStructureBuilder(self.handle) };
    }
}

impl Default for StructureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct Structure {
    pub(crate) handle: *mut BNStructure,
}

impl Structure {
    unsafe fn from_raw(handle: *mut BNStructure) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNStructure) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn builder() -> StructureBuilder {
        StructureBuilder::new()
    }

    pub fn width(&self) -> u64 {
        unsafe { BNGetStructureWidth(self.handle) }
    }

    pub fn structure_type(&self) -> StructureType {
        unsafe { BNGetStructureType(self.handle) }
    }

    // TODO: Omit `Option` and pass empty vec? Actually the core will only nullptr on failed allocation, use debug_assert.
    pub fn members(&self) -> Option<Vec<StructureMember>> {
        unsafe {
            let mut count = 0;
            let members_raw_ptr: *mut BNStructureMember =
                BNGetStructureMembers(self.handle, &mut count);
            // TODO: Debug assert members_raw_ptr.
            match members_raw_ptr.is_null() {
                false => {
                    let members_raw = std::slice::from_raw_parts(members_raw_ptr, count);
                    let members = members_raw.iter().map(Into::into).collect();
                    BNFreeStructureMemberList(members_raw_ptr, count);
                    Some(members)
                },
                true => None,
            }
        }
    }

    // TODO: Omit `Option` and pass empty vec?
    pub fn base_structures(&self) -> Option<Vec<BaseStructure>> {
        let mut count = 0;
        let bases_raw_ptr = unsafe { BNGetBaseStructuresForStructure(self.handle, &mut count) };
        match bases_raw_ptr.is_null() {
            false => {
                let bases_raw = unsafe { std::slice::from_raw_parts(bases_raw_ptr, count) };
                let bases = bases_raw.iter().copied().map(Into::into).collect();
                unsafe { BNFreeBaseStructureList(bases_raw_ptr, count) };
                Some(bases)
            },
            true => None,
        }
    }

    // TODO : The other methods in the python version (alignment, packed, type, members, remove, replace, etc)
}

impl Debug for Structure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Structure {{")?;
        if let Some(members) = self.members() {
            for member in members {
                write!(f, " {:?}", member)?;
            }
        }
        write!(f, "}}")
    }
}

unsafe impl RefCountable for Structure {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(BNNewStructureReference(handle.handle))
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeStructure(handle.handle);
    }
}

impl ToOwned for Structure {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct StructureMember {
    pub ty: Conf<Ref<Type>>,
    pub name: String,
    pub offset: u64,
    pub access: MemberAccess,
    pub scope: MemberScope,
}

impl StructureMember {
    pub fn new(
        ty: Conf<Ref<Type>>,
        name: String,
        offset: u64,
        access: MemberAccess,
        scope: MemberScope,
    ) -> Self {
        Self {
            ty,
            name,
            offset,
            access,
            scope,
        }
    }
}

impl From<BNStructureMember> for StructureMember {
    fn from(value: BNStructureMember) -> Self {
        Self {
            ty: Conf::new(
                unsafe { Type::ref_from_raw(value.type_) },
                value.typeConfidence,
            ),
            name: unsafe { BnString::from_raw(value.name) }.to_string(),
            offset: value.offset,
            access: value.access,
            scope: value.scope,
        }
    }
}

impl From<&BNStructureMember> for StructureMember {
    fn from(value: &BNStructureMember) -> Self {
        Self {
            ty: Conf::new(
                unsafe { Type::from_raw(value.type_).to_owned() },
                value.typeConfidence,
            ),
            // TODO: I dislike using this function here.
            name: raw_to_string(value.name as *mut _).unwrap(),
            offset: value.offset,
            access: value.access,
            scope: value.scope,
        }
    }
}

impl From<StructureMember> for BNStructureMember {
    fn from(value: StructureMember) -> Self {
        let bn_name = BnString::new(value.name);
        // TODO: Dec ref here?
        Self {
            type_: value.ty.contents.handle,
            name: bn_name.into_raw(),
            offset: value.offset,
            typeConfidence: value.ty.confidence,
            access: value.access,
            scope: value.scope,
        }
    }
}

impl CoreArrayProvider for StructureMember {
    type Raw = BNStructureMember;
    type Context = ();
    type Wrapped<'a> = StructureMember;
}

unsafe impl CoreArrayProviderInner for StructureMember {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeStructureMemberList(raw, count)
    }
    
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from(raw)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct InheritedStructureMember {
    pub base: Ref<NamedTypeReference>,
    pub base_offset: u64,
    pub member: StructureMember,
    pub member_index: usize,
}

impl InheritedStructureMember {
    pub fn new(
        base: Ref<NamedTypeReference>,
        base_offset: u64,
        member: StructureMember,
        member_index: usize,
    ) -> Self {
        Self {
            base,
            base_offset,
            member,
            member_index,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct BaseStructure {
    pub ty: Ref<NamedTypeReference>,
    pub offset: u64,
    pub width: u64,
}

impl BaseStructure {
    pub fn new(ty: Ref<NamedTypeReference>, offset: u64, width: u64) -> Self {
        Self { ty, offset, width }
    }
}

impl From<BNBaseStructure> for BaseStructure {
    fn from(value: BNBaseStructure) -> Self {
        Self {
            ty: unsafe { NamedTypeReference::ref_from_raw(value.type_) },
            offset: value.offset,
            width: value.width,
        }
    }
}

impl From<BaseStructure> for BNBaseStructure {
    fn from(value: BaseStructure) -> Self {
        Self {
            type_: value.ty.handle,
            offset: value.offset,
            width: value.width,
        }
    }
}

impl From<&BaseStructure> for BNBaseStructure {
    fn from(value: &BaseStructure) -> Self {
        Self {
            // TODO: In the core there doesn't appear to be a ref increment.
            // TODO: Do we want to increment the ref here for the &BaseStructure impl?
            // TODO: See BNSetBaseStructuresForStructureBuilder for an example.
            type_: value.ty.handle,
            offset: value.offset,
            width: value.width,
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct NamedTypeReference {
    pub(crate) handle: *mut BNNamedTypeReference,
}

impl NamedTypeReference {
    pub(crate) unsafe fn from_raw(handle: *mut BNNamedTypeReference) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNNamedTypeReference) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    /// Create an NTR to a type that did not come directly from a BinaryView's types list.
    /// That is to say, if you're referencing a new type you're GOING to add, use this.
    /// You should not assign type ids yourself, that is the responsibility of the BinaryView
    /// implementation after your types have been added. Just make sure the names match up and
    /// the core will do the id stuff for you.
    pub fn new(type_class: NamedTypeReferenceClass, mut name: QualifiedName) -> Ref<Self> {
        unsafe {
            Self::ref_from_raw(BNCreateNamedType(type_class, std::ptr::null() as *const _, &mut name.0))
        }
    }

    /// Create an NTR to a type with an existing type id, which generally means it came directly
    /// from a BinaryView's types list and its id was looked up using `BinaryView::get_type_id`.
    /// You should not assign type ids yourself: if you use this to reference a type you are going
    /// to create but have not yet created, you may run into problems when giving your types to
    /// a BinaryView.
    pub fn new_with_id<S: BnStrCompatible>(
        type_class: NamedTypeReferenceClass,
        type_id: S,
        mut name: QualifiedName,
    ) -> Ref<Self> {
        let type_id = type_id.into_bytes_with_nul();

        unsafe {
            Self::ref_from_raw(BNCreateNamedType(type_class, type_id.as_ref().as_ptr() as _, &mut name.0))
        }
    }

    pub fn name(&self) -> QualifiedName {
        let named_ref: BNQualifiedName = unsafe { BNGetTypeReferenceName(self.handle) };
        QualifiedName(named_ref)
    }

    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetTypeReferenceId(self.handle)) }
    }

    pub fn class(&self) -> NamedTypeReferenceClass {
        unsafe { BNGetTypeReferenceClass(self.handle) }
    }

    fn target_helper(&self, bv: &BinaryView, visited: &mut HashSet<BnString>) -> Option<Ref<Type>> {
        // TODO : This is a clippy bug (#10088, I think); remove after we upgrade past 2022-12-12
        #[allow(clippy::manual_filter)]
        if let Some(t) = bv.get_type_by_id(self.id()) {
            if t.type_class() != TypeClass::NamedTypeReferenceClass {
                Some(t)
            } else {
                let t = t.get_named_type_reference().unwrap();
                if visited.contains(&t.id()) {
                    error!("Can't get target for recursively defined type!");
                    None
                } else {
                    visited.insert(t.id());
                    t.target_helper(bv, visited)
                }
            }
        } else {
            None
        }
    }

    pub fn target(&self, bv: &BinaryView) -> Option<Ref<Type>> {
        //! Returns the type referenced by this named type reference
        self.target_helper(bv, &mut HashSet::new())
    }
}

impl ToOwned for NamedTypeReference {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for NamedTypeReference {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(BNNewNamedTypeReference(handle.handle))
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeNamedTypeReference(handle.handle)
    }
}

impl Debug for NamedTypeReference {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (id: {})", self.name(), self.id())
    }
}

#[repr(transparent)]
pub struct QualifiedName(pub(crate) BNQualifiedName);

impl QualifiedName {
    // TODO : I think this is bad
    pub fn string(&self) -> String {
        unsafe {
            std::slice::from_raw_parts(self.0.name, self.0.nameCount)
                .iter()
                .map(|c| CStr::from_ptr(*c).to_string_lossy())
                .collect::<Vec<_>>()
                .join("::")
        }
    }

    pub fn join(&self) -> Cow<str> {
        let join: *mut c_char = self.0.join;
        unsafe { CStr::from_ptr(join) }.to_string_lossy()
    }

    pub fn strings(&self) -> Vec<Cow<str>> {
        let names: *mut *mut c_char = self.0.name;
        unsafe {
            std::slice::from_raw_parts(names, self.0.nameCount)
                .iter()
                .map(|name| CStr::from_ptr(*name).to_string_lossy())
                .collect::<Vec<_>>()
        }
    }

    pub fn len(&self) -> usize {
        self.0.nameCount
    }

    pub fn is_empty(&self) -> bool {
        self.0.nameCount == 0
    }
}

impl<S: BnStrCompatible> From<S> for QualifiedName {
    fn from(name: S) -> Self {
        let join = BnString::new("::");
        let name = name.into_bytes_with_nul();
        let mut list = vec![name.as_ref().as_ptr() as *const _];

        QualifiedName(BNQualifiedName {
            name: unsafe { BNAllocStringList(list.as_mut_ptr(), 1) },
            join: join.into_raw(),
            nameCount: 1,
        })
    }
}

impl<S: BnStrCompatible> From<Vec<S>> for QualifiedName {
    fn from(names: Vec<S>) -> Self {
        let join = BnString::new("::");
        let names = names
            .into_iter()
            .map(|n| n.into_bytes_with_nul())
            .collect::<Vec<_>>();
        let mut list = names
            .iter()
            .map(|n| n.as_ref().as_ptr() as *const _)
            .collect::<Vec<_>>();

        QualifiedName(BNQualifiedName {
            name: unsafe { BNAllocStringList(list.as_mut_ptr(), list.len()) },
            join: join.into_raw(),
            nameCount: list.len(),
        })
    }
}

impl Clone for QualifiedName {
    fn clone(&self) -> Self {
        let strings = self.strings();
        let name = Self::from(strings.iter().collect::<Vec<&Cow<str>>>());
        name
    }
}

impl Hash for QualifiedName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.join().hash(state);
        self.strings().hash(state);
    }
}

impl Debug for QualifiedName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string())
    }
}

impl Display for QualifiedName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string())
    }
}

impl PartialEq for QualifiedName {
    fn eq(&self, other: &Self) -> bool {
        self.strings() == other.strings()
    }
}

impl Eq for QualifiedName {}

impl Drop for QualifiedName {
    fn drop(&mut self) {
        unsafe {
            BNFreeQualifiedName(&mut self.0);
        }
    }
}

impl CoreArrayProvider for QualifiedName {
    type Raw = BNQualifiedName;
    type Context = ();
    type Wrapped<'a> = &'a QualifiedName;
}

unsafe impl CoreArrayProviderInner for QualifiedName {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeNameList(raw, count);
    }
    
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        std::mem::transmute(raw)
    }
}

#[repr(transparent)]
pub struct QualifiedNameAndType(pub(crate) BNQualifiedNameAndType);

impl QualifiedNameAndType {
    pub fn name(&self) -> &QualifiedName {
        unsafe { std::mem::transmute(&self.0.name) }
    }

    pub fn type_object(&self) -> Guard<Type> {
        unsafe { Guard::new(Type::from_raw(self.0.type_), self) }
    }
}

impl Drop for QualifiedNameAndType {
    fn drop(&mut self) {
        unsafe {
            BNFreeQualifiedNameAndType(&mut self.0);
        }
    }
}

impl CoreArrayProvider for QualifiedNameAndType {
    type Raw = BNQualifiedNameAndType;
    type Context = ();
    type Wrapped<'a> = &'a QualifiedNameAndType;
}

unsafe impl CoreArrayProviderInner for QualifiedNameAndType {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeAndNameList(raw, count);
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        std::mem::transmute(raw)
    }
}

#[repr(transparent)]
pub struct QualifiedNameTypeAndId(pub(crate) BNQualifiedNameTypeAndId);

impl QualifiedNameTypeAndId {
    pub fn name(&self) -> &QualifiedName {
        unsafe { std::mem::transmute(&self.0.name) }
    }

    pub fn id(&self) -> &str {
        unsafe { CStr::from_ptr(self.0.id).to_str().unwrap() }
    }

    pub fn ty(&self) -> Guard<Type> {
        unsafe { Guard::new(Type::from_raw(self.0.type_), self) }
    }
}

impl Drop for QualifiedNameTypeAndId {
    fn drop(&mut self) {
        unsafe {
            BNFreeQualifiedNameTypeAndId(&mut self.0);
        }
    }
}

impl CoreArrayProvider for QualifiedNameTypeAndId {
    type Raw = BNQualifiedNameTypeAndId;
    type Context = ();
    type Wrapped<'a> = &'a QualifiedNameTypeAndId;
}

unsafe impl CoreArrayProviderInner for QualifiedNameTypeAndId {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeIdList(raw, count);
    }
    
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // TODO: Oh my god what is wrong with all of you people
        std::mem::transmute(raw)
    }
}

// TODO: Document how this type is used for many different purposes. (this is literally (string, type))
// TODO: Ex. the name might be the parser it came from
// TODO: Ex. the name might be the param name for an intrinsic input
// TODO: Should we make new types for each varying use case?
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct NameAndType {
    pub name: String,
    pub ty: Conf<Ref<Type>>,
}

impl NameAndType {
    pub fn new(name: impl Into<String>, ty: Conf<Ref<Type>>) -> Self {
        Self { name: name.into(), ty}
    }
}

impl From<BNNameAndType> for NameAndType {
    fn from(value: BNNameAndType) -> Self {
        Self  {
            name: unsafe { BnString::from_raw(value.name) }.to_string(),
            ty: Conf::new(
                unsafe { Type::ref_from_raw(value.type_) },
                value.typeConfidence,
            ),
        }
    }
}

impl From<&BNNameAndType> for NameAndType {
    fn from(value: &BNNameAndType) -> Self {
        Self  {
            // TODO: I dislike using this function here.
            name: raw_to_string(value.name as *mut _).unwrap(),
            ty: Conf::new(
                unsafe { Type::from_raw(value.type_).to_owned() },
                value.typeConfidence,
            ),
        }
    }
}

impl From<NameAndType> for BNNameAndType {
    fn from(value: NameAndType) -> Self {
        let bn_name = BnString::new(value.name);
        Self {
            name: bn_name.into_raw(),
            type_: value.ty.contents.handle,
            typeConfidence: value.ty.confidence,
        }
    }
}

impl CoreArrayProvider for NameAndType {
    type Raw = BNNameAndType;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for NameAndType {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeNameAndTypeList(raw, count);
    }
    
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        raw.into()
    }
}
