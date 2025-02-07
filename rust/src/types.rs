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
#![allow(unused)]

// TODO : More widely enforce the use of ref_from_raw vs just from_raw to simplify internal binding usage?  Perhaps remove from_raw functions?
// TODO : Add documentation and fix examples
// TODO : Test the get_enumeration and get_structure methods

use binaryninjacore_sys::*;

use crate::{
    architecture::{Architecture, CoreArchitecture},
    binary_view::{BinaryView, BinaryViewExt},
    calling_convention::CoreCallingConvention,
    rc::*,
    string::{BnStrCompatible, BnString},
};

use crate::confidence::{Conf, MAX_CONFIDENCE, MIN_CONFIDENCE};
use crate::string::{raw_to_string, strings_to_string_list};
use crate::variable::{Variable, VariableSourceType};
use std::borrow::Cow;
use std::num::NonZeroUsize;
use std::ops::{Index, IndexMut};
use std::{
    collections::HashSet,
    ffi::CStr,
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    iter::IntoIterator,
};

pub type StructureType = BNStructureVariant;
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
            false => Some(Conf::<Ref<Type>>::from_owned_raw(raw_target)),
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

    pub fn calling_convention(&self) -> Option<Conf<Ref<CoreCallingConvention>>> {
        let raw_convention_confidence = unsafe { BNGetTypeBuilderCallingConvention(self.handle) };
        match raw_convention_confidence.convention.is_null() {
            false => Some(Conf::<Ref<CoreCallingConvention>>::from_owned_raw(
                raw_convention_confidence,
            )),
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
                    let parameters = raw_parameters
                        .iter()
                        .map(FunctionParameter::from_raw)
                        .collect();
                    BNFreeTypeParameterList(raw_parameters_ptr, count);
                    Some(parameters)
                }
                true => None,
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

    pub fn array<'a, T: Into<Conf<&'a Type>>>(ty: T, count: u64) -> Self {
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe { Self::from_raw(BNCreateArrayTypeBuilder(&owned_raw_ty, count)) }
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

    pub fn named_type_from_type<T: Into<QualifiedName>>(name: T, t: &Type) -> Self {
        let mut raw_name = QualifiedName::into_raw(name.into());
        let id = c"";

        let result = unsafe {
            Self::from_raw(BNCreateNamedTypeReferenceBuilderFromTypeAndId(
                id.as_ptr() as *mut _,
                &mut raw_name,
                t.handle,
            ))
        };
        QualifiedName::free_raw(raw_name);
        result
    }

    // TODO : BNCreateFunctionTypeBuilder

    pub fn pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, ty: T) -> Self {
        let mut is_const = Conf::new(false, MIN_CONFIDENCE).into();
        let mut is_volatile = Conf::new(false, MIN_CONFIDENCE).into();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilder(
                arch.as_ref().handle,
                &owned_raw_ty,
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            ))
        }
    }

    pub fn const_pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, ty: T) -> Self {
        let mut is_const = Conf::new(true, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(false, MIN_CONFIDENCE).into();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilder(
                arch.as_ref().handle,
                &owned_raw_ty,
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            ))
        }
    }

    pub fn pointer_of_width<'a, T: Into<Conf<&'a Type>>>(
        ty: T,
        size: usize,
        is_const: bool,
        is_volatile: bool,
        ref_type: Option<ReferenceType>,
    ) -> Self {
        let mut is_const = Conf::new(is_const, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(is_volatile, MAX_CONFIDENCE).into();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilderOfWidth(
                size,
                &owned_raw_ty,
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or(ReferenceType::PointerReferenceType),
            ))
        }
    }

    pub fn pointer_with_options<'a, A: Architecture, T: Into<Conf<&'a Type>>>(
        arch: &A,
        ty: T,
        is_const: bool,
        is_volatile: bool,
        ref_type: Option<ReferenceType>,
    ) -> Self {
        let mut is_const = Conf::new(is_const, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(is_volatile, MAX_CONFIDENCE).into();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilder(
                arch.as_ref().handle,
                &owned_raw_ty,
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
/// # use crate::binaryninja::binary_view::BinaryViewExt;
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
            false => Some(Conf::<Ref<Type>>::from_owned_raw(raw_target)),
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

    pub fn calling_convention(&self) -> Option<Conf<Ref<CoreCallingConvention>>> {
        let convention_confidence = unsafe { BNGetTypeCallingConvention(self.handle) };
        match convention_confidence.convention.is_null() {
            false => Some(Conf::<Ref<CoreCallingConvention>>::from_owned_raw(
                convention_confidence,
            )),
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
                    let parameters = raw_parameters
                        .iter()
                        .map(FunctionParameter::from_raw)
                        .collect();
                    BNFreeTypeParameterList(raw_parameters_ptr, count);
                    Some(parameters)
                }
                true => None,
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

    pub fn array<'a, T: Into<Conf<&'a Type>>>(ty: T, count: u64) -> Ref<Self> {
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe { Self::ref_from_raw(BNCreateArrayType(&owned_raw_ty, count)) }
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

    pub fn named_type_from_type<T: Into<QualifiedName>>(name: T, t: &Type) -> Ref<Self> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        // TODO: No id is present for this call?
        let id = c"";

        let result = unsafe {
            Self::ref_from_raw(BNCreateNamedTypeReferenceFromTypeAndId(
                id.as_ptr(),
                &mut raw_name,
                t.handle,
            ))
        };
        QualifiedName::free_raw(raw_name);
        result
    }

    // TODO: FunctionBuilder
    pub fn function<'a, T: Into<Conf<&'a Type>>>(
        return_type: T,
        parameters: Vec<FunctionParameter>,
        variable_arguments: bool,
    ) -> Ref<Self> {
        let mut owned_raw_return_type = Conf::<&Type>::into_raw(return_type.into());
        let mut variable_arguments = Conf::new(variable_arguments, MAX_CONFIDENCE).into();
        let mut can_return = Conf::new(true, MIN_CONFIDENCE).into();
        let mut pure = Conf::new(false, MIN_CONFIDENCE).into();

        let mut raw_calling_convention: BNCallingConventionWithConfidence =
            BNCallingConventionWithConfidence {
                convention: std::ptr::null_mut(),
                confidence: MIN_CONFIDENCE,
            };

        let mut stack_adjust = Conf::new(0, MIN_CONFIDENCE).into();
        let mut raw_parameters = parameters
            .into_iter()
            .map(FunctionParameter::into_raw)
            .collect::<Vec<_>>();
        let reg_stack_adjust_regs = std::ptr::null_mut();
        let reg_stack_adjust_values = std::ptr::null_mut();

        let mut return_regs: BNRegisterSetWithConfidence = BNRegisterSetWithConfidence {
            regs: std::ptr::null_mut(),
            count: 0,
            confidence: 0,
        };

        let result = unsafe {
            Self::ref_from_raw(BNNewTypeReference(BNCreateFunctionType(
                &mut owned_raw_return_type,
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
        };

        for raw_param in raw_parameters {
            FunctionParameter::free_raw(raw_param);
        }

        result
    }

    // TODO: FunctionBuilder
    pub fn function_with_opts<
        'a,
        T: Into<Conf<&'a Type>>,
        C: Into<Conf<Ref<CoreCallingConvention>>>,
    >(
        return_type: T,
        parameters: &[FunctionParameter],
        variable_arguments: bool,
        calling_convention: C,
        stack_adjust: Conf<i64>,
    ) -> Ref<Self> {
        let mut owned_raw_return_type = Conf::<&Type>::into_raw(return_type.into());
        let mut variable_arguments = Conf::new(variable_arguments, MAX_CONFIDENCE).into();
        let mut can_return = Conf::new(true, MIN_CONFIDENCE).into();
        let mut pure = Conf::new(false, MIN_CONFIDENCE).into();

        let mut owned_raw_calling_convention =
            Conf::<Ref<CoreCallingConvention>>::into_owned_raw(&calling_convention.into());

        let mut stack_adjust = stack_adjust.into();
        let mut raw_parameters = parameters
            .iter()
            .cloned()
            .map(FunctionParameter::into_raw)
            .collect::<Vec<_>>();

        // TODO: Update type signature and include these (will be a breaking change)
        let reg_stack_adjust_regs = std::ptr::null_mut();
        let reg_stack_adjust_values = std::ptr::null_mut();

        let mut return_regs: BNRegisterSetWithConfidence = BNRegisterSetWithConfidence {
            regs: std::ptr::null_mut(),
            count: 0,
            confidence: 0,
        };

        let result = unsafe {
            Self::ref_from_raw(BNCreateFunctionType(
                &mut owned_raw_return_type,
                &mut owned_raw_calling_convention,
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
        };

        for raw_param in raw_parameters {
            FunctionParameter::free_raw(raw_param);
        }

        result
    }

    pub fn pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, ty: T) -> Ref<Self> {
        let mut is_const = Conf::new(false, MIN_CONFIDENCE).into();
        let mut is_volatile = Conf::new(false, MIN_CONFIDENCE).into();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            Self::ref_from_raw(BNCreatePointerType(
                arch.as_ref().handle,
                &owned_raw_ty,
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            ))
        }
    }

    pub fn const_pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(
        arch: &A,
        ty: T,
    ) -> Ref<Self> {
        let mut is_const = Conf::new(true, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(false, MIN_CONFIDENCE).into();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            Self::ref_from_raw(BNCreatePointerType(
                arch.as_ref().handle,
                &owned_raw_ty,
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            ))
        }
    }

    pub fn pointer_of_width<'a, T: Into<Conf<&'a Type>>>(
        ty: T,
        size: usize,
        is_const: bool,
        is_volatile: bool,
        ref_type: Option<ReferenceType>,
    ) -> Ref<Self> {
        let mut is_const = Conf::new(is_const, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(is_volatile, MAX_CONFIDENCE).into();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            Self::ref_from_raw(BNCreatePointerTypeOfWidth(
                size,
                &owned_raw_ty,
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or(ReferenceType::PointerReferenceType),
            ))
        }
    }

    pub fn pointer_with_options<'a, A: Architecture, T: Into<Conf<&'a Type>>>(
        arch: &A,
        ty: T,
        is_const: bool,
        is_volatile: bool,
        ref_type: Option<ReferenceType>,
    ) -> Ref<Self> {
        let mut is_const = Conf::new(is_const, MAX_CONFIDENCE).into();
        let mut is_volatile = Conf::new(is_volatile, MAX_CONFIDENCE).into();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            Self::ref_from_raw(BNCreatePointerType(
                arch.as_ref().handle,
                &owned_raw_ty,
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or(ReferenceType::PointerReferenceType),
            ))
        }
    }

    pub fn generate_auto_demangled_type_id<T: Into<QualifiedName>>(name: T) -> BnString {
        let mut raw_name = QualifiedName::into_raw(name.into());
        let type_id = unsafe { BnString::from_raw(BNGenerateAutoDemangledTypeId(&mut raw_name)) };
        QualifiedName::free_raw(raw_name);
        type_id
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

impl Debug for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // You might be tempted to rip this atrocity out and make this more "sensible". READ BELOW!
        // Type is a one-size fits all structure, these are actually its fields! If we wanted to
        // omit some fields for different type classes what you really want to do is implement your
        // own formatter. This is supposed to represent the structure entirely, it's not supposed to be pretty!
        f.debug_struct("Type")
            .field("type_class", &self.type_class())
            .field("width", &self.width())
            .field("alignment", &self.alignment())
            .field("is_signed", &self.is_signed())
            .field("is_const", &self.is_const())
            .field("is_volatile", &self.is_volatile())
            .field("is_floating_point", &self.is_floating_point())
            .field("child_type", &self.child_type())
            .field("calling_convention", &self.calling_convention())
            .field("parameters", &self.parameters())
            .field("has_variable_arguments", &self.has_variable_arguments())
            .field("can_return", &self.can_return())
            .field("pure", &self.pure())
            .field("get_structure", &self.get_structure())
            .field("get_enumeration", &self.get_enumeration())
            .field("get_named_type_reference", &self.get_named_type_reference())
            .field("count", &self.count())
            .field("offset", &self.offset())
            .field("stack_adjustment", &self.stack_adjustment())
            .field("registered_name", &self.registered_name())
            .finish()
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

impl CoreArrayProvider for Type {
    type Raw = *mut BNType;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for Type {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // TODO: This is assuming &'a Type is &*mut BNType
        std::mem::transmute(raw)
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
    pub(crate) fn from_raw(value: &BNFunctionParameter) -> Self {
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

    pub(crate) fn from_owned_raw(value: BNFunctionParameter) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNFunctionParameter {
        let bn_name = BnString::new(value.name);
        BNFunctionParameter {
            name: BnString::into_raw(bn_name),
            type_: unsafe { Ref::into_raw(value.ty.contents) }.handle,
            typeConfidence: value.ty.confidence,
            defaultLocation: value.location.is_none(),
            location: value.location.map(Into::into).unwrap_or_default(),
        }
    }

    pub(crate) fn free_raw(value: BNFunctionParameter) {
        let _ = unsafe { BnString::from_raw(value.name) };
        let _ = unsafe { Type::ref_from_raw(value.type_) };
    }

    pub fn new<T: Into<Conf<Ref<Type>>>>(ty: T, name: String, location: Option<Variable>) -> Self {
        Self {
            ty: ty.into(),
            name,
            location,
        }
    }
}

// TODO: We need to delete this...
// Name, Variable and Type
impl CoreArrayProvider for (&str, Variable, &Type) {
    type Raw = BNVariableNameAndType;
    type Context = ();
    type Wrapped<'a>
        = (&'a str, Variable, &'a Type)
    where
        Self: 'a;
}

// TODO: This needs to go!
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
        let var_type = &*(raw.type_ as *mut Type);
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
    pub(crate) fn from_raw(value: &BNEnumerationMember) -> Self {
        Self {
            name: raw_to_string(value.name).unwrap(),
            value: value.value,
            default: value.isDefault,
        }
    }

    pub(crate) fn from_owned_raw(value: BNEnumerationMember) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNEnumerationMember {
        let bn_name = BnString::new(value.name);
        BNEnumerationMember {
            name: BnString::into_raw(bn_name),
            value: value.value,
            isDefault: value.default,
        }
    }

    pub(crate) fn free_raw(value: BNEnumerationMember) {
        let _ = unsafe { BnString::from_raw(value.name) };
    }

    pub fn new(name: String, value: u64, default: bool) -> Self {
        Self {
            name,
            value,
            default,
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

    pub fn append<S: BnStrCompatible>(&mut self, name: S) -> &mut Self {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNAddEnumerationBuilderMember(self.handle, name.as_ref().as_ptr() as _);
        }
        self
    }

    pub fn insert<S: BnStrCompatible>(&mut self, name: S, value: u64) -> &mut Self {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNAddEnumerationBuilderMemberWithValue(self.handle, name.as_ref().as_ptr() as _, value);
        }
        self
    }

    pub fn replace<S: BnStrCompatible>(&mut self, id: usize, name: S, value: u64) -> &mut Self {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNReplaceEnumerationBuilderMember(self.handle, id, name.as_ref().as_ptr() as _, value);
        }
        self
    }

    pub fn remove(&mut self, id: usize) -> &mut Self {
        unsafe {
            BNRemoveEnumerationBuilderMember(self.handle, id);
        }

        self
    }

    pub fn members(&self) -> Vec<EnumerationMember> {
        unsafe {
            let mut count = 0;
            let members_raw_ptr = BNGetEnumerationBuilderMembers(self.handle, &mut count);
            let members_raw: &[BNEnumerationMember] =
                std::slice::from_raw_parts(members_raw_ptr, count);
            let members = members_raw
                .iter()
                .map(EnumerationMember::from_raw)
                .collect();
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
            debug_assert!(!members_raw_ptr.is_null());
            let members_raw: &[BNEnumerationMember] =
                std::slice::from_raw_parts(members_raw_ptr, count);
            let members = members_raw
                .iter()
                .map(EnumerationMember::from_raw)
                .collect();
            BNFreeEnumerationMemberList(members_raw_ptr, count);
            members
        }
    }
}

impl Debug for Enumeration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enumeration")
            .field("members", &self.members())
            .finish()
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

#[derive(PartialEq, Eq, Hash)]
pub struct StructureBuilder {
    pub(crate) handle: *mut BNStructureBuilder,
}

/// ```no_run
/// // Includes
/// # use binaryninja::binary_view::BinaryViewExt;
/// use binaryninja::types::{MemberAccess, MemberScope, Structure, StructureBuilder, Type};
///
/// // Types to use in the members
/// let field_1_ty = Type::named_int(5, false, "my_weird_int_type");
/// let field_2_ty = Type::int(4, false);
/// let field_3_ty = Type::int(8, false);
///
/// // Assign those fields
/// let mut my_custom_struct = StructureBuilder::new();
/// my_custom_struct
///     .insert(
///         &field_1_ty,
///         "field_1",
///         0,
///         false,
///         MemberAccess::PublicAccess,
///         MemberScope::NoScope,
///     )
///     .insert(
///         &field_2_ty,
///         "field_2",
///         5,
///         false,
///         MemberAccess::PublicAccess,
///         MemberScope::NoScope,
///     )
///     .insert(
///         &field_3_ty,
///         "field_3",
///         9,
///         false,
///         MemberAccess::PublicAccess,
///         MemberScope::NoScope,
///     )
///     .append(
///         &field_1_ty,
///         "field_4",
///         MemberAccess::PublicAccess,
///         MemberScope::NoScope,
///     );
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

    // TODO: Document the width adjustment with alignment.
    pub fn finalize(&mut self) -> Ref<Structure> {
        let raw_struct_ptr = unsafe { BNFinalizeStructureBuilder(self.handle) };
        unsafe { Structure::ref_from_raw(raw_struct_ptr) }
    }

    /// Sets the width of the [`StructureBuilder`] to the new width.
    ///
    /// This will remove all previously inserted members outside the new width. This is done by computing
    /// the member access range (member offset + member width) and if it is larger than the new width
    /// it will be removed.
    pub fn width(&mut self, width: u64) -> &mut Self {
        unsafe {
            BNSetStructureBuilderWidth(self.handle, width);
        }
        self
    }

    pub fn alignment(&mut self, alignment: usize) -> &mut Self {
        unsafe {
            BNSetStructureBuilderAlignment(self.handle, alignment);
        }
        self
    }

    /// Sets whether the [`StructureBuilder`] is packed.
    ///
    /// If set the alignment of the structure will be `1`. You do not need to set the alignment to `1`.
    pub fn packed(&mut self, packed: bool) -> &mut Self {
        unsafe {
            BNSetStructureBuilderPacked(self.handle, packed);
        }
        self
    }

    pub fn structure_type(&mut self, t: StructureType) -> &mut Self {
        unsafe { BNSetStructureBuilderType(self.handle, t) };
        self
    }

    pub fn pointer_offset(&mut self, offset: i64) -> &mut Self {
        unsafe { BNSetStructureBuilderPointerOffset(self.handle, offset) };
        self
    }

    pub fn propagates_data_var_refs(&mut self, propagates: bool) -> &mut Self {
        unsafe { BNSetStructureBuilderPropagatesDataVariableReferences(self.handle, propagates) };
        self
    }

    pub fn base_structures(&mut self, bases: &[BaseStructure]) -> &mut Self {
        let raw_base_structs: Vec<BNBaseStructure> =
            bases.iter().map(BaseStructure::into_owned_raw).collect();
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
        &mut self,
        ty: T,
        name: S,
        access: MemberAccess,
        scope: MemberScope,
    ) -> &mut Self {
        let name = name.into_bytes_with_nul();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            BNAddStructureBuilderMember(
                self.handle,
                &owned_raw_ty,
                name.as_ref().as_ptr() as _,
                access,
                scope,
            );
        }
        self
    }

    pub fn insert_member(
        &mut self,
        member: StructureMember,
        overwrite_existing: bool,
    ) -> &mut Self {
        self.insert(
            &member.ty,
            member.name,
            member.offset,
            overwrite_existing,
            member.access,
            member.scope,
        );
        self
    }

    pub fn insert<'a, S: BnStrCompatible, T: Into<Conf<&'a Type>>>(
        &mut self,
        ty: T,
        name: S,
        offset: u64,
        overwrite_existing: bool,
        access: MemberAccess,
        scope: MemberScope,
    ) -> &mut Self {
        let name = name.into_bytes_with_nul();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            BNAddStructureBuilderMemberAtOffset(
                self.handle,
                &owned_raw_ty,
                name.as_ref().as_ptr() as _,
                offset,
                overwrite_existing,
                access,
                scope,
            );
        }
        self
    }

    pub fn replace<'a, S: BnStrCompatible, T: Into<Conf<&'a Type>>>(
        &mut self,
        index: usize,
        ty: T,
        name: S,
        overwrite_existing: bool,
    ) -> &mut Self {
        let name = name.into_bytes_with_nul();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            BNReplaceStructureBuilderMember(
                self.handle,
                index,
                &owned_raw_ty,
                name.as_ref().as_ptr() as _,
                overwrite_existing,
            )
        }
        self
    }

    pub fn remove(&mut self, index: usize) -> &mut Self {
        unsafe { BNRemoveStructureBuilderMember(self.handle, index) };
        self
    }

    // TODO: We should add BNGetStructureBuilderAlignedWidth
    /// Gets the current **unaligned** width of the structure.
    ///
    /// This cannot be used to accurately get the width of a non-packed structure.
    pub fn current_width(&self) -> u64 {
        unsafe { BNGetStructureBuilderWidth(self.handle) }
    }
}

impl From<&Structure> for StructureBuilder {
    fn from(structure: &Structure) -> StructureBuilder {
        unsafe { Self::from_raw(BNCreateStructureBuilderFromStructure(structure.handle)) }
    }
}

impl From<Vec<StructureMember>> for StructureBuilder {
    fn from(members: Vec<StructureMember>) -> StructureBuilder {
        let mut builder = StructureBuilder::new();
        for member in members {
            builder.insert_member(member, false);
        }
        builder
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

    pub fn members(&self) -> Vec<StructureMember> {
        unsafe {
            let mut count = 0;
            let members_raw_ptr: *mut BNStructureMember =
                BNGetStructureMembers(self.handle, &mut count);
            debug_assert!(!members_raw_ptr.is_null());
            let members_raw = std::slice::from_raw_parts(members_raw_ptr, count);
            let members = members_raw.iter().map(StructureMember::from_raw).collect();
            BNFreeStructureMemberList(members_raw_ptr, count);
            members
        }
    }

    pub fn base_structures(&self) -> Vec<BaseStructure> {
        let mut count = 0;
        let bases_raw_ptr = unsafe { BNGetBaseStructuresForStructure(self.handle, &mut count) };
        debug_assert!(!bases_raw_ptr.is_null());
        let bases_raw = unsafe { std::slice::from_raw_parts(bases_raw_ptr, count) };
        let bases = bases_raw.iter().map(BaseStructure::from_raw).collect();
        unsafe { BNFreeBaseStructureList(bases_raw_ptr, count) };
        bases
    }

    // TODO : The other methods in the python version (alignment, packed, type, members, remove, replace, etc)
}

impl Debug for Structure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Structure")
            .field("width", &self.width())
            .field("structure_type", &self.structure_type())
            .field("base_structures", &self.base_structures())
            .field("members", &self.members())
            .finish()
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
    // TODO: Shouldnt this be a QualifiedName? The ffi says no...
    pub name: String,
    pub offset: u64,
    pub access: MemberAccess,
    pub scope: MemberScope,
}

impl StructureMember {
    pub(crate) fn from_raw(value: &BNStructureMember) -> Self {
        Self {
            ty: Conf::new(
                unsafe { Type::from_raw(value.type_) }.to_owned(),
                value.typeConfidence,
            ),
            // TODO: I dislike using this function here.
            name: raw_to_string(value.name as *mut _).unwrap(),
            offset: value.offset,
            access: value.access,
            scope: value.scope,
        }
    }

    pub(crate) fn from_owned_raw(value: BNStructureMember) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNStructureMember {
        let bn_name = BnString::new(value.name);
        BNStructureMember {
            type_: unsafe { Ref::into_raw(value.ty.contents) }.handle,
            name: BnString::into_raw(bn_name),
            offset: value.offset,
            typeConfidence: value.ty.confidence,
            access: value.access,
            scope: value.scope,
        }
    }

    pub(crate) fn free_raw(value: BNStructureMember) {
        let _ = unsafe { Type::ref_from_raw(value.type_) };
        let _ = unsafe { BnString::from_raw(value.name) };
    }

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

impl CoreArrayProvider for StructureMember {
    type Raw = BNStructureMember;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for StructureMember {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeStructureMemberList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(raw)
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
    pub(crate) fn from_raw(value: &BNBaseStructure) -> Self {
        Self {
            ty: unsafe { NamedTypeReference::from_raw(value.type_) }.to_owned(),
            offset: value.offset,
            width: value.width,
        }
    }

    pub(crate) fn from_owned_raw(value: BNBaseStructure) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNBaseStructure {
        BNBaseStructure {
            type_: unsafe { Ref::into_raw(value.ty) }.handle,
            offset: value.offset,
            width: value.width,
        }
    }

    pub(crate) fn into_owned_raw(value: &Self) -> BNBaseStructure {
        BNBaseStructure {
            type_: value.ty.handle,
            offset: value.offset,
            width: value.width,
        }
    }

    pub(crate) fn free_raw(value: BNBaseStructure) {
        let _ = unsafe { NamedTypeReference::ref_from_raw(value.type_) };
    }

    pub fn new(ty: Ref<NamedTypeReference>, offset: u64, width: u64) -> Self {
        Self { ty, offset, width }
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
    pub fn new<T: Into<QualifiedName>>(type_class: NamedTypeReferenceClass, name: T) -> Ref<Self> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        let result = unsafe {
            Self::ref_from_raw(BNCreateNamedType(
                type_class,
                std::ptr::null(),
                &mut raw_name,
            ))
        };
        QualifiedName::free_raw(raw_name);
        result
    }

    /// Create an NTR to a type with an existing type id, which generally means it came directly
    /// from a BinaryView's types list and its id was looked up using `BinaryView::get_type_id`.
    /// You should not assign type ids yourself: if you use this to reference a type you are going
    /// to create but have not yet created, you may run into problems when giving your types to
    /// a BinaryView.
    pub fn new_with_id<T: Into<QualifiedName>, S: BnStrCompatible>(
        type_class: NamedTypeReferenceClass,
        type_id: S,
        name: T,
    ) -> Ref<Self> {
        let type_id = type_id.into_bytes_with_nul();
        let mut raw_name = QualifiedName::into_raw(name.into());
        let result = unsafe {
            Self::ref_from_raw(BNCreateNamedType(
                type_class,
                type_id.as_ref().as_ptr() as _,
                &mut raw_name,
            ))
        };
        QualifiedName::free_raw(raw_name);
        result
    }

    pub fn name(&self) -> QualifiedName {
        let raw_name = unsafe { BNGetTypeReferenceName(self.handle) };
        QualifiedName::from_owned_raw(raw_name)
    }

    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetTypeReferenceId(self.handle)) }
    }

    pub fn class(&self) -> NamedTypeReferenceClass {
        unsafe { BNGetTypeReferenceClass(self.handle) }
    }

    fn target_helper(&self, bv: &BinaryView, visited: &mut HashSet<BnString>) -> Option<Ref<Type>> {
        let ty = bv.type_by_id(self.id())?;
        match ty.type_class() {
            TypeClass::NamedTypeReferenceClass => {
                // Recurse into the NTR type until we get the target type.
                let ntr = ty.get_named_type_reference().unwrap();
                match visited.insert(ntr.id()) {
                    true => ntr.target_helper(bv, visited),
                    false => {
                        log::error!("Can't get target for recursively defined type!");
                        None
                    }
                }
            }
            // Found target type
            _ => Some(ty),
        }
    }

    /// Type referenced by this [`NamedTypeReference`].
    pub fn target(&self, bv: &BinaryView) -> Option<Ref<Type>> {
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

// TODO: Document usage, specifically how to make a qualified name and why it exists.
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub struct QualifiedName {
    // TODO: Make this Option<String> where default is "::".
    pub separator: String,
    pub items: Vec<String>,
}

impl QualifiedName {
    pub(crate) fn from_raw(value: &BNQualifiedName) -> Self {
        // TODO: This could be improved...
        let raw_names = unsafe { std::slice::from_raw_parts(value.name, value.nameCount) };
        let items = raw_names
            .iter()
            .filter_map(|&raw_name| raw_to_string(raw_name as *const _))
            .collect();
        let separator = raw_to_string(value.join).unwrap();
        Self { items, separator }
    }

    pub(crate) fn from_owned_raw(value: BNQualifiedName) -> Self {
        let result = Self::from_raw(&value);
        Self::free_raw(value);
        result
    }

    pub fn into_raw(value: Self) -> BNQualifiedName {
        let bn_join = BnString::new(&value.separator);
        BNQualifiedName {
            // NOTE: Leaking string list must be freed by core or us!
            name: strings_to_string_list(&value.items),
            // NOTE: Leaking string must be freed by core or us!
            join: BnString::into_raw(bn_join),
            nameCount: value.items.len(),
        }
    }

    pub(crate) fn free_raw(value: BNQualifiedName) {
        unsafe { BNFreeString(value.join) };
        unsafe { BNFreeStringList(value.name, value.nameCount) };
    }

    pub fn new(items: Vec<String>) -> Self {
        Self::new_with_separator(items, "::".to_string())
    }

    pub fn new_with_separator(items: Vec<String>, separator: String) -> Self {
        Self { items, separator }
    }

    pub fn with_item(&self, item: impl Into<String>) -> Self {
        let mut items = self.items.clone();
        items.push(item.into());
        Self::new_with_separator(items, self.separator.clone())
    }

    pub fn push(&mut self, item: String) {
        self.items.push(item);
    }

    pub fn pop(&mut self) -> Option<String> {
        self.items.pop()
    }

    pub fn insert(&mut self, index: usize, item: String) {
        if index <= self.items.len() {
            self.items.insert(index, item);
        }
    }

    pub fn split_last(&self) -> Option<(String, QualifiedName)> {
        self.items.split_last().map(|(a, b)| {
            (
                a.to_owned(),
                QualifiedName::new_with_separator(b.to_vec(), self.separator.clone()),
            )
        })
    }

    /// Replaces all occurrences of a substring with another string in all items of the `QualifiedName`
    /// and returns an owned version of the modified `QualifiedName`.
    ///
    /// # Example
    ///
    /// ```
    /// use binaryninja::types::QualifiedName;
    ///
    /// let qualified_name =
    ///     QualifiedName::new(vec!["my::namespace".to_string(), "mytype".to_string()]);
    /// let replaced = qualified_name.replace("my", "your");
    /// assert_eq!(
    ///     replaced.items,
    ///     vec!["your::namespace".to_string(), "yourtype".to_string()]
    /// );
    /// ```
    pub fn replace(&self, from: &str, to: &str) -> Self {
        Self {
            items: self
                .items
                .iter()
                .map(|item| item.replace(from, to))
                .collect(),
            separator: self.separator.clone(),
        }
    }

    /// Returns the last item, or `None` if it is empty.
    pub fn last(&self) -> Option<&String> {
        self.items.last()
    }

    /// Returns a mutable reference to the last item, or `None` if it is empty.
    pub fn last_mut(&mut self) -> Option<&mut String> {
        self.items.last_mut()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// A [`QualifiedName`] is empty if it has no items.
    ///
    /// If you want to know if the unqualified name is empty (i.e. no characters)
    /// you must first convert the qualified name to unqualified via the `to_string` method.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl From<String> for QualifiedName {
    fn from(value: String) -> Self {
        Self {
            items: vec![value],
            // TODO: See comment in struct def.
            separator: String::from("::"),
        }
    }
}

impl From<&str> for QualifiedName {
    fn from(value: &str) -> Self {
        Self::from(value.to_string())
    }
}

impl From<&String> for QualifiedName {
    fn from(value: &String) -> Self {
        Self::from(value.to_owned())
    }
}

impl From<Cow<'_, str>> for QualifiedName {
    fn from(value: Cow<'_, str>) -> Self {
        Self::from(value.to_string())
    }
}

impl From<Vec<String>> for QualifiedName {
    fn from(value: Vec<String>) -> Self {
        Self::new(value)
    }
}

impl From<Vec<&str>> for QualifiedName {
    fn from(value: Vec<&str>) -> Self {
        value
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .into()
    }
}

impl From<QualifiedName> for String {
    fn from(value: QualifiedName) -> Self {
        value.to_string()
    }
}

impl Index<usize> for QualifiedName {
    type Output = String;

    fn index(&self, index: usize) -> &Self::Output {
        &self.items[index]
    }
}

impl IndexMut<usize> for QualifiedName {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.items[index]
    }
}

impl Display for QualifiedName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.items.join(&self.separator))
    }
}

impl CoreArrayProvider for QualifiedName {
    type Raw = BNQualifiedName;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for QualifiedName {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeNameList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        QualifiedName::from_raw(raw)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct QualifiedNameAndType {
    pub name: QualifiedName,
    pub ty: Ref<Type>,
}

impl QualifiedNameAndType {
    pub(crate) fn from_raw(value: &BNQualifiedNameAndType) -> Self {
        Self {
            name: QualifiedName::from_raw(&value.name),
            ty: unsafe { Type::from_raw(value.type_).to_owned() },
        }
    }

    pub(crate) fn from_owned_raw(value: BNQualifiedNameAndType) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNQualifiedNameAndType {
        BNQualifiedNameAndType {
            name: QualifiedName::into_raw(value.name),
            type_: unsafe { Ref::into_raw(value.ty).handle },
        }
    }

    pub(crate) fn free_raw(value: BNQualifiedNameAndType) {
        QualifiedName::free_raw(value.name);
        let _ = unsafe { Type::ref_from_raw(value.type_) };
    }

    pub fn new(name: QualifiedName, ty: Ref<Type>) -> Self {
        Self { name, ty }
    }
}

impl<T> From<(T, Ref<Type>)> for QualifiedNameAndType
where
    T: Into<QualifiedName>,
{
    fn from(value: (T, Ref<Type>)) -> Self {
        Self {
            name: value.0.into(),
            ty: value.1,
        }
    }
}

impl<T> From<(T, &Type)> for QualifiedNameAndType
where
    T: Into<QualifiedName>,
{
    fn from(value: (T, &Type)) -> Self {
        let ty = value.1.to_owned();
        Self {
            name: value.0.into(),
            ty,
        }
    }
}

impl CoreArrayProvider for QualifiedNameAndType {
    type Raw = BNQualifiedNameAndType;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for QualifiedNameAndType {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeAndNameList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        QualifiedNameAndType::from_raw(raw)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct QualifiedNameTypeAndId {
    pub name: QualifiedName,
    pub ty: Ref<Type>,
    pub id: String,
}

impl QualifiedNameTypeAndId {
    pub(crate) fn from_raw(value: &BNQualifiedNameTypeAndId) -> Self {
        Self {
            name: QualifiedName::from_raw(&value.name),
            ty: unsafe { Type::from_raw(value.type_) }.to_owned(),
            id: raw_to_string(value.id).unwrap(),
        }
    }

    pub(crate) fn from_owned_raw(value: BNQualifiedNameTypeAndId) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNQualifiedNameTypeAndId {
        let bn_id = BnString::new(value.id);
        BNQualifiedNameTypeAndId {
            name: QualifiedName::into_raw(value.name),
            id: BnString::into_raw(bn_id),
            type_: unsafe { Ref::into_raw(value.ty) }.handle,
        }
    }

    pub(crate) fn free_raw(value: BNQualifiedNameTypeAndId) {
        QualifiedName::free_raw(value.name);
        let _ = unsafe { Type::ref_from_raw(value.type_) };
        let _ = unsafe { BnString::from_raw(value.id) };
    }
}

impl CoreArrayProvider for QualifiedNameTypeAndId {
    type Raw = BNQualifiedNameTypeAndId;
    type Context = ();
    type Wrapped<'a> = QualifiedNameTypeAndId;
}

unsafe impl CoreArrayProviderInner for QualifiedNameTypeAndId {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeIdList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        QualifiedNameTypeAndId::from_raw(raw)
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
    pub(crate) fn from_raw(value: &BNNameAndType) -> Self {
        Self {
            // TODO: I dislike using this function here.
            name: raw_to_string(value.name as *mut _).unwrap(),
            ty: Conf::new(
                unsafe { Type::from_raw(value.type_).to_owned() },
                value.typeConfidence,
            ),
        }
    }

    pub(crate) fn from_owned_raw(value: BNNameAndType) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNNameAndType {
        let bn_name = BnString::new(value.name);
        BNNameAndType {
            name: BnString::into_raw(bn_name),
            type_: unsafe { Ref::into_raw(value.ty.contents) }.handle,
            typeConfidence: value.ty.confidence,
        }
    }

    pub(crate) fn free_raw(value: BNNameAndType) {
        let _ = unsafe { BnString::from_raw(value.name) };
        let _ = unsafe { Type::ref_from_raw(value.type_) };
    }

    pub fn new(name: impl Into<String>, ty: Conf<Ref<Type>>) -> Self {
        Self {
            name: name.into(),
            ty,
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
        NameAndType::from_raw(raw)
    }
}
