// Copyright 2021-2026 Vector 35 Inc.
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
//! The model for representing types in Binary Ninja.
//!
//! [`Type`]'s are fundamental to analysis. With types, you can influence how decompilation resolves accesses,
//! renders data, and tell the analysis of properties such as volatility and constness.
//!
//! Types are typically stored within a [`BinaryView`], [`TypeArchive`] or a [`TypeLibrary`].
//!
//! Types can be created using the [`TypeBuilder`] or one of the convenience functions. Another way
//! to create a type is with a [`TypeParser`] if you have C type definitions.
//!
//! Some interfaces may expect to be passed a [`TypeContainer`] which itself does not store any type
//! information, rather a generic interface to query for types by name or by id.

pub mod archive;
pub mod container;
pub mod enumeration;
pub mod library;
pub mod parser;
pub mod printer;
pub mod structure;

use binaryninjacore_sys::*;

use crate::{
    architecture::Architecture,
    binary_view::{BinaryView, BinaryViewExt},
    calling_convention::CoreCallingConvention,
    rc::*,
    string::{BnString, IntoCStr},
};

use crate::confidence::{Conf, MAX_CONFIDENCE, MIN_CONFIDENCE};
use crate::string::raw_to_string;
use crate::variable::{Variable, VariableSourceType};
use std::num::NonZeroUsize;
use std::{
    collections::HashSet,
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    iter::IntoIterator,
};

pub use archive::{TypeArchive, TypeArchiveId, TypeArchiveSnapshotId};
pub use container::TypeContainer;
pub use enumeration::{Enumeration, EnumerationBuilder, EnumerationMember};
pub use library::TypeLibrary;
pub use parser::{
    CoreTypeParser, ParsedType, TypeParser, TypeParserError, TypeParserErrorSeverity,
    TypeParserResult,
};
pub use printer::{CoreTypePrinter, TypePrinter};
pub use structure::{
    BaseStructure, InheritedStructureMember, Structure, StructureBuilder, StructureMember,
};

#[deprecated(note = "Use crate::qualified_name::QualifiedName instead")]
// Re-export QualifiedName so that we do not break public consumers.
pub use crate::qualified_name::QualifiedName;

pub type StructureType = BNStructureVariant;
pub type ReferenceType = BNReferenceType;
pub type TypeClass = BNTypeClass;
pub type NamedTypeReferenceClass = BNNamedTypeReferenceClass;
pub type MemberAccess = BNMemberAccess;
pub type MemberScope = BNMemberScope;
pub type IntegerDisplayType = BNIntegerDisplayType;
pub type PointerBaseType = BNPointerBaseType;

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

    /// Turn the [`TypeBuilder`] into a [`Type`].
    pub fn finalize(&self) -> Ref<Type> {
        unsafe { Type::ref_from_raw(BNFinalizeTypeBuilder(self.handle)) }
    }

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

    /// Set the width of the type.
    ///
    /// Typically only done for named type references, which will not have their width set otherwise.
    pub fn set_width(&self, width: usize) -> &Self {
        unsafe { BNTypeBuilderSetWidth(self.handle, width) }
        self
    }

    /// Set the alignment of the type.
    ///
    /// Typically only done for named type references, which will not have their alignment set otherwise.
    pub fn set_alignment(&self, alignment: usize) -> &Self {
        unsafe { BNTypeBuilderSetAlignment(self.handle, alignment) }
        self
    }

    pub fn set_pointer_base(&self, base_type: PointerBaseType, base_offset: i64) -> &Self {
        unsafe { BNSetTypeBuilderPointerBase(self.handle, base_type, base_offset) }
        self
    }

    pub fn set_child_type<'a, T: Into<Conf<&'a Type>>>(&self, ty: T) -> &Self {
        let mut type_with_confidence = Conf::<&Type>::into_raw(ty.into());
        unsafe { BNTypeBuilderSetChildType(self.handle, &mut type_with_confidence) };
        self
    }

    /// This is an alias for [`Self::set_child_type`].
    pub fn set_target<'a, T: Into<Conf<&'a Type>>>(&self, ty: T) -> &Self {
        self.set_child_type(ty)
    }

    /// This is an alias for [`Self::set_child_type`].
    pub fn set_element_type<'a, T: Into<Conf<&'a Type>>>(&self, ty: T) -> &Self {
        self.set_child_type(ty)
    }

    /// This is an alias for [`Self::set_child_type`].
    pub fn set_return_value<'a, T: Into<Conf<&'a Type>>>(&self, ty: T) -> &Self {
        self.set_child_type(ty)
    }

    pub fn set_signed<T: Into<Conf<bool>>>(&self, value: T) -> &Self {
        let mut bool_with_confidence = value.into().into();
        unsafe { BNTypeBuilderSetSigned(self.handle, &mut bool_with_confidence) };
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

    pub fn pointer_base_type(&self) -> PointerBaseType {
        unsafe { BNTypeBuilderGetPointerBaseType(self.handle) }
    }

    pub fn pointer_base_offset(&self) -> i64 {
        unsafe { BNTypeBuilderGetPointerBaseOffset(self.handle) }
    }

    // TODO : This and properties
    // pub fn tokens(&self) -> ? {}

    /// Create a void [`TypeBuilder`]. Analogous to [`Type::void`].
    pub fn void() -> Self {
        unsafe { Self::from_raw(BNCreateVoidTypeBuilder()) }
    }

    /// Create a bool [`TypeBuilder`]. Analogous to [`Type::bool`].
    pub fn bool() -> Self {
        unsafe { Self::from_raw(BNCreateBoolTypeBuilder()) }
    }

    /// Create a signed one byte integer [`TypeBuilder`]. Analogous to [`Type::char`].
    pub fn char() -> Self {
        Self::int(1, true)
    }

    /// Create an integer [`TypeBuilder`] with the given width and signedness. Analogous to [`Type::int`].
    pub fn int(width: usize, is_signed: bool) -> Self {
        let mut is_signed = Conf::new(is_signed, MAX_CONFIDENCE).into();

        unsafe {
            Self::from_raw(BNCreateIntegerTypeBuilder(
                width,
                &mut is_signed,
                c"".as_ptr() as _,
            ))
        }
    }

    /// Create an integer [`TypeBuilder`] with the given width and signedness and an alternative name.
    /// Analogous to [`Type::named_int`].
    pub fn named_int(width: usize, is_signed: bool, alt_name: &str) -> Self {
        let mut is_signed = Conf::new(is_signed, MAX_CONFIDENCE).into();
        let alt_name = alt_name.to_cstr();

        unsafe {
            Self::from_raw(BNCreateIntegerTypeBuilder(
                width,
                &mut is_signed,
                alt_name.as_ref().as_ptr() as _,
            ))
        }
    }

    /// Create a float [`TypeBuilder`] with the given width. Analogous to [`Type::float`].
    pub fn float(width: usize) -> Self {
        unsafe { Self::from_raw(BNCreateFloatTypeBuilder(width, c"".as_ptr())) }
    }

    /// Create a float [`TypeBuilder`] with the given width and alternative name. Analogous to [`Type::named_float`].
    pub fn named_float(width: usize, alt_name: &str) -> Self {
        let alt_name = alt_name.to_cstr();
        unsafe { Self::from_raw(BNCreateFloatTypeBuilder(width, alt_name.as_ptr())) }
    }

    /// Create an array [`TypeBuilder`] with the given element type and count. Analogous to [`Type::array`].
    pub fn array<'a, T: Into<Conf<&'a Type>>>(ty: T, count: u64) -> Self {
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe { Self::from_raw(BNCreateArrayTypeBuilder(&owned_raw_ty, count)) }
    }

    /// Create an enumeration [`TypeBuilder`] with the given width and signedness. Analogous to [`Type::enumeration`].
    ///
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

    /// Create a structure [`TypeBuilder`]. Analogous to [`Type::structure`].
    pub fn structure(structure_type: &Structure) -> Self {
        unsafe { Self::from_raw(BNCreateStructureTypeBuilder(structure_type.handle)) }
    }

    /// Create a named type reference [`TypeBuilder`]. Analogous to [`Type::named_type`].
    pub fn named_type(type_reference: &NamedTypeReference) -> Self {
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

    /// Create a named type reference [`TypeBuilder`] from a type and name. Analogous to [`Type::named_type_from_type`].
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

    // TODO: Deprecate this for a FunctionBuilder (along with the Type variant?)
    /// NOTE: This is likely to be deprecated and removed in favor of a function type builder, please
    /// use [`Type::function`] where possible.
    pub fn function<'a, T: Into<Conf<&'a Type>>>(
        return_type: T,
        parameters: Vec<FunctionParameter>,
        variable_arguments: bool,
    ) -> Self {
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
            Self::from_raw(BNCreateFunctionTypeBuilder(
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
            ))
        };

        for raw_param in raw_parameters {
            FunctionParameter::free_raw(raw_param);
        }

        result
    }

    // TODO: Deprecate this for a FunctionBuilder (along with the Type variant?)
    /// NOTE: This is likely to be deprecated and removed in favor of a function type builder, please
    /// use [`Type::function_with_opts`] where possible.
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
    ) -> Self {
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
            Self::from_raw(BNCreateFunctionTypeBuilder(
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

    /// Create a pointer [`TypeBuilder`] with the given target type. Analogous to [`Type::pointer`].
    pub fn pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, ty: T) -> Self {
        Self::pointer_with_options(arch, ty, false, false, None)
    }

    /// Create a const pointer [`TypeBuilder`] with the given target type. Analogous to [`Type::const_pointer`].
    pub fn const_pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, ty: T) -> Self {
        Self::pointer_with_options(arch, ty, true, false, None)
    }

    pub fn pointer_with_options<'a, A: Architecture, T: Into<Conf<&'a Type>>>(
        arch: &A,
        ty: T,
        is_const: bool,
        is_volatile: bool,
        ref_type: Option<ReferenceType>,
    ) -> Self {
        let arch_ptr_size = arch.address_size();
        Self::pointer_of_width(ty, arch_ptr_size, is_const, is_volatile, ref_type)
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
}

impl Display for TypeBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", unsafe {
            BnString::into_string(BNGetTypeBuilderString(self.handle, std::ptr::null_mut()))
        })
    }
}

impl Drop for TypeBuilder {
    fn drop(&mut self) {
        unsafe { BNFreeTypeBuilder(self.handle) };
    }
}

/// The core model for types in Binary Ninja.
///
/// A [`Type`] is how we model the storage of a [`Variable`] or [`crate::variable::DataVariable`] as
/// well as propagate information such as the constness of a variable. Types are also used to declare
/// function signatures, such as the [`FunctionParameter`]'s and return type.
///
/// Types are immutable. To change a type, you must create a new one either using [`TypeBuilder`] or
/// one of the helper functions:
///
/// - [`Type::void`]
/// - [`Type::bool`]
/// - [`Type::char`]
/// - [`Type::wide_char`]
/// - [`Type::int`], [`Type::named_int`]
/// - [`Type::float`], [`Type::named_float`]
/// - [`Type::array`]
/// - [`Type::enumeration`]
/// - [`Type::structure`]
/// - [`Type::named_type`], [`Type::named_type_from_type`]
/// - [`Type::function`], [`Type::function_with_opts`]
/// - [`Type::pointer`], [`Type::const_pointer`], [`Type::pointer_of_width`], [`Type::pointer_with_options`]
///
/// # Example
///
/// As an example, defining a _named_ type within a [`BinaryView`]:
///
/// ```no_run
/// # use crate::binaryninja::binary_view::BinaryViewExt;
/// # use binaryninja::types::Type;
/// let bv = binaryninja::load("example.bin").unwrap();
/// let my_custom_type_1 = Type::named_int(5, false, "my_w");
/// let my_custom_type_2 = Type::int(5, false);
/// bv.define_user_type("int_1", &my_custom_type_1);
/// bv.define_user_type("int_2", &my_custom_type_2);
/// ```
#[repr(transparent)]
pub struct Type {
    pub handle: *mut BNType,
}

impl Type {
    pub unsafe fn from_raw(handle: *mut BNType) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub unsafe fn ref_from_raw(handle: *mut BNType) -> Ref<Self> {
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
    /// The size of the type in bytes.
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

    pub fn pointer_base_type(&self) -> BNPointerBaseType {
        unsafe { BNTypeGetPointerBaseType(self.handle) }
    }

    pub fn pointer_base_offset(&self) -> i64 {
        unsafe { BNTypeGetPointerBaseOffset(self.handle) }
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
        unsafe { Self::ref_from_raw(BNCreateWideCharType(width, c"".as_ptr())) }
    }

    pub fn int(width: usize, is_signed: bool) -> Ref<Self> {
        let mut is_signed = Conf::new(is_signed, MAX_CONFIDENCE).into();
        unsafe { Self::ref_from_raw(BNCreateIntegerType(width, &mut is_signed, c"".as_ptr())) }
    }

    pub fn named_int(width: usize, is_signed: bool, alt_name: &str) -> Ref<Self> {
        let mut is_signed = Conf::new(is_signed, MAX_CONFIDENCE).into();
        let alt_name = alt_name.to_cstr();

        unsafe {
            Self::ref_from_raw(BNCreateIntegerType(
                width,
                &mut is_signed,
                alt_name.as_ptr(),
            ))
        }
    }

    pub fn float(width: usize) -> Ref<Self> {
        unsafe { Self::ref_from_raw(BNCreateFloatType(width, c"".as_ptr())) }
    }

    pub fn named_float(width: usize, alt_name: &str) -> Ref<Self> {
        let alt_name = alt_name.to_cstr();
        unsafe { Self::ref_from_raw(BNCreateFloatType(width, alt_name.as_ptr())) }
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
            Self::ref_from_raw(BNCreateFunctionType(
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
            ))
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
        Self::pointer_with_options(arch, ty, false, false, None)
    }

    pub fn const_pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(
        arch: &A,
        ty: T,
    ) -> Ref<Self> {
        Self::pointer_with_options(arch, ty, true, false, None)
    }

    pub fn pointer_with_options<'a, A: Architecture, T: Into<Conf<&'a Type>>>(
        arch: &A,
        ty: T,
        is_const: bool,
        is_volatile: bool,
        ref_type: Option<ReferenceType>,
    ) -> Ref<Self> {
        let arch_pointer_size = arch.address_size();
        Self::pointer_of_width(ty, arch_pointer_size, is_const, is_volatile, ref_type)
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

    pub fn generate_auto_demangled_type_id<T: Into<QualifiedName>>(name: T) -> String {
        let mut raw_name = QualifiedName::into_raw(name.into());
        let type_id =
            unsafe { BnString::into_string(BNGenerateAutoDemangledTypeId(&mut raw_name)) };
        QualifiedName::free_raw(raw_name);
        type_id
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", unsafe {
            BnString::into_string(BNGetTypeString(
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
        // omit some fields for different type classes, what you really want to do is implement your
        // own formatter. This is supposed to represent the structure entirely, it's not supposed to be pretty!
        f.debug_struct("Type")
            .field("type_class", &self.type_class())
            .field("width", &self.width())
            .field("alignment", &self.alignment())
            .field("is_signed", &self.is_signed())
            .field("is_const", &self.is_const())
            .field("is_volatile", &self.is_volatile())
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

    #[allow(unused)]
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
        unsafe { BnString::free_raw(value.name) };
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
    pub fn new_with_id<T: Into<QualifiedName>>(
        type_class: NamedTypeReferenceClass,
        type_id: &str,
        name: T,
    ) -> Ref<Self> {
        let type_id = type_id.to_cstr();
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

    pub fn id(&self) -> String {
        unsafe { BnString::into_string(BNGetTypeReferenceId(self.handle)) }
    }

    pub fn class(&self) -> NamedTypeReferenceClass {
        unsafe { BNGetTypeReferenceClass(self.handle) }
    }

    fn target_helper(&self, bv: &BinaryView, visited: &mut HashSet<String>) -> Option<Ref<Type>> {
        let ty = bv.type_by_id(&self.id())?;
        match ty.type_class() {
            TypeClass::NamedTypeReferenceClass => {
                // Recurse into the NTR type until we get the target type.
                let ntr = ty
                    .get_named_type_reference()
                    .expect("NTR type class should always have a valid NTR");
                match visited.insert(ntr.id()) {
                    true => ntr.target_helper(bv, visited),
                    // Cyclic reference, return None.
                    false => None,
                }
            }
            // Found target type
            _ => Some(ty),
        }
    }

    /// Type referenced by this [`NamedTypeReference`].
    ///
    /// Will return `None` if the reference is cyclic, or the target type does not exist.
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

    #[allow(unused)]
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

    #[allow(unused)]
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
        unsafe { BnString::free_raw(value.name) };
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
