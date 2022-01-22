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

// TODO : More widely enforce the use of ref_from_raw vs just from_raw to simplify internal binding usage?  Perhaps remove from_raw functions?
// TODO : Add documentation and fix examples
// TODO : Test the get_enumeration and get_structure methods

use binaryninjacore_sys::*;
use std::{ffi::CStr, fmt, mem, ptr, result, slice};

use crate::architecture::{Architecture, CoreArchitecture};
use crate::callingconvention::CallingConvention;
use crate::string::{raw_to_string, BnStr, BnStrCompatible, BnString};

use crate::rc::*;

pub type Result<R> = result::Result<R, ()>;

pub type ReferenceType = BNReferenceType;
pub type TypeClass = BNTypeClass;
pub type NamedTypeReferenceClass = BNNamedTypeReferenceClass;
pub type MemberAccess = BNMemberAccess;
pub type MemberScope = BNMemberScope;

////////////////
// Confidence

pub struct Conf<T> {
    pub contents: T,
    pub confidence: u8,
}

impl<T> Conf<T> {
    pub fn new(contents: T, confidence: u8) -> Self {
        Self {
            contents,
            confidence,
        }
    }
}

#[inline]
pub fn min_confidence() -> u8 {
    u8::MIN
}

#[inline]
pub fn max_confidence() -> u8 {
    u8::MAX
}

impl<T: Clone> Clone for Conf<T> {
    fn clone(&self) -> Self {
        Self {
            contents: self.contents.clone(),
            confidence: self.confidence,
        }
    }
}

impl<T> From<T> for Conf<T> {
    fn from(contents: T) -> Self {
        Self::new(contents, max_confidence())
    }
}

impl From<BNTypeWithConfidence> for Conf<Ref<Type>> {
    fn from(type_with_confidence: BNTypeWithConfidence) -> Self {
        Self::new(
            unsafe { Type::ref_from_raw(type_with_confidence.type_) },
            type_with_confidence.confidence,
        )
    }
}

impl From<BNBoolWithConfidence> for Conf<bool> {
    fn from(bool_with_confidence: BNBoolWithConfidence) -> Self {
        Self::new(bool_with_confidence.value, bool_with_confidence.confidence)
    }
}

impl From<BNCallingConventionWithConfidence> for Conf<Ref<CallingConvention<CoreArchitecture>>> {
    fn from(cc_with_confidence: BNCallingConventionWithConfidence) -> Self {
        Self::new(
            unsafe {
                CallingConvention::ref_from_raw(
                    cc_with_confidence.convention,
                    CoreArchitecture::from_raw(BNGetCallingConventionArchitecture(
                        cc_with_confidence.convention,
                    )),
                )
            },
            cc_with_confidence.confidence,
        )
    }
}

impl From<BNOffsetWithConfidence> for Conf<i64> {
    fn from(offset_with_confidence: BNOffsetWithConfidence) -> Self {
        Self::new(
            offset_with_confidence.value,
            offset_with_confidence.confidence,
        )
    }
}

impl Into<BNTypeWithConfidence> for Conf<&Type> {
    fn into(self) -> BNTypeWithConfidence {
        BNTypeWithConfidence {
            type_: self.contents.handle,
            confidence: self.confidence,
        }
    }
}

impl Into<BNTypeWithConfidence> for &Conf<&Type> {
    fn into(self) -> BNTypeWithConfidence {
        BNTypeWithConfidence {
            type_: self.contents.handle,
            confidence: self.confidence,
        }
    }
}

impl Into<BNBoolWithConfidence> for Conf<bool> {
    fn into(self) -> BNBoolWithConfidence {
        BNBoolWithConfidence {
            value: self.contents,
            confidence: self.confidence,
        }
    }
}

impl<A: Architecture> Into<BNCallingConventionWithConfidence> for Conf<&CallingConvention<A>> {
    fn into(self) -> BNCallingConventionWithConfidence {
        BNCallingConventionWithConfidence {
            convention: self.contents.handle,
            confidence: self.confidence,
        }
    }
}

impl Into<BNOffsetWithConfidence> for Conf<i64> {
    fn into(self) -> BNOffsetWithConfidence {
        BNOffsetWithConfidence {
            value: self.contents,
            confidence: self.confidence,
        }
    }
}

//////////////////
// Type Builder

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

    // Settable properties

    pub fn set_const<'a, T: Into<Conf<bool>>>(&'a mut self, value: T) -> &'a mut Self {
        let mut bool_with_confidence = value.into().into();
        unsafe { BNTypeBuilderSetConst(self.handle, &mut bool_with_confidence) };
        self
    }

    pub fn set_volatile<'a, T: Into<Conf<bool>>>(&'a mut self, value: T) -> &'a mut Self {
        let mut bool_with_confidence = value.into().into();
        unsafe { BNTypeBuilderSetVolatile(self.handle, &mut bool_with_confidence) };
        self
    }

    // Chainable terminal

    pub fn finalize(&self) -> Ref<Type> {
        unsafe { Type::ref_from_raw(BNFinalizeTypeBuilder(self.handle)) }
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

    pub fn target(&self) -> Result<Conf<Ref<Type>>> {
        let raw_target = unsafe { BNGetTypeBuilderChildType(self.handle) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn element_type(&self) -> Result<Conf<Ref<Type>>> {
        let raw_target = unsafe { BNGetTypeBuilderChildType(self.handle) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn return_value(&self) -> Result<Conf<Ref<Type>>> {
        let raw_target = unsafe { BNGetTypeBuilderChildType(self.handle) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn calling_convention(&self) -> Result<Conf<Ref<CallingConvention<CoreArchitecture>>>> {
        let convention_confidence = unsafe { BNGetTypeBuilderCallingConvention(self.handle) };
        if convention_confidence.convention.is_null() {
            Err(())
        } else {
            Ok(convention_confidence.into())
        }
    }

    // pub fn parameters(&self) -> ? {}

    pub fn has_variable_arguments(&self) -> Conf<bool> {
        unsafe { BNTypeBuilderHasVariableArguments(self.handle).into() }
    }

    pub fn get_structure(&self) -> Result<Ref<Structure>> {
        let result = unsafe { BNGetTypeBuilderStructure(self.handle) };
        if result.is_null() {
            Err(())
        } else {
            Ok(unsafe { Structure::ref_from_raw(result) })
        }
    }

    pub fn get_enumeration(&self) -> Result<Ref<Enumeration>> {
        let result = unsafe { BNGetTypeBuilderEnumeration(self.handle) };
        if result.is_null() {
            Err(())
        } else {
            Ok(Enumeration::ref_from_raw(result))
        }
    }

    pub fn get_named_type_reference(&self) -> Result<NamedTypeReference> {
        let result = unsafe { BNGetTypeBuilderNamedTypeReference(self.handle) };
        if result.is_null() {
            Err(())
        } else {
            Ok(unsafe { NamedTypeReference::from_raw(result) })
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
        let mut is_signed = Conf::new(is_signed, max_confidence()).into();

        unsafe {
            Self::from_raw(BNCreateIntegerTypeBuilder(
                width,
                &mut is_signed,
                BnString::new("").as_ptr() as *mut _,
            ))
        }
    }

    pub fn named_int<S: BnStrCompatible>(width: usize, is_signed: bool, alt_name: S) -> Self {
        let mut is_signed = Conf::new(is_signed, max_confidence()).into();
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.as_bytes_with_nul(); // This segfaulted once, so the above version is there if we need to change to it, but in theory this is copied into a `const string&` on the C++ side; I'm just not 100% confident that a constant reference copies data

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
        let alt_name = alt_name.as_bytes_with_nul(); // See same line in `named_int` above

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

    pub fn enumeration(enumeration: &Enumeration, width: usize, is_signed: Conf<bool>) -> Self {
        //! The C/C++ APIs require an associated architecture, but in the core we only query the default_int_size if the given width is 0
        //! For simplicity's sake, that convention isn't followed and you can query the default_int_size from an arch, if you have it, if you need to

        unsafe {
            // TODO : This is _extremely fragile_, we should change the internals of BNCreateEnumerationTypeBuilder instead of doing this
            let mut fake_arch: BNArchitecture = mem::zeroed();
            Self::from_raw(BNCreateEnumerationTypeBuilder(
                &mut fake_arch,
                enumeration.handle,
                width,
                &mut is_signed.into(),
            ))
        }
    }

    pub fn structure(structure_type: &Structure) -> Self {
        unsafe { Self::from_raw(BNCreateStructureTypeBuilder(structure_type.handle)) }
    }

    pub fn named_type(type_reference: NamedTypeReference) -> Self {
        let mut is_const = Conf::new(false, min_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();
        unsafe {
            Self::from_raw(BNCreateNamedTypeReferenceBuilder(
                type_reference.handle,
                0,
                1,
                &mut is_const,
                &mut is_volatile
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
        let mut is_const = Conf::new(false, min_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();

        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilder(
                arch.as_ref().0,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            ))
        }
    }

    pub fn const_pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, t: T) -> Self {
        let mut is_const = Conf::new(true, max_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();

        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilder(
                arch.as_ref().0,
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
        let mut is_const = Conf::new(is_const, max_confidence()).into();
        let mut is_volatile = Conf::new(is_volatile, max_confidence()).into();

        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilderOfWidth(
                size,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or_else(|| ReferenceType::PointerReferenceType),
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
        let mut is_const = Conf::new(is_const, max_confidence()).into();
        let mut is_volatile = Conf::new(is_volatile, max_confidence()).into();
        unsafe {
            Self::from_raw(BNCreatePointerTypeBuilder(
                arch.as_ref().0,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or_else(|| ReferenceType::PointerReferenceType),
            ))
        }
    }
}

impl fmt::Display for TypeBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", unsafe {
            BnString::from_raw(BNGetTypeBuilderString(self.handle, ptr::null_mut()))
        })
    }
}

impl Drop for TypeBuilder {
    fn drop(&mut self) {
        unsafe { BNFreeTypeBuilder(self.handle) };
    }
}

//////////
// Type

#[derive(PartialEq, Eq, Hash)]
pub struct Type {
    pub(crate) handle: *mut BNType,
}

impl Type {
    //!   use binaryninja::types::Type;
    //!   let bv = unsafe { BinaryView::from_raw(view) };
    //!   let my_custom_type_1 = Self::named_int(5, false, "my_w");
    //!   let my_custom_type_2 = Self::int(5, false);
    //!   bv.define_user_type("int_1", &my_custom_type_1);
    //!   bv.define_user_type("int_2", &my_custom_type_2);

    unsafe fn from_raw(handle: *mut BNType) -> Self {
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

    // Readable properties

    pub fn type_class(&self) -> TypeClass {
        unsafe { BNGetTypeClass(self.handle) }
    }

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

    pub fn target(&self) -> Result<Conf<Ref<Type>>> {
        let raw_target = unsafe { BNGetChildType(self.handle) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn element_type(&self) -> Result<Conf<Ref<Type>>> {
        let raw_target = unsafe { BNGetChildType(self.handle) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn return_value(&self) -> Result<Conf<Ref<Type>>> {
        let raw_target = unsafe { BNGetChildType(self.handle) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn calling_convention(&self) -> Result<Conf<Ref<CallingConvention<CoreArchitecture>>>> {
        let convention_confidence = unsafe { BNGetTypeCallingConvention(self.handle) };
        if convention_confidence.convention.is_null() {
            Err(())
        } else {
            Ok(convention_confidence.into())
        }
    }

    // TODO : This
    // pub fn parameters(&self) -> ? {}

    pub fn has_variable_arguments(&self) -> Conf<bool> {
        unsafe { BNTypeHasVariableArguments(self.handle).into() }
    }

    pub fn can_return(&self) -> Conf<bool> {
        unsafe { BNFunctionTypeCanReturn(self.handle).into() }
    }

    pub fn get_structure(&self) -> Result<Ref<Structure>> {
        let result = unsafe { BNGetTypeStructure(self.handle) };
        if result.is_null() {
            Err(())
        } else {
            Ok(unsafe { Structure::ref_from_raw(result) })
        }
    }

    pub fn get_enumeration(&self) -> Result<Ref<Enumeration>> {
        let result = unsafe { BNGetTypeEnumeration(self.handle) };
        if result.is_null() {
            Err(())
        } else {
            Ok(Enumeration::ref_from_raw(result))
        }
    }

    pub fn get_named_type_reference(&self) -> Result<NamedTypeReference> {
        let result = unsafe { BNGetTypeNamedTypeReference(self.handle) };
        if result.is_null() {
            Err(())
        } else {
            Ok(unsafe { NamedTypeReference::from_raw(result) })
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

    pub fn registered_name(&self) -> Result<NamedTypeReference> {
        let result = unsafe { BNGetRegisteredTypeName(self.handle) };
        if result.is_null() {
            Err(())
        } else {
            Ok(unsafe { NamedTypeReference::from_raw(result) })
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

    pub fn int(width: usize, is_signed: bool) -> Ref<Self> {
        let mut is_signed = Conf::new(is_signed, max_confidence()).into();
        unsafe {
            Self::ref_from_raw(BNCreateIntegerType(
                width,
                &mut is_signed,
                BnString::new("").as_ptr() as *mut _,
            ))
        }
    }

    pub fn named_int<S: BnStrCompatible>(width: usize, is_signed: bool, alt_name: S) -> Ref<Self> {
        let mut is_signed = Conf::new(is_signed, max_confidence()).into();
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.as_bytes_with_nul(); // This segfaulted once, so the above version is there if we need to change to it, but in theory this is copied into a `const string&` on the C++ side; I'm just not 100% confident that a constant reference copies data

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
        let alt_name = alt_name.as_bytes_with_nul(); // See same line in `named_int` above

        unsafe { Self::ref_from_raw(BNCreateFloatType(width, alt_name.as_ref().as_ptr() as _)) }
    }

    pub fn array<'a, T: Into<Conf<&'a Type>>>(t: T, count: u64) -> Ref<Self> {
        unsafe { Self::ref_from_raw(BNCreateArrayType(&t.into().into(), count)) }
    }

    pub fn enumeration(enumeration: &Enumeration, width: usize, is_signed: Conf<bool>) -> Ref<Self> {
        //! The C/C++ APIs require an associated architecture, but in the core we only query the default_int_size if the given width is 0
        //! For simplicity's sake, that convention isn't followed and you can query the default_int_size from an arch, if you have it, if you need to
        unsafe {
            // TODO : This is _extremely fragile_, we should change the internals of BNCreateEnumerationType instead of doing this
            let mut fake_arch: BNArchitecture = mem::zeroed();
            Self::ref_from_raw(BNCreateEnumerationType(
                &mut fake_arch,
                enumeration.handle,
                width,
                &mut is_signed.into(),
            ))
        }
    }

    pub fn structure(structure: &Structure) -> Ref<Self> {
        unsafe { Self::ref_from_raw(BNCreateStructureType(structure.handle)) }
    }

    pub fn named_type(type_reference: &NamedTypeReference) -> Ref<Self> {
        let mut is_const = Conf::new(false, min_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();
        unsafe { Self::ref_from_raw(BNCreateNamedTypeReference(type_reference.handle,
                0,
                1,
                &mut is_const,
                &mut is_volatile)) }
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

    pub fn function<'a, S: BnStrCompatible + Copy, T: Into<Conf<&'a Type>>>(
        return_type: T,
        parameters: &[FunctionParameter<S>],
        variable_arguments: bool,
    ) -> Ref<Self> {
        let mut return_type = return_type.into().into();
        let mut variable_arguments = Conf::new(variable_arguments, max_confidence()).into();

        let mut raw_calling_convention: BNCallingConventionWithConfidence =
            BNCallingConventionWithConfidence {
                convention: ptr::null_mut(),
                confidence: min_confidence(),
            };

        let mut stack_adjust = Conf::<i64>::new(0, min_confidence()).into();
        let mut raw_parameters = Vec::<BNFunctionParameter>::with_capacity(parameters.len());
        let mut parameter_name_references = Vec::with_capacity(parameters.len());
        for parameter in parameters {
            let raw_name = parameter.name.clone().as_bytes_with_nul();
            let location = match &parameter.location {
                Some(location) => location.into_raw(),
                None => unsafe { mem::zeroed() },
            };

            raw_parameters.push(BNFunctionParameter {
                name: raw_name.as_ref().as_ptr() as *mut _,
                type_: parameter.t.contents.handle,
                typeConfidence: parameter.t.confidence,
                defaultLocation: parameter.location.is_none(),
                location,
            });
            parameter_name_references.push(raw_name);
        }

        unsafe {
            Self::ref_from_raw(BNCreateFunctionType(
                &mut return_type,
                &mut raw_calling_convention,
                raw_parameters.as_mut_ptr(),
                raw_parameters.len(),
                &mut variable_arguments,
                &mut stack_adjust,
            ))
        }
    }

    pub fn function_with_options<
        'a,
        A: Architecture,
        S: BnStrCompatible + Copy,
        T: Into<Conf<&'a Type>>,
    >(
        return_type: T,
        parameters: &[FunctionParameter<S>],
        variable_arguments: bool,
        calling_convention: Conf<&CallingConvention<A>>,
        stack_adjust: Conf<i64>,
    ) -> Ref<Self> {
        let mut return_type = return_type.into().into();
        let mut variable_arguments = Conf::new(variable_arguments, max_confidence()).into();
        let mut raw_calling_convention: BNCallingConventionWithConfidence =
            calling_convention.into();
        let mut stack_adjust = stack_adjust.into();

        let mut raw_parameters = Vec::<BNFunctionParameter>::with_capacity(parameters.len());
        let mut parameter_name_references = Vec::with_capacity(parameters.len());
        for parameter in parameters {
            let raw_name = parameter.name.as_bytes_with_nul();
            let location = match &parameter.location {
                Some(location) => location.into_raw(),
                None => unsafe { mem::zeroed() },
            };

            raw_parameters.push(BNFunctionParameter {
                name: raw_name.as_ref().as_ptr() as *mut _,
                type_: parameter.t.contents.handle,
                typeConfidence: parameter.t.confidence,
                defaultLocation: parameter.location.is_none(),
                location,
            });
            parameter_name_references.push(raw_name);
        }

        unsafe {
            Self::ref_from_raw(BNCreateFunctionType(
                &mut return_type,
                &mut raw_calling_convention,
                raw_parameters.as_mut_ptr(),
                raw_parameters.len(),
                &mut variable_arguments,
                &mut stack_adjust,
            ))
        }
    }

    pub fn pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, t: T) -> Ref<Self> {
        let mut is_const = Conf::new(false, min_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();
        unsafe {
            Self::ref_from_raw(BNCreatePointerType(
                arch.as_ref().0,
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
        let mut is_const = Conf::new(true, max_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();
        unsafe {
            Self::ref_from_raw(BNCreatePointerType(
                arch.as_ref().0,
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
        let mut is_const = Conf::new(is_const, max_confidence()).into();
        let mut is_volatile = Conf::new(is_volatile, max_confidence()).into();
        unsafe {
            Self::ref_from_raw(BNCreatePointerTypeOfWidth(
                size,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or_else(|| ReferenceType::PointerReferenceType),
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
        let mut is_const = Conf::new(is_const, max_confidence()).into();
        let mut is_volatile = Conf::new(is_volatile, max_confidence()).into();
        unsafe {
            Self::ref_from_raw(BNCreatePointerType(
                arch.as_ref().0,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or_else(|| ReferenceType::PointerReferenceType),
            ))
        }
    }

    pub fn generate_auto_demangled_type_id<'a, S: BnStrCompatible>(name: S) -> &'a BnStr {
        let mut name = QualifiedName::from(name);
        unsafe { BnStr::from_raw(BNGenerateAutoDemangledTypeId(&mut name.0)) }
    }

    pub fn demangle_gnu3<Mangled: BnStrCompatible>(
        arch: &CoreArchitecture,
        mangled_name: Mangled,
        simplify: bool,
    ) -> Result<(Option<Type>, Vec<String>)> {
        let mangled_name_bwn = mangled_name.as_bytes_with_nul();
        let mangled_name_ptr = mangled_name_bwn.as_ref();
        unsafe {
            let mut out_type: *mut BNType = std::mem::zeroed();
            let mut out_name: *mut *mut std::os::raw::c_char = std::mem::zeroed();
            let mut out_size: usize = 0;
            let mut names = Vec::new();
            let res = BNDemangleGNU3(
                arch.0,
                mangled_name_ptr.as_ptr() as *const i8,
                &mut out_type,
                &mut out_name,
                &mut out_size,
                simplify,
            );

            if !res || out_size == 0 {
                let cstr = match CStr::from_bytes_with_nul(mangled_name_ptr) {
                    Ok(cstr) => cstr,
                    Err(_) => {
                        log::error!("demangle_gnu3: failed to parse mangled name");
                        return Err(());
                    }
                };
                return Ok((None, vec![cstr.to_string_lossy().into_owned()]));
            }

            let out_type = match out_type.is_null() {
                true => {
                    log::debug!("demangle_gnu3: out_type is NULL");
                    None
                }
                false => Some(Type::from_raw(out_type)),
            };

            if out_name.is_null() {
                log::error!("v: out_name is NULL");
                return Err(());
            }

            for offset in 0..out_size {
                let array_entry = *out_name.add(offset);
                if !array_entry.is_null() {
                    let cstr = CStr::from_ptr(array_entry as *const i8);
                    names.push(cstr.to_string_lossy().into_owned())
                } else {
                    log::debug!("demangle_gnu3: array_entry is null; skipping");
                }
            }

            BNFreeDemangledName(&mut out_name, out_size);

            Ok((out_type, names))
        }
    }

    pub fn demangle_ms<Mangled: BnStrCompatible>(
        arch: &CoreArchitecture,
        mangled_name: Mangled,
        simplify: bool,
    ) -> Result<(Option<Type>, Vec<String>)> {
        let mangled_name_bwn = mangled_name.as_bytes_with_nul();
        let mangled_name_ptr = mangled_name_bwn.as_ref();
        unsafe {
            let mut out_type: *mut BNType = std::mem::zeroed();
            let mut out_name: *mut *mut std::os::raw::c_char = std::mem::zeroed();
            let mut out_size: usize = 0;
            let mut names = Vec::new();
            let res = BNDemangleMS(
                arch.0,
                mangled_name_ptr.as_ptr() as *const i8,
                &mut out_type,
                &mut out_name,
                &mut out_size,
                simplify,
            );

            if !res || out_size == 0 {
                let cstr = match CStr::from_bytes_with_nul(mangled_name_ptr) {
                    Ok(cstr) => cstr,
                    Err(_) => {
                        log::error!("demangle_ms: failed to parse mangled name");
                        return Err(());
                    }
                };
                return Ok((None, vec![cstr.to_string_lossy().into_owned()]));
            }

            let out_type = match out_type.is_null() {
                true => {
                    log::debug!("demangle_ms: out_type is NULL");
                    None
                }
                false => Some(Type::from_raw(out_type)),
            };

            if out_name.is_null() {
                log::error!("demangle_ms: out_name is NULL");
                return Err(());
            }

            for offset in 0..out_size {
                let array_entry = *out_name.add(offset);
                if !array_entry.is_null() {
                    let cstr = CStr::from_ptr(array_entry as *const i8);
                    names.push(cstr.to_string_lossy().into_owned())
                } else {
                    log::debug!("demangle_ms: array_entry is null; skipping");
                }
            }

            BNFreeDemangledName(&mut out_name, out_size);

            Ok((out_type, names))
        }
    }
}

impl From<&TypeBuilder> for Ref<Type> {
    fn from(builder: &TypeBuilder) -> Self {
        unsafe { Type::ref_from_raw(BNFinalizeTypeBuilder(builder.handle)) }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", unsafe {
            BnString::from_raw(BNGetTypeString(self.handle, ptr::null_mut()))
        })
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

///////////////////////
// FunctionParameter

pub struct FunctionParameter<S: BnStrCompatible> {
    pub t: Conf<Ref<Type>>,
    pub name: S,
    pub location: Option<Variable>,
}

impl<'a, S: BnStrCompatible> FunctionParameter<S> {
    pub fn new<T: Into<Conf<Ref<Type>>>>(t: T, name: S, location: Option<Variable>) -> Self {
        Self {
            t: t.into(),
            name,
            location,
        }
    }
}

//////////////
// Variable

pub struct Variable {
    pub t: BNVariableSourceType,
    pub index: u32,
    pub storage: i64,
}

impl Variable {
    pub fn new(t: BNVariableSourceType, index: u32, storage: i64) -> Self {
        Self { t, index, storage }
    }

    // pub(crate) unsafe fn from_raw(var: *mut BNVariable) -> Self {
    //     Self {
    //         t: (*var).type_,
    //         index: (*var).index,
    //         storage: (*var).storage,
    //     }
    // }

    pub(crate) fn into_raw(&self) -> BNVariable {
        BNVariable {
            type_: self.t,
            index: self.index,
            storage: self.storage,
        }
    }
}

////////////////////////
// EnumerationBuilder

pub struct EnumerationMember {
    pub name: BnString,
    pub value: u64,
    pub is_default: bool,
}

impl EnumerationMember {
    pub fn new<S: BnStrCompatible>(name: S, value: u64, is_default: bool) -> Self {
        Self {
            name: BnString::new(name),
            value,
            is_default,
        }
    }

    pub(crate) unsafe fn from_raw(handle: *mut BNEnumerationMember) -> Self {
        Self {
            name: BnString::new(BnStr::from_raw((*handle).name)),
            value: (*handle).value,
            is_default: (*handle).isDefault,
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
        Enumeration::new(self)
    }

    pub fn append<'a, S: BnStrCompatible>(&'a mut self, name: S) -> &'a mut Self {
        let name = name.as_bytes_with_nul();
        unsafe {
            BNAddEnumerationBuilderMember(self.handle, name.as_ref().as_ptr() as _);
        }
        self
    }

    pub fn insert<'a, S: BnStrCompatible>(&'a mut self, name: S, value: u64) -> &'a mut Self {
        let name = name.as_bytes_with_nul();
        unsafe {
            BNAddEnumerationBuilderMemberWithValue(self.handle, name.as_ref().as_ptr() as _, value);
        }
        self
    }

    pub fn replace<'a, S: BnStrCompatible>(
        &'a mut self,
        id: usize,
        name: S,
        value: u64,
    ) -> &'a mut Self {
        let name = name.as_bytes_with_nul();
        unsafe {
            BNReplaceEnumerationBuilderMember(self.handle, id, name.as_ref().as_ptr() as _, value);
        }
        self
    }

    pub fn remove<'a>(&'a mut self, id: usize) -> &'a mut Self {
        unsafe {
            BNRemoveEnumerationBuilderMember(self.handle, id);
        }

        self
    }

    pub fn members(&self) -> Vec<EnumerationMember> {
        unsafe {
            let mut count: usize = mem::zeroed();
            let members_raw = BNGetEnumerationBuilderMembers(self.handle, &mut count);
            let members: &[*mut BNEnumerationMember] =
                slice::from_raw_parts(members_raw as *mut _, count);

            let result = (0..count)
                .map(|i| EnumerationMember::from_raw(members[i]))
                .collect();

            BNFreeEnumerationMemberList(members_raw, count);

            result
        }
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

/////////////////
// Enumeration

#[derive(PartialEq, Eq, Hash)]
pub struct Enumeration {
    pub(crate) handle: *mut BNEnumeration,
}

impl Enumeration {
    pub fn new(builder: &EnumerationBuilder) -> Ref<Self> {
        unsafe {
            let handle = BNFinalizeEnumerationBuilder(builder.handle);
            Ref::new(Self { handle })
        }
    }

    fn from_raw(handle: *mut BNEnumeration) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) fn ref_from_raw(handle: *mut BNEnumeration) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        unsafe { Ref::new(Self { handle }) }
    }

    pub fn members(&self) -> Vec<EnumerationMember> {
        unsafe {
            let mut count: usize = mem::zeroed();
            let members_raw = BNGetEnumerationMembers(self.handle, &mut count);
            let members: &[*mut BNEnumerationMember] =
                slice::from_raw_parts(members_raw as *mut _, count);

            let result = (0..count)
                .map(|i| EnumerationMember::from_raw(members[i]))
                .collect();

            BNFreeEnumerationMemberList(members_raw, count);

            result
        }
    }
}

impl From<&EnumerationBuilder> for Ref<Enumeration> {
    fn from(builder: &EnumerationBuilder) -> Self {
        Enumeration::new(builder)
    }
}

unsafe impl RefCountable for Enumeration {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self::from_raw(BNNewEnumerationReference(handle.handle)))
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

//////////////////////
// StructureBuilder

pub type StructureType = BNStructureVariant;

#[derive(PartialEq, Eq, Hash)]
pub struct StructureBuilder {
    pub(crate) handle: *mut BNStructureBuilder,
}

impl StructureBuilder {
    //! // Includes
    //! use binaryninja::types::{Structure, Type};

    //! // Define struct, set size (in bytes)
    //! let mut my_custom_struct = Structure::new();BnStr::from_raw(raw.name)
    //! let field_1 = Self::named_int(5, false, "my_weird_int_type");
    //! let field_2 = Self::int(4, false);
    //! let field_3 = Self::int(8, false);

    //! // Assign those fields
    //! my_custom_struct.append(&field_1, "field_4");
    //! my_custom_struct.insert(&field_1, "field_1", 0);
    //! my_custom_struct.insert(&field_2, "field_2", 5);
    //! my_custom_struct.insert(&field_3, "field_3", 9);

    //! // Convert structure to type
    //! let my_custom_structure_type = Self::structure_type(&mut my_custom_struct);

    //! // Add the struct to the binary view to use in analysis
    //! let bv = unsafe { BinaryView::from_raw(view) };
    //! bv.define_user_type("my_custom_struct", &my_custom_structure_type);

    pub fn new() -> Self {
        Self {
            handle: unsafe { BNCreateStructureBuilder() },
        }
    }

    pub(crate) unsafe fn from_raw(handle: *mut BNStructureBuilder) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    // Chainable terminal
    pub fn finalize(&self) -> Ref<Structure> {
        Structure::new(self)
    }

    // Chainable builders/setters

    pub fn set_width<'a>(&'a mut self, width: u64) -> &'a mut Self {
        unsafe {
            BNSetStructureBuilderWidth(self.handle, width);
        }

        self
    }

    pub fn append<'a, 'b, S: BnStrCompatible, T: Into<Conf<&'b Type>>>(
        &'a mut self,
        t: T,
        name: S,
        access: MemberAccess,
        scope: MemberScope,
    ) -> &'a mut Self {
        let name = name.as_bytes_with_nul();
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

    pub fn insert<'a, 'b, S: BnStrCompatible, T: Into<Conf<&'b Type>>>(
        &'a mut self,
        t: T,
        name: S,
        offset: u64,
        overwrite_existing: bool,
        access: MemberAccess,
        scope: MemberScope,
    ) -> &'a mut Self {
        let name = name.as_bytes_with_nul();
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

    pub fn set_structure_type<'a>(&'a mut self, t: StructureType) -> &'a Self {
        unsafe { BNSetStructureBuilderType(self.handle, t) };
        self
    }

    // Getters

    pub fn width(&self) -> u64 {
        unsafe { BNGetStructureBuilderWidth(self.handle) }
    }

    pub fn structure_type(&self) -> StructureType {
        unsafe { BNGetStructureBuilderType(self.handle) }
    }

    // TODO : The other methods in the python version (alignment, packed, type, members, remove, replace, etc)
}

impl From<&Structure> for StructureBuilder {
    fn from(structure: &Structure) -> StructureBuilder {
        unsafe { Self::from_raw(BNCreateStructureBuilderFromStructure(structure.handle)) }
    }
}

impl Drop for StructureBuilder {
    fn drop(&mut self) {
        unsafe { BNFreeStructureBuilder(self.handle) };
    }
}

///////////////
// Structure

#[derive(PartialEq, Eq, Hash)]
pub struct Structure {
    pub(crate) handle: *mut BNStructure,
}

impl Structure {
    //! // Includes
    //! use binaryninja::types::{Structure, Type};

    //! // Define struct, set size (in bytes)
    //! let mut my_custom_struct = Structure::new();
    //! my_custom_struct.set_width(17);

    //! // Create some fields for the struct
    //! let field_1 = Self::named_int(5, false, "my_weird_int_type");
    //! let field_2 = Self::int(4, false);
    //! let field_3 = Self::int(8, false);

    //! // Assign those fields
    //! my_custom_struct.append(&field_1, "field_4");
    //! my_custom_struct.insert(&field_1, "field_1", 0);
    //! my_custom_struct.insert(&field_2, "field_2", 5);
    //! my_custom_struct.insert(&field_3, "field_3", 9);

    //! // Convert structure to type
    //! let my_custom_structure_type = Self::structure_type(&mut my_custom_struct);

    //! // Add the struct to the binary view to use in analysis
    //! let bv = unsafe { BinaryView::from_raw(view) };
    //! bv.define_user_type("my_custom_struct", &my_custom_structure_type);

    pub fn new(builder: &StructureBuilder) -> Ref<Self> {
        unsafe {
            let handle = BNFinalizeStructureBuilder(builder.handle);
            Ref::new(Self { handle })
        }
    }

    unsafe fn from_raw(handle: *mut BNStructure) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNStructure) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn width(&self) -> u64 {
        unsafe { BNGetStructureWidth(self.handle) }
    }

    pub fn structure_type(&self) -> StructureType {
        unsafe { BNGetStructureType(self.handle) }
    }

    // TODO : The other methods in the python version (alignment, packed, type, members, remove, replace, etc)
}

impl From<&StructureBuilder> for Ref<Structure> {
    fn from(builder: &StructureBuilder) -> Self {
        Structure::new(builder)
    }
}

unsafe impl RefCountable for Structure {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self::from_raw(BNNewStructureReference(handle.handle)))
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

// TODO : Use
// #[derive(PartialEq, Eq, Hash)]
// pub struct StructureMember {
//     pub(crate) handle: *mut BNStructureMember,
// }

// impl StructureMember {
//     // pub fn new() -> Self {}
// }

////////////////////////
// NamedTypeReference

#[derive(PartialEq, Eq, Hash)]
pub struct NamedTypeReference {
    pub(crate) handle: *mut BNNamedTypeReference,
}

impl NamedTypeReference {
    pub(crate) unsafe fn from_raw(handle: *mut BNNamedTypeReference) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    pub fn new<S: BnStrCompatible>(
        type_class: NamedTypeReferenceClass,
        type_id: S,
        mut name: QualifiedName,
    ) -> Self {
        let type_id = type_id.as_bytes_with_nul();

        Self {
            handle: unsafe {
                BNCreateNamedType(type_class, type_id.as_ref().as_ptr() as _, &mut name.0)
            },
        }
    }
}

///////////////////
// QualifiedName

#[repr(transparent)]
pub struct QualifiedName(pub(crate) BNQualifiedName);

impl QualifiedName {
    // TODO : I think this is bad
    pub fn string(&self) -> String {
        use std::ffi::CStr;

        unsafe {
            slice::from_raw_parts(self.0.name, self.0.nameCount)
                .iter()
                .map(|c| CStr::from_ptr(*c).to_string_lossy())
                .collect::<Vec<_>>()
                .join("::")
        }
    }
}

impl<S: BnStrCompatible> From<S> for QualifiedName {
    fn from(name: S) -> Self {
        let join = BnString::new("::");
        let name = name.as_bytes_with_nul();
        let mut list = vec![name.as_ref().as_ptr() as *const _];

        QualifiedName(BNQualifiedName {
            name: unsafe { BNAllocStringList(list.as_mut_ptr(), 1) },
            join: join.into_raw(),
            nameCount: 1,
        })
    }
}

impl Drop for QualifiedName {
    fn drop(&mut self) {
        unsafe {
            BNFreeQualifiedName(&mut self.0);
        }
    }
}

//////////////////////////
// QualifiedNameAndType

#[repr(transparent)]
pub struct QualifiedNameAndType(pub(crate) BNQualifiedNameAndType);

impl QualifiedNameAndType {
    pub fn name(&self) -> &QualifiedName {
        unsafe { mem::transmute(&self.0.name) }
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

unsafe impl CoreOwnedArrayProvider for QualifiedNameAndType {
    type Raw = BNQualifiedNameAndType;
    type Context = ();

    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeList(raw, count);
    }
}

unsafe impl<'a> CoreOwnedArrayWrapper<'a> for QualifiedNameAndType {
    type Wrapped = &'a QualifiedNameAndType;

    unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
        mem::transmute(raw)
    }
}

//////////////////////////
// QualifiedNameAndType

pub struct NameAndType<S: BnStrCompatible> {
    pub name: S,
    t: Conf<Ref<Type>>,
}

impl NameAndType<String> {
    pub(crate) fn from_raw(raw: &BNNameAndType) -> Self {
        Self::new(
            raw_to_string(raw.name).unwrap(),
            unsafe { &Type::ref_from_raw(raw.type_) },
            raw.typeConfidence,
        )
    }
}

impl<S: BnStrCompatible> NameAndType<S> {
    pub fn new(name: S, t: &Ref<Type>, confidence: u8) -> Self {
        Self {
            name: name,
            t: Conf::new(t.clone(), confidence),
        }
    }

    pub fn type_with_confidence(&self) -> Conf<Ref<Type>> {
        self.t.clone()
    }
}

unsafe impl<S: BnStrCompatible> CoreOwnedArrayProvider for NameAndType<S> {
    type Raw = BNNameAndType;
    type Context = ();

    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeNameAndTypeList(raw, count);
    }
}

unsafe impl<'a, S: 'a + BnStrCompatible> CoreOwnedArrayWrapper<'a> for NameAndType<S> {
    type Wrapped = &'a NameAndType<S>;

    unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
        mem::transmute(raw)
    }
}

//////////////////
// DataVariable

pub struct DataVariable {
    pub address: u64,
    pub t: Conf<Ref<Type>>,
    pub auto_discovered: bool,
}

// impl DataVariable {
//     pub(crate) fn from_raw(var: &BNDataVariable) -> Self {
//         Self {
//             address: var.address,
//             t: Conf::new(unsafe { Type::ref_from_raw(var.type_) }, var.typeConfidence),
//             auto_discovered: var.autoDiscovered,
//         }
//     }
// }

impl DataVariable {
    pub fn type_with_confidence(&self) -> Conf<Ref<Type>> {
        Conf::new(self.t.contents.clone(), self.t.confidence)
    }
}

unsafe impl CoreOwnedArrayProvider for DataVariable {
    type Raw = BNDataVariable;
    type Context = ();

    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeDataVariables(raw, count);
    }
}

unsafe impl<'a> CoreOwnedArrayWrapper<'a> for DataVariable {
    type Wrapped = &'a DataVariable;

    unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
        mem::transmute(raw)
    }
}

/////////////////////////
// DataVariableAndName

pub struct DataVariableAndName<S: BnStrCompatible> {
    pub address: u64,
    pub t: Conf<Ref<Type>>,
    pub auto_discovered: bool,
    pub name: S,
}

impl DataVariableAndName<String> {
    pub(crate) fn from_raw(var: &BNDataVariableAndName) -> Self {
        Self {
            address: var.address,
            t: Conf::new(unsafe { Type::ref_from_raw(var.type_) }, var.typeConfidence),
            auto_discovered: var.autoDiscovered,
            name: raw_to_string(var.name).unwrap(),
        }
    }
}

impl<S: BnStrCompatible> DataVariableAndName<S> {
    pub fn type_with_confidence(&self) -> Conf<Ref<Type>> {
        Conf::new(self.t.contents.clone(), self.t.confidence)
    }
}

// unsafe impl<S: BnStrCompatible> CoreOwnedArrayProvider for DataVariableAndName<S> {
//     type Raw = BNDataVariableAndName;
//     type Context = ();

//     unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
//         BNFreeDataVariablesAndName(raw, count);
//     }
// }

// unsafe impl<'a, S: 'a + BnStrCompatible> CoreOwnedArrayWrapper<'a> for DataVariableAndName<S> {
//     type Wrapped = &'a DataVariableAndName<S>;

//     unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
//         mem::transmute(raw)
//     }
// }
