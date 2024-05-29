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
    function::Function,
    mlil::MediumLevelILFunction,
    rc::*,
    string::{raw_to_string, BnStrCompatible, BnString},
    symbol::Symbol,
};

use lazy_static::lazy_static;
use std::{
    borrow::{Borrow, Cow},
    collections::{HashMap, HashSet},
    ffi::CStr,
    fmt::{self, Debug, Display, Formatter},
    hash::{Hash, Hasher},
    iter::IntoIterator,
    mem::{self, ManuallyDrop},
    ops::Range,
    os::raw::c_char,
    ptr::{self, NonNull},
    result, slice,
    sync::Mutex,
};

pub type Result<R> = result::Result<R, ()>;

pub type ReferenceType = BNReferenceType;
pub type TypeClass = BNTypeClass;
pub type NamedTypeReferenceClass = BNNamedTypeReferenceClass;
pub type MemberAccess = BNMemberAccess;
pub type MemberScope = BNMemberScope;
pub type ILBranchDependence = BNILBranchDependence;
pub type DataFlowQueryOption = BNDataFlowQueryOption;

////////////////
// Confidence

/// Compatible with the `BNType*WithConfidence` types
pub struct Conf<T> {
    pub contents: T,
    pub confidence: u8,
}

pub trait ConfMergable<T, O> {
    type Result;
    /// Merge two confidence types' values depending on whichever has higher confidence
    /// In the event of a tie, the LHS (caller's) value is used.
    fn merge(self, other: O) -> Self::Result;
}

impl<T> Conf<T> {
    pub fn new(contents: T, confidence: u8) -> Self {
        Self {
            contents,
            confidence,
        }
    }

    pub fn map<U, F>(self, f: F) -> Conf<U>
    where
        F: FnOnce(T) -> U,
    {
        Conf::new(f(self.contents), self.confidence)
    }

    pub fn as_ref(&self) -> Conf<&T> {
        let Conf {
            ref contents,
            confidence,
        } = *self;
        Conf::new(contents, confidence)
    }
}

/// Returns best value or LHS on tie
///
/// `Conf<T>` + `Conf<T>` → `Conf<T>`
impl<T> ConfMergable<T, Conf<T>> for Conf<T> {
    type Result = Conf<T>;
    fn merge(self, other: Conf<T>) -> Conf<T> {
        if other.confidence > self.confidence {
            other
        } else {
            self
        }
    }
}

/// Returns LHS if RHS is None
///
/// `Conf<T>` + `Option<Conf<T>>` → `Conf<T>`
impl<T> ConfMergable<T, Option<Conf<T>>> for Conf<T> {
    type Result = Conf<T>;
    fn merge(self, other: Option<Conf<T>>) -> Conf<T> {
        match other {
            Some(c @ Conf { confidence, .. }) if confidence > self.confidence => c,
            _ => self,
        }
    }
}

/// Returns RHS if LHS is None
///
/// `Option<Conf<T>>` + `Conf<T>` → `Conf<T>`
impl<T> ConfMergable<T, Conf<T>> for Option<Conf<T>> {
    type Result = Conf<T>;
    fn merge(self, other: Conf<T>) -> Conf<T> {
        match self {
            Some(c @ Conf { confidence, .. }) if confidence >= other.confidence => c,
            _ => other,
        }
    }
}

/// Returns best non-None value or None
///
/// `Option<Conf<T>>` + `Option<Conf<T>>` → `Option<Conf<T>>`
impl<T> ConfMergable<T, Option<Conf<T>>> for Option<Conf<T>> {
    type Result = Option<Conf<T>>;
    fn merge(self, other: Option<Conf<T>>) -> Option<Conf<T>> {
        match (self, other) {
            (
                Some(
                    this @ Conf {
                        confidence: this_confidence,
                        ..
                    },
                ),
                Some(
                    other @ Conf {
                        confidence: other_confidence,
                        ..
                    },
                ),
            ) => {
                if this_confidence >= other_confidence {
                    Some(this)
                } else {
                    Some(other)
                }
            }
            (None, Some(c)) => Some(c),
            (Some(c), None) => Some(c),
            (None, None) => None,
        }
    }
}

impl<T: Debug> Debug for Conf<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} ({} confidence)", self.contents, self.confidence)
    }
}

impl<T: Display> Display for Conf<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} confidence)", self.contents, self.confidence)
    }
}

impl<'a, T> From<&'a Conf<T>> for Conf<&'a T> {
    fn from(c: &'a Conf<T>) -> Self {
        Conf::new(&c.contents, c.confidence)
    }
}

impl<'a, T: RefCountable> From<&'a Conf<Ref<T>>> for Conf<&'a T> {
    fn from(c: &'a Conf<Ref<T>>) -> Self {
        Conf::new(c.contents.as_ref(), c.confidence)
    }
}

impl<'a, T: RefCountable> From<&'a Ref<T>> for Conf<&'a T> {
    fn from(r: &'a Ref<T>) -> Self {
        r.as_ref().into()
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

impl<T: Copy> Copy for Conf<T> {}

impl<T> From<T> for Conf<T> {
    fn from(contents: T) -> Self {
        Self::new(contents, max_confidence())
    }
}

impl From<BNTypeWithConfidence> for Conf<Type> {
    fn from(type_with_confidence: BNTypeWithConfidence) -> Self {
        Self::new(
            unsafe { Type::from_raw(NonNull::new(type_with_confidence.type_).unwrap()) },
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

impl From<Conf<&Type>> for BNTypeWithConfidence {
    fn from(conf: Conf<&Type>) -> Self {
        Self {
            type_: conf.contents.as_raw(),
            confidence: conf.confidence,
        }
    }
}

impl From<Conf<bool>> for BNBoolWithConfidence {
    fn from(conf: Conf<bool>) -> Self {
        Self {
            value: conf.contents,
            confidence: conf.confidence,
        }
    }
}

impl<A: Architecture> From<Conf<&CallingConvention<A>>> for BNCallingConventionWithConfidence {
    fn from(conf: Conf<&CallingConvention<A>>) -> Self {
        Self {
            convention: conf.contents.handle,
            confidence: conf.confidence,
        }
    }
}

impl From<Conf<i64>> for BNOffsetWithConfidence {
    fn from(conf: Conf<i64>) -> Self {
        Self {
            value: conf.contents,
            confidence: conf.confidence,
        }
    }
}

//////////////////
// Type Builder

#[repr(transparent)]
#[derive(PartialEq, Eq, Hash)]
pub struct TypeBuilder {
    pub(crate) handle: NonNull<BNTypeBuilder>,
}

impl TypeBuilder {
    pub fn new(t: &Type) -> Self {
        unsafe { Self::from_raw(NonNull::new(BNCreateTypeBuilderFromType(t.as_raw())).unwrap()) }
    }

    pub(crate) unsafe fn from_raw(handle: NonNull<BNTypeBuilder>) -> Self {
        Self { handle }
    }

    pub(crate) fn as_raw(&self) -> &mut BNTypeBuilder {
        unsafe { &mut (*self.handle.as_ptr()) }
    }

    // Chainable terminal
    pub fn finalize(&self) -> Type {
        unsafe { Type::from_raw(NonNull::new(BNFinalizeTypeBuilder(self.as_raw())).unwrap()) }
    }

    // Settable properties

    pub fn set_can_return<T: Into<Conf<bool>>>(&self, value: T) -> &Self {
        let mut bool_with_confidence = value.into().into();
        unsafe { BNSetFunctionTypeBuilderCanReturn(self.as_raw(), &mut bool_with_confidence) };
        self
    }

    pub fn set_pure<T: Into<Conf<bool>>>(&self, value: T) -> &Self {
        let mut bool_with_confidence = value.into().into();
        unsafe { BNSetTypeBuilderPure(self.as_raw(), &mut bool_with_confidence) };
        self
    }

    pub fn set_const<T: Into<Conf<bool>>>(&self, value: T) -> &Self {
        let mut bool_with_confidence = value.into().into();
        unsafe { BNTypeBuilderSetConst(self.as_raw(), &mut bool_with_confidence) };
        self
    }

    pub fn set_volatile<T: Into<Conf<bool>>>(&self, value: T) -> &Self {
        let mut bool_with_confidence = value.into().into();
        unsafe { BNTypeBuilderSetVolatile(self.as_raw(), &mut bool_with_confidence) };
        self
    }

    // Readable properties

    pub fn type_class(&self) -> TypeClass {
        unsafe { BNGetTypeBuilderClass(self.as_raw()) }
    }

    pub fn width(&self) -> u64 {
        unsafe { BNGetTypeBuilderWidth(self.as_raw()) }
    }

    pub fn alignment(&self) -> usize {
        unsafe { BNGetTypeBuilderAlignment(self.as_raw()) }
    }

    pub fn is_signed(&self) -> Conf<bool> {
        unsafe { BNIsTypeBuilderSigned(self.as_raw()).into() }
    }

    pub fn is_const(&self) -> Conf<bool> {
        unsafe { BNIsTypeBuilderConst(self.as_raw()).into() }
    }

    pub fn is_volatile(&self) -> Conf<bool> {
        unsafe { BNIsTypeBuilderVolatile(self.as_raw()).into() }
    }

    pub fn is_floating_point(&self) -> bool {
        unsafe { BNIsTypeBuilderFloatingPoint(self.as_raw()) }
    }

    pub fn target(&self) -> Result<Conf<Type>> {
        let raw_target = unsafe { BNGetTypeBuilderChildType(self.as_raw()) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn element_type(&self) -> Result<Conf<Type>> {
        let raw_target = unsafe { BNGetTypeBuilderChildType(self.as_raw()) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn return_value(&self) -> Result<Conf<Type>> {
        let raw_target = unsafe { BNGetTypeBuilderChildType(self.as_raw()) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn calling_convention(&self) -> Result<Conf<Ref<CallingConvention<CoreArchitecture>>>> {
        let convention_confidence = unsafe { BNGetTypeBuilderCallingConvention(self.as_raw()) };
        if convention_confidence.convention.is_null() {
            Err(())
        } else {
            Ok(convention_confidence.into())
        }
    }

    pub fn parameters(&self) -> Result<Array<FunctionParameter>> {
        unsafe {
            let mut count = 0;
            let parameters_raw = BNGetTypeBuilderParameters(self.as_raw(), &mut count);
            if parameters_raw.is_null() {
                Err(())
            } else {
                Ok(Array::new(parameters_raw, count, ()))
            }
        }
    }

    pub fn has_variable_arguments(&self) -> Conf<bool> {
        unsafe { BNTypeBuilderHasVariableArguments(self.as_raw()).into() }
    }

    pub fn can_return(&self) -> Conf<bool> {
        unsafe { BNFunctionTypeBuilderCanReturn(self.as_raw()).into() }
    }

    pub fn pure(&self) -> Conf<bool> {
        unsafe { BNIsTypeBuilderPure(self.as_raw()).into() }
    }

    pub fn get_structure(&self) -> Result<Structure> {
        NonNull::new(unsafe { BNGetTypeBuilderStructure(self.as_raw()) })
            .map(|result| unsafe { Structure::from_raw(result) })
            .ok_or(())
    }

    pub fn get_enumeration(&self) -> Result<Enumeration> {
        NonNull::new(unsafe { BNGetTypeBuilderEnumeration(self.as_raw()) })
            .map(|result| unsafe { Enumeration::from_raw(result) })
            .ok_or(())
    }

    pub fn get_named_type_reference(&self) -> Result<Ref<NamedTypeReference>> {
        let result = unsafe { BNGetTypeBuilderNamedTypeReference(self.as_raw()) };
        if result.is_null() {
            Err(())
        } else {
            Ok(unsafe { NamedTypeReference::ref_from_raw(result) })
        }
    }

    pub fn count(&self) -> u64 {
        unsafe { BNGetTypeBuilderElementCount(self.as_raw()) }
    }

    pub fn offset(&self) -> u64 {
        unsafe { BNGetTypeBuilderOffset(self.as_raw()) }
    }

    pub fn stack_adjustment(&self) -> Conf<i64> {
        unsafe { BNGetTypeBuilderStackAdjustment(self.as_raw()).into() }
    }

    // TODO : This and properties
    // pub fn tokens(&self) -> ? {}

    pub fn void() -> Self {
        unsafe { Self::from_raw(NonNull::new(BNCreateVoidTypeBuilder()).unwrap()) }
    }

    pub fn bool() -> Self {
        unsafe { Self::from_raw(NonNull::new(BNCreateBoolTypeBuilder()).unwrap()) }
    }

    pub fn char() -> Self {
        Self::int(1, true)
    }

    pub fn int(width: usize, is_signed: bool) -> Self {
        let mut is_signed = Conf::new(is_signed, max_confidence()).into();

        unsafe {
            let result = BNCreateIntegerTypeBuilder(
                width,
                &mut is_signed,
                BnString::new("").as_ptr() as *mut _,
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn named_int<S: BnStrCompatible>(width: usize, is_signed: bool, alt_name: S) -> Self {
        let mut is_signed = Conf::new(is_signed, max_confidence()).into();
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.into_bytes_with_nul(); // This segfaulted once, so the above version is there if we need to change to it, but in theory this is copied into a `const string&` on the C++ side; I'm just not 100% confident that a constant reference copies data

        unsafe {
            let result =
                BNCreateIntegerTypeBuilder(width, &mut is_signed, alt_name.as_ref().as_ptr() as _);
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn float(width: usize) -> Self {
        unsafe {
            let result = BNCreateFloatTypeBuilder(width, BnString::new("").as_ptr() as *mut _);
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn named_float<S: BnStrCompatible>(width: usize, alt_name: S) -> Self {
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.into_bytes_with_nul(); // See same line in `named_int` above

        unsafe {
            let result = BNCreateFloatTypeBuilder(width, alt_name.as_ref().as_ptr() as _);
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn array<'a, T: Into<Conf<&'a Type>>>(t: T, count: u64) -> Self {
        unsafe {
            Self::from_raw(NonNull::new(BNCreateArrayTypeBuilder(&t.into().into(), count)).unwrap())
        }
    }

    /// The C/C++ APIs require an associated architecture, but in the core we only query the default_int_size if the given width is 0
    /// For simplicity's sake, that convention isn't followed and you can query the default_int_size from an arch, if you have it, if you need to
    pub fn enumeration<T: Into<Conf<bool>>>(
        enumeration: &Enumeration,
        width: usize,
        is_signed: T,
    ) -> Self {
        unsafe {
            // TODO : This is _extremely fragile_, we should change the internals of BNCreateEnumerationTypeBuilder instead of doing this
            let mut fake_arch: BNArchitecture = mem::zeroed();
            let result = BNCreateEnumerationTypeBuilder(
                &mut fake_arch,
                enumeration.as_raw(),
                width,
                &mut is_signed.into().into(),
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn structure(structure_type: &Structure) -> Self {
        unsafe {
            Self::from_raw(
                NonNull::new(BNCreateStructureTypeBuilder(structure_type.as_raw())).unwrap(),
            )
        }
    }

    pub fn named_type(type_reference: NamedTypeReference) -> Self {
        let mut is_const = Conf::new(false, min_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();
        unsafe {
            let result = BNCreateNamedTypeReferenceBuilder(
                type_reference.handle,
                0,
                1,
                &mut is_const,
                &mut is_volatile,
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn named_type_from_type<S: BnStrCompatible>(name: S, t: &Type) -> Self {
        let mut name = QualifiedName::from(name);

        unsafe {
            let result = BNCreateNamedTypeReferenceBuilderFromTypeAndId(
                BnString::new("").as_ptr() as *mut _,
                &mut name.0,
                t.as_raw(),
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    // TODO : BNCreateFunctionTypeBuilder

    pub fn pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, t: T) -> Self {
        let mut is_const = Conf::new(false, min_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();

        unsafe {
            let result = BNCreatePointerTypeBuilder(
                arch.as_ref().0,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn const_pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, t: T) -> Self {
        let mut is_const = Conf::new(true, max_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();

        unsafe {
            let result = BNCreatePointerTypeBuilder(
                arch.as_ref().0,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            );
            Self::from_raw(NonNull::new(result).unwrap())
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
            let result = BNCreatePointerTypeBuilderOfWidth(
                size,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or(ReferenceType::PointerReferenceType),
            );
            Self::from_raw(NonNull::new(result).unwrap())
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
            let result = BNCreatePointerTypeBuilder(
                arch.as_ref().0,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or(ReferenceType::PointerReferenceType),
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }
}

impl fmt::Display for TypeBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", unsafe {
            BnString::from_raw(
                NonNull::new(BNGetTypeBuilderString(self.as_raw(), ptr::null_mut())).unwrap(),
            )
        })
    }
}

impl Drop for TypeBuilder {
    fn drop(&mut self) {
        unsafe { BNFreeTypeBuilder(self.as_raw()) };
    }
}

//////////
// Type

#[repr(transparent)]
pub struct Type {
    handle: NonNull<BNType>,
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
    pub(crate) unsafe fn from_raw(handle: NonNull<BNType>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNType) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    pub(crate) fn as_raw(&self) -> &mut BNType {
        unsafe { &mut (*self.handle.as_ptr()) }
    }

    pub(crate) fn into_raw(self) -> *mut BNType {
        ManuallyDrop::new(self).handle.as_ptr()
    }

    pub fn to_builder(&self) -> TypeBuilder {
        TypeBuilder::new(self)
    }

    // Readable properties

    pub fn type_class(&self) -> TypeClass {
        unsafe { BNGetTypeClass(self.as_raw()) }
    }

    pub fn width(&self) -> u64 {
        unsafe { BNGetTypeWidth(self.as_raw()) }
    }

    pub fn alignment(&self) -> usize {
        unsafe { BNGetTypeAlignment(self.as_raw()) }
    }

    pub fn is_signed(&self) -> Conf<bool> {
        unsafe { BNIsTypeSigned(self.as_raw()).into() }
    }

    pub fn is_const(&self) -> Conf<bool> {
        unsafe { BNIsTypeConst(self.as_raw()).into() }
    }

    pub fn is_volatile(&self) -> Conf<bool> {
        unsafe { BNIsTypeVolatile(self.as_raw()).into() }
    }

    pub fn is_floating_point(&self) -> bool {
        unsafe { BNIsTypeFloatingPoint(self.as_raw()) }
    }

    pub fn target(&self) -> Result<Conf<Type>> {
        let raw_target = unsafe { BNGetChildType(self.as_raw()) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn element_type(&self) -> Result<Conf<Type>> {
        let raw_target = unsafe { BNGetChildType(self.as_raw()) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn return_value(&self) -> Result<Conf<Type>> {
        let raw_target = unsafe { BNGetChildType(self.as_raw()) };
        if raw_target.type_.is_null() {
            Err(())
        } else {
            Ok(raw_target.into())
        }
    }

    pub fn calling_convention(&self) -> Result<Conf<Ref<CallingConvention<CoreArchitecture>>>> {
        let convention_confidence = unsafe { BNGetTypeCallingConvention(self.as_raw()) };
        if convention_confidence.convention.is_null() {
            Err(())
        } else {
            Ok(convention_confidence.into())
        }
    }

    pub fn parameters(&self) -> Result<Array<FunctionParameter>> {
        unsafe {
            let mut count = 0;
            let parameters_raw: *mut BNFunctionParameter =
                BNGetTypeParameters(self.as_raw(), &mut count);
            if parameters_raw.is_null() {
                Err(())
            } else {
                Ok(Array::new(parameters_raw, count, ()))
            }
        }
    }

    pub fn has_variable_arguments(&self) -> Conf<bool> {
        unsafe { BNTypeHasVariableArguments(self.as_raw()).into() }
    }

    pub fn can_return(&self) -> Conf<bool> {
        unsafe { BNFunctionTypeCanReturn(self.as_raw()).into() }
    }

    pub fn pure(&self) -> Conf<bool> {
        unsafe { BNIsTypePure(self.as_raw()).into() }
    }

    pub fn get_structure(&self) -> Result<Structure> {
        NonNull::new(unsafe { BNGetTypeStructure(self.as_raw()) })
            .map(|result| unsafe { Structure::from_raw(result) })
            .ok_or(())
    }

    pub fn get_enumeration(&self) -> Result<Enumeration> {
        NonNull::new(unsafe { BNGetTypeEnumeration(self.as_raw()) })
            .map(|result| unsafe { Enumeration::from_raw(result) })
            .ok_or(())
    }

    pub fn get_named_type_reference(&self) -> Result<Ref<NamedTypeReference>> {
        let result = unsafe { BNGetTypeNamedTypeReference(self.as_raw()) };
        if result.is_null() {
            Err(())
        } else {
            Ok(unsafe { NamedTypeReference::ref_from_raw(result) })
        }
    }

    pub fn count(&self) -> u64 {
        unsafe { BNGetTypeElementCount(self.as_raw()) }
    }

    pub fn offset(&self) -> u64 {
        unsafe { BNGetTypeOffset(self.as_raw()) }
    }

    pub fn stack_adjustment(&self) -> Conf<i64> {
        unsafe { BNGetTypeStackAdjustment(self.as_raw()).into() }
    }

    pub fn registered_name(&self) -> Result<Ref<NamedTypeReference>> {
        let result = unsafe { BNGetRegisteredTypeName(self.as_raw()) };
        if result.is_null() {
            Err(())
        } else {
            Ok(unsafe { NamedTypeReference::ref_from_raw(result) })
        }
    }

    // TODO : This and properties
    // pub fn tokens(&self) -> ? {}

    pub fn void() -> Self {
        unsafe { Self::from_raw(NonNull::new(BNCreateVoidType()).unwrap()) }
    }

    pub fn bool() -> Self {
        unsafe { Self::from_raw(NonNull::new(BNCreateBoolType()).unwrap()) }
    }

    pub fn char() -> Self {
        Self::int(1, true)
    }

    pub fn wide_char(width: usize) -> Self {
        unsafe {
            let result = BNCreateWideCharType(width, BnString::new("").as_ptr() as *mut _);
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn int(width: usize, is_signed: bool) -> Self {
        let mut is_signed = Conf::new(is_signed, max_confidence()).into();
        unsafe {
            let result =
                BNCreateIntegerType(width, &mut is_signed, BnString::new("").as_ptr() as *mut _);
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn named_int<S: BnStrCompatible>(width: usize, is_signed: bool, alt_name: S) -> Self {
        let mut is_signed = Conf::new(is_signed, max_confidence()).into();
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.into_bytes_with_nul(); // This segfaulted once, so the above version is there if we need to change to it, but in theory this is copied into a `const string&` on the C++ side; I'm just not 100% confident that a constant reference copies data

        unsafe {
            let result =
                BNCreateIntegerType(width, &mut is_signed, alt_name.as_ref().as_ptr() as _);
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn float(width: usize) -> Self {
        unsafe {
            let result = BNCreateFloatType(width, BnString::new("").as_ptr() as *mut _);
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn named_float<S: BnStrCompatible>(width: usize, alt_name: S) -> Self {
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.into_bytes_with_nul(); // See same line in `named_int` above

        unsafe {
            Self::from_raw(
                NonNull::new(BNCreateFloatType(width, alt_name.as_ref().as_ptr() as _)).unwrap(),
            )
        }
    }

    pub fn array<'a, T: Into<Conf<&'a Type>>>(t: T, count: u64) -> Self {
        unsafe { Self::from_raw(NonNull::new(BNCreateArrayType(&t.into().into(), count)).unwrap()) }
    }

    /// The C/C++ APIs require an associated architecture, but in the core we only query the default_int_size if the given width is 0
    ///
    /// For simplicity's sake, that convention isn't followed and you can query the default_int_size from an arch, if you have it, if you need to
    pub fn enumeration<T: Into<Conf<bool>>>(
        enumeration: &Enumeration,
        width: usize,
        is_signed: T,
    ) -> Self {
        unsafe {
            // TODO : This is _extremely fragile_, we should change the internals of BNCreateEnumerationType instead of doing this
            let mut fake_arch: BNArchitecture = mem::zeroed();
            let result = BNCreateEnumerationType(
                &mut fake_arch,
                enumeration.as_raw(),
                width,
                &mut is_signed.into().into(),
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn structure(structure: &Structure) -> Self {
        unsafe { Self::from_raw(NonNull::new(BNCreateStructureType(structure.as_raw())).unwrap()) }
    }

    pub fn named_type(type_reference: &NamedTypeReference) -> Self {
        let mut is_const = Conf::new(false, min_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();
        unsafe {
            let result = BNCreateNamedTypeReference(
                type_reference.handle,
                0,
                1,
                &mut is_const,
                &mut is_volatile,
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn named_type_from_type<S: BnStrCompatible>(name: S, t: &Type) -> Self {
        let mut name = QualifiedName::from(name);

        unsafe {
            let result = BNCreateNamedTypeReferenceFromTypeAndId(
                BnString::new("").as_ptr() as *mut _,
                &mut name.0,
                t.as_raw(),
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn function<'a, T: Into<Conf<&'a Type>>>(
        return_type: T,
        parameters: &[FunctionParameter],
        variable_arguments: bool,
    ) -> Self {
        let mut return_type = return_type.into().into();
        let mut variable_arguments = Conf::new(variable_arguments, max_confidence()).into();
        let mut can_return = Conf::new(true, min_confidence()).into();
        let mut pure = Conf::new(false, min_confidence()).into();

        let mut raw_calling_convention: BNCallingConventionWithConfidence =
            BNCallingConventionWithConfidence {
                convention: ptr::null_mut(),
                confidence: min_confidence(),
            };

        let mut stack_adjust = Conf::<i64>::new(0, min_confidence()).into();
        // SAFETY: FunctionParameter and BNFunctionParameter are transparent,
        // so this can be safelly transmuted
        let raw_parameters: &[BNFunctionParameter] = unsafe { mem::transmute(parameters) };
        let reg_stack_adjust_regs = ptr::null_mut();
        let reg_stack_adjust_values = ptr::null_mut();

        let mut return_regs: BNRegisterSetWithConfidence = BNRegisterSetWithConfidence {
            regs: ptr::null_mut(),
            count: 0,
            confidence: 0,
        };

        unsafe {
            let result = BNNewTypeReference(BNCreateFunctionType(
                &mut return_type,
                &mut raw_calling_convention,
                raw_parameters.as_ptr() as *mut BNFunctionParameter,
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
            ));
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn function_with_options<
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
    ) -> Self {
        let mut return_type = return_type.into().into();
        let mut variable_arguments = Conf::new(variable_arguments, max_confidence()).into();
        let mut can_return = Conf::new(true, min_confidence()).into();
        let mut pure = Conf::new(false, min_confidence()).into();
        let mut raw_calling_convention: BNCallingConventionWithConfidence =
            calling_convention.into().into();
        let mut stack_adjust = stack_adjust.into();

        let mut name_ptrs = vec![];
        for parameter in parameters {
            name_ptrs.push(parameter.name().clone());
        }

        // SAFETY: FunctionParameter and BNFunctionParameter are transparent,
        // so this can be safelly transmuted
        let raw_parameters: &[BNFunctionParameter] = unsafe { mem::transmute(parameters) };

        // TODO: Update type signature and include these (will be a breaking change)
        let reg_stack_adjust_regs = ptr::null_mut();
        let reg_stack_adjust_values = ptr::null_mut();

        let mut return_regs: BNRegisterSetWithConfidence = BNRegisterSetWithConfidence {
            regs: ptr::null_mut(),
            count: 0,
            confidence: 0,
        };

        unsafe {
            let result = BNCreateFunctionType(
                &mut return_type,
                &mut raw_calling_convention,
                raw_parameters.as_ptr() as *mut BNFunctionParameter,
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
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, t: T) -> Self {
        let mut is_const = Conf::new(false, min_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();
        unsafe {
            let result = BNCreatePointerType(
                arch.as_ref().0,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn const_pointer<'a, A: Architecture, T: Into<Conf<&'a Type>>>(arch: &A, t: T) -> Self {
        let mut is_const = Conf::new(true, max_confidence()).into();
        let mut is_volatile = Conf::new(false, min_confidence()).into();
        unsafe {
            let result = BNCreatePointerType(
                arch.as_ref().0,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ReferenceType::PointerReferenceType,
            );
            Self::from_raw(NonNull::new(result).unwrap())
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
            let result = BNCreatePointerTypeOfWidth(
                size,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or(ReferenceType::PointerReferenceType),
            );
            Self::from_raw(NonNull::new(result).unwrap())
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
            let result = BNCreatePointerType(
                arch.as_ref().0,
                &t.into().into(),
                &mut is_const,
                &mut is_volatile,
                ref_type.unwrap_or(ReferenceType::PointerReferenceType),
            );
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn generate_auto_demangled_type_id<S: BnStrCompatible>(name: S) -> BnString {
        let mut name = QualifiedName::from(name);
        unsafe {
            BnString::from_raw(NonNull::new(BNGenerateAutoDemangledTypeId(&mut name.0)).unwrap())
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", unsafe {
            let result = BNGetTypeString(
                self.as_raw(),
                ptr::null_mut(),
                BNTokenEscapingType::NoTokenEscapingType,
            );
            BnString::from_raw(NonNull::new(result).unwrap())
        })
    }
}

lazy_static! {
    static ref TYPE_DEBUG_BV: Mutex<Option<Ref<BinaryView>>> =
        Mutex::new(BinaryView::from_data(&FileMetadata::new(), &[]).ok());
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(lock) = TYPE_DEBUG_BV.lock() {
            if let Some(bv) = &*lock {
                let mut count: usize = 0;
                let container = unsafe { BNGetAnalysisTypeContainer(bv.handle) };
                let lines: *mut BNTypeDefinitionLine = unsafe {
                    BNGetTypeLines(
                        self.as_raw(),
                        container,
                        "\x00".as_ptr() as *const c_char,
                        64,
                        false,
                        BNTokenEscapingType::NoTokenEscapingType,
                        &mut count as *mut usize,
                    )
                };
                unsafe {
                    BNFreeTypeContainer(container);
                }

                if lines.is_null() {
                    return Err(fmt::Error);
                }

                let line_slice: &[BNTypeDefinitionLine] =
                    unsafe { slice::from_raw_parts(lines, count) };

                for (i, line) in line_slice.iter().enumerate() {
                    if i > 0 {
                        writeln!(f)?;
                    }

                    let tokens: &[BNInstructionTextToken] =
                        unsafe { slice::from_raw_parts(line.tokens, line.count) };

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
        Err(fmt::Error)
    }
}

impl PartialEq for Type {
    fn eq(&self, other: &Self) -> bool {
        unsafe { BNTypesEqual(self.as_raw(), other.as_raw()) }
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

impl Clone for Type {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(NonNull::new(BNNewTypeReference(self.as_raw())).unwrap()) }
    }
}

impl Drop for Type {
    fn drop(&mut self) {
        unsafe { BNFreeType(self.as_raw()) };
    }
}

///////////////////////
// FunctionParameter

#[repr(C)]
#[derive(Clone, Debug)]
pub struct FunctionParameter {
    name: Option<BnString>,
    pub t: Type,
    type_confidence: u8,
    default_location: bool,
    location: Variable,
}

impl FunctionParameter {
    pub fn new<S: BnStrCompatible, T: Into<Conf<Type>>>(
        t: T,
        name: S,
        location: Option<Variable>,
    ) -> Self {
        let t = t.into();
        let dummy_var: Variable =
            Variable::new(BNVariableSourceType::StackVariableSourceType, 0, 0);
        Self {
            name: Some(BnString::new(name)),
            t: t.contents,
            type_confidence: t.confidence,
            default_location: location.is_some(),
            location: location.unwrap_or(dummy_var),
        }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &BNFunctionParameter) -> &Self {
        assert!(!handle.type_.is_null());
        mem::transmute(handle)
    }

    pub fn location(&self) -> Option<Variable> {
        (!self.default_location).then_some(self.location)
    }

    pub fn name(&self) -> Cow<str> {
        if let Some(name) = &self.name {
            Cow::Borrowed(name.as_str())
        } else {
            match self.location() {
                Some(Variable {
                    t: BNVariableSourceType::RegisterVariableSourceType,
                    ..
                }) => Cow::Owned(format!("reg_{}", self.location.storage)),
                Some(Variable {
                    t: BNVariableSourceType::StackVariableSourceType,
                    ..
                }) => Cow::Owned(format!("arg_{}", self.location.storage)),
                Some(Variable {
                    t: BNVariableSourceType::FlagVariableSourceType,
                    ..
                })
                | None => Cow::Borrowed(""),
            }
        }
    }
}

impl CoreArrayProvider for FunctionParameter {
    type Raw = BNFunctionParameter;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for FunctionParameter {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeParameterList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

//////////////
// Variable

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Variable {
    pub t: BNVariableSourceType,
    pub index: u32,
    pub storage: i64,
}

impl Variable {
    pub fn new(t: BNVariableSourceType, index: u32, storage: i64) -> Self {
        Self { t, index, storage }
    }

    pub(crate) unsafe fn from_raw(var: BNVariable) -> Self {
        Self {
            t: var.type_,
            index: var.index,
            storage: var.storage,
        }
    }
    pub(crate) unsafe fn from_identifier(var: u64) -> Self {
        Self::from_raw(unsafe { BNFromVariableIdentifier(var) })
    }

    pub(crate) fn raw(&self) -> BNVariable {
        BNVariable {
            type_: self.t,
            index: self.index,
            storage: self.storage,
        }
    }
}

impl CoreArrayProvider for Variable {
    type Raw = BNVariable;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for Variable {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeVariableList(raw)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Variable::from_raw(*raw)
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
        let var = Variable::from_raw(raw.var);
        let var_type = core::mem::transmute(&raw.type_);
        (name, var, var_type)
    }
}

//////////////
// SSAVariable

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct SSAVariable {
    pub variable: Variable,
    pub version: usize,
}

impl SSAVariable {
    pub fn new(variable: Variable, version: usize) -> Self {
        Self { variable, version }
    }
}

impl CoreArrayProvider for SSAVariable {
    type Raw = usize;
    type Context = Variable;
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for SSAVariable {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeILInstructionList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        SSAVariable::new(*context, *raw)
    }
}

impl CoreArrayProvider for Array<SSAVariable> {
    type Raw = BNVariable;
    type Context = Ref<MediumLevelILFunction>;
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for Array<SSAVariable> {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeVariableList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let mut count = 0;
        let versions =
            unsafe { BNGetMediumLevelILVariableSSAVersions(context.handle, raw, &mut count) };
        Array::new(versions, count, Variable::from_raw(*raw))
    }
}

///////////////
// NamedVariable

#[repr(C)]
#[derive(Debug, Clone)]
pub struct NamedTypedVariable {
    var: Variable,
    // ManuallyDrop because this is droped by the BNFreeVariableNameAndType
    // and not but Type::drop and BnString::drop
    ty: ManuallyDrop<Type>,
    name: ManuallyDrop<BnString>,
    auto_defined: bool,
    type_confidence: u8,
}

impl NamedTypedVariable {
    pub(crate) unsafe fn ref_from_raw(handle: &BNVariableNameAndType) -> &Self {
        assert!(!handle.type_.is_null());
        assert!(!handle.name.is_null());
        mem::transmute(handle)
    }

    pub(crate) fn as_raw(&self) -> &BNVariableNameAndType {
        unsafe { mem::transmute(self) }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn var(&self) -> Variable {
        self.var
    }

    pub fn auto_defined(&self) -> bool {
        self.auto_defined
    }

    pub fn var_type(&self) -> Conf<&Type> {
        Conf::new(&self.ty, self.type_confidence)
    }
}

impl Drop for NamedTypedVariable {
    fn drop(&mut self) {
        unsafe {
            BNFreeVariableNameAndType(self.as_raw() as *const _ as *mut BNVariableNameAndType)
        }
    }
}

impl CoreArrayProvider for NamedTypedVariable {
    type Raw = BNVariableNameAndType;
    type Context = ();
    type Wrapped<'a> = &'a NamedTypedVariable;
}

unsafe impl CoreArrayProviderInner for NamedTypedVariable {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeVariableNameAndTypeList(raw, count)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

////////////////////////
// EnumerationBuilder

#[repr(C)]
#[derive(Debug, Clone)]
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

    pub(crate) unsafe fn ref_from_raw(member: &BNEnumerationMember) -> &Self {
        mem::transmute(member)
    }
}

impl CoreArrayProvider for EnumerationMember {
    type Raw = BNEnumerationMember;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for EnumerationMember {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeEnumerationMemberList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

#[repr(transparent)]
#[derive(PartialEq, Eq, Hash)]
pub struct EnumerationBuilder {
    handle: NonNull<BNEnumerationBuilder>,
}

impl EnumerationBuilder {
    pub fn new() -> Self {
        Self {
            handle: NonNull::new(unsafe { BNCreateEnumerationBuilder() }).unwrap(),
        }
    }

    pub(crate) unsafe fn from_raw(handle: NonNull<BNEnumerationBuilder>) -> Self {
        Self { handle }
    }

    pub(crate) fn as_raw(&self) -> &mut BNEnumerationBuilder {
        unsafe { &mut (*self.handle.as_ptr()) }
    }

    pub fn finalize(&self) -> Enumeration {
        unsafe {
            let result = BNFinalizeEnumerationBuilder(self.as_raw());
            Enumeration::from_raw(NonNull::new(result).unwrap())
        }
    }

    pub fn append<S: BnStrCompatible>(&self, name: S) -> &Self {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNAddEnumerationBuilderMember(self.as_raw(), name.as_ref().as_ptr() as _);
        }
        self
    }

    pub fn insert<S: BnStrCompatible>(&self, name: S, value: u64) -> &Self {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNAddEnumerationBuilderMemberWithValue(
                self.as_raw(),
                name.as_ref().as_ptr() as _,
                value,
            );
        }
        self
    }

    pub fn replace<S: BnStrCompatible>(&self, id: usize, name: S, value: u64) -> &Self {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNReplaceEnumerationBuilderMember(
                self.as_raw(),
                id,
                name.as_ref().as_ptr() as _,
                value,
            );
        }
        self
    }

    pub fn remove(&self, id: usize) -> &Self {
        unsafe {
            BNRemoveEnumerationBuilderMember(self.as_raw(), id);
        }

        self
    }

    pub fn members(&self) -> Array<EnumerationMember> {
        unsafe {
            let mut count = 0;
            let members_raw = BNGetEnumerationBuilderMembers(self.as_raw(), &mut count);
            Array::new(members_raw, count, ())
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
            let result = BNCreateEnumerationBuilderFromEnumeration(enumeration.as_raw());
            Self::from_raw(NonNull::new(result).unwrap())
        }
    }
}

impl Drop for EnumerationBuilder {
    fn drop(&mut self) {
        unsafe { BNFreeEnumerationBuilder(self.as_raw()) };
    }
}

/////////////////
// Enumeration

#[repr(transparent)]
#[derive(PartialEq, Eq, Hash)]
pub struct Enumeration {
    handle: NonNull<BNEnumeration>,
}

impl Enumeration {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNEnumeration>) -> Self {
        Self { handle }
    }

    pub(crate) fn as_raw(&self) -> &mut BNEnumeration {
        unsafe { &mut (*self.handle.as_ptr()) }
    }

    pub fn builder() -> EnumerationBuilder {
        EnumerationBuilder::new()
    }

    pub fn members(&self) -> Array<EnumerationMember> {
        unsafe {
            let mut count = 0;
            let members_raw = BNGetEnumerationMembers(self.as_raw(), &mut count);
            Array::new(members_raw, count, ())
        }
    }
}

impl Clone for Enumeration {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(NonNull::new(BNNewEnumerationReference(self.as_raw())).unwrap()) }
    }
}

impl Drop for Enumeration {
    fn drop(&mut self) {
        unsafe { BNFreeEnumeration(self.as_raw()) };
    }
}

//////////////////////
// StructureBuilder

pub type StructureType = BNStructureVariant;

#[repr(transparent)]
#[derive(PartialEq, Eq, Hash)]
pub struct StructureBuilder {
    handle: NonNull<BNStructureBuilder>,
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
            handle: unsafe { NonNull::new(BNCreateStructureBuilder()).unwrap() },
        }
    }

    pub(crate) unsafe fn from_raw(handle: NonNull<BNStructureBuilder>) -> Self {
        Self { handle }
    }

    pub(crate) fn as_raw(&self) -> &mut BNStructureBuilder {
        unsafe { &mut (*self.handle.as_ptr()) }
    }

    // Chainable terminal
    pub fn finalize(&self) -> Structure {
        let result = unsafe { BNFinalizeStructureBuilder(self.as_raw()) };
        unsafe { Structure::from_raw(NonNull::new(result).unwrap()) }
    }

    // Chainable builders/setters

    pub fn set_width(&self, width: u64) -> &Self {
        unsafe {
            BNSetStructureBuilderWidth(self.as_raw(), width);
        }

        self
    }

    pub fn set_alignment(&self, alignment: usize) -> &Self {
        unsafe {
            BNSetStructureBuilderAlignment(self.as_raw(), alignment);
        }

        self
    }

    pub fn set_packed(&self, packed: bool) -> &Self {
        unsafe {
            BNSetStructureBuilderPacked(self.as_raw(), packed);
        }

        self
    }

    pub fn set_structure_type(&self, t: StructureType) -> &Self {
        unsafe { BNSetStructureBuilderType(self.as_raw(), t) };
        self
    }

    pub fn set_pointer_offset(&self, offset: i64) -> &Self {
        unsafe { BNSetStructureBuilderPointerOffset(self.as_raw(), offset) };
        self
    }

    pub fn set_propagates_data_var_refs(&self, does: bool) -> &Self {
        unsafe { BNSetStructureBuilderPropagatesDataVariableReferences(self.as_raw(), does) };
        self
    }

    pub fn set_base_structures(&self, bases: Vec<BaseStructure>) -> &Self {
        let mut bases_api = vec![];
        for base in bases {
            bases_api.push(BNBaseStructure {
                type_: base.ty.handle,
                offset: base.offset,
                width: base.width,
            });
        }

        unsafe {
            BNSetBaseStructuresForStructureBuilder(
                self.as_raw(),
                bases_api.as_mut_ptr(),
                bases_api.len(),
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
                self.as_raw(),
                &t.into().into(),
                name.as_ref().as_ptr() as _,
                access,
                scope,
            );
        }

        self
    }

    pub fn insert_member(&self, member: &StructureMember, overwrite_existing: bool) -> &Self {
        let ty = member.ty.clone();
        self.insert(
            &ty,
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
                self.as_raw(),
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

    // Getters

    pub fn width(&self) -> u64 {
        unsafe { BNGetStructureBuilderWidth(self.as_raw()) }
    }

    pub fn alignment(&self) -> usize {
        unsafe { BNGetStructureBuilderAlignment(self.as_raw()) }
    }

    pub fn packed(&self) -> bool {
        unsafe { BNIsStructureBuilderPacked(self.as_raw()) }
    }

    pub fn structure_type(&self) -> StructureType {
        unsafe { BNGetStructureBuilderType(self.as_raw()) }
    }

    pub fn pointer_offset(&self) -> i64 {
        unsafe { BNGetStructureBuilderPointerOffset(self.as_raw()) }
    }

    pub fn propagates_data_var_refs(&self) -> bool {
        unsafe { BNStructureBuilderPropagatesDataVariableReferences(self.as_raw()) }
    }

    pub fn base_structures(&self) -> Result<Vec<BaseStructure>> {
        let mut count = 0usize;
        let bases = unsafe { BNGetBaseStructuresForStructureBuilder(self.as_raw(), &mut count) };
        if bases.is_null() {
            Err(())
        } else {
            let bases_slice = unsafe { slice::from_raw_parts_mut(bases, count) };

            let result = bases_slice
                .iter()
                .map(|base| unsafe { BaseStructure::from_raw(*base) })
                .collect::<Vec<_>>();

            unsafe {
                BNFreeBaseStructureList(bases, count);
            }

            Ok(result)
        }
    }

    pub fn members(&self) -> Array<StructureMember> {
        let mut count = 0;
        let members_raw = unsafe { BNGetStructureBuilderMembers(self.as_raw(), &mut count) };
        unsafe { Array::new(members_raw, count, ()) }
    }

    pub fn index_by_name(&self, name: &str) -> Option<usize> {
        self.members()
            .iter()
            .position(|member| member.name() == name)
    }

    pub fn index_by_offset(&self, offset: u64) -> Option<usize> {
        self.members()
            .iter()
            .position(|member| member.offset == offset)
    }

    // Setters

    pub fn clear_members(&self) {
        let len = self.members().len();
        for idx in (0..len).rev() {
            self.remove(idx)
        }
    }

    pub fn add_members<'a>(&self, members: impl IntoIterator<Item = &'a StructureMember>) {
        for member in members {
            self.append(&member.ty, member.name(), member.access, member.scope);
        }
    }

    pub fn set_members<'a>(&self, members: impl IntoIterator<Item = &'a StructureMember>) {
        self.clear_members();
        self.add_members(members);
    }

    pub fn remove(&self, index: usize) {
        unsafe { BNRemoveStructureBuilderMember(self.as_raw(), index) }
    }

    pub fn replace(&self, index: usize, type_: Conf<&Type>, name: &str, overwrite: bool) {
        let name = name.into_bytes_with_nul();
        let name_ptr = name.as_ptr() as *const _;

        let raw_type_ = BNTypeWithConfidence {
            type_: type_.contents as *const Type as *mut _,
            confidence: type_.confidence,
        };
        unsafe {
            BNReplaceStructureBuilderMember(self.as_raw(), index, &raw_type_, name_ptr, overwrite)
        }
    }
}

impl From<&Structure> for StructureBuilder {
    fn from(structure: &Structure) -> StructureBuilder {
        let result = unsafe { BNCreateStructureBuilderFromStructure(structure.as_raw()) };
        unsafe { Self::from_raw(NonNull::new(result).unwrap()) }
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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "StructureBuilder {{ ... }}")
    }
}

impl Clone for StructureBuilder {
    fn clone(&self) -> Self {
        let result = unsafe { BNDuplicateStructureBuilder(self.as_raw()) };
        Self {
            handle: NonNull::new(result).unwrap(),
        }
    }
}

impl Drop for StructureBuilder {
    fn drop(&mut self) {
        unsafe { BNFreeStructureBuilder(self.as_raw()) };
    }
}

impl Default for StructureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

///////////////
// Structure

#[repr(transparent)]
#[derive(PartialEq, Eq, Hash)]
pub struct Structure {
    handle: NonNull<BNStructure>,
}

impl Structure {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNStructure>) -> Self {
        Self { handle }
    }

    pub(crate) fn as_raw(&self) -> &mut BNStructure {
        unsafe { &mut (*self.handle.as_ptr()) }
    }

    pub fn builder() -> StructureBuilder {
        StructureBuilder::new()
    }

    pub fn width(&self) -> u64 {
        unsafe { BNGetStructureWidth(self.as_raw()) }
    }

    pub fn structure_type(&self) -> StructureType {
        unsafe { BNGetStructureType(self.as_raw()) }
    }

    pub fn members(&self) -> Result<Array<StructureMember>> {
        unsafe {
            let mut count = 0;
            let members_raw: *mut BNStructureMember =
                BNGetStructureMembers(self.as_raw(), &mut count);
            if members_raw.is_null() {
                return Err(());
            }
            Ok(Array::new(members_raw, count, ()))
        }
    }

    pub fn base_structures(&self) -> Result<Vec<BaseStructure>> {
        let mut count = 0usize;
        let bases = unsafe { BNGetBaseStructuresForStructure(self.as_raw(), &mut count) };
        if bases.is_null() {
            Err(())
        } else {
            let bases_slice = unsafe { slice::from_raw_parts_mut(bases, count) };

            let result = bases_slice
                .iter()
                .map(|base| unsafe { BaseStructure::from_raw(*base) })
                .collect::<Vec<_>>();

            unsafe {
                BNFreeBaseStructureList(bases, count);
            }

            Ok(result)
        }
    }

    // TODO : The other methods in the python version (alignment, packed, type, members, remove, replace, etc)
}

impl Debug for Structure {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Structure {{")?;
        if let Ok(members) = self.members() {
            for member in &members {
                write!(f, " {:?}", member)?;
            }
        }
        write!(f, "}}")
    }
}

impl Clone for Structure {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(NonNull::new(BNNewStructureReference(self.as_raw())).unwrap()) }
    }
}

impl Drop for Structure {
    fn drop(&mut self) {
        unsafe { BNFreeStructure(self.as_raw()) }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct StructureMember {
    ty: Type,
    name: BnString,
    pub offset: u64,
    type_confidence: u8,
    pub access: MemberAccess,
    pub scope: MemberScope,
}

impl StructureMember {
    pub fn new<S: BnStrCompatible>(
        ty: Conf<Type>,
        name: S,
        offset: u64,
        access: MemberAccess,
        scope: MemberScope,
    ) -> Self {
        Self {
            ty: ty.contents,
            name: BnString::new(name),
            offset,
            type_confidence: ty.confidence,
            access,
            scope,
        }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &BNStructureMember) -> &Self {
        mem::transmute(handle)
    }

    pub fn ty(&self) -> Conf<&Type> {
        Conf::new(&self.ty, self.type_confidence)
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl CoreArrayProvider for StructureMember {
    type Raw = BNStructureMember;
    type Context = ();
    type Wrapped<'a> = &'a StructureMember;
}

unsafe impl CoreArrayProviderInner for StructureMember {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeStructureMemberList(raw, count)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        StructureMember::ref_from_raw(raw)
    }
}

#[derive(Debug, Clone)]
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

    // pub(crate) unsafe fn from_raw(handle: BNInheritedStructureMember) -> Self {
    //     Self {
    //         base: RefCountable::inc_ref(&NamedTypeReference::from_raw(handle.base)),
    //         base_offset: handle.baseOffset,
    //         member: StructureMember::from_raw(handle.member),
    //         member_index: handle.memberIndex,
    //     }
    // }
}

#[derive(Debug, Clone)]
pub struct BaseStructure {
    pub ty: Ref<NamedTypeReference>,
    pub offset: u64,
    pub width: u64,
}

impl BaseStructure {
    pub fn new(ty: Ref<NamedTypeReference>, offset: u64, width: u64) -> Self {
        Self { ty, offset, width }
    }

    pub(crate) unsafe fn from_raw(handle: BNBaseStructure) -> Self {
        Self {
            ty: RefCountable::inc_ref(&NamedTypeReference::from_raw(handle.type_)),
            offset: handle.offset,
            width: handle.width,
        }
    }
}

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
            RefCountable::inc_ref(&Self {
                handle: BNCreateNamedType(type_class, ptr::null() as *const _, &mut name.0),
            })
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
            RefCountable::inc_ref(&Self {
                handle: BNCreateNamedType(type_class, type_id.as_ref().as_ptr() as _, &mut name.0),
            })
        }
    }

    pub fn name(&self) -> QualifiedName {
        let named_ref: BNQualifiedName = unsafe { BNGetTypeReferenceName(self.handle) };
        QualifiedName(named_ref)
    }

    pub fn id(&self) -> BnString {
        unsafe { BnString::from_raw(NonNull::new(BNGetTypeReferenceId(self.handle)).unwrap()) }
    }

    pub fn class(&self) -> NamedTypeReferenceClass {
        unsafe { BNGetTypeReferenceClass(self.handle) }
    }

    fn target_helper(&self, bv: &BinaryView, visited: &mut HashSet<BnString>) -> Option<Type> {
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

    pub fn target(&self, bv: &BinaryView) -> Option<Type> {
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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} (id: {})", self.name(), self.id())
    }
}

///////////////////
// QualifiedName

#[repr(transparent)]
pub struct QualifiedName(pub(crate) BNQualifiedName);

impl QualifiedName {
    // TODO : I think this is bad
    pub fn string(&self) -> String {
        unsafe {
            slice::from_raw_parts(self.0.name, self.0.nameCount)
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
            slice::from_raw_parts(names, self.0.nameCount)
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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.string())
    }
}

impl Display for QualifiedName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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
        mem::transmute(raw)
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
        unsafe { Guard::new(Type::from_raw(NonNull::new(self.0.type_).unwrap()), self) }
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
        mem::transmute(raw)
    }
}

//////////////////////////
// QualifiedNameTypeAndId

#[repr(transparent)]
pub struct QualifiedNameTypeAndId(pub(crate) BNQualifiedNameTypeAndId);

impl QualifiedNameTypeAndId {
    pub fn name(&self) -> &QualifiedName {
        unsafe { mem::transmute(&self.0.name) }
    }

    pub fn id(&self) -> &str {
        unsafe { CStr::from_ptr(self.0.id).to_str().unwrap() }
    }

    pub fn type_object(&self) -> Guard<Type> {
        unsafe { Guard::new(Type::from_raw(NonNull::new(self.0.type_).unwrap()), self) }
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
        mem::transmute(raw)
    }
}

//////////////////////////
// NameAndType

pub struct NameAndType(pub(crate) BNNameAndType);

impl NameAndType {
    pub(crate) unsafe fn from_raw(raw: &BNNameAndType) -> Self {
        Self(*raw)
    }
}

impl NameAndType {
    pub fn new<S: BnStrCompatible>(name: S, t: Type, confidence: u8) -> Ref<Self> {
        unsafe {
            Ref::new(Self(BNNameAndType {
                name: BNAllocString(name.into_bytes_with_nul().as_ref().as_ptr() as *mut _),
                type_: t.into_raw(),
                typeConfidence: confidence,
            }))
        }
    }

    pub fn name(&self) -> &str {
        let c_str = unsafe { CStr::from_ptr(self.0.name) };
        c_str.to_str().unwrap()
    }

    pub fn t(&self) -> &Type {
        unsafe { Type::ref_from_raw(&self.0.type_) }
    }

    pub fn type_with_confidence(&self) -> Conf<&Type> {
        Conf::new(self.t(), self.0.typeConfidence)
    }
}

impl ToOwned for NameAndType {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for NameAndType {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::new(
            CStr::from_ptr(handle.0.name),
            handle.t().clone(),
            handle.0.typeConfidence,
        )
    }

    unsafe fn dec_ref(handle: &Self) {
        unsafe {
            BNFreeString(handle.0.name);
            let _ = Type::from_raw(NonNull::new(handle.0.type_).unwrap());
        }
    }
}

impl CoreArrayProvider for NameAndType {
    type Raw = BNNameAndType;
    type Context = ();
    type Wrapped<'a> = Guard<'a, NameAndType>;
}

unsafe impl CoreArrayProviderInner for NameAndType {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeNameAndTypeList(raw, count);
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        unsafe { Guard::new(NameAndType::from_raw(raw), raw) }
    }
}

//////////////////
// DataVariable

#[repr(transparent)]
pub struct DataVariable(pub(crate) BNDataVariable);

// impl DataVariable {
//     pub(crate) fn from_raw(var: &BNDataVariable) -> Self {
//         let var = DataVariable(*var);
//         Self(BNDataVariable {
//             type_: unsafe { Ref::into_raw(var.t().to_owned()).handle },
//             ..var.0
//         })
//     }
// }

impl DataVariable {
    pub fn address(&self) -> u64 {
        self.0.address
    }

    pub fn auto_discovered(&self) -> bool {
        self.0.autoDiscovered
    }

    pub fn t(&self) -> &Type {
        unsafe { mem::transmute(&self.0.type_) }
    }

    pub fn type_with_confidence(&self) -> Conf<&Type> {
        Conf::new(self.t(), self.0.typeConfidence)
    }

    pub fn symbol(&self, bv: &BinaryView) -> Option<Ref<Symbol>> {
        bv.symbol_by_address(self.0.address).ok()
    }
}

impl ToOwned for DataVariable {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for DataVariable {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        unsafe {
            Ref::new(Self(BNDataVariable {
                type_: handle.t().clone().into_raw(),
                ..handle.0
            }))
        }
    }

    unsafe fn dec_ref(handle: &Self) {
        unsafe { BNFreeType(handle.0.type_) }
    }
}

impl CoreArrayProvider for DataVariable {
    type Raw = BNDataVariable;
    type Context = ();
    type Wrapped<'a> = &'a DataVariable;
}
unsafe impl CoreArrayProviderInner for DataVariable {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeDataVariables(raw, count);
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        mem::transmute(raw)
    }
}

/////////////////////////
// DataVariableAndName

pub struct DataVariableAndName<S: BnStrCompatible> {
    pub address: u64,
    pub t: Conf<Type>,
    pub auto_discovered: bool,
    pub name: S,
}

impl DataVariableAndName<String> {
    pub(crate) fn from_raw(var: &BNDataVariableAndName) -> Self {
        Self {
            address: var.address,
            t: Conf::new(
                unsafe { Type::from_raw(NonNull::new(var.type_).unwrap()) },
                var.typeConfidence,
            ),
            auto_discovered: var.autoDiscovered,
            name: raw_to_string(var.name).unwrap(),
        }
    }
}

impl<S: BnStrCompatible> DataVariableAndName<S> {
    pub fn new(address: u64, t: Conf<Type>, auto_discovered: bool, name: S) -> Self {
        Self {
            address,
            t,
            auto_discovered,
            name,
        }
    }

    pub fn type_with_confidence(&self) -> Conf<Type> {
        Conf::new(self.t.contents.clone(), self.t.confidence)
    }
}

/////////////////////////
// RegisterValueType

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum RegisterValueType {
    UndeterminedValue,
    EntryValue,
    ConstantValue,
    ConstantPointerValue,
    ExternalPointerValue,
    StackFrameOffset,
    ReturnAddressValue,
    ImportedAddressValue,
    SignedRangeValue,
    UnsignedRangeValue,
    LookupTableValue,
    InSetOfValues,
    NotInSetOfValues,
    ConstantDataValue,
    ConstantDataZeroExtendValue,
    ConstantDataSignExtendValue,
    ConstantDataAggregateValue,
}

impl RegisterValueType {
    pub(crate) fn from_raw_value(value: u32) -> Option<Self> {
        use BNRegisterValueType::*;
        Some(match value {
            x if x == UndeterminedValue as u32 => Self::UndeterminedValue,
            x if x == EntryValue as u32 => Self::EntryValue,
            x if x == ConstantValue as u32 => Self::ConstantValue,
            x if x == ConstantPointerValue as u32 => Self::ConstantPointerValue,
            x if x == ExternalPointerValue as u32 => Self::ExternalPointerValue,
            x if x == StackFrameOffset as u32 => Self::StackFrameOffset,
            x if x == ReturnAddressValue as u32 => Self::ReturnAddressValue,
            x if x == ImportedAddressValue as u32 => Self::ImportedAddressValue,
            x if x == SignedRangeValue as u32 => Self::SignedRangeValue,
            x if x == UnsignedRangeValue as u32 => Self::UnsignedRangeValue,
            x if x == LookupTableValue as u32 => Self::LookupTableValue,
            x if x == InSetOfValues as u32 => Self::InSetOfValues,
            x if x == NotInSetOfValues as u32 => Self::NotInSetOfValues,
            x if x == ConstantDataValue as u32 => Self::ConstantDataValue,
            x if x == ConstantDataZeroExtendValue as u32 => Self::ConstantDataZeroExtendValue,
            x if x == ConstantDataSignExtendValue as u32 => Self::ConstantDataSignExtendValue,
            x if x == ConstantDataAggregateValue as u32 => Self::ConstantDataAggregateValue,
            _ => return None,
        })
    }

    pub(crate) fn into_raw_value(self) -> BNRegisterValueType {
        use BNRegisterValueType::*;
        match self {
            Self::UndeterminedValue => UndeterminedValue,
            Self::EntryValue => EntryValue,
            Self::ConstantValue => ConstantValue,
            Self::ConstantPointerValue => ConstantPointerValue,
            Self::ExternalPointerValue => ExternalPointerValue,
            Self::StackFrameOffset => StackFrameOffset,
            Self::ReturnAddressValue => ReturnAddressValue,
            Self::ImportedAddressValue => ImportedAddressValue,
            Self::SignedRangeValue => SignedRangeValue,
            Self::UnsignedRangeValue => UnsignedRangeValue,
            Self::LookupTableValue => LookupTableValue,
            Self::InSetOfValues => InSetOfValues,
            Self::NotInSetOfValues => NotInSetOfValues,
            Self::ConstantDataValue => ConstantDataValue,
            Self::ConstantDataZeroExtendValue => ConstantDataZeroExtendValue,
            Self::ConstantDataSignExtendValue => ConstantDataSignExtendValue,
            Self::ConstantDataAggregateValue => ConstantDataAggregateValue,
        }
    }
}

/////////////////////////
// RegisterValue

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct RegisterValue {
    pub(crate) state: RegisterValueType,
    pub(crate) value: i64,
    pub(crate) offset: i64,
    pub(crate) size: usize,
}

impl RegisterValue {
    pub fn new(state: RegisterValueType, value: i64, offset: i64, size: usize) -> Self {
        Self {
            state,
            value,
            offset,
            size,
        }
    }
}

impl From<BNRegisterValue> for RegisterValue {
    fn from(value: BNRegisterValue) -> Self {
        Self {
            state: RegisterValueType::from_raw_value(value.state as u32).unwrap(),
            value: value.value,
            offset: value.offset,
            size: value.size,
        }
    }
}

impl From<RegisterValue> for BNRegisterValue {
    fn from(value: RegisterValue) -> Self {
        Self {
            state: value.state.into_raw_value(),
            value: value.value,
            offset: value.offset,
            size: value.size,
        }
    }
}

/////////////////////////
// ConstantData

#[derive(Clone, Debug, PartialEq, Hash)]
pub struct ConstantData {
    function: Ref<Function>,
    value: RegisterValue,
}

impl ConstantData {
    pub(crate) fn new(function: Ref<Function>, value: RegisterValue) -> Self {
        Self { function, value }
    }
}

// unsafe impl<S: BnStrCompatible> CoreArrayProvider for DataVariableAndName<S> {
//     type Raw = BNDataVariableAndName;
//     type Context = ();
// }

// unsafe impl<S: BnStrCompatible> CoreOwnedArrayProvider for DataVariableAndName<S> {
//     unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
//         BNFreeDataVariablesAndName(raw, count);
//     }
// }

// unsafe impl<'a, S: 'a + BnStrCompatible> CoreArrayWrapper<'a> for DataVariableAndName<S> {
//     type Wrapped = &'a DataVariableAndName<S>;
// }

// unsafe impl<'a, S: 'a + BnStrCompatible> CoreArrayWrapper<'a> for DataVariableAndName<S> {
//     unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
//         mem::transmute(raw)
//     }
// }

/////////////////////////
// ValueRange

#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct ValueRange<T> {
    raw: BNValueRange,
    _t: core::marker::PhantomData<T>,
}

impl<T> ValueRange<T> {
    fn from_raw(value: BNValueRange) -> Self {
        Self {
            raw: value,
            _t: core::marker::PhantomData,
        }
    }
    fn into_raw(self) -> BNValueRange {
        self.raw
    }
}

impl IntoIterator for ValueRange<u64> {
    type Item = u64;
    type IntoIter = core::iter::StepBy<Range<u64>>;

    fn into_iter(self) -> Self::IntoIter {
        (self.raw.start..self.raw.end).step_by(self.raw.step.try_into().unwrap())
    }
}
impl IntoIterator for ValueRange<i64> {
    type Item = i64;
    type IntoIter = core::iter::StepBy<Range<i64>>;

    fn into_iter(self) -> Self::IntoIter {
        (self.raw.start as i64..self.raw.end as i64).step_by(self.raw.step.try_into().unwrap())
    }
}

/////////////////////////
// PossibleValueSet

#[derive(Clone, Debug)]
pub enum PossibleValueSet {
    UndeterminedValue,
    EntryValue {
        reg: i64,
    },
    ConstantValue {
        value: i64,
    },
    ConstantPointerValue {
        value: i64,
    },
    ExternalPointerValue,
    StackFrameOffset {
        offset: i64,
    },
    ReturnAddressValue,
    ImportedAddressValue,
    SignedRangeValue {
        offset: i64,
        ranges: Vec<ValueRange<i64>>,
    },
    UnsignedRangeValue {
        offset: i64,
        ranges: Vec<ValueRange<u64>>,
    },
    LookupTableValue {
        tables: Vec<LookupTableEntry>,
    },
    InSetOfValues {
        values: HashSet<i64>,
    },
    NotInSetOfValues {
        values: HashSet<i64>,
    },
    ConstantDataValue {
        value_type: ConstantDataType,
        value: i64,
    },
}

#[derive(Copy, Clone, Debug)]
pub enum ConstantDataType {
    Value,
    ZeroExtend,
    SignExtend,
    Aggregate,
}

impl PossibleValueSet {
    pub(crate) unsafe fn from_raw(value: BNPossibleValueSet) -> Self {
        unsafe fn from_range<T>(value: BNPossibleValueSet) -> Vec<ValueRange<T>> {
            core::slice::from_raw_parts(value.ranges, value.count)
                .iter()
                .copied()
                .map(|range| ValueRange::from_raw(range))
                .collect()
        }
        let from_sets = |value: BNPossibleValueSet| {
            unsafe { core::slice::from_raw_parts(value.valueSet, value.count) }
                .iter()
                .copied()
                .collect()
        };
        use BNRegisterValueType::*;
        match value.state {
            UndeterminedValue => Self::UndeterminedValue,
            EntryValue => Self::EntryValue { reg: value.value },
            ConstantValue => Self::ConstantValue { value: value.value },
            ConstantPointerValue => Self::ConstantPointerValue { value: value.value },
            StackFrameOffset => Self::StackFrameOffset {
                offset: value.value,
            },
            ConstantDataValue => Self::ConstantDataValue {
                value_type: ConstantDataType::Value,
                value: value.value,
            },
            ConstantDataZeroExtendValue => Self::ConstantDataValue {
                value_type: ConstantDataType::ZeroExtend,
                value: value.value,
            },
            ConstantDataSignExtendValue => Self::ConstantDataValue {
                value_type: ConstantDataType::SignExtend,
                value: value.value,
            },
            ConstantDataAggregateValue => Self::ConstantDataValue {
                value_type: ConstantDataType::Aggregate,
                value: value.value,
            },
            SignedRangeValue => Self::SignedRangeValue {
                offset: value.value,
                ranges: from_range(value),
            },
            UnsignedRangeValue => Self::UnsignedRangeValue {
                offset: value.value,
                ranges: from_range(value),
            },
            LookupTableValue => {
                let raw_tables = unsafe { core::slice::from_raw_parts(value.table, value.count) };
                let raw_from_tables = |i: &BNLookupTableEntry| unsafe {
                    core::slice::from_raw_parts(i.fromValues, i.fromCount)
                };
                let tables = raw_tables
                    .iter()
                    .map(|table| LookupTableEntry {
                        from_values: raw_from_tables(table).to_vec(),
                        to_value: table.toValue,
                    })
                    .collect();
                Self::LookupTableValue { tables }
            }
            NotInSetOfValues => Self::NotInSetOfValues {
                values: from_sets(value),
            },
            InSetOfValues => Self::InSetOfValues {
                values: from_sets(value),
            },
            ImportedAddressValue => Self::ImportedAddressValue,
            ReturnAddressValue => Self::ReturnAddressValue,
            ExternalPointerValue => Self::ExternalPointerValue,
        }
    }
    pub(crate) fn into_raw(self) -> PossibleValueSetRaw {
        let mut raw: BNPossibleValueSet = unsafe { core::mem::zeroed() };
        // set the state field
        raw.state = self.value_type().into_raw_value();
        // set all other fields
        match self {
            PossibleValueSet::UndeterminedValue
            | PossibleValueSet::ExternalPointerValue
            | PossibleValueSet::ReturnAddressValue
            | PossibleValueSet::ImportedAddressValue => {}
            PossibleValueSet::EntryValue { reg: value }
            | PossibleValueSet::ConstantValue { value }
            | PossibleValueSet::ConstantPointerValue { value }
            | PossibleValueSet::ConstantDataValue { value, .. }
            | PossibleValueSet::StackFrameOffset { offset: value } => raw.value = value,
            PossibleValueSet::NotInSetOfValues { values }
            | PossibleValueSet::InSetOfValues { values } => {
                let values = Box::leak(values.into_iter().collect());
                raw.valueSet = values.as_mut_ptr();
                raw.count = values.len();
            }
            PossibleValueSet::SignedRangeValue { offset, ranges } => {
                let ranges = Box::leak(ranges.into_iter().map(|x| x.into_raw()).collect());
                raw.value = offset;
                raw.ranges = ranges.as_mut_ptr();
                raw.count = ranges.len();
            }
            PossibleValueSet::UnsignedRangeValue { offset, ranges } => {
                let ranges = Box::leak(ranges.into_iter().map(|x| x.into_raw()).collect());
                raw.value = offset;
                raw.ranges = ranges.as_mut_ptr();
                raw.count = ranges.len();
            }
            PossibleValueSet::LookupTableValue { tables } => {
                let tables = Box::leak(tables.into_iter().map(|table| table.into_raw()).collect());
                // SAFETY: BNLookupTableEntry and LookupTableEntryRaw are transparent
                raw.table = tables.as_mut_ptr() as *mut BNLookupTableEntry;
                raw.count = tables.len();
            }
        }
        PossibleValueSetRaw(raw)
    }

    pub fn value_type(&self) -> RegisterValueType {
        use RegisterValueType::*;
        match self {
            PossibleValueSet::UndeterminedValue => UndeterminedValue,
            PossibleValueSet::EntryValue { .. } => EntryValue,
            PossibleValueSet::ConstantValue { .. } => ConstantValue,
            PossibleValueSet::ConstantPointerValue { .. } => ConstantPointerValue,
            PossibleValueSet::ExternalPointerValue => ExternalPointerValue,
            PossibleValueSet::StackFrameOffset { .. } => StackFrameOffset,
            PossibleValueSet::ReturnAddressValue => ReturnAddressValue,
            PossibleValueSet::ImportedAddressValue => ImportedAddressValue,
            PossibleValueSet::SignedRangeValue { .. } => SignedRangeValue,
            PossibleValueSet::UnsignedRangeValue { .. } => UnsignedRangeValue,
            PossibleValueSet::LookupTableValue { .. } => LookupTableValue,
            PossibleValueSet::InSetOfValues { .. } => InSetOfValues,
            PossibleValueSet::NotInSetOfValues { .. } => NotInSetOfValues,
            PossibleValueSet::ConstantDataValue {
                value_type: ConstantDataType::Value,
                ..
            } => ConstantDataValue,
            PossibleValueSet::ConstantDataValue {
                value_type: ConstantDataType::ZeroExtend,
                ..
            } => ConstantDataZeroExtendValue,
            PossibleValueSet::ConstantDataValue {
                value_type: ConstantDataType::SignExtend,
                ..
            } => ConstantDataSignExtendValue,
            PossibleValueSet::ConstantDataValue {
                value_type: ConstantDataType::Aggregate,
                ..
            } => ConstantDataAggregateValue,
        }
    }
}

/// The owned version of the BNPossibleValueSet
#[repr(transparent)]
pub(crate) struct PossibleValueSetRaw(BNPossibleValueSet);

impl PossibleValueSetRaw {
    pub fn as_ffi(&self) -> &BNPossibleValueSet {
        &self.0
    }
}

impl Drop for PossibleValueSetRaw {
    fn drop(&mut self) {
        use BNRegisterValueType::*;
        match self.0.state {
            UndeterminedValue
            | ExternalPointerValue
            | ReturnAddressValue
            | ImportedAddressValue
            | EntryValue
            | ConstantValue
            | ConstantPointerValue
            | StackFrameOffset
            | ConstantDataValue
            | ConstantDataZeroExtendValue
            | ConstantDataSignExtendValue
            | ConstantDataAggregateValue => {}
            InSetOfValues | NotInSetOfValues => {
                let _values: Box<[i64]> = unsafe {
                    Box::from_raw(ptr::slice_from_raw_parts_mut(self.0.valueSet, self.0.count))
                };
            }
            SignedRangeValue | UnsignedRangeValue => {
                let _ranges: Box<[BNValueRange]> = unsafe {
                    Box::from_raw(ptr::slice_from_raw_parts_mut(self.0.ranges, self.0.count))
                };
            }
            LookupTableValue => {
                // SAFETY: LookupTableEntryRaw and BNLookupTableEntry can be safely transmuted
                let table_ptr = self.0.table as *mut LookupTableEntryRaw;
                let _table: Box<[LookupTableEntryRaw]> = unsafe {
                    Box::from_raw(ptr::slice_from_raw_parts_mut(table_ptr, self.0.count))
                };
            }
        }
    }
}

/////////////////////////
// LookupTableEntry

#[derive(Clone, Debug)]
pub struct LookupTableEntry {
    pub from_values: Vec<i64>,
    pub to_value: i64,
}

impl LookupTableEntry {
    fn into_raw(self) -> LookupTableEntryRaw {
        let from_value = Box::leak(self.from_values.into_boxed_slice());
        LookupTableEntryRaw(BNLookupTableEntry {
            toValue: self.to_value,
            fromValues: from_value.as_mut_ptr(),
            fromCount: from_value.len(),
        })
    }
}

/// The owned version of the BNLookupTableEntry
#[repr(transparent)]
struct LookupTableEntryRaw(BNLookupTableEntry);
impl Drop for LookupTableEntryRaw {
    fn drop(&mut self) {
        let _from_value: Box<[i64]> = unsafe {
            Box::from_raw(ptr::slice_from_raw_parts_mut(
                self.0.fromValues,
                self.0.fromCount,
            ))
        };
    }
}

/////////////////////////
// ArchAndAddr

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct ArchAndAddr {
    pub arch: CoreArchitecture,
    pub address: u64,
}

/////////////////////////
// UserVariableValues

pub struct UserVariableValues {
    pub(crate) vars: *const [BNUserVariableValue],
}

impl UserVariableValues {
    pub fn into_hashmap(self) -> HashMap<Variable, HashMap<ArchAndAddr, PossibleValueSet>> {
        let mut result: HashMap<Variable, HashMap<ArchAndAddr, PossibleValueSet>> = HashMap::new();
        for (var, def_site, possible_val) in self.all() {
            result
                .entry(var)
                .or_default()
                .entry(def_site)
                .or_insert(possible_val);
        }
        result
    }
    pub fn all(&self) -> impl Iterator<Item = (Variable, ArchAndAddr, PossibleValueSet)> {
        unsafe { &*self.vars }.iter().map(|var_val| {
            let var = unsafe { Variable::from_raw(var_val.var) };
            let def_site = ArchAndAddr {
                arch: unsafe { CoreArchitecture::from_raw(var_val.defSite.arch) },
                address: var_val.defSite.address,
            };
            let possible_val = unsafe { PossibleValueSet::from_raw(var_val.value) };
            (var, def_site, possible_val)
        })
    }
    pub fn values_from_variable(
        &self,
        var: Variable,
    ) -> impl Iterator<Item = (ArchAndAddr, PossibleValueSet)> {
        self.all()
            .filter(move |(t_var, _, _)| t_var == &var)
            .map(|(_var, def_site, possible_val)| (def_site, possible_val))
    }
}

impl Drop for UserVariableValues {
    fn drop(&mut self) {
        unsafe { BNFreeUserVariableValues(self.vars as *mut BNUserVariableValue) };
    }
}

/////////////////////////
// ConstantReference

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct ConstantReference {
    pub value: i64,
    pub size: usize,
    pub pointer: bool,
    pub intermediate: bool,
}

impl ConstantReference {
    pub fn from_raw(value: BNConstantReference) -> Self {
        Self {
            value: value.value,
            size: value.size,
            pointer: value.pointer,
            intermediate: value.intermediate,
        }
    }
    pub fn into_raw(self) -> BNConstantReference {
        BNConstantReference {
            value: self.value,
            size: self.size,
            pointer: self.pointer,
            intermediate: self.intermediate,
        }
    }
}

impl CoreArrayProvider for ConstantReference {
    type Raw = BNConstantReference;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for ConstantReference {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeConstantReferenceList(raw)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(*raw)
    }
}

/////////////////////////
// IndirectBranchInfo

pub struct IndirectBranchInfo {
    pub source_arch: CoreArchitecture,
    pub source_addr: u64,
    pub dest_arch: CoreArchitecture,
    pub dest_addr: u64,
    pub auto_defined: bool,
}

impl IndirectBranchInfo {
    pub fn from_raw(value: BNIndirectBranchInfo) -> Self {
        Self {
            source_arch: unsafe { CoreArchitecture::from_raw(value.sourceArch) },
            source_addr: value.sourceAddr,
            dest_arch: unsafe { CoreArchitecture::from_raw(value.destArch) },
            dest_addr: value.destAddr,
            auto_defined: value.autoDefined,
        }
    }
    pub fn into_raw(self) -> BNIndirectBranchInfo {
        BNIndirectBranchInfo {
            sourceArch: self.source_arch.0,
            sourceAddr: self.source_addr,
            destArch: self.dest_arch.0,
            destAddr: self.dest_addr,
            autoDefined: self.auto_defined,
        }
    }
}

impl CoreArrayProvider for IndirectBranchInfo {
    type Raw = BNIndirectBranchInfo;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for IndirectBranchInfo {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeIndirectBranchList(raw)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(*raw)
    }
}

/////////////////////////
// HighlightStandardColor

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum HighlightStandardColor {
    //NoHighlightColor,
    BlueHighlightColor,
    GreenHighlightColor,
    CyanHighlightColor,
    RedHighlightColor,
    MagentaHighlightColor,
    YellowHighlightColor,
    OrangeHighlightColor,
    WhiteHighlightColor,
    BlackHighlightColor,
}

impl HighlightStandardColor {
    pub fn from_raw(value: BNHighlightStandardColor) -> Option<Self> {
        Some(match value {
            BNHighlightStandardColor::NoHighlightColor => return None,
            BNHighlightStandardColor::BlueHighlightColor => Self::BlueHighlightColor,
            BNHighlightStandardColor::GreenHighlightColor => Self::GreenHighlightColor,
            BNHighlightStandardColor::CyanHighlightColor => Self::CyanHighlightColor,
            BNHighlightStandardColor::RedHighlightColor => Self::RedHighlightColor,
            BNHighlightStandardColor::MagentaHighlightColor => Self::MagentaHighlightColor,
            BNHighlightStandardColor::YellowHighlightColor => Self::YellowHighlightColor,
            BNHighlightStandardColor::OrangeHighlightColor => Self::OrangeHighlightColor,
            BNHighlightStandardColor::WhiteHighlightColor => Self::WhiteHighlightColor,
            BNHighlightStandardColor::BlackHighlightColor => Self::BlackHighlightColor,
        })
    }
    pub fn into_raw(self) -> BNHighlightStandardColor {
        match self {
            //Self::NoHighlightColor => BNHighlightStandardColor::NoHighlightColor,
            Self::BlueHighlightColor => BNHighlightStandardColor::BlueHighlightColor,
            Self::GreenHighlightColor => BNHighlightStandardColor::GreenHighlightColor,
            Self::CyanHighlightColor => BNHighlightStandardColor::CyanHighlightColor,
            Self::RedHighlightColor => BNHighlightStandardColor::RedHighlightColor,
            Self::MagentaHighlightColor => BNHighlightStandardColor::MagentaHighlightColor,
            Self::YellowHighlightColor => BNHighlightStandardColor::YellowHighlightColor,
            Self::OrangeHighlightColor => BNHighlightStandardColor::OrangeHighlightColor,
            Self::WhiteHighlightColor => BNHighlightStandardColor::WhiteHighlightColor,
            Self::BlackHighlightColor => BNHighlightStandardColor::BlackHighlightColor,
        }
    }
}

/////////////////////////
// HighlightColor

#[derive(Debug, Copy, Clone)]
pub enum HighlightColor {
    NoHighlightColor {
        alpha: u8,
    },
    StandardHighlightColor {
        color: HighlightStandardColor,
        alpha: u8,
    },
    MixedHighlightColor {
        color: HighlightStandardColor,
        mix_color: HighlightStandardColor,
        mix: u8,
        alpha: u8,
    },
    CustomHighlightColor {
        r: u8,
        g: u8,
        b: u8,
        alpha: u8,
    },
}

impl HighlightColor {
    pub fn from_raw(raw: BNHighlightColor) -> Self {
        const HIGHLIGHT_COLOR: u32 = BNHighlightColorStyle::StandardHighlightColor as u32;
        const MIXED_HIGHLIGHT_COLOR: u32 = BNHighlightColorStyle::MixedHighlightColor as u32;
        const CUSTOM_HIGHLIHGT_COLOR: u32 = BNHighlightColorStyle::CustomHighlightColor as u32;
        match raw.style as u32 {
            HIGHLIGHT_COLOR => {
                let Some(color) = HighlightStandardColor::from_raw(raw.color) else {
                    // StandardHighlightColor with NoHighlightColor, is no color
                    return Self::NoHighlightColor { alpha: raw.alpha };
                };
                Self::StandardHighlightColor {
                    color,
                    alpha: raw.alpha,
                }
            }
            MIXED_HIGHLIGHT_COLOR => {
                let Some(color) = HighlightStandardColor::from_raw(raw.color) else {
                    panic!("Highlight mixed color with no color");
                };
                let Some(mix_color) = HighlightStandardColor::from_raw(raw.mixColor) else {
                    panic!("Highlight mixed color with no mix_color");
                };
                Self::MixedHighlightColor {
                    color,
                    mix_color,
                    mix: raw.mix,
                    alpha: raw.alpha,
                }
            }
            CUSTOM_HIGHLIHGT_COLOR => Self::CustomHighlightColor {
                r: raw.r,
                g: raw.g,
                b: raw.b,
                alpha: raw.alpha,
            },
            // other color style is just no color
            _ => Self::NoHighlightColor { alpha: u8::MAX },
        }
    }

    pub fn into_raw(self) -> BNHighlightColor {
        let zeroed: BNHighlightColor = unsafe { core::mem::zeroed() };
        match self {
            Self::NoHighlightColor { alpha } => BNHighlightColor {
                style: BNHighlightColorStyle::StandardHighlightColor,
                color: BNHighlightStandardColor::NoHighlightColor,
                alpha,
                ..zeroed
            },
            Self::StandardHighlightColor { color, alpha } => BNHighlightColor {
                style: BNHighlightColorStyle::StandardHighlightColor,
                color: color.into_raw(),
                alpha,
                ..zeroed
            },
            Self::MixedHighlightColor {
                color,
                mix_color,
                mix,
                alpha,
            } => BNHighlightColor {
                color: color.into_raw(),
                mixColor: mix_color.into_raw(),
                mix,
                alpha,
                ..zeroed
            },
            Self::CustomHighlightColor { r, g, b, alpha } => BNHighlightColor {
                r,
                g,
                b,
                alpha,
                ..zeroed
            },
        }
    }
}

/////////////////////////
// IntegerDisplayType

pub type IntegerDisplayType = binaryninjacore_sys::BNIntegerDisplayType;

/////////////////////////
// StackVariableReference

#[derive(Debug, Clone)]
pub struct StackVariableReference {
    _source_operand: u32,
    var_type: Conf<Type>,
    name: BnString,
    var: Variable,
    offset: i64,
    size: usize,
}

impl StackVariableReference {
    pub fn from_raw(value: BNStackVariableReference) -> Self {
        let var_type = Conf::new(
            unsafe { Type::from_raw(NonNull::new(value.type_).unwrap()) },
            value.typeConfidence,
        );
        let name = unsafe { BnString::from_raw(NonNull::new(value.name).unwrap()) };
        let var = unsafe { Variable::from_identifier(value.varIdentifier) };
        let offset = value.referencedOffset;
        let size = value.size;
        Self {
            _source_operand: value.sourceOperand,
            var_type,
            name,
            var,
            offset,
            size,
        }
    }
    pub fn variable(&self) -> &Variable {
        &self.var
    }
    pub fn variable_type(&self) -> Conf<&Type> {
        self.var_type.as_ref()
    }
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    pub fn offset(&self) -> i64 {
        self.offset
    }
    pub fn size(&self) -> usize {
        self.size
    }
}

impl CoreArrayProvider for StackVariableReference {
    type Raw = BNStackVariableReference;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for StackVariableReference {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeStackVariableReferenceList(raw, count)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(*raw), context)
    }
}

/////////////////////////
// RegisterStackAdjustment

#[derive(Debug, Copy, Clone)]
pub struct RegisterStackAdjustment<A: Architecture> {
    reg_id: u32,
    adjustment: Conf<i32>,
    arch: A::Handle,
}

impl<A: Architecture> RegisterStackAdjustment<A> {
    pub(crate) unsafe fn from_raw(value: BNRegisterStackAdjustment, arch: A::Handle) -> Self {
        RegisterStackAdjustment {
            reg_id: value.regStack,
            adjustment: Conf::new(value.adjustment, value.confidence),
            arch,
        }
    }
    pub(crate) fn into_raw(self) -> BNRegisterStackAdjustment {
        BNRegisterStackAdjustment {
            regStack: self.reg_id,
            adjustment: self.adjustment.contents,
            confidence: self.adjustment.confidence,
        }
    }
    pub fn new<I>(reg_id: u32, adjustment: I, arch_handle: A::Handle) -> Self
    where
        I: Into<Conf<i32>>,
    {
        Self {
            reg_id,
            adjustment: adjustment.into(),
            arch: arch_handle,
        }
    }
    pub const fn register_id(&self) -> u32 {
        self.reg_id
    }
    pub fn register(&self) -> A::Register {
        self.arch.borrow().register_from_id(self.reg_id).unwrap()
    }
}

impl<A: Architecture> CoreArrayProvider for RegisterStackAdjustment<A> {
    type Raw = BNRegisterStackAdjustment;
    type Context = A::Handle;
    type Wrapped<'a> = Self;
}

unsafe impl<A: Architecture> CoreArrayProviderInner for RegisterStackAdjustment<A> {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeRegisterStackAdjustments(raw)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(*raw, context.clone())
    }
}

/////////////////////////
// RegisterStackAdjustment

// NOTE only exists as part of an Array, never owned
pub struct MergedVariable {
    target: Variable,
    // droped by the CoreArrayProviderInner::free
    sources: ManuallyDrop<Array<Variable>>,
}

impl MergedVariable {
    pub fn target(&self) -> Variable {
        self.target
    }
    pub fn sources(&self) -> &Array<Variable> {
        &self.sources
    }
}

impl CoreArrayProvider for MergedVariable {
    type Raw = BNMergedVariable;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for MergedVariable {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeMergedVariableList(raw, count)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self {
            target: Variable::from_raw(raw.target),
            sources: ManuallyDrop::new(Array::new(raw.sources, raw.sourceCount, ())),
        }
    }
}

/////////////////////////
// UnresolvedIndirectBranches

// NOTE only exists as part of an Array, never owned
pub struct UnresolvedIndirectBranches(u64);

impl UnresolvedIndirectBranches {
    pub fn address(&self) -> u64 {
        self.0
    }
}

impl CoreArrayProvider for UnresolvedIndirectBranches {
    type Raw = u64;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for UnresolvedIndirectBranches {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeAddressList(raw)
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self(*raw)
    }
}

#[cfg(test)]
mod test {
    use crate::types::{FunctionParameter, TypeClass};

    use super::{Type, TypeBuilder};

    #[test]
    fn create_bool_type() {
        let type_builder = TypeBuilder::new(&Type::bool());
        assert_eq!(type_builder.type_class(), TypeClass::BoolTypeClass);
        assert_eq!(type_builder.width(), 1);
        assert!(type_builder.alignment() <= 1);
        //assert_eq!(type_builder.is_signed().contents, true);
        assert_eq!(type_builder.is_const().contents, false);
        assert_eq!(type_builder.is_floating_point(), false);
        assert!(type_builder.return_value().is_err());
        assert!(type_builder.calling_convention().is_err());
        let type_built = type_builder.finalize();
        assert_eq!(type_built, Type::bool());
    }

    #[test]
    fn create_function_type() {
        let expected_type = Type::function(
            &Type::int(4, true),
            &[
                FunctionParameter::new(Type::int(4, true), "a".to_string(), None),
                FunctionParameter::new(Type::int(4, true), "b".to_string(), None),
            ],
            false,
        );
        let type_builder = TypeBuilder::new(&expected_type);
        assert_eq!(type_builder.type_class(), TypeClass::FunctionTypeClass);
        assert_eq!(type_builder.is_floating_point(), false);
        assert_eq!(
            type_builder.return_value().unwrap().contents,
            Type::int(4, true)
        );
        //assert_eq!(type_builder.calling_convention(), CallingConvention);
        let type_built = type_builder.finalize();
        assert_eq!(type_built, expected_type);
    }
}
