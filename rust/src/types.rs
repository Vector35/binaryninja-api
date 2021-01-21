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

use binaryninjacore_sys::*;
use std::{fmt, mem, ptr, slice};

use crate::architecture::Architecture;
use crate::string::{BnStr, BnStrCompatible, BnString};

use crate::rc::*;

pub type ReferenceType = BNReferenceType;
pub type TypeClass = BNTypeClass;
pub type NamedTypeReferenceClass = BNNamedTypeReferenceClass;

//////////
// Type

#[derive(PartialEq, Eq, Hash)]
pub struct Type {
    pub(crate) handle: *mut BNType,
    pub(crate) confidence: u8,
}

impl Type {
    pub(crate) unsafe fn from_raw(handle: *mut BNType) -> Self {
        debug_assert!(!handle.is_null());

        Self {
            handle,
            // TODO : Remove this field and and make Confidence<Type>
            confidence: 255,
        }
    }

    // TODO : Implement type builders (how I did with structures)
    // pub(crate) unsafe fn from_builder(handle: *mut BNTypeBuilder) -> Self {
    //     debug_assert!(!handle.is_null());

    //     Self { handle }
    // }

    // TODO : Add this to a real doc_string:
    //   use binaryninja::types::Type;
    //   let bv = unsafe { BinaryView::from_raw(view) };
    //   let my_custom_type_1 = Type::named_int(5, false, "my_w");
    //   let my_custom_type_2 = Type::int(5, false);
    //   bv.define_user_type("int_1", &my_custom_type_1);
    //   bv.define_user_type("int_2", &my_custom_type_2);

    pub fn void() -> Self {
        unsafe { Type::from_raw(BNCreateVoidType()) }
    }

    pub fn bool() -> Self {
        unsafe { Type::from_raw(BNCreateBoolType()) }
    }

    pub fn char() -> Self {
        Type::int(1, true)
    }

    pub fn int(width: usize, is_signed: bool) -> Self {
        let mut is_signed = BoolWithConfidence::new(is_signed, 0);
        unsafe {
            Type::from_raw(BNCreateIntegerType(
                width,
                &mut is_signed.0,
                BnString::new("").as_ptr() as *mut _,
            ))
        }
    }

    pub fn named_int<S: BnStrCompatible>(width: usize, is_signed: bool, alt_name: S) -> Self {
        let mut is_signed = BoolWithConfidence::new(is_signed, 0);
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.as_bytes_with_nul(); // This segfaulted once, so the above version is there if we need to change to it, but in theory this is copied into a `const string&` on the C++ side; I'm just not 100% confident that a constant reference copies data

        unsafe {
            Type::from_raw(BNCreateIntegerType(
                width,
                &mut is_signed.0,
                alt_name.as_ref().as_ptr() as _,
            ))
        }
    }

    pub fn float(width: usize) -> Self {
        unsafe {
            Type::from_raw(BNCreateFloatType(
                width,
                BnString::new("").as_ptr() as *mut _,
            ))
        }
    }

    pub fn named_float<S: BnStrCompatible>(width: usize, alt_name: S) -> Self {
        // let alt_name = BnString::new(alt_name);
        let alt_name = alt_name.as_bytes_with_nul(); // See same line in `named_int` above

        unsafe { Type::from_raw(BNCreateFloatType(width, alt_name.as_ref().as_ptr() as _)) }
    }

    pub fn array(t: &Type, count: u64) -> Self {
        let mut type_conf = TypeWithConfidence::new(&t, t.confidence);
        unsafe { Type::from_raw(BNCreateArrayType(&mut type_conf.0, count)) }
    }

    pub fn structure_type(structure_type: &mut Structure) -> Self {
        unsafe { Type::from_raw(BNCreateStructureType(structure_type.handle())) }
    }

    // TODO : Create enumeration type and finish implementing this
    // pub fn enumeration<A: Architecture>(
    //     arch: A,
    //     enum_type: Enumeration,
    //     width: usize,
    //     is_signed: bool,
    // ) -> Self {
    //     unsafe { Type::from_raw(BNCreateEnumerationType(arch, enum_type, width, is_signed)) }
    // }

    pub fn named_type(type_reference: NamedTypeReference) -> Self {
        unsafe {
            Type::from_raw(BNFinalizeTypeBuilder(BNCreateNamedTypeReferenceBuilder(
                type_reference.handle,
                0,
                1,
            )))
        }
    }

    pub fn named_type_from_type<S: BnStrCompatible>(name: S, t: &Type) -> Self {
        let mut name = QualifiedName::from(name);

        unsafe {
            Type::from_raw(BNFinalizeTypeBuilder(
                BNCreateNamedTypeReferenceBuilderFromTypeAndId(
                    BnString::new("").as_ptr() as *mut _,
                    &mut name.0, // BNCreateNamedTypeReferenceBuilderFromTypeAndId copy's qualified the name
                    t.handle,
                ),
            ))
        }
    }

    // TODO : BNCreateFunctionType

    pub fn pointer<A: Architecture>(arch: &A, t: &Type) -> Self {
        let mut is_const = BoolWithConfidence::new(false, 0);
        let mut is_volatile = BoolWithConfidence::new(false, 0);
        let mut type_conf = TypeWithConfidence::new(&t, t.confidence);
        unsafe {
            Type::from_raw(BNCreatePointerType(
                arch.as_ref().0,
                &mut type_conf.0,
                &mut is_const.0,
                &mut is_volatile.0,
                ReferenceType::PointerReferenceType,
            ))
        }
    }

    pub fn const_pointer<A: Architecture>(arch: &A, t: &Type) -> Self {
        let mut is_const = BoolWithConfidence::new(true, 0);
        let mut is_volatile = BoolWithConfidence::new(false, 0);
        let mut type_conf = TypeWithConfidence::new(&t, t.confidence);
        unsafe {
            Type::from_raw(BNCreatePointerType(
                arch.as_ref().0,
                &mut type_conf.0,
                &mut is_const.0,
                &mut is_volatile.0,
                ReferenceType::PointerReferenceType,
            ))
        }
    }

    pub fn pointer_with_options<A: Architecture>(
        arch: &A,
        t: &Type,
        is_const: bool,
        is_volatile: bool,
        ref_type: Option<ReferenceType>,
    ) -> Self {
        let mut is_const = BoolWithConfidence::new(is_const, 0);
        let mut is_volatile = BoolWithConfidence::new(is_volatile, 0);
        let mut type_conf = TypeWithConfidence::new(&t, t.confidence);
        unsafe {
            Type::from_raw(BNCreatePointerType(
                arch.as_ref().0,
                &mut type_conf.0,
                &mut is_const.0,
                &mut is_volatile.0,
                ref_type.unwrap_or_else(|| ReferenceType::PointerReferenceType),
            ))
        }
    }

    pub fn generate_auto_demangled_type_id<'a, S: BnStrCompatible>(name: S) -> &'a BnStr {
        let mut name = QualifiedName::from(name);
        unsafe { BnStr::from_raw(BNGenerateAutoDemangledTypeId(&mut name.0)) }
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
        Ref::new(Self {
            handle: BNNewTypeReference(handle.handle),
            confidence: handle.confidence,
        })
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

///////////////
// Structure

#[derive(PartialEq, Eq, Hash)]
pub struct Structure {
    pub builder: *mut BNStructureBuilder,
    pub handle: Option<*mut BNStructure>,
}

// TODO : Throw asserts or return results?
impl Structure {
    // TODO : Turn this into a real docstring
    // // Includes
    // use binaryninja::types::{Structure, Type};

    // // Define struct, set size (in bytes)
    // let mut my_custom_struct = Structure::new();
    // my_custom_struct.set_width(17);

    // // Create some fields for the struct
    // let field_1 = Type::named_int(5, false, "my_weird_int_type");
    // let field_2 = Type::int(4, false);
    // let field_3 = Type::int(8, false);

    // // Assign those fields
    // my_custom_struct.append(&field_1, "field_4");
    // my_custom_struct.insert(&field_1, "field_1", 0);
    // my_custom_struct.insert(&field_2, "field_2", 5);
    // my_custom_struct.insert(&field_3, "field_3", 9);

    // // Convert structure to type
    // let my_custom_structure_type = Type::structure_type(&mut my_custom_struct);

    // // Add the struct to the binary view to use in analysis
    // let bv = unsafe { BinaryView::from_raw(view) };
    // bv.define_user_type("my_custom_struct", &my_custom_structure_type);

    pub fn new() -> Self {
        Structure {
            builder: unsafe { BNCreateStructureBuilder() },
            handle: None,
        }
    }

    pub(crate) fn handle(&mut self) -> *mut BNStructure {
        if let Some(handle) = self.handle {
            handle
        } else {
            unsafe {
                self.handle = Some(BNFinalizeStructureBuilder(self.builder));
                BNFreeStructureBuilder(self.builder);
            }
            self.handle.unwrap()
        }
    }

    pub fn set_width(&self, width: u64) {
        assert!(self.handle.is_none());
        unsafe {
            BNSetStructureBuilderWidth(self.builder, width);
        }
    }

    pub fn get_width(&self) -> u64 {
        if let Some(structure_handle) = self.handle {
            unsafe { BNGetStructureWidth(structure_handle) }
        } else {
            unsafe { BNGetStructureBuilderWidth(self.builder) }
        }
    }

    pub fn append<S: BnStrCompatible>(&self, t: &Type, name: S) {
        assert!(self.handle.is_none());
        let mut type_conf = TypeWithConfidence::new(t, t.confidence);
        let name = name.as_bytes_with_nul();
        unsafe {
            BNAddStructureBuilderMember(
                self.builder,
                &mut type_conf.0,
                name.as_ref().as_ptr() as _,
            );
        }
    }

    pub fn insert<S: BnStrCompatible>(&self, t: &Type, name: S, offset: u64) {
        assert!(self.handle.is_none());
        let mut type_conf = TypeWithConfidence::new(t, t.confidence);
        let name = name.as_bytes_with_nul();
        unsafe {
            BNAddStructureBuilderMemberAtOffset(
                self.builder,
                &mut type_conf.0,
                name.as_ref().as_ptr() as _,
                offset,
            );
        }
    }

    // TODO : The other methods in the python version (alignment, packed, type, members, remove, replace, etc)
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
// BoolWithConfidence

pub struct BoolWithConfidence(BNBoolWithConfidence);

impl BoolWithConfidence {
    pub fn new(value: bool, confidence: u8) -> Self {
        BoolWithConfidence(BNBoolWithConfidence { value, confidence })
    }
}

////////////////////////
// TypeWithConfidence

pub struct TypeWithConfidence(BNTypeWithConfidence);

impl TypeWithConfidence {
    pub fn new(t: &Type, confidence: u8) -> Self {
        TypeWithConfidence(BNTypeWithConfidence {
            type_: t.handle,
            confidence,
        })
    }
}

////////////////////////
// NamedTypeReference

#[derive(PartialEq, Eq, Hash)]
pub struct NamedTypeReference {
    pub(crate) handle: *mut BNNamedTypeReference,
}

impl NamedTypeReference {
    pub fn new<S: BnStrCompatible>(
        type_class: NamedTypeReferenceClass,
        type_id: S,
        mut name: QualifiedName,
    ) -> Self {
        let type_id = type_id.as_bytes_with_nul();

        NamedTypeReference {
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
