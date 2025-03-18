// Copyright 2022-2024 Vector 35 Inc.
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

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::struct_grouper::group_structure;
use crate::PDBParserInstance;
use anyhow::{anyhow, Result};
use binaryninja::architecture::Architecture;
use binaryninja::binary_view::BinaryViewExt;
use binaryninja::calling_convention::CoreCallingConvention;
use binaryninja::confidence::{Conf, MAX_CONFIDENCE};
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::types::{
    BaseStructure, EnumerationBuilder, EnumerationMember, FunctionParameter, MemberAccess,
    MemberScope, NamedTypeReference, NamedTypeReferenceClass, QualifiedName, StructureBuilder,
    StructureMember, StructureType, Type, TypeBuilder, TypeClass,
};
use log::warn;
use pdb::Error::UnimplementedTypeKind;
use pdb::{
    ArgumentList, ArrayType, BaseClassType, BitfieldType, ClassKind, ClassType, EnumerateType,
    EnumerationType, FallibleIterator, FieldAttributes, FieldList, FunctionAttributes, Indirection,
    ItemFinder, MemberFunctionType, MemberType, MethodList, MethodType, ModifierType, NestedType,
    OverloadedMethodType, PointerMode, PointerType, PrimitiveKind, PrimitiveType, ProcedureType,
    Source, StaticMemberType, TypeData, TypeIndex, UnionType, Variant, VirtualBaseClassType,
    VirtualFunctionTablePointerType, VirtualFunctionTableType, VirtualTableShapeType,
};
use regex::Regex;

static BUILTIN_NAMES: &[&str] = &[
    "size_t",
    "ssize_t",
    "ptrdiff_t",
    "wchar_t",
    "wchar16",
    "wchar32",
    "bool",
];
// const VOID_RETURN_CONFIDENCE: u8 = 16;

/// Function types
#[derive(Debug, Clone)]
pub struct ParsedProcedureType {
    /// Interpreted type of the method, with thisptr, __return, etc
    pub method_type: Ref<Type>,
    /// Base method type right outta the pdb with no frills
    pub raw_method_type: Ref<Type>,
}

/// Bitfield member type, if we ever get around to implementing these
#[derive(Debug, Clone)]
pub struct ParsedBitfieldType {
    /// Size in bits
    pub size: u64,
    /// Bit offset in the current bitfield set
    pub position: u64,
    /// Underlying type of the whole bitfield set
    pub ty: Ref<Type>,
}

/// Parsed member of a class/structure, basically just binaryninja::StructureMember but with bitfields :(
#[derive(Debug, Clone)]
pub struct ParsedMember {
    /// Member type
    pub ty: Conf<Ref<Type>>,
    /// Member name
    pub name: String,
    /// Offset in structure
    pub offset: u64,
    /// Access flags
    pub access: MemberAccess,
    /// Scope doesn't really mean anything in binja
    pub scope: MemberScope,
    /// Bitfield size, if this is in a bitfield. Mainly you should just be checking for Some()
    pub bitfield_size: Option<u64>,
    /// Bit offset, if this is in a bitfield. Mainly you should just be checking for Some()
    pub bitfield_position: Option<u64>,
}

/// Parsed named method of a class
#[derive(Debug, Clone)]
pub struct ParsedMethod {
    /// Attributes from pdb-rs
    pub attributes: FieldAttributes,
    /// Name of method
    pub name: String,
    /// Type of the method + class info
    pub method_type: ParsedMemberFunction,
    /// Offset in class's virtual table, if virtual
    pub vtable_offset: Option<usize>,
}

/// One entry in a list of parsed methods? This is just here so overloaded methods have a struct to use
#[derive(Debug, Clone)]
pub struct ParsedMethodListEntry {
    /// Attributes from pdb-rs
    pub attributes: FieldAttributes,
    /// Type of the method + class info
    pub method_type: ParsedMemberFunction,
    /// Offset in class's virtual table, if virtual
    pub vtable_offset: Option<usize>,
}

/// Parsed member function type info
#[derive(Debug, Clone)]
pub struct ParsedMemberFunction {
    /// Attributes from pdb-rs
    pub attributes: FunctionAttributes,
    /// Parent class's name
    pub class_name: String,
    /// Interpreted type of the method, with thisptr, __return, etc
    pub method_type: Ref<Type>,
    /// Base method type right outta the pdb with no frills
    pub raw_method_type: Ref<Type>,
    /// Type of thisptr object, if relevant
    pub this_pointer_type: Option<Ref<Type>>,
    /// Adjust to thisptr at start, for virtual bases or something
    pub this_adjustment: usize,
}

/// Virtual base class, c++ nightmare fuel
#[derive(Debug, Clone)]
pub struct VirtualBaseClass {
    /// Base class name
    pub base_name: QualifiedName,
    /// Base class type
    pub base_type: Ref<Type>,
    /// Offset in this class where the base's fields are located
    pub base_offset: u64,
    /// Type of vbtable, probably
    pub base_table_type: Ref<Type>,
    /// Offset of this base in the vbtable
    pub base_table_offset: u64,
}

/// Mega enum of all the different types of types we can parse
#[derive(Debug, Clone)]
pub enum ParsedType {
    /// No info other than type data
    Bare(Ref<Type>),
    /// Named fully parsed class/enum/union/etc type
    Named(QualifiedName, Ref<Type>),
    /// Function procedure
    Procedure(ParsedProcedureType),
    /// Bitfield entries
    BitfieldType(ParsedBitfieldType),
    /// A list of members for a structure / union
    FieldList(Vec<ParsedType>),
    /// One member in a structure/union
    Member(ParsedMember),
    /// Base class name and offset details
    BaseClass(QualifiedName, StructureMember),
    /// One member in an enumeration
    Enumerate(EnumerationMember),
    /// List of arguments to a function
    ArgumentList(Vec<FunctionParameter>),
    /// Parsed member function type info
    MemberFunction(ParsedMemberFunction),
    /// Parsed named method of a class
    Method(ParsedMethod),
    /// List of all the methods in a class
    MethodList(Vec<ParsedMethodListEntry>),
    /// (Name, Overloads) equivalent to ParsedMethod
    OverloadedMethod(String, Vec<ParsedMethodListEntry>),
    /// Virtual table shape straight outta pdb-rs
    VTableShape(Vec<u8>),
    /// Also virtual table shape, but you want a pointer this time
    VTablePointer(Vec<u8>),
    /// Virtual base class, c++ nightmare fuel
    VBaseClass(VirtualBaseClass),
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum CV_call_t {
    NEAR_C = 1,
    FAR_C = 2,
    NEAR_PASCAL = 3,
    FAR_PASCAL = 4,
    NEAR_FAST = 5,
    FAR_FAST = 6,
    SKIPPED = 7,
    NEAR_STD = 8,
    FAR_STD = 9,
    NEAR_SYS = 10,
    FAR_SYS = 11,
    THISCALL = 12,
    MIPSCALL = 13,
    GENERIC = 14,
    ALPHACALL = 15,
    PPCCALL = 16,
    SHCALL = 17,
    ARMCALL = 18,
    AM33CALL = 19,
    TRICALL = 20,
    SH5CALL = 21,
    M32RCALL = 22,
    ALWAYS_INLINED = 23,
    NEAR_VECTOR = 24,
    RESERVED = 25,
}

impl TryFrom<u8> for CV_call_t {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Err(anyhow!("Empty calling convention")),
            1 => Ok(Self::NEAR_C),
            2 => Ok(Self::FAR_C),
            3 => Ok(Self::NEAR_PASCAL),
            4 => Ok(Self::FAR_PASCAL),
            5 => Ok(Self::NEAR_FAST),
            6 => Ok(Self::FAR_FAST),
            7 => Ok(Self::SKIPPED),
            8 => Ok(Self::NEAR_STD),
            9 => Ok(Self::FAR_STD),
            10 => Ok(Self::NEAR_SYS),
            11 => Ok(Self::FAR_SYS),
            12 => Ok(Self::THISCALL),
            13 => Ok(Self::MIPSCALL),
            14 => Ok(Self::GENERIC),
            15 => Ok(Self::ALPHACALL),
            16 => Ok(Self::PPCCALL),
            17 => Ok(Self::SHCALL),
            18 => Ok(Self::ARMCALL),
            19 => Ok(Self::AM33CALL),
            20 => Ok(Self::TRICALL),
            21 => Ok(Self::SH5CALL),
            22 => Ok(Self::M32RCALL),
            23 => Ok(Self::ALWAYS_INLINED),
            24 => Ok(Self::NEAR_VECTOR),
            25 => Ok(Self::RESERVED),
            e => Err(anyhow!("Unknown CV_call_t convention {}", e)),
        }
    }
}

/// This is all done in the parser instance namespace because the lifetimes are impossible to
/// wrangle otherwise.
impl<'a, S: Source<'a> + 'a> PDBParserInstance<'a, S> {
    /// Parse all the types in a pdb
    pub fn parse_types(
        &mut self,
        progress: Box<dyn Fn(usize, usize) -> Result<()> + '_>,
    ) -> Result<()> {
        // Hack: This is needed for primitive types but it's not defined in the pdb itself
        self.named_types
            .insert("HRESULT".into(), Type::int(4, true));

        let type_information = self.pdb.type_information()?;
        let mut finder = type_information.finder();

        let mut type_count = 0;

        // Do an initial pass on the types to find the full indexes for named types
        // In case something like an array needs to reference them before they're fully defined
        let mut prepass_types = type_information.iter();
        while let Some(ty) = prepass_types.next()? {
            type_count += 1;
            finder.update(&prepass_types);
            match ty.parse() {
                Ok(TypeData::Class(data)) => {
                    if !data.properties.forward_reference() {
                        self.full_type_indices.insert(
                            data.unique_name
                                .unwrap_or(data.name)
                                .to_string()
                                .to_string(),
                            ty.index(),
                        );
                    }
                }
                Ok(TypeData::Enumeration(data)) => {
                    if !data.properties.forward_reference() {
                        self.full_type_indices.insert(
                            data.unique_name
                                .unwrap_or(data.name)
                                .to_string()
                                .to_string(),
                            ty.index(),
                        );
                    }
                }
                Ok(TypeData::Union(data)) => {
                    if !data.properties.forward_reference() {
                        self.full_type_indices.insert(
                            data.unique_name
                                .unwrap_or(data.name)
                                .to_string()
                                .to_string(),
                            ty.index(),
                        );
                    }
                }
                _ => {}
            }
        }

        self.log(|| "Now parsing named types");

        // Parse the types we care about, so that recursion gives us parent relationships for free
        let mut types = type_information.iter();
        let mut i = 0;
        while let Some(ty) = types.next()? {
            i += 1;
            (progress)(i, type_count * 2)?;

            match ty.parse() {
                Ok(TypeData::Class(_)) | Ok(TypeData::Enumeration(_)) | Ok(TypeData::Union(_)) => {
                    self.handle_type_index(ty.index(), &mut finder)?;
                }
                _ => {}
            }

            assert!(self.namespace_stack.is_empty());
            assert!(self.type_stack.is_empty());
        }

        self.log(|| "Now parsing unused floating types");

        // Parse the rest because symbols often use them
        let mut postpass_types = type_information.iter();
        while let Some(ty) = postpass_types.next()? {
            i += 1;
            (progress)(i, type_count * 2)?;

            self.handle_type_index(ty.index(), &mut finder)?;
        }

        self.log(|| "Now adding all unreferenced named types");
        // Any referenced named types that are only forward-declared will cause missing type references,
        // so create empty types for those here.
        for parsed in self.indexed_types.values() {
            match parsed {
                ParsedType::Bare(ty) if ty.type_class() == TypeClass::NamedTypeReferenceClass => {
                    // See if we have this type
                    let name = ty
                        .get_named_type_reference()
                        .ok_or(anyhow!("expected ntr"))?
                        .name();
                    if Self::is_name_anonymous(&name) {
                        continue;
                    }
                    if self.named_types.contains_key(&name) {
                        continue;
                    }
                    // If the bv has this type, DebugInfo will just update us to reference it
                    if self.bv.type_by_name(name.to_owned()).is_some() {
                        continue;
                    }

                    self.log(|| format!("Got undefined but referenced named type: {}", &name));
                    let type_class = ty
                        .get_named_type_reference()
                        .ok_or(anyhow!("expected ntr"))?
                        .class();

                    let bare_type = match type_class {
                        NamedTypeReferenceClass::ClassNamedTypeClass => Type::structure(
                            StructureBuilder::new()
                                .structure_type(StructureType::ClassStructureType)
                                .finalize()
                                .as_ref(),
                        ),
                        // Missing typedefs are just going to become structures
                        NamedTypeReferenceClass::UnknownNamedTypeClass
                        | NamedTypeReferenceClass::TypedefNamedTypeClass
                        | NamedTypeReferenceClass::StructNamedTypeClass => {
                            Type::structure(StructureBuilder::new().finalize().as_ref())
                        }
                        NamedTypeReferenceClass::UnionNamedTypeClass => Type::structure(
                            StructureBuilder::new()
                                .structure_type(StructureType::UnionStructureType)
                                .finalize()
                                .as_ref(),
                        ),
                        NamedTypeReferenceClass::EnumNamedTypeClass => Type::enumeration(
                            EnumerationBuilder::new().finalize().as_ref(),
                            self.arch.default_integer_size().try_into()?,
                            false,
                        ),
                    };

                    self.log(|| format!("Bare type created: {} {}", &name, &bare_type));
                    self.named_types.insert(name, bare_type);
                }
                _ => {}
            }
        }

        // Cleanup a couple builtin names
        for &name in BUILTIN_NAMES {
            let builtin_qualified_name = QualifiedName::from(name);
            if self.named_types.contains_key(&builtin_qualified_name) {
                self.named_types.remove(&builtin_qualified_name);
                self.log(|| format!("Remove builtin type {}", name));
            }
        }

        static MEM: OnceLock<Regex> = OnceLock::new();
        let uint_regex = MEM.get_or_init(|| Regex::new(r"u?int\d+_t").unwrap());

        let float_regex = MEM.get_or_init(|| Regex::new(r"float\d+").unwrap());

        let mut remove_names = vec![];
        for name in self.named_types.keys() {
            let name_str = name.to_string();
            if uint_regex.is_match(&name_str) {
                remove_names.push(name.clone());
            }
            if float_regex.is_match(&name_str) {
                remove_names.push(name.clone());
            }
        }
        for name in remove_names {
            self.named_types.remove(&name);
            self.log(|| format!("Remove builtin type {}", &name));
        }

        Ok(())
    }

    /// Lookup a type in the parsed types by its index (ie for a procedure)
    pub(crate) fn lookup_type(
        &self,
        index: &TypeIndex,
        fancy_procs: bool,
    ) -> Result<Option<Ref<Type>>> {
        match self.indexed_types.get(index) {
            Some(ParsedType::Bare(ty)) => Ok(Some(ty.clone())),
            Some(ParsedType::Named(name, ty)) => {
                Ok(Some(Type::named_type_from_type(name.clone(), ty)))
            }
            Some(ParsedType::Procedure(ParsedProcedureType {
                method_type,
                raw_method_type,
            })) => {
                if fancy_procs {
                    Ok(Some(method_type.clone()))
                } else {
                    Ok(Some(raw_method_type.clone()))
                }
            }
            Some(ParsedType::MemberFunction(ParsedMemberFunction {
                method_type,
                raw_method_type,
                ..
            })) => {
                if fancy_procs {
                    Ok(Some(method_type.clone()))
                } else {
                    Ok(Some(raw_method_type.clone()))
                }
            }
            Some(ParsedType::Member(ParsedMember { ty, .. })) => Ok(Some(ty.contents.clone())),
            _ => Ok(None),
        }
    }

    /// Lookup a type in the parsed types and get a confidence value for it too
    pub(crate) fn lookup_type_conf(
        &self,
        index: &TypeIndex,
        fancy_procs: bool,
    ) -> Result<Option<Conf<Ref<Type>>>> {
        match self.lookup_type(index, fancy_procs)? {
            Some(ty) if ty.type_class() == TypeClass::VoidTypeClass => Ok(Some(Conf::new(ty, 0))),
            Some(ty) => {
                let mut confidence = MAX_CONFIDENCE;

                // Extra check here for void(void) functions, they should get minimum confidence since this
                // is the signature PDB uses when it doesn't actually know the signature
                if ty.type_class() == TypeClass::FunctionTypeClass {
                    if let Some(ret) = ty.return_value() {
                        if ret.contents.type_class() == TypeClass::VoidTypeClass {
                            if let Some(params) = ty.parameters() {
                                if params.len() == 0 {
                                    confidence = 0;
                                }
                            }
                        }
                    }
                }

                // Also array of bare function pointers (often seen in vtables)
                // These should not be marked confidently, as they don't actually know
                // the types of their contents

                if ty.type_class() == TypeClass::ArrayTypeClass {
                    if let Some(ptr) = ty.element_type() {
                        if ptr.contents.type_class() == TypeClass::PointerTypeClass {
                            if let Some(fun) = ptr.contents.target() {
                                if fun.contents.type_class() == TypeClass::FunctionTypeClass
                                    && fun
                                        .contents
                                        .parameters()
                                        .map(|pars| pars.len())
                                        .unwrap_or(0)
                                        == 0
                                {
                                    if let Some(ret) = fun.contents.return_value() {
                                        if ret.contents.type_class() == TypeClass::VoidTypeClass {
                                            confidence = 0;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                Ok(Some(Conf::new(ty, confidence)))
            }
            None => Ok(None),
        }
    }

    /// Parse and return a type by its index, used as lookup-or-parse
    fn handle_type_index(
        &mut self,
        ty: TypeIndex,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<&ParsedType>> {
        if let None = self.indexed_types.get(&ty) {
            self.log(|| format!("Parsing Type {:x?} ", ty));

            match finder.find(ty).and_then(|item| item.parse()) {
                Ok(data) => {
                    self.type_stack.push(ty);
                    let handled = self.handle_type(&data, finder);
                    self.type_stack.pop();

                    match handled {
                        Ok(Some(parsed)) => {
                            self.log(|| format!("Type {} parsed into: {:?}", ty, parsed));
                            match &*parsed {
                                ParsedType::Named(name, parsed) => {
                                    // PDB does this thing where anonymous inner types are represented as
                                    // some_type::<anonymous-tag>
                                    if !Self::is_name_anonymous(name) {
                                        if let Some(_old) =
                                            self.named_types.insert(name.clone(), parsed.clone())
                                        {
                                            warn!("Found two types both named `{}`, only one will be used.", name);
                                        }
                                    }
                                }
                                _ => {}
                            }
                            self.indexed_types.insert(ty, *parsed);
                        }
                        e => {
                            self.log(|| format!("Error parsing type {}: {:x?}", ty, e));
                        }
                    }
                }
                Err(UnimplementedTypeKind(k)) if k != 0 => {
                    warn!("Not parsing unimplemented type {}: kind {:x?}", ty, k);
                }
                Err(e) => {
                    self.log(|| format!("Could not parse type: {}: {}", ty, e));
                }
            };
        }

        Ok(self.indexed_types.get(&ty))
    }

    /// Parse a new type's data
    fn handle_type(
        &mut self,
        data: &TypeData,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        match data {
            TypeData::Primitive(data) => Ok(self.handle_primitive_type(data, finder)?),
            TypeData::Class(data) => Ok(self.handle_class_type(data, finder)?),
            TypeData::Member(data) => Ok(self.handle_member_type(data, finder)?),
            TypeData::MemberFunction(data) => Ok(self.handle_member_function_type(data, finder)?),
            TypeData::OverloadedMethod(data) => {
                Ok(self.handle_overloaded_method_type(data, finder)?)
            }
            TypeData::Method(data) => Ok(self.handle_method_type(data, finder)?),
            TypeData::StaticMember(data) => Ok(self.handle_static_member_type(data, finder)?),
            TypeData::Nested(data) => Ok(self.handle_nested_type(data, finder)?),
            TypeData::BaseClass(data) => Ok(self.handle_base_class_type(data, finder)?),
            TypeData::VirtualBaseClass(data) => {
                Ok(self.handle_virtual_base_class_type(data, finder)?)
            }
            TypeData::VirtualFunctionTable(data) => {
                Ok(self.handle_virtual_function_table_type(data, finder)?)
            }
            TypeData::VirtualTableShape(data) => {
                Ok(self.handle_virtual_table_shape_type(data, finder)?)
            }
            TypeData::VirtualFunctionTablePointer(data) => {
                Ok(self.handle_virtual_function_table_pointer_type(data, finder)?)
            }
            TypeData::Procedure(data) => Ok(self.handle_procedure_type(data, finder)?),
            TypeData::Pointer(data) => Ok(self.handle_pointer_type(data, finder)?),
            TypeData::Modifier(data) => Ok(self.handle_modifier_type(data, finder)?),
            TypeData::Enumeration(data) => Ok(self.handle_enumeration_type(data, finder)?),
            TypeData::Enumerate(data) => Ok(self.handle_enumerate_type(data, finder)?),
            TypeData::Array(data) => Ok(self.handle_array_type(data, finder)?),
            TypeData::Union(data) => Ok(self.handle_union_type(data, finder)?),
            TypeData::Bitfield(data) => Ok(self.handle_bitfield_type(data, finder)?),
            TypeData::FieldList(data) => Ok(self.handle_field_list_type(data, finder)?),
            TypeData::ArgumentList(data) => Ok(self.handle_argument_list_type(data, finder)?),
            TypeData::MethodList(data) => Ok(self.handle_method_list_type(data, finder)?),
            _ => Err(anyhow!("Unknown typedata")),
        }
    }

    /// Get the raw (mangled) name out of a type, if possible
    fn type_data_to_raw_name(data: &TypeData) -> Option<String> {
        match data {
            TypeData::Class(data) => Some(
                data.unique_name
                    .unwrap_or(data.name)
                    .to_string()
                    .to_string(),
            ),
            TypeData::Enumeration(data) => Some(
                data.unique_name
                    .unwrap_or(data.name)
                    .to_string()
                    .to_string(),
            ),
            TypeData::Union(data) => Some(
                data.unique_name
                    .unwrap_or(data.name)
                    .to_string()
                    .to_string(),
            ),
            _ => None,
        }
    }

    fn handle_primitive_type(
        &mut self,
        data: &PrimitiveType,
        _finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Primitive type: {:x?}", data));
        let base = match data.kind {
            PrimitiveKind::NoType => Ok(Type::void()),
            PrimitiveKind::Void => Ok(Type::void()),
            PrimitiveKind::Char => Ok(Type::int(1, true)),
            PrimitiveKind::UChar => Ok(Type::int(1, false)),
            PrimitiveKind::RChar => Ok(Type::int(1, true)),
            PrimitiveKind::WChar => Ok(Type::wide_char(2)),
            PrimitiveKind::RChar16 => Ok(Type::wide_char(2)),
            PrimitiveKind::RChar32 => Ok(Type::wide_char(4)),
            PrimitiveKind::I8 => Ok(Type::int(1, true)),
            PrimitiveKind::U8 => Ok(Type::int(1, false)),
            PrimitiveKind::Short => Ok(Type::int(2, true)),
            PrimitiveKind::UShort => Ok(Type::int(2, false)),
            PrimitiveKind::I16 => Ok(Type::int(2, true)),
            PrimitiveKind::U16 => Ok(Type::int(2, false)),
            PrimitiveKind::Long => Ok(Type::int(4, true)),
            PrimitiveKind::ULong => Ok(Type::int(4, false)),
            PrimitiveKind::I32 => Ok(Type::int(4, true)),
            PrimitiveKind::U32 => Ok(Type::int(4, false)),
            PrimitiveKind::Quad => Ok(Type::int(8, true)),
            PrimitiveKind::UQuad => Ok(Type::int(8, false)),
            PrimitiveKind::I64 => Ok(Type::int(8, true)),
            PrimitiveKind::U64 => Ok(Type::int(8, false)),
            PrimitiveKind::Octa => Ok(Type::int(16, true)),
            PrimitiveKind::UOcta => Ok(Type::int(16, false)),
            PrimitiveKind::I128 => Ok(Type::int(16, true)),
            PrimitiveKind::U128 => Ok(Type::int(16, false)),
            PrimitiveKind::F16 => Ok(Type::float(2)),
            PrimitiveKind::F32 => Ok(Type::float(4)),
            PrimitiveKind::F32PP => Ok(Type::float(4)),
            PrimitiveKind::F48 => Ok(Type::float(6)),
            PrimitiveKind::F64 => Ok(Type::float(8)),
            PrimitiveKind::F80 => Ok(Type::float(10)),
            PrimitiveKind::F128 => Ok(Type::float(16)),
            PrimitiveKind::Complex32 => Err(anyhow!("Complex32 unimplmented")),
            PrimitiveKind::Complex64 => Err(anyhow!("Complex64 unimplmented")),
            PrimitiveKind::Complex80 => Err(anyhow!("Complex80 unimplmented")),
            PrimitiveKind::Complex128 => Err(anyhow!("Complex128 unimplmented")),
            PrimitiveKind::Bool8 => Ok(Type::int(1, false)),
            PrimitiveKind::Bool16 => Ok(Type::int(2, false)),
            PrimitiveKind::Bool32 => Ok(Type::int(4, false)),
            PrimitiveKind::Bool64 => Ok(Type::int(8, false)),
            // Hack: this isn't always defined
            PrimitiveKind::HRESULT => Ok(Type::named_type_from_type(
                "HRESULT",
                Type::int(4, true).as_ref(),
            )),
            _ => Err(anyhow!("Unknown type unimplmented")),
        }?;

        // TODO: Pointer suffix is not exposed
        match data.indirection {
            Some(Indirection::Near16) => Ok(Some(Box::new(ParsedType::Bare(Type::pointer(
                &self.arch, &base,
            ))))),
            Some(Indirection::Far16) => Ok(Some(Box::new(ParsedType::Bare(Type::pointer(
                &self.arch, &base,
            ))))),
            Some(Indirection::Huge16) => Ok(Some(Box::new(ParsedType::Bare(Type::pointer(
                &self.arch, &base,
            ))))),
            Some(Indirection::Near32) => Ok(Some(Box::new(ParsedType::Bare(Type::pointer(
                &self.arch, &base,
            ))))),
            Some(Indirection::Far32) => Ok(Some(Box::new(ParsedType::Bare(Type::pointer(
                &self.arch, &base,
            ))))),
            Some(Indirection::Near64) => Ok(Some(Box::new(ParsedType::Bare(Type::pointer(
                &self.arch, &base,
            ))))),
            Some(Indirection::Near128) => Ok(Some(Box::new(ParsedType::Bare(Type::pointer(
                &self.arch, &base,
            ))))),
            None => Ok(Some(Box::new(ParsedType::Bare(base)))),
        }
    }

    fn handle_class_type(
        &mut self,
        data: &ClassType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Class type: {:x?}", data));

        let raw_class_name = data.name.to_string();
        let class_name = QualifiedName::from(raw_class_name);

        self.log(|| format!("Named: {}", class_name));

        if data.properties.forward_reference() {
            // Try and find it first
            if let Some(existing) = self.named_types.get(&class_name) {
                return Ok(Some(Box::new(ParsedType::Bare(
                    Type::named_type_from_type(class_name, existing),
                ))));
            }

            let ntr_class = match data.kind {
                ClassKind::Class => NamedTypeReferenceClass::ClassNamedTypeClass,
                ClassKind::Struct => NamedTypeReferenceClass::StructNamedTypeClass,
                ClassKind::Interface => NamedTypeReferenceClass::StructNamedTypeClass,
            };
            return Ok(Some(Box::new(ParsedType::Bare(Type::named_type(
                &NamedTypeReference::new(ntr_class, class_name),
            )))));
        }

        let struct_kind = match &data.kind {
            ClassKind::Class => StructureType::ClassStructureType,
            ClassKind::Struct => StructureType::StructStructureType,
            ClassKind::Interface => StructureType::StructStructureType,
        };

        let mut structure = StructureBuilder::new();
        structure.structure_type(struct_kind);
        structure.width(data.size);
        structure.packed(data.properties.packed());

        if let Some(fields) = data.fields {
            self.namespace_stack.push(class_name.to_string());
            let success = self.parse_structure_fields(&mut structure, fields, finder);
            self.namespace_stack.pop();
            let _ = success?;
        }

        let new_type = Type::structure(structure.finalize().as_ref());
        Ok(Some(Box::new(ParsedType::Named(class_name, new_type))))
    }

    /// Handle all the structure field parsing for a given field list, putting the fields into a struct
    fn parse_structure_fields(
        &mut self,
        structure: &mut StructureBuilder,
        fields: TypeIndex,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<()> {
        let mut base_classes = vec![];
        let mut virt_methods = HashMap::new();
        let mut non_virt_methods = Vec::new();

        let mut members = vec![];

        match self.handle_type_index(fields, finder)? {
            Some(ParsedType::FieldList(fields)) => {
                for field in fields {
                    match field {
                        ParsedType::Member(member) => {
                            members.push(member.clone());
                        }
                        b @ ParsedType::BaseClass(..) => {
                            base_classes.push(b.clone());
                        }
                        b @ ParsedType::VBaseClass(..) => {
                            base_classes.push(b.clone());
                        }
                        ParsedType::Named(..) => {}
                        ParsedType::VTablePointer(_vt) => {}
                        ParsedType::Method(method) => {
                            if let Some(offset) = method.vtable_offset {
                                virt_methods.insert(
                                    offset,
                                    (method.name.clone(), method.method_type.clone()),
                                );
                            } else {
                                non_virt_methods
                                    .push((method.name.clone(), method.method_type.clone()));
                            }
                        }
                        ParsedType::OverloadedMethod(name, methods) => {
                            for method in methods {
                                if let Some(offset) = method.vtable_offset {
                                    virt_methods
                                        .insert(offset, (name.clone(), method.method_type.clone()));
                                }
                            }
                        }
                        f => {
                            return Err(anyhow!("Unexpected field type {:?}", f));
                        }
                    }
                }
            }
            Some(_) => {
                return Err(anyhow!(
                    "Structure fields list did not parse into member list?"
                ));
            }
            // No fields?
            None => {}
        }

        // Combine bitfields into structures
        let mut combined_bitfield_members = vec![];
        let mut last_bitfield_offset = u64::MAX;
        let mut last_bitfield_pos = u64::MAX;
        let mut last_bitfield_idx = 0;
        let mut bitfield_builder: Option<StructureBuilder> = None;

        fn bitfield_name(offset: u64, idx: u64) -> String {
            if idx > 0 {
                format!("__bitfield{:x}_{}", offset, idx)
            } else {
                format!("__bitfield{:x}", offset)
            }
        }

        for m in members {
            match (m.bitfield_position, m.bitfield_size) {
                (Some(pos), Some(_size)) => {
                    if last_bitfield_offset != m.offset || last_bitfield_pos >= pos {
                        if let Some(mut builder) = bitfield_builder.take() {
                            combined_bitfield_members.push(ParsedMember {
                                ty: Conf::new(
                                    Type::structure(builder.finalize().as_ref()),
                                    MAX_CONFIDENCE,
                                ),
                                name: bitfield_name(last_bitfield_offset, last_bitfield_idx),
                                offset: last_bitfield_offset,
                                access: MemberAccess::PublicAccess,
                                scope: MemberScope::NoScope,
                                bitfield_size: None,
                                bitfield_position: None,
                            });
                        }
                        let mut new_builder = StructureBuilder::new();
                        new_builder.structure_type(StructureType::UnionStructureType);
                        new_builder.width(m.ty.contents.width());
                        bitfield_builder = Some(new_builder);

                        if last_bitfield_offset != m.offset {
                            last_bitfield_idx = 0;
                        } else {
                            last_bitfield_idx += 1;
                        }
                    }

                    last_bitfield_pos = pos;
                    last_bitfield_offset = m.offset;
                    bitfield_builder
                        .as_mut()
                        .expect("Invariant")
                        .insert(&m.ty, m.name, 0, false, m.access, m.scope);
                }
                (None, None) => {
                    if let Some(mut builder) = bitfield_builder.take() {
                        combined_bitfield_members.push(ParsedMember {
                            ty: Conf::new(
                                Type::structure(builder.finalize().as_ref()),
                                MAX_CONFIDENCE,
                            ),
                            name: bitfield_name(last_bitfield_offset, last_bitfield_idx),
                            offset: last_bitfield_offset,
                            access: MemberAccess::PublicAccess,
                            scope: MemberScope::NoScope,
                            bitfield_size: None,
                            bitfield_position: None,
                        });
                    }
                    last_bitfield_offset = u64::MAX;
                    last_bitfield_pos = u64::MAX;
                    combined_bitfield_members.push(m);
                }
                e => return Err(anyhow!("Unexpected bitfield parameters {:?}", e)),
            }
        }
        if let Some(mut builder) = bitfield_builder.take() {
            combined_bitfield_members.push(ParsedMember {
                ty: Conf::new(Type::structure(builder.finalize().as_ref()), MAX_CONFIDENCE),
                name: bitfield_name(last_bitfield_offset, last_bitfield_idx),
                offset: last_bitfield_offset,
                access: MemberAccess::PublicAccess,
                scope: MemberScope::NoScope,
                bitfield_size: None,
                bitfield_position: None,
            });
        }
        members = combined_bitfield_members;
        group_structure(
            &format!(
                "`{}`",
                self.namespace_stack
                    .items
                    .last()
                    .ok_or_else(|| anyhow!("Expected class in ns stack"))?
            ),
            &members,
            structure,
        )?;

        let mut bases = vec![];

        for base_class in &base_classes {
            match base_class {
                ParsedType::BaseClass(name, base) => {
                    let ntr_class = match self.named_types.get(name) {
                        Some(ty) if ty.type_class() == TypeClass::StructureTypeClass => {
                            match ty.get_structure() {
                                Some(str)
                                    if str.structure_type()
                                        == StructureType::StructStructureType =>
                                {
                                    NamedTypeReferenceClass::StructNamedTypeClass
                                }
                                Some(str)
                                    if str.structure_type()
                                        == StructureType::ClassStructureType =>
                                {
                                    NamedTypeReferenceClass::ClassNamedTypeClass
                                }
                                _ => NamedTypeReferenceClass::StructNamedTypeClass,
                            }
                        }
                        _ => NamedTypeReferenceClass::StructNamedTypeClass,
                    };
                    bases.push(BaseStructure::new(
                        NamedTypeReference::new(ntr_class, name.clone()),
                        base.offset,
                        base.ty.contents.width(),
                    ));
                }
                ParsedType::VBaseClass(VirtualBaseClass {
                    base_name,
                    base_type,
                    base_offset,
                    ..
                }) => {
                    let ntr_class = match self.named_types.get(base_name) {
                        Some(ty) if ty.type_class() == TypeClass::StructureTypeClass => {
                            match ty.get_structure() {
                                Some(str)
                                    if str.structure_type()
                                        == StructureType::StructStructureType =>
                                {
                                    NamedTypeReferenceClass::StructNamedTypeClass
                                }
                                Some(str)
                                    if str.structure_type()
                                        == StructureType::ClassStructureType =>
                                {
                                    NamedTypeReferenceClass::ClassNamedTypeClass
                                }
                                _ => NamedTypeReferenceClass::StructNamedTypeClass,
                            }
                        }
                        _ => NamedTypeReferenceClass::StructNamedTypeClass,
                    };
                    bases.push(BaseStructure::new(
                        NamedTypeReference::new(ntr_class, base_name.clone()),
                        *base_offset,
                        base_type.width(),
                    ));
                    warn!(
                        "Class `{}` uses virtual inheritance. Type information may be inaccurate.",
                        self.namespace_stack
                            .items
                            .last()
                            .ok_or_else(|| anyhow!("Expected class in ns stack"))?
                    );
                }
                e => return Err(anyhow!("Unexpected base class type: {:x?}", e)),
            }
        }

        if bases.len() > 1 {
            warn!(
                "Class `{}` has multiple base classes. Type information may be inaccurate.",
                self.namespace_stack
                    .items
                    .last()
                    .ok_or_else(|| anyhow!("Expected class in ns stack"))?
            );
        }
        structure.base_structures(&bases);

        if self.settings.get_bool_with_opts(
            "pdb.features.generateVTables",
            &mut self.settings_query_opts,
        ) && !virt_methods.is_empty()
        {
            let mut vt = StructureBuilder::new();

            let mut vt_bases = vec![];

            for base_class in &base_classes {
                match base_class {
                    ParsedType::BaseClass(base_name, _base_type) => {
                        let mut vt_base_name = base_name.clone();
                        vt_base_name.items.push("VTable".to_string());

                        match self.named_types.get(&vt_base_name) {
                            Some(vt_base_type)
                                if vt_base_type.type_class() == TypeClass::StructureTypeClass =>
                            {
                                let ntr_class =
                                    if vt_base_type.type_class() == TypeClass::StructureTypeClass {
                                        match vt_base_type.get_structure() {
                                            Some(str)
                                                if str.structure_type()
                                                    == StructureType::StructStructureType =>
                                            {
                                                NamedTypeReferenceClass::StructNamedTypeClass
                                            }
                                            Some(str)
                                                if str.structure_type()
                                                    == StructureType::ClassStructureType =>
                                            {
                                                NamedTypeReferenceClass::ClassNamedTypeClass
                                            }
                                            _ => NamedTypeReferenceClass::StructNamedTypeClass,
                                        }
                                    } else {
                                        NamedTypeReferenceClass::StructNamedTypeClass
                                    };
                                vt_bases.push(BaseStructure::new(
                                    NamedTypeReference::new(ntr_class, vt_base_name),
                                    0,
                                    vt_base_type.width(),
                                ));
                            }
                            e @ Some(_) => {
                                return Err(anyhow!("Unexpected vtable base class: {:?}", e))
                            }
                            None => {
                                // Parent might just not have a vtable
                            }
                        }
                    }
                    ParsedType::VBaseClass(_vbase) => {}
                    e => return Err(anyhow!("Unexpected base class type: {:x?}", e)),
                }
            }

            let mut min_width = 0;
            for base in &vt_bases {
                min_width = min_width.max(base.width);
            }

            vt.base_structures(&vt_bases);
            vt.propagates_data_var_refs(true);

            for (offset, (name, method)) in virt_methods {
                vt.insert(
                    &Conf::new(
                        Type::pointer(&self.arch, &Conf::new(method.method_type, MAX_CONFIDENCE)),
                        MAX_CONFIDENCE,
                    ),
                    &name,
                    offset as u64,
                    true,
                    MemberAccess::PublicAccess,
                    MemberScope::NoScope,
                );
                min_width = min_width.max((offset + self.arch.address_size()) as u64);
            }

            vt.width(min_width);

            let vt_type = Type::structure(vt.finalize().as_ref());
            // Need to insert a new named type for the vtable
            if self.namespace_stack.is_empty() {
                return Err(anyhow!("Expected class in ns stack"));
            }

            let mut vt_name = self.namespace_stack.clone();
            vt_name.items.push("VTable".to_string());
            self.named_types.insert(vt_name.clone(), vt_type.clone());

            let vt_pointer = Type::pointer(
                &self.arch,
                &Conf::new(
                    Type::named_type_from_type(vt_name, vt_type.as_ref()),
                    MAX_CONFIDENCE,
                ),
            );

            structure.insert(
                &Conf::new(vt_pointer, MAX_CONFIDENCE),
                "vtable",
                0,
                true,
                MemberAccess::PublicAccess,
                MemberScope::NoScope,
            );
        }

        Ok(())
    }

    fn handle_member_type(
        &mut self,
        data: &MemberType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Member type: {:x?}", data));

        let member_name = data.name.to_string();
        let member_offset = data.offset;
        let member_attrs = data.attributes;

        let access = match member_attrs.access() {
            1 /* CV_private */ => MemberAccess::PrivateAccess,
            2 /* CV_protected */ => MemberAccess::ProtectedAccess,
            3 /* CV_public */ => MemberAccess::PublicAccess,
            _ => return Err(anyhow!("Unknown access"))
        };

        let scope = MemberScope::NoScope;

        match self.try_type_index_to_bare(data.field_type, finder, true)? {
            Some(ty) => Ok(Some(Box::new(ParsedType::Member(ParsedMember {
                ty: Conf::new(ty, MAX_CONFIDENCE),
                name: member_name.into_owned(),
                offset: member_offset,
                access,
                scope,
                bitfield_position: None,
                bitfield_size: None,
            })))),
            None => match self.handle_type_index(data.field_type, finder)? {
                Some(ParsedType::BitfieldType(bitfield)) => {
                    Ok(Some(Box::new(ParsedType::Member(ParsedMember {
                        ty: Conf::new(bitfield.ty.clone(), MAX_CONFIDENCE),
                        name: member_name.into_owned(),
                        offset: member_offset,
                        access,
                        scope,
                        bitfield_position: Some(bitfield.position),
                        bitfield_size: Some(bitfield.size),
                    }))))
                }
                e => Err(anyhow!("Unexpected member type: {:x?}", e)),
            },
        }
    }

    fn handle_member_function_type(
        &mut self,
        data: &MemberFunctionType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got MemberFunction type: {:x?}", data));
        let return_type = self.type_index_to_bare(data.return_type, finder, false)?;

        let class_name = match self.handle_type_index(data.class_type, finder)? {
            Some(ParsedType::Bare(ty)) if ty.type_class() == TypeClass::NamedTypeReferenceClass => {
                ty.get_named_type_reference()
                    .ok_or(anyhow!("Expected NTR to have NTR"))?
                    .name()
                    .to_string()
            }
            e => return Err(anyhow!("Unexpected class type: {:x?}", e)),
        };

        let this_pointer_type = if let Some(this_pointer_type) = data.this_pointer_type {
            match self.handle_type_index(this_pointer_type, finder)? {
                Some(ParsedType::Bare(ty)) => Some(ty.clone()),
                e => return Err(anyhow!("Unexpected this pointer type: {:x?}", e)),
            }
        } else {
            None
        };

        let mut arguments = match self.handle_type_index(data.argument_list, finder)? {
            Some(ParsedType::ArgumentList(args)) => args.clone(),
            e => return Err(anyhow!("Unexpected argument list type: {:x?}", e)),
        };

        // It looks like pdb stores varargs by having the final argument be void
        let mut is_varargs = false;
        if let Some(last) = arguments.pop() {
            if last.ty.contents.as_ref().type_class() == TypeClass::VoidTypeClass {
                is_varargs = true;
            } else {
                arguments.push(last);
            }
        }

        let mut fancy_return_type = return_type.clone();
        let mut fancy_arguments = arguments.clone();

        if data.attributes.cxx_return_udt()
            || !self.can_fit_in_register(data.return_type, finder, true)
        {
            // Return UDT??
            // This probably means the return value got pushed to the stack
            fancy_return_type =
                Type::pointer(&self.arch, &Conf::new(return_type.clone(), MAX_CONFIDENCE));
            fancy_arguments.insert(
                0,
                FunctionParameter::new(
                    Conf::new(fancy_return_type.clone(), MAX_CONFIDENCE),
                    "__return".to_string(),
                    None,
                ),
            );
        }

        if let Some(this_ptr) = &this_pointer_type {
            self.insert_this_pointer(&mut fancy_arguments, this_ptr.clone())?;
        }

        let convention = self
            .cv_call_t_to_calling_convention(data.attributes.calling_convention())
            .map(|cc| Conf::new(cc, MAX_CONFIDENCE))
            .unwrap_or({
                if is_varargs {
                    Conf::new(self.cdecl_cc.clone(), MAX_CONFIDENCE)
                } else if this_pointer_type.is_some() {
                    Conf::new(self.thiscall_cc.clone(), MAX_CONFIDENCE)
                } else {
                    Conf::new(self.default_cc.clone(), 16)
                }
            });

        let func = Type::function_with_opts(
            &Conf::new(return_type, MAX_CONFIDENCE),
            arguments.as_slice(),
            is_varargs,
            convention.clone(),
            Conf::new(0, 0),
        );

        let fancy_func = Type::function_with_opts(
            &Conf::new(fancy_return_type, MAX_CONFIDENCE),
            fancy_arguments.as_slice(),
            is_varargs,
            convention,
            Conf::new(0, 0),
        );

        Ok(Some(Box::new(ParsedType::MemberFunction(
            ParsedMemberFunction {
                attributes: data.attributes,
                class_name,
                method_type: fancy_func,
                raw_method_type: func,
                this_pointer_type,
                this_adjustment: data.this_adjustment as usize,
            },
        ))))
    }

    fn handle_overloaded_method_type(
        &mut self,
        data: &OverloadedMethodType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got OverloadedMethod type: {:x?}", data));
        // This is just a MethodList in disguise
        let method_list = match self.handle_type_index(data.method_list, finder)? {
            Some(ParsedType::MethodList(list)) => list.clone(),
            e => return Err(anyhow!("Unexpected method list type: {:x?}", e)),
        };

        Ok(Some(Box::new(ParsedType::OverloadedMethod(
            data.name.to_string().to_string(),
            method_list,
        ))))
    }

    fn handle_method_type(
        &mut self,
        data: &MethodType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Method type: {:x?}", data));

        let member_function = match self.handle_type_index(data.method_type, finder)? {
            Some(ParsedType::MemberFunction(func)) => func.clone(),
            e => return Err(anyhow!("Unexpected method type {:?}", e)),
        };

        Ok(Some(Box::new(ParsedType::Method(ParsedMethod {
            attributes: data.attributes,
            name: data.name.to_string().to_string(),
            method_type: member_function,
            vtable_offset: data.vtable_offset.map(|o| o as usize),
        }))))
    }

    fn handle_static_member_type(
        &mut self,
        data: &StaticMemberType,
        _finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got StaticMember type: {:x?}", data));
        // TODO: Not handling these
        Ok(None)
    }

    fn handle_nested_type(
        &mut self,
        data: &NestedType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Nested type: {:x?}", data));
        let mut class_name_ns = self.namespace_stack.clone();
        class_name_ns.push(data.name.to_string().into());
        let ty = self.type_index_to_bare(data.nested_type, finder, false)?;
        Ok(Some(Box::new(ParsedType::Named(class_name_ns, ty))))
    }

    fn handle_base_class_type(
        &mut self,
        data: &BaseClassType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got BaseClass type: {:x?}", data));

        let base_offset = data.offset;
        let base_attrs = data.attributes;

        let (member_name, t) = match self.handle_type_index(data.base_class, finder)? {
            Some(ParsedType::Named(n, t)) => (n.clone(), t.clone()),
            Some(ParsedType::Bare(t)) if t.type_class() == TypeClass::NamedTypeReferenceClass => {
                let name = t
                    .get_named_type_reference()
                    .ok_or(anyhow!("Expected NTR to have NTR"))?
                    .name();
                (name, t.clone())
            }
            e => return Err(anyhow!("Unexpected base class type: {:x?}", e)),
        };

        // Try to resolve the full base type
        let resolved_type = match self.try_type_index_to_bare(data.base_class, finder, true)? {
            Some(ty) => Type::named_type_from_type(member_name.clone(), ty.as_ref()),
            None => t.clone(),
        };

        let access = match base_attrs.access() {
            1 /* CV_private */ => MemberAccess::PrivateAccess,
            2 /* CV_protected */ => MemberAccess::ProtectedAccess,
            3 /* CV_public */ => MemberAccess::PublicAccess,
            _ => return Err(anyhow!("Unknown access"))
        };

        let scope = MemberScope::NoScope;
        Ok(Some(Box::new(ParsedType::BaseClass(
            member_name.clone(),
            StructureMember::new(
                Conf::new(resolved_type, MAX_CONFIDENCE),
                member_name.to_string(),
                base_offset as u64,
                access,
                scope,
            ),
        ))))
    }

    fn handle_virtual_base_class_type(
        &mut self,
        data: &VirtualBaseClassType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got VirtualBaseClass type: {:x?}", data));

        let (n, ty) = match self.handle_type_index(data.base_class, finder)? {
            Some(ParsedType::Named(n, t)) => (n.clone(), t.clone()),
            Some(ParsedType::Bare(t)) if t.type_class() == TypeClass::NamedTypeReferenceClass => {
                let name = t
                    .get_named_type_reference()
                    .ok_or(anyhow!("Expected NTR to have NTR"))?
                    .name();
                (name, t.clone())
            }
            e => return Err(anyhow!("Unexpected base class type: {:x?}", e)),
        };

        // In addition to the base class, we also have a vbtable
        let vbptr_type = match self.handle_type_index(data.base_pointer, finder)? {
            Some(ParsedType::Bare(t)) => t.clone(),
            e => return Err(anyhow!("Unexpected virtual base pointer type: {:x?}", e)),
        };

        Ok(Some(Box::new(ParsedType::VBaseClass(VirtualBaseClass {
            base_name: n,
            base_type: ty,
            base_offset: data.base_pointer_offset as u64,
            base_table_type: vbptr_type,
            base_table_offset: data.virtual_base_offset as u64,
        }))))
    }

    fn handle_virtual_function_table_type(
        &mut self,
        data: &VirtualFunctionTableType,
        _finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got VirtualFunctionTableType type: {:x?}", data));
        Err(anyhow!("VirtualFunctionTableType unimplemented"))
    }

    fn handle_virtual_table_shape_type(
        &mut self,
        data: &VirtualTableShapeType,
        _finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got VirtualTableShapeType type: {:x?}", data));
        Ok(Some(Box::new(ParsedType::VTableShape(
            data.descriptors.clone(),
        ))))
    }

    fn handle_virtual_function_table_pointer_type(
        &mut self,
        data: &VirtualFunctionTablePointerType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got VirtualFunctionTablePointer type: {:x?}", data));
        let shape = match self.handle_type_index(data.table, finder)? {
            Some(ParsedType::VTablePointer(shape)) => shape.clone(),
            e => {
                return Err(anyhow!(
                    "Could not parse virtual function table pointer type: {:x?}",
                    e
                ))
            }
        };

        Ok(Some(Box::new(ParsedType::VTablePointer(shape))))
    }

    fn handle_procedure_type(
        &mut self,
        data: &ProcedureType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Procedure type: {:x?}", data));
        let return_type = if let Some(return_type_index) = data.return_type {
            self.try_type_index_to_bare(return_type_index, finder, false)?
        } else {
            None
        }
        .map(|r| Conf::new(r, MAX_CONFIDENCE))
        .unwrap_or(Conf::new(Type::void(), 0));

        let mut arguments = match self.handle_type_index(data.argument_list, finder)? {
            Some(ParsedType::ArgumentList(args)) => args.clone(),
            e => return Err(anyhow!("Unexpected argument list type: {:x?}", e)),
        };

        // It looks like pdb stores varargs by having the final argument be void
        let mut is_varargs = false;
        if let Some(last) = arguments.pop() {
            if last.ty.contents.as_ref().type_class() == TypeClass::VoidTypeClass {
                is_varargs = true;
            } else {
                arguments.push(last);
            }
        }

        let mut fancy_return_type = return_type.clone();
        let mut fancy_arguments = arguments.clone();

        let mut return_stacky = data.attributes.cxx_return_udt();
        if let Some(return_type_index) = data.return_type {
            return_stacky |= !self.can_fit_in_register(return_type_index, finder, true);
        }
        if return_stacky {
            // Stack return via a pointer in the first parameter
            fancy_return_type = Conf::new(
                Type::pointer(&self.arch, &return_type.clone()),
                MAX_CONFIDENCE,
            );
            fancy_arguments.insert(
                0,
                FunctionParameter::new(fancy_return_type.clone(), "__return".to_string(), None),
            );
        }

        let convention = self
            .cv_call_t_to_calling_convention(data.attributes.calling_convention())
            .map(|cc| Conf::new(cc, MAX_CONFIDENCE))
            .unwrap_or(Conf::new(self.default_cc.clone(), 0));
        self.log(|| format!("Convention: {:?}", convention));

        let func = Type::function_with_opts(
            &return_type,
            arguments.as_slice(),
            is_varargs,
            convention.clone(),
            Conf::new(0, 0),
        );

        let fancy_func = Type::function_with_opts(
            &fancy_return_type,
            fancy_arguments.as_slice(),
            is_varargs,
            convention,
            Conf::new(0, 0),
        );

        Ok(Some(Box::new(ParsedType::Procedure(ParsedProcedureType {
            method_type: fancy_func,
            raw_method_type: func,
        }))))
    }

    fn handle_pointer_type(
        &mut self,
        data: &PointerType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Pointer type: {:x?}", data));
        let base = match self.try_type_index_to_bare(data.underlying_type, finder, false)? {
            Some(ty) => Some(ty.clone()),
            None => match self.handle_type_index(data.underlying_type, finder)? {
                Some(ParsedType::VTableShape(descriptors)) => {
                    return Ok(Some(Box::new(ParsedType::VTablePointer(
                        descriptors.clone(),
                    ))));
                }
                _ => None,
            },
        };

        if let Some(base) = base {
            Ok(Some(Box::new(ParsedType::Bare(Type::pointer(
                &self.arch, &base,
            )))))
        } else {
            Ok(None)
        }
    }

    fn handle_modifier_type(
        &mut self,
        data: &ModifierType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Modifier type: {:x?}", data));
        let base = self.try_type_index_to_bare(data.underlying_type, finder, false)?;

        if let Some(base) = base {
            let builder = TypeBuilder::new(base.as_ref());
            builder.set_const(data.constant);
            builder.set_volatile(data.volatile);
            Ok(Some(Box::new(ParsedType::Bare(builder.finalize()))))
        } else {
            Ok(None)
        }
    }

    fn handle_enumeration_type(
        &mut self,
        data: &EnumerationType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Enumeration type: {:x?}", data));

        let raw_enum_name = data.name.to_string();
        let enum_name = QualifiedName::from(raw_enum_name);
        self.log(|| format!("Named: {}", enum_name));

        if data.properties.forward_reference() {
            // Try and find it first
            if let Some(existing) = self.named_types.get(&enum_name) {
                return Ok(Some(Box::new(ParsedType::Bare(
                    Type::named_type_from_type(enum_name, existing),
                ))));
            }

            let ntr_class = NamedTypeReferenceClass::EnumNamedTypeClass;
            return Ok(Some(Box::new(ParsedType::Bare(Type::named_type(
                &NamedTypeReference::new(ntr_class, enum_name),
            )))));
        }

        let mut enumeration = EnumerationBuilder::new();

        match self.handle_type_index(data.fields, finder)? {
            Some(ParsedType::FieldList(fields)) => {
                for field in fields {
                    match field {
                        ParsedType::Enumerate(member) => {
                            enumeration.insert(member.name.clone(), member.value);
                        }
                        e => return Err(anyhow!("Unexpected enumerate member: {:?}", e)),
                    }
                }
            }
            // No fields?
            None => {}
            e => return Err(anyhow!("Unexpected enumeration field list: {:?}", e)),
        }

        let underlying = match self.handle_type_index(data.underlying_type, finder)? {
            Some(ParsedType::Bare(ty)) => ty.clone(),
            e => return Err(anyhow!("Making enumeration from unexpected type: {:x?}", e)),
        };

        let new_type = Type::enumeration(
            enumeration.finalize().as_ref(),
            // TODO: This looks bad, look at the comment in [`Type::width`].
            (underlying.width() as usize).try_into()?,
            underlying.is_signed().contents,
        );

        Ok(Some(Box::new(ParsedType::Named(enum_name, new_type))))
    }

    fn handle_enumerate_type(
        &mut self,
        data: &EnumerateType,
        _finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Enumerate type: {:x?}", data));
        Ok(Some(Box::new(ParsedType::Enumerate(EnumerationMember {
            name: data.name.to_string().to_string(),
            value: match data.value {
                Variant::U8(v) => v as u64,
                Variant::U16(v) => v as u64,
                Variant::U32(v) => v as u64,
                Variant::U64(v) => v as u64,
                Variant::I8(v) => (v as i64) as u64,
                Variant::I16(v) => (v as i64) as u64,
                Variant::I32(v) => (v as i64) as u64,
                Variant::I64(v) => (v as i64) as u64,
            },
            default: false,
        }))))
    }

    fn handle_array_type(
        &mut self,
        data: &ArrayType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Array type: {:x?}", data));
        // PDB stores array sizes as TOTAL bytes not element count
        // So we need to look up the original type's size to know how many there are
        let base = self.try_type_index_to_bare(data.element_type, finder, true)?;

        if let Some(base) = base {
            let mut new_type = base;
            if new_type.width() == 0 {
                if new_type.width() == 0 {
                    return Err(anyhow!(
                        "Cannot calculate array of 0-size elements: {}",
                        new_type
                    ));
                }
            }

            let mut counts = data
                .dimensions
                .iter()
                .map(|t| *t as u64)
                .collect::<Vec<_>>();
            for i in 0..counts.len() {
                for j in i..counts.len() {
                    if counts[j] % new_type.width() != 0 {
                        return Err(anyhow!(
                            "Array stride {} is not a multiple of element {} size {}",
                            counts[j],
                            new_type,
                            new_type.width()
                        ));
                    }
                    counts[j] /= new_type.width();
                }

                new_type = Type::array(&new_type, counts[i]);
            }

            Ok(Some(Box::new(ParsedType::Bare(new_type))))
        } else {
            Ok(None)
        }
    }

    fn handle_union_type(
        &mut self,
        data: &UnionType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Union type: {:x?}", data));

        let raw_union_name = data.name.to_string();
        let union_name = QualifiedName::from(raw_union_name);
        self.log(|| format!("Named: {}", union_name));

        if data.properties.forward_reference() {
            // Try and find it first
            if let Some(existing) = self.named_types.get(&union_name) {
                return Ok(Some(Box::new(ParsedType::Bare(
                    Type::named_type_from_type(union_name, existing),
                ))));
            }

            let ntr_class = NamedTypeReferenceClass::UnionNamedTypeClass;
            return Ok(Some(Box::new(ParsedType::Bare(Type::named_type(
                &NamedTypeReference::new(ntr_class, union_name),
            )))));
        }

        let mut structure = StructureBuilder::new();
        structure.structure_type(StructureType::UnionStructureType);
        structure.width(data.size);

        self.namespace_stack.push(union_name.to_string());
        let success = self.parse_union_fields(&mut structure, data.fields, finder);
        self.namespace_stack.pop();
        let _ = success?;

        let new_type = Type::structure(structure.finalize().as_ref());
        Ok(Some(Box::new(ParsedType::Named(union_name, new_type))))
    }

    /// Parse the fields in a union's field list
    fn parse_union_fields(
        &mut self,
        structure: &mut StructureBuilder,
        fields: TypeIndex,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<()> {
        let mut union_groups = vec![];
        let mut last_union_group = u64::MAX;

        match self.handle_type_index(fields, finder) {
            Ok(Some(ParsedType::FieldList(fields))) => {
                for field in fields {
                    match field {
                        ParsedType::Member(member) => {
                            if member.offset <= last_union_group {
                                union_groups.push(vec![]);
                            }
                            last_union_group = member.offset;
                            union_groups
                                .last_mut()
                                .expect("invariant")
                                .push(member.clone());
                        }
                        ParsedType::Method(..) => {}
                        ParsedType::Named(..) => {}
                        e => return Err(anyhow!("Unexpected union member type {:?}", e)),
                    }
                }
            }
            e => return Err(anyhow!("Unexpected union field list type {:?}", e)),
        }

        for (i, group) in union_groups.into_iter().enumerate() {
            if group.len() == 1 {
                structure.insert(
                    &group[0].ty,
                    group[0].name.clone(),
                    group[0].offset,
                    false,
                    group[0].access,
                    group[0].scope,
                );
            } else {
                let mut inner_struct = StructureBuilder::new();
                for member in group {
                    inner_struct.insert(
                        &member.ty,
                        member.name.clone(),
                        member.offset,
                        false,
                        member.access,
                        member.scope,
                    );
                }
                structure.insert(
                    &Conf::new(
                        Type::structure(inner_struct.finalize().as_ref()),
                        MAX_CONFIDENCE,
                    ),
                    format!("__inner{:x}", i),
                    0,
                    false,
                    MemberAccess::PublicAccess,
                    MemberScope::NoScope,
                );
            }
        }

        Ok(())
    }

    fn handle_bitfield_type(
        &mut self,
        data: &BitfieldType,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got Bitfield type: {:x?}", data));
        Ok(self
            .try_type_index_to_bare(data.underlying_type, finder, true)?
            .map(|ty| {
                Box::new(ParsedType::BitfieldType(ParsedBitfieldType {
                    size: data.length as u64,
                    position: data.position as u64,
                    ty,
                }))
            }))
    }

    fn handle_field_list_type(
        &mut self,
        data: &FieldList,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got FieldList type: {:x?}", data));

        let mut fields = vec![];
        for (i, field) in data.fields.iter().enumerate() {
            match self.handle_type(field, finder)? {
                Some(f) => {
                    self.log(|| format!("Inner field {} parsed into {:?}", i, f));
                    fields.push(*f);
                }
                None => {
                    self.log(|| format!("Inner field {} parsed into None", i));
                }
            }
        }

        if let Some(cont) = data.continuation {
            match self.handle_type_index(cont, finder)? {
                Some(ParsedType::FieldList(cont_fields)) => {
                    fields.extend(cont_fields.clone());
                }
                None => {}
                f => {
                    return Err(anyhow!("Unexpected field list continuation {:?}", f));
                }
            }
        }
        Ok(Some(Box::new(ParsedType::FieldList(fields))))
    }

    fn handle_argument_list_type(
        &mut self,
        data: &ArgumentList,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got ArgumentList type: {:x?}", data));
        let mut args = vec![];
        for &arg in data.arguments.iter() {
            match self.try_type_index_to_bare(arg, finder, false)? {
                Some(ty) => {
                    // On x86_32, structures are stored on the stack directly
                    // On x64, they are put into pointers if they are not a int size
                    // TODO: Ugly hack
                    if self.arch.address_size() == 4 || Self::size_can_fit_in_register(ty.width()) {
                        args.push(FunctionParameter::new(
                            Conf::new(ty.clone(), MAX_CONFIDENCE),
                            "".to_string(),
                            None,
                        ));
                    } else {
                        args.push(FunctionParameter::new(
                            Conf::new(Type::pointer(self.arch.as_ref(), &ty), MAX_CONFIDENCE),
                            "".to_string(),
                            None,
                        ));
                    }
                }
                e => {
                    return Err(anyhow!("Unexpected argument type {:?}", e));
                }
            }
        }
        Ok(Some(Box::new(ParsedType::ArgumentList(args))))
    }

    fn handle_method_list_type(
        &mut self,
        data: &MethodList,
        finder: &mut ItemFinder<TypeIndex>,
    ) -> Result<Option<Box<ParsedType>>> {
        self.log(|| format!("Got MethodList type: {:x?}", data));

        let mut list = vec![];
        for method in &data.methods {
            match self.handle_type_index(method.method_type, finder)? {
                Some(ParsedType::MemberFunction(func)) => {
                    list.push(ParsedMethodListEntry {
                        attributes: method.attributes,
                        method_type: func.clone(),
                        vtable_offset: method.vtable_offset.map(|o| o as usize),
                    });
                }
                e => return Err(anyhow!("Unexpected method list entry: {:?}", e)),
            }
        }

        Ok(Some(Box::new(ParsedType::MethodList(list))))
    }

    /// Given a type index, get a bare binja type (or fail if not found)
    /// Optionally, set fully_resolve to true to parse and get the real type back in the case of NTRs
    fn type_index_to_bare(
        &mut self,
        index: TypeIndex,
        finder: &mut ItemFinder<TypeIndex>,
        fully_resolve: bool,
    ) -> Result<Ref<Type>> {
        match self.try_type_index_to_bare(index, finder, fully_resolve)? {
            Some(ty) => Ok(ty),
            None => Err(anyhow!("Unresolved expected type {:?}", index)),
        }
    }

    /// Given a type index, try to get a bare binja type
    /// Optionally, set fully_resolve to true to parse and get the real type back in the case of NTRs
    fn try_type_index_to_bare(
        &mut self,
        index: TypeIndex,
        finder: &mut ItemFinder<TypeIndex>,
        fully_resolve: bool,
    ) -> Result<Option<Ref<Type>>> {
        let (mut type_, inner) = match self.handle_type_index(index, finder)? {
            Some(ParsedType::Bare(ty)) => (ty.clone(), None),
            Some(ParsedType::Named(name, ty)) => (
                Type::named_type_from_type(name.to_owned(), ty),
                Some(ty.clone()),
            ),
            Some(ParsedType::Procedure(ParsedProcedureType { method_type, .. })) => {
                (method_type.clone(), Some(method_type.clone()))
            }
            Some(ParsedType::MemberFunction(ParsedMemberFunction { method_type, .. })) => {
                (method_type.clone(), Some(method_type.clone()))
            }
            Some(ParsedType::Member(ParsedMember { ty, .. })) => {
                (ty.contents.clone(), Some(ty.contents.clone()))
            }
            _ => return Ok(None),
        };

        if type_.type_class() == TypeClass::NamedTypeReferenceClass {
            if type_.width() == 0 {
                // Replace empty NTR with fully parsed NTR, if we can
                let name = type_
                    .get_named_type_reference()
                    .ok_or(anyhow!("expected ntr"))?
                    .name();
                if let Some(full_ntr) = self.named_types.get(&name) {
                    type_ = Type::named_type_from_type(name, full_ntr.as_ref());
                }
            }
        }

        if !fully_resolve {
            return Ok(Some(type_));
        }

        if type_.type_class() == TypeClass::NamedTypeReferenceClass {
            if type_.width() == 0 {
                // Look up raw name of this type
                if let Ok(raw) = finder.find(index) {
                    if let Ok(parsed) = raw.parse() {
                        // Have to use raw name here because self.full_type_indices uses raw name
                        // for some reason
                        if let Some(raw_name) = Self::type_data_to_raw_name(&parsed) {
                            if let Some(&full_index) = self.full_type_indices.get(&raw_name) {
                                if let None = self.type_stack.iter().find(|&&idx| idx == full_index)
                                {
                                    if full_index != index {
                                        return self.try_type_index_to_bare(
                                            full_index,
                                            finder,
                                            fully_resolve,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if type_.type_class() == TypeClass::NamedTypeReferenceClass {
            // PDB does this thing where anonymous inner types are represented as
            // some_type::<anonymous-tag>
            let name = type_
                .get_named_type_reference()
                .ok_or(anyhow!("expected ntr"))?
                .name();
            if Self::is_name_anonymous(&name) {
                if let Some(inner) = inner.as_ref() {
                    type_ = inner.clone();
                } else {
                    // Look up raw name of this type
                    if let Ok(raw) = finder.find(index) {
                        if let Ok(parsed) = raw.parse() {
                            // Have to use raw name here because self.full_type_indices uses raw name
                            // for some reason
                            if let Some(raw_name) = Self::type_data_to_raw_name(&parsed) {
                                if let Some(&full_index) = self.full_type_indices.get(&raw_name) {
                                    if let None =
                                        self.type_stack.iter().find(|&&idx| idx == full_index)
                                    {
                                        if full_index != index {
                                            return self.try_type_index_to_bare(
                                                full_index,
                                                finder,
                                                fully_resolve,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(Some(type_))
    }

    /// Is this name one of the stupid microsoft unnamed type names
    fn is_name_anonymous(name: &QualifiedName) -> bool {
        match name.items.last() {
            Some(item) if item == "<anonymous-tag>" => true,
            Some(item) if item.contains("<unnamed-") => true,
            _ => false,
        }
    }

    /// Find a calling convention in the platform
    pub(crate) fn find_calling_convention(
        platform: &Platform,
        name: &str,
    ) -> Option<Ref<CoreCallingConvention>> {
        platform
            .calling_conventions()
            .iter()
            .find(|c| c.name().as_str() == name)
            .map(|g| g.clone())
    }

    /// Convert pdb calling convention enum to binja
    fn cv_call_t_to_calling_convention(&self, cv: u8) -> Option<Ref<CoreCallingConvention>> {
        match CV_call_t::try_from(cv) {
            Ok(CV_call_t::NEAR_FAST) | Ok(CV_call_t::FAR_FAST) => {
                self.platform.get_fastcall_calling_convention()
            }
            Ok(CV_call_t::NEAR_STD) | Ok(CV_call_t::FAR_STD) => {
                self.platform.get_stdcall_calling_convention()
            }
            Ok(CV_call_t::NEAR_C) | Ok(CV_call_t::FAR_C) => {
                self.platform.get_cdecl_calling_convention()
            }
            Ok(CV_call_t::THISCALL) => {
                Self::find_calling_convention(self.platform.as_ref(), "thiscall")
            }
            Ok(CV_call_t::NEAR_PASCAL) | Ok(CV_call_t::FAR_PASCAL) => {
                Self::find_calling_convention(self.platform.as_ref(), "pascal")
            }
            Ok(CV_call_t::NEAR_SYS) | Ok(CV_call_t::FAR_SYS) => {
                Self::find_calling_convention(self.platform.as_ref(), "sys")
            }
            Ok(CV_call_t::MIPSCALL) => {
                Self::find_calling_convention(self.platform.as_ref(), "mipscall")
            }
            Ok(CV_call_t::ALPHACALL) => {
                Self::find_calling_convention(self.platform.as_ref(), "alphacall")
            }
            Ok(CV_call_t::PPCCALL) => {
                Self::find_calling_convention(self.platform.as_ref(), "ppccall")
            }
            Ok(CV_call_t::SHCALL) => {
                Self::find_calling_convention(self.platform.as_ref(), "shcall")
            }
            Ok(CV_call_t::ARMCALL) => {
                Self::find_calling_convention(self.platform.as_ref(), "armcall")
            }
            Ok(CV_call_t::AM33CALL) => {
                Self::find_calling_convention(self.platform.as_ref(), "am33call")
            }
            Ok(CV_call_t::TRICALL) => {
                Self::find_calling_convention(self.platform.as_ref(), "tricall")
            }
            Ok(CV_call_t::SH5CALL) => {
                Self::find_calling_convention(self.platform.as_ref(), "sh5call")
            }
            Ok(CV_call_t::M32RCALL) => {
                Self::find_calling_convention(self.platform.as_ref(), "m32rcall")
            }
            Ok(CV_call_t::NEAR_VECTOR) => {
                Self::find_calling_convention(self.platform.as_ref(), "vectorcall")
            }
            _ => None,
        }
    }

    /// Insert an argument for the thisptr in a function param list
    fn insert_this_pointer(
        &self,
        parameters: &mut Vec<FunctionParameter>,
        this_type: Ref<Type>,
    ) -> Result<()> {
        parameters.insert(
            0,
            FunctionParameter::new(
                Conf::new(this_type, MAX_CONFIDENCE),
                "this".to_string(),
                None,
            ),
        );

        Ok(())
    }

    /// Does this type get returned in rax? Or should we put it on the stack?
    pub fn can_fit_in_register(
        &mut self,
        index: TypeIndex,
        finder: &mut ItemFinder<TypeIndex>,
        treat_references_like_pointers: bool,
    ) -> bool {
        // TLDR "This is impossible so we're making a best-guess"
        // GET READY OKAY

        // "A scalar return value that can fit into 64 bits, including the __m64 type, is returned
        // through RAX. Non-scalar types including floats, doubles, and vector types such as __m128,
        // __m128i, __m128d are returned in XMM0. The state of unused bits in the value returned
        // in RAX or XMM0 is undefined.

        // "User-defined types can be returned by value from global functions and static member
        // functions. To return a user-defined type by value in RAX, it must have a length of
        // 1, 2, 4, 8, 16, 32, or 64 bits. It must also have no user-defined constructor, destructor,
        // or copy assignment operator. It can have no private or protected non-static data members,
        // and no non-static data members of reference type. It can't have base classes or virtual
        // functions. And, it can only have data members that also meet these requirements.
        // (This definition is essentially the same as a C++03 POD type. Because the definition has
        // changed in the C++11 standard, we don't recommend using std::is_pod for this test.)
        // Otherwise, the caller must allocate memory for the return value and pass a pointer to it
        // as the first argument. The remaining arguments are then shifted one argument to the right.
        // The same pointer must be returned by the callee in RAX."

        // - length of 1, 2, 4, 8, 16, 32, or 64 bits
        // - no user-defined constructor
        // - no user-defined destructor
        // - no user-defined copy assignment operator
        // - no private data members
        // - no protected data members
        // - no reference data members
        // - no base classes
        // - no virtual functions

        // This one is incorrect, so we're not including it:
        // - all members meet these requirements
        // https://godbolt.org/z/hsTxrxq9c extremely cool

        // Are we going to implement all of this?
        // No? We're just going to do something close and leave it to the users to figure out the rest
        // There's no way I'm digging through all nonsense

        // Glenn: "Never mind this got deleted... MS has done it again"
        // After a quick GitHub discussion (https://github.com/MicrosoftDocs/cpp-docs/issues/4152)
        // I've determined this is unknowable.
        // Microsoft does it again!!!!

        if let Some(&returnable) = self.type_default_returnable.get(&index) {
            returnable
        } else {
            let returnable =
                self.can_fit_in_register_impl(index, finder, treat_references_like_pointers);
            self.log(|| format!("Type {} is default returnable: {}", index, returnable));
            self.type_default_returnable.insert(index, returnable);
            returnable
        }
    }

    fn size_can_fit_in_register(size: u64) -> bool {
        matches!(size, 0 | 1 | 2 | 4 | 8)
    }

    // Memoized... because this has gotta be real slow
    fn can_fit_in_register_impl(
        &mut self,
        index: TypeIndex,
        finder: &mut ItemFinder<TypeIndex>,
        treat_references_like_pointers: bool,
    ) -> bool {
        let ty = match finder.find(index) {
            Ok(item) => match item.parse() {
                Ok(ty) => ty,
                Err(_) => return false,
            },
            Err(_) => return false,
        };

        fn get_fields<'a>(
            index: TypeIndex,
            finder: &mut ItemFinder<'a, TypeIndex>,
        ) -> Result<Vec<TypeData<'a>>> {
            match finder.find(index).and_then(|fields| fields.parse()) {
                Ok(TypeData::FieldList(fields)) => {
                    if let Some(cont) = fields.continuation {
                        Ok(fields
                            .fields
                            .into_iter()
                            .chain(get_fields(cont, finder)?)
                            .collect::<Vec<_>>())
                    } else {
                        Ok(fields.fields)
                    }
                }
                _ => Err(anyhow!("can't lookup fields")),
            }
        }

        match ty {
            TypeData::Primitive(_) => true,
            TypeData::Pointer(p) => match p.attributes.pointer_mode() {
                PointerMode::Pointer => true,
                PointerMode::Member => true,
                PointerMode::MemberFunction => true,
                // - no reference data members
                PointerMode::LValueReference => treat_references_like_pointers,
                PointerMode::RValueReference => treat_references_like_pointers,
            },
            TypeData::Array(a) => {
                Self::size_can_fit_in_register(*a.dimensions.last().unwrap_or(&0) as u64)
                    && self.can_fit_in_register(a.element_type, finder, false)
            }
            TypeData::Modifier(m) => {
                self.can_fit_in_register(m.underlying_type, finder, treat_references_like_pointers)
            }
            TypeData::Enumeration(e) => self.can_fit_in_register(e.underlying_type, finder, false),
            TypeData::Class(c) => {
                if c.properties.forward_reference() {
                    if let Some(raw_name) = c.unique_name {
                        if let Some(&full) = self
                            .full_type_indices
                            .get(&raw_name.to_string().to_string())
                        {
                            return self.can_fit_in_register(
                                full,
                                finder,
                                treat_references_like_pointers,
                            );
                        }
                    }
                    // Can't look up, assume not
                    return false;
                }

                // - length of 1, 2, 4, 8, 16, 32, or 64 bits
                if !Self::size_can_fit_in_register(c.size) {
                    return false;
                }

                // - no user-defined constructor
                // - no user-defined destructor
                // - no user-defined copy assignment operator
                if c.properties.constructors() || c.properties.overloaded_assignment() {
                    return false;
                }

                // - no base classes
                if c.derived_from.is_some() {
                    return false;
                }
                // - no virtual functions
                if c.vtable_shape.is_some() {
                    return false;
                }

                let fields = if let Some(fields_idx) = c.fields {
                    if let Ok(fields) = get_fields(fields_idx, finder) {
                        fields
                    } else {
                        return false;
                    }
                } else {
                    // No fields?
                    return true;
                };

                for field in fields {
                    match field {
                        TypeData::Member(m) => {
                            // - no private data members
                            // - no protected data members
                            if m.attributes.access() == 1 || m.attributes.access() == 2 {
                                return false;
                            }
                        }
                        TypeData::OverloadedMethod(m) => {
                            match finder.find(m.method_list).and_then(|l| l.parse()) {
                                Ok(TypeData::MethodList(list)) => {
                                    for m in list.methods {
                                        // - no virtual functions
                                        if m.attributes.is_virtual() {
                                            return false;
                                        }
                                    }
                                }
                                _ => return false,
                            }
                        }
                        TypeData::Method(m) => {
                            // - no virtual functions
                            if m.attributes.is_virtual() {
                                return false;
                            }
                        }
                        // - no base classes
                        TypeData::BaseClass(_) => return false,
                        TypeData::VirtualBaseClass(_) => return false,
                        TypeData::VirtualFunctionTable(_) => return false,
                        TypeData::VirtualTableShape(_) => return false,
                        TypeData::VirtualFunctionTablePointer(_) => return false,
                        _ => {}
                    }
                }
                true
            }
            TypeData::Union(u) => {
                if u.properties.forward_reference() {
                    if let Some(raw_name) = u.unique_name {
                        if let Some(&full) = self
                            .full_type_indices
                            .get(&raw_name.to_string().to_string())
                        {
                            return self.can_fit_in_register(
                                full,
                                finder,
                                treat_references_like_pointers,
                            );
                        }
                    }
                    // Can't look up, assume not
                    return false;
                }

                // - length of 1, 2, 4, 8, 16, 32, or 64 bits
                if !Self::size_can_fit_in_register(u.size) {
                    return false;
                }

                // - no user-defined constructor
                // - no user-defined destructor
                // - no user-defined copy assignment operator
                if u.properties.constructors() || u.properties.overloaded_assignment() {
                    return false;
                }

                let fields = if let Ok(fields) = get_fields(u.fields, finder) {
                    fields
                } else {
                    return false;
                };

                for field in fields {
                    match field {
                        TypeData::Member(m) => {
                            // - no private data members
                            // - no protected data members
                            if m.attributes.access() == 1 || m.attributes.access() == 2 {
                                return false;
                            }
                        }
                        TypeData::OverloadedMethod(m) => {
                            match finder.find(m.method_list).and_then(|l| l.parse()) {
                                Ok(TypeData::MethodList(list)) => {
                                    for m in list.methods {
                                        // - no virtual functions
                                        if m.attributes.is_virtual() {
                                            return false;
                                        }
                                    }
                                }
                                _ => return false,
                            }
                        }
                        TypeData::Method(m) => {
                            // - no virtual functions
                            if m.attributes.is_virtual() {
                                return false;
                            }
                        }
                        // - no base classes
                        TypeData::BaseClass(_) => return false,
                        TypeData::VirtualBaseClass(_) => return false,
                        TypeData::VirtualFunctionTable(_) => return false,
                        TypeData::VirtualTableShape(_) => return false,
                        TypeData::VirtualFunctionTablePointer(_) => return false,
                        _ => {}
                    }
                }
                true
            }
            _ => false,
        }
    }
}
