//! Translate type information from IDB to Binary Ninja, this will not discover type information
//! by which we mean pull type information from outside sources, the mapper does that.

use binaryninja::architecture::{Architecture, ArchitectureExt, CoreArchitecture};
use binaryninja::calling_convention::CoreCallingConvention;
use binaryninja::confidence::Conf;
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::types::{
    EnumerationBuilder, FunctionParameter, MemberAccess, MemberScope, NamedTypeReference,
    NamedTypeReferenceClass, StructureBuilder, StructureMember, StructureType, TypeBuilder,
    TypeContainer,
};
use idb_rs::til::function::CallingConvention;
use idb_rs::til::r#enum::EnumMembers;
use idb_rs::til::{Basic, TILTypeInfo, TypeVariant, TyperefType, TyperefValue};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Mutex;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ReferencedType {
    pub name: String,
    pub ordinal: Option<u64>,
    /// The width of the type in bytes, if known.
    ///
    /// This is required to be able to place NTR's in structures and unions.
    pub width: Option<usize>,
}

impl ReferencedType {
    pub fn new(name: String) -> Self {
        Self {
            ordinal: None,
            name,
            width: None,
        }
    }

    pub fn new_with_ordinal(name: String, ordinal: u64) -> Self {
        Self {
            ordinal: Some(ordinal),
            name,
            width: None,
        }
    }
}

impl From<&TILTypeInfo> for ReferencedType {
    fn from(value: &TILTypeInfo) -> Self {
        Self {
            ordinal: match value.ordinal {
                0 => None,
                ord => Some(ord),
            },
            name: value.name.to_string(),
            width: None,
        }
    }
}

pub struct TILTranslator {
    /// Default size of addresses.
    pub address_size: usize,
    /// Default size of enumerations.
    pub enum_size: usize,
    /// Reference types, for use with typedefs.
    ///
    /// This is necessary because ordinals do not have names and can't be made into a [`NamedTypeReference`].
    pub reference_types_by_ord: HashMap<u64, ReferencedType>,
    pub reference_types_by_name: HashMap<String, ReferencedType>,
    /// The types that have been used in the translation process.
    ///
    /// For a complete analysis, we will take these used types, attempt to find them in type libraries,
    /// then add them to the binary view.
    ///
    /// NOTE: Not to be confused with `reference_types_by_ord`, which is a map of ordinal to reference types.
    pub used_types: Rc<Mutex<HashSet<ReferencedType>>>,
    // pub referenced_types: Rc<Mutex<Vec<ReferencedType>>>,
    pub default_calling_convention: Option<Ref<CoreCallingConvention>>,
    pub cdecl_calling_convention: Option<Ref<CoreCallingConvention>>,
    pub stdcall_calling_convention: Option<Ref<CoreCallingConvention>>,
    pub fastcall_calling_convention: Option<Ref<CoreCallingConvention>>,
}

impl TILTranslator {
    pub fn new(address_size: usize) -> Self {
        Self {
            address_size,
            enum_size: address_size / 2,
            reference_types_by_ord: HashMap::new(),
            reference_types_by_name: HashMap::new(),
            used_types: Rc::new(Mutex::new(HashSet::new())),
            default_calling_convention: None,
            cdecl_calling_convention: None,
            stdcall_calling_convention: None,
            fastcall_calling_convention: None,
        }
    }

    pub fn new_from_platform(platform: &Platform) -> Self {
        Self {
            address_size: platform.address_size(),
            enum_size: platform.arch().default_integer_size(),
            reference_types_by_ord: HashMap::new(),
            reference_types_by_name: HashMap::new(),
            used_types: Rc::new(Mutex::new(HashSet::new())),
            default_calling_convention: platform.get_default_calling_convention(),
            cdecl_calling_convention: platform.get_cdecl_calling_convention(),
            stdcall_calling_convention: platform.get_stdcall_calling_convention(),
            fastcall_calling_convention: platform.get_fastcall_calling_convention(),
        }
    }

    pub fn new_from_arch(arch: &CoreArchitecture) -> Self {
        Self {
            address_size: arch.address_size(),
            enum_size: arch.default_integer_size(),
            reference_types_by_ord: HashMap::new(),
            reference_types_by_name: HashMap::new(),
            used_types: Rc::new(Mutex::new(HashSet::new())),
            default_calling_convention: arch.get_default_calling_convention(),
            cdecl_calling_convention: arch.get_cdecl_calling_convention(),
            stdcall_calling_convention: arch.get_stdcall_calling_convention(),
            fastcall_calling_convention: arch.get_fastcall_calling_convention(),
        }
    }

    pub fn with_til_info(mut self, til: &idb_rs::til::section::TILSection) -> Self {
        if let Some(size_enum) = til.header.size_enum {
            self.enum_size = size_enum.get() as usize;
        }

        // Add referencable types so that type def lookups can occur.
        self.reference_types_by_ord.reserve(til.types.len());
        for (_idx, ty) in til.types.iter().enumerate() {
            self.add_referenced_type_info(ty);
        }

        // TODO: Handle address (pointer) size information?
        self
    }

    /// Populate referencable types with the ones in a type container.
    pub fn with_type_container(mut self, container: &TypeContainer) -> Self {
        for (_, (name, ty)) in container.types().unwrap_or_default() {
            self.add_referenced_named_type(&name.to_string(), Some(ty.width() as usize));
        }
        self
    }

    /// Add a type that can be referenced by ordinal or name.
    pub fn add_referenced_type_info(&mut self, ty: &TILTypeInfo) {
        let mut referenced_type = ReferencedType::from(ty);
        referenced_type.width = self.width_of_type(&ty.tinfo).ok();
        self.reference_types_by_ord
            .insert(ty.ordinal, referenced_type.clone());
        self.reference_types_by_name
            .insert(referenced_type.name.clone(), referenced_type);
    }

    /// Add a named type that can be referenced by ONLY name.
    ///
    /// Useful to populate with types coming from platform or other "system" types in Binary Ninja.
    pub fn add_referenced_named_type(&mut self, name: &str, width: Option<usize>) {
        let mut referenced_type = ReferencedType::new(name.to_string());
        referenced_type.width = width;
        self.reference_types_by_name
            .insert(referenced_type.name.clone(), referenced_type);
    }

    pub fn translate_type_info(
        &self,
        til_ty: &idb_rs::til::Type,
    ) -> anyhow::Result<Ref<binaryninja::types::Type>> {
        let builder = match &til_ty.type_variant {
            TypeVariant::Basic(v) => self.build_basic_ty(&v)?,
            TypeVariant::Pointer(v) => self.build_pointer_ty(&v)?,
            TypeVariant::Function(v) => self.build_function_ty(&v)?,
            TypeVariant::Array(v) => self.build_array_ty(&v)?,
            TypeVariant::Typeref(v) => self.build_type_ref_ty(&v)?,
            TypeVariant::Struct(v) => self.build_udt_ty(&v, false)?,
            TypeVariant::Union(v) => self.build_udt_ty(&v, true)?,
            TypeVariant::Enum(v) => self.build_enum_ty(&v)?,
            TypeVariant::Bitfield(v) => self.build_bitfield_ty(&v)?,
        };

        builder.set_const(til_ty.is_const);
        builder.set_volatile(til_ty.is_volatile);
        Ok(builder.finalize())
    }

    pub fn build_basic_ty(&self, basic_ty: &idb_rs::til::Basic) -> anyhow::Result<TypeBuilder> {
        use idb_rs::til::Basic;
        // TODO: Grab the sizing information of these types from the TIL instead of hardcoding.
        match basic_ty {
            Basic::Void => Ok(TypeBuilder::void()),
            Basic::Unknown { bytes } => {
                // In the samples provided it appears that unknown can be used to represent a byte,
                // so we are going to be liberal and allow unknown basic types to be treated as a sized int.
                Ok(TypeBuilder::int(*bytes as usize, false))
            }
            Basic::Bool => Ok(TypeBuilder::bool()),
            Basic::BoolSized { .. } => {
                // TODO: This needs to be resized, if that cannot be done, make a NTR to an int named BOOL?
                Ok(TypeBuilder::bool())
            }
            Basic::Char => Ok(TypeBuilder::char()),
            Basic::SegReg => Err(anyhow::anyhow!("SegReg is not supported")),
            Basic::Short { is_signed } => Ok(TypeBuilder::int(2, is_signed.unwrap_or(true))),
            Basic::Long { is_signed } => Ok(TypeBuilder::int(4, is_signed.unwrap_or(true))),
            Basic::LongLong { is_signed } => Ok(TypeBuilder::int(8, is_signed.unwrap_or(true))),
            Basic::Int { is_signed } => Ok(TypeBuilder::int(4, is_signed.unwrap_or(true))),
            Basic::IntSized { bytes, is_signed } => {
                let bytes: u8 = u8::try_from(*bytes).unwrap_or(4);
                Ok(TypeBuilder::int(bytes as usize, is_signed.unwrap_or(true)))
            }
            Basic::Float { bytes } => {
                let bytes: u8 = u8::try_from(*bytes).unwrap_or(4);
                Ok(TypeBuilder::float(bytes as usize))
            }
            Basic::LongDouble => Ok(TypeBuilder::float(8)),
        }
    }

    pub fn build_pointer_ty(
        &self,
        pointer_ty: &idb_rs::til::pointer::Pointer,
    ) -> anyhow::Result<TypeBuilder> {
        // TODO: Consult pointer_ty.closure (is this how we can get based pointers?)
        let inner_ty = self.translate_type_info(&pointer_ty.typ)?;
        Ok(TypeBuilder::pointer_of_width(
            &inner_ty,
            self.address_size,
            // NOTE: Set later in `translate_type_info`.
            false,
            // NOTE: Set later in `translate_type_info`.
            false,
            None,
        ))
    }

    pub fn build_function_ty(
        &self,
        function_ty: &idb_rs::til::function::Function,
    ) -> anyhow::Result<TypeBuilder> {
        // TODO: Once branch `test_call_layout` lands use function_ty.retloc to recover return location.
        let return_ty = self.translate_type_info(&function_ty.ret)?;
        let params: Vec<FunctionParameter> = self.build_function_params(&function_ty.args)?;
        let has_variable_args = false;
        let stack_adjust = Conf::new(0, 0);

        let builder = match function_ty.calling_convention {
            Some(CallingConvention::Cdecl) | Some(CallingConvention::Thiscall)
                if self.cdecl_calling_convention.is_some() =>
            {
                let cc = self.cdecl_calling_convention.clone().unwrap();
                TypeBuilder::function_with_opts(
                    &return_ty,
                    &params,
                    has_variable_args,
                    cc,
                    stack_adjust,
                )
            }
            Some(CallingConvention::Stdcall) if self.stdcall_calling_convention.is_some() => {
                let cc = self.stdcall_calling_convention.clone().unwrap();
                TypeBuilder::function_with_opts(
                    &return_ty,
                    &params,
                    has_variable_args,
                    cc,
                    stack_adjust,
                )
            }
            Some(CallingConvention::Fastcall) if self.fastcall_calling_convention.is_some() => {
                let cc = self.fastcall_calling_convention.clone().unwrap();
                TypeBuilder::function_with_opts(
                    &return_ty,
                    &params,
                    has_variable_args,
                    cc,
                    stack_adjust,
                )
            }
            _ => TypeBuilder::function(&return_ty, params, has_variable_args),
        };

        Ok(builder)
    }

    pub fn build_function_params(
        &self,
        args: &[idb_rs::til::function::FunctionArg],
    ) -> anyhow::Result<Vec<FunctionParameter>> {
        args.iter()
            .enumerate()
            .map(|(idx, arg)| {
                let arg_name = arg
                    .name
                    .clone()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("arg{}", idx));
                self.translate_type_info(&arg.ty)
                    .map(|ty| FunctionParameter::new(ty, arg_name, None))
            })
            .collect()
    }

    pub fn build_array_ty(
        &self,
        _array_ty: &idb_rs::til::array::Array,
    ) -> anyhow::Result<TypeBuilder> {
        let elem_ty = self.translate_type_info(&_array_ty.elem_type)?;
        // NOTE: IDA seems to allow DST array (optional nelem) we are just going to default zero count
        // for those and assume that to be fine, this obviously is a little bit tricky to assume but
        // I imagine IDA only allows these at the end of a struct, and makes the structure unsized,
        // not exactly sure how to handle this yet.
        let count = _array_ty.nelem.map(|n| n.get()).unwrap_or(0);
        Ok(TypeBuilder::array(&elem_ty, count as u64))
    }

    pub fn build_type_ref_ty(
        &self,
        typ_ref_ty: &idb_rs::til::Typeref,
    ) -> anyhow::Result<TypeBuilder> {
        let type_class = match typ_ref_ty.ref_type {
            Some(TyperefType::Struct) => NamedTypeReferenceClass::StructNamedTypeClass,
            Some(TyperefType::Union) => NamedTypeReferenceClass::UnionNamedTypeClass,
            Some(TyperefType::Enum) => NamedTypeReferenceClass::EnumNamedTypeClass,
            None => NamedTypeReferenceClass::UnknownNamedTypeClass,
        };

        // Named type references can be placed directly, otherwise we have to resolve the ordinal
        // to get a name for the type reference. Once we get that, we make a NamedTypeReference
        // and then place the types ordinal in the list of referenced types, so that we can pull
        // them into the binary view later.
        match &typ_ref_ty.typeref_value {
            TyperefValue::Name(Some(ref_name)) => {
                if let Ok(mut used_types) = self.used_types.lock() {
                    let ty_ref = ReferencedType::new(ref_name.to_string());
                    used_types.insert(ty_ref.clone());
                }
                let ntr = NamedTypeReference::new(type_class, ref_name.to_string());
                Ok(TypeBuilder::named_type(&ntr))
            }
            TyperefValue::Name(None) => {
                // IDA will use an unnamed type reference for a struct, union or enum with no definition.
                match typ_ref_ty.ref_type {
                    Some(TyperefType::Struct) => {
                        let empty_struct = StructureBuilder::new().finalize();
                        Ok(TypeBuilder::structure(&empty_struct))
                    }
                    Some(TyperefType::Union) => {
                        let empty_union = StructureBuilder::new()
                            .structure_type(StructureType::UnionStructureType)
                            .finalize();
                        Ok(TypeBuilder::structure(&empty_union))
                    }
                    None | Some(TyperefType::Enum) => {
                        Err(anyhow::anyhow!("Unnamed type references are not supported"))
                    }
                }
            }
            TyperefValue::Ordinal(ref_ord) => {
                if let Some(ty_ref) = self.reference_types_by_ord.get(&(*ref_ord as u64)) {
                    // The ordinal has an associated reference type, use the name and insert this into
                    // the list of used types.
                    if let Ok(mut used_types) = self.used_types.lock() {
                        used_types.insert(ty_ref.clone());
                    }
                    let ntr = NamedTypeReference::new(type_class, &ty_ref.name);
                    Ok(TypeBuilder::named_type(&ntr))
                } else {
                    Err(anyhow::anyhow!(
                        "Type reference ordinal not found: {}",
                        ref_ord
                    ))
                }
            }
        }
    }

    pub fn build_udt_ty(
        &self,
        udt_ty: &idb_rs::til::udt::UDT,
        is_union: bool,
    ) -> anyhow::Result<TypeBuilder> {
        let mut builder = StructureBuilder::new();
        if let Some(align) = udt_ty.alignment {
            builder.alignment(align.get().into());
        }
        builder.packed(udt_ty.is_unaligned && udt_ty.is_unknown_8);
        if is_union {
            builder.structure_type(StructureType::UnionStructureType);
        }

        let (members, width) = self.build_udt_members(&udt_ty.members)?;
        for mut member in members {
            if is_union {
                member.offset = 0;
            }
            builder.insert_member(member, false);
        }

        builder.width(width);
        // TODO: Handle udt_ty.extra_padding (is that tail padding?)
        Ok(TypeBuilder::structure(&builder.finalize()))
    }

    pub fn build_udt_members(
        &self,
        udt_members: &[idb_rs::til::udt::UDTMember],
    ) -> anyhow::Result<(Vec<StructureMember>, u64)> {
        let mut current_offset = 0;
        let mut member_iter = udt_members.iter().peekable();
        let mut structure_members = Vec::new();
        while let Some(member) = member_iter.next() {
            let current_byte_offset = current_offset / 8;
            let member_name = member
                .name
                .clone()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("field_{}", current_byte_offset));
            let member_ty = Conf::new(self.translate_type_info(&member.member_type)?, 255);
            let bn_member = match member.member_type.type_variant {
                TypeVariant::Bitfield(bf) => StructureMember::new_bitfield(
                    member_ty,
                    member_name,
                    current_offset,
                    bf.width as u8,
                    MemberAccess::PublicAccess,
                    MemberScope::NoScope,
                ),
                _ => {
                    let member_align = member_ty.contents.alignment().max(1) as u64;
                    let member_offset = if current_byte_offset % member_align == 0 {
                        current_byte_offset
                    } else {
                        current_byte_offset + (member_align - (current_byte_offset % member_align))
                    };
                    // NTR will be zero-sized, we need to handle this by computing the width ourselves.
                    let referenced_width = self.width_of_type(&member.member_type)?;
                    current_offset += referenced_width as u64 * 8;
                    StructureMember::new(
                        member_ty,
                        member_name,
                        member_offset,
                        MemberAccess::PublicAccess,
                        MemberScope::NoScope,
                    )
                }
            };

            structure_members.push(bn_member);
        }

        // We need to return the width of the structure as NTR resolution will happen after the structure
        // width would be computed, so we need to manually set the structures width in `build_udt_ty`.
        Ok((structure_members, current_offset / 8))
    }

    pub fn build_enum_ty(
        &self,
        enum_ty: &idb_rs::til::r#enum::Enum,
    ) -> anyhow::Result<TypeBuilder> {
        let mut enumeration_builder = EnumerationBuilder::new();
        match &enum_ty.members {
            EnumMembers::Regular(members) => {
                for (idx, member) in members.iter().enumerate() {
                    let member_name = member
                        .name
                        .as_ref()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("member_{}", idx));
                    enumeration_builder.insert(&member_name, member.value);
                }
            }
            EnumMembers::Groups(groups) => {
                for (idx, group) in groups.iter().enumerate() {
                    // TODO: How does this grouping actually impact the enum besides the name?
                    let group_name = group
                        .field
                        .name
                        .as_ref()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("group_{}", idx));
                    for (idx, member) in group.sub_fields.iter().enumerate() {
                        let member_name = member
                            .name
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| format!("member_{}", idx));
                        let grouped_member_name = format!("{}_{}", group_name, member_name);
                        enumeration_builder.insert(&grouped_member_name, member.value);
                    }
                }
            }
        }

        let width = enum_ty
            .storage_size
            .map(|s| s.get() as usize)
            .unwrap_or(self.enum_size);
        Ok(TypeBuilder::enumeration(
            &enumeration_builder.finalize(),
            width.try_into()?,
            enum_ty.is_signed,
        ))
    }

    /// A bitfield is a single member in an udt that plays the role of a bit-aligned integer.
    ///
    /// NOTE: This does not return the bit-aligned integer, this returns the **byte-aligned** integer,
    /// you must constrain the integer yourself when constructing a Binary Ninja structure.
    pub fn build_bitfield_ty(
        &self,
        bitfield_ty: &idb_rs::til::bitfield::Bitfield,
    ) -> anyhow::Result<TypeBuilder> {
        self.build_basic_ty(&idb_rs::til::Basic::IntSized {
            bytes: bitfield_ty.nbytes,
            is_signed: Some(!bitfield_ty.unsigned),
        })
    }

    /// Computes the width of a type, in bytes.
    pub fn width_of_type(&self, ty: &idb_rs::til::Type) -> anyhow::Result<usize> {
        match &ty.type_variant {
            TypeVariant::Basic(basic) => match basic {
                Basic::Void => Ok(0),
                Basic::Unknown { bytes } => Ok(*bytes as usize),
                Basic::Bool => Ok(1),
                Basic::BoolSized { bytes } => Ok(bytes.get() as usize),
                Basic::Char => Ok(1),
                Basic::SegReg => Ok(8),
                Basic::Short { .. } => Ok(2),
                Basic::Long { .. } => Ok(4),
                Basic::LongLong { .. } => Ok(8),
                Basic::Int { .. } => Ok(4),
                Basic::IntSized { bytes, .. } => Ok(bytes.get() as usize),
                Basic::Float { bytes } => Ok(bytes.get() as usize),
                Basic::LongDouble => Ok(8),
            },
            TypeVariant::Pointer(_) => Ok(self.address_size),
            TypeVariant::Function(_) => Err(anyhow::anyhow!("Function types do not have a width")),
            TypeVariant::Array(arr) => {
                let elem_width = self.width_of_type(&arr.elem_type)?;
                // TODO: A DST array is unsized or what? I think we should error IMO.
                let count = arr.nelem.map(|n| n.get()).unwrap_or(0);
                Ok(elem_width * count as usize)
            }
            TypeVariant::Typeref(r) => {
                let resolved_ty = self.resolve_type_ref(r).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Type reference {:?} could not be resolved to a type",
                        r.typeref_value
                    )
                })?;
                resolved_ty.width.ok_or_else(|| {
                    anyhow::anyhow!("Type reference has no width: {:?}", resolved_ty)
                })
            }
            TypeVariant::Struct(s) => {
                let mut total_width = 0;
                for member in &s.members {
                    total_width += self.width_of_type(&member.member_type)?;
                }
                // TODO: Handle alignment and bitfields.
                Ok(total_width)
            }
            TypeVariant::Union(u) => {
                // Size of the largest member + alignment
                let mut max_width = 0;
                for member in &u.members {
                    let member_width = self.width_of_type(&member.member_type)?;
                    max_width = max_width.max(member_width);
                }
                // TODO: Handle alignment
                Ok(max_width)
            }
            TypeVariant::Enum(e) => Ok(e
                .storage_size
                .map(|s| s.get() as usize)
                .unwrap_or(self.enum_size)),
            TypeVariant::Bitfield(b) => {
                // NOTE: We return the byte aligned width here if inside a structure you need to
                // constrain the width to the storage yourself.
                Ok(b.nbytes.get() as usize)
            }
        }
    }

    /// Try and find the [`ReferencedType`] for a given type reference.
    pub fn resolve_type_ref(&self, type_ref: &idb_rs::til::Typeref) -> Option<ReferencedType> {
        match &type_ref.typeref_value {
            TyperefValue::Name(Some(ref_name)) => self
                .reference_types_by_name
                .get(&ref_name.to_string())
                .cloned(),
            TyperefValue::Ordinal(ref_ord) => {
                self.reference_types_by_ord.get(&(*ref_ord as u64)).cloned()
            }
            _ => None,
        }
    }
}
