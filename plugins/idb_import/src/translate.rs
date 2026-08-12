//! Translate type information from IDB to Binary Ninja, this will not discover type information
//! by which we mean pull type information from outside sources, the mapper does that.

use binaryninja::architecture::{Architecture, ArchitectureExt, CoreArchitecture};
use binaryninja::calling_convention::CoreCallingConvention;
use binaryninja::confidence::{Conf, MAX_CONFIDENCE};
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::types::{
    EnumerationBuilder, FunctionParameter, MemberAccess, MemberScope, NamedTypeReference,
    NamedTypeReferenceClass, PointerBaseType, ReturnValue, StructureBuilder, StructureMember,
    StructureType, Type, TypeBuilder, TypeContainer, ValueLocation, ValueLocationComponent,
    ValueLocationSource,
};
use binaryninja::variable::Variable;
use idb_rs::til::function::{ArgLoc, CallingConvention};
use idb_rs::til::pointer::{PointerModifier, PointerType};
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
    /// Default size of a `bool` in bytes.
    pub bool_size: usize,
    /// Default size of a `short` in bytes.
    pub short_size: usize,
    /// Default size of an `int` in bytes.
    pub int_size: usize,
    /// Default size of a `long` in bytes.
    pub long_size: usize,
    /// Default size of a `long long` in bytes.
    pub long_long_size: usize,
    /// Default size of a `long double` in bytes.
    pub long_double_size: usize,
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
    /// Architecture used to resolve register names into register ids for value locations.
    pub arch: Option<CoreArchitecture>,
    /// Processor register names indexed by IDA register number (see [`crate::parse::ID0Info`]).
    pub register_names: Vec<String>,
}

impl TILTranslator {
    pub fn new(address_size: usize) -> Self {
        Self {
            address_size,
            enum_size: address_size / 2,
            bool_size: 1,
            short_size: 2,
            int_size: 4,
            long_size: 4,
            long_long_size: 8,
            long_double_size: 8,
            reference_types_by_ord: HashMap::new(),
            reference_types_by_name: HashMap::new(),
            used_types: Rc::new(Mutex::new(HashSet::new())),
            default_calling_convention: None,
            cdecl_calling_convention: None,
            stdcall_calling_convention: None,
            fastcall_calling_convention: None,
            arch: None,
            register_names: Vec::new(),
        }
    }

    pub fn new_from_platform(platform: &Platform) -> Self {
        Self {
            address_size: platform.address_size(),
            enum_size: platform.arch().default_integer_size(),
            bool_size: 1,
            short_size: 2,
            int_size: 4,
            long_size: 4,
            long_long_size: 8,
            long_double_size: 8,
            reference_types_by_ord: HashMap::new(),
            reference_types_by_name: HashMap::new(),
            used_types: Rc::new(Mutex::new(HashSet::new())),
            default_calling_convention: platform.get_default_calling_convention(),
            cdecl_calling_convention: platform.get_cdecl_calling_convention(),
            stdcall_calling_convention: platform.get_stdcall_calling_convention(),
            fastcall_calling_convention: platform.get_fastcall_calling_convention(),
            arch: Some(platform.arch()),
            register_names: Vec::new(),
        }
    }

    pub fn new_from_arch(arch: &CoreArchitecture) -> Self {
        Self {
            address_size: arch.address_size(),
            enum_size: arch.default_integer_size(),
            bool_size: 1,
            short_size: 2,
            int_size: 4,
            long_size: 4,
            long_long_size: 8,
            long_double_size: 8,
            reference_types_by_ord: HashMap::new(),
            reference_types_by_name: HashMap::new(),
            used_types: Rc::new(Mutex::new(HashSet::new())),
            default_calling_convention: arch.get_default_calling_convention(),
            cdecl_calling_convention: arch.get_cdecl_calling_convention(),
            stdcall_calling_convention: arch.get_stdcall_calling_convention(),
            fastcall_calling_convention: arch.get_fastcall_calling_convention(),
            arch: Some(*arch),
            register_names: Vec::new(),
        }
    }

    /// Provide the processor register names (indexed by IDA register number) used to resolve
    /// register-based argument and return value locations.
    pub fn with_register_names(mut self, register_names: Vec<String>) -> Self {
        self.register_names = register_names;
        self
    }

    pub fn with_til_info(mut self, til: &idb_rs::til::section::TILSection) -> Self {
        if let Some(size_enum) = til.header.size_enum {
            self.enum_size = size_enum.get() as usize;
        }

        // The TIL header carries the C basic-type sizing for the compiler the IDB was built
        // for; prefer it over our architecture-derived defaults so types translate with the
        // same widths IDA used.
        self.bool_size = til.header.size_bool.get() as usize;
        self.int_size = til.header.size_int.get() as usize;
        self.short_size = til.sizeof_short().get() as usize;
        self.long_size = til.sizeof_long().get() as usize;
        self.long_long_size = til.sizeof_long_long().get() as usize;
        if let Some(size_long_double) = til.header.size_long_double {
            self.long_double_size = size_long_double.get() as usize;
        }

        // Add referencable types so that type def lookups can occur.
        self.reference_types_by_ord.reserve(til.types.len());
        for ty in &til.types {
            self.add_referenced_type_info(ty);
        }

        // NOTE: The TIL exposes `addr_size()`, but it is derived from the compiler model and
        // defaults to 4 when that is absent, which would silently truncate pointers on a
        // 64-bit binary. The platform/architecture `address_size` we were constructed with is
        // authoritative for pointer widths, so we intentionally keep it.
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
            TypeVariant::Basic(v) => self.build_basic_ty(v)?,
            TypeVariant::Pointer(v) => self.build_pointer_ty(v)?,
            TypeVariant::Function(v) => self.build_function_ty(v)?,
            TypeVariant::Array(v) => self.build_array_ty(v)?,
            TypeVariant::Typeref(v) => self.build_type_ref_ty(v)?,
            TypeVariant::Struct(v) => self.build_udt_ty(v, false)?,
            TypeVariant::Union(v) => self.build_udt_ty(v, true)?,
            TypeVariant::Enum(v) => self.build_enum_ty(v)?,
            TypeVariant::Bitfield(v) => self.build_bitfield_ty(v)?,
        };

        builder.set_const(til_ty.is_const);
        builder.set_volatile(til_ty.is_volatile);
        Ok(builder.finalize())
    }

    pub fn build_basic_ty(&self, basic_ty: &idb_rs::til::Basic) -> anyhow::Result<TypeBuilder> {
        use idb_rs::til::Basic;
        // The variable-width C types (short/int/long/...) are sized from the TIL header when
        // one is available (see `with_til_info`), falling back to the standard C ABI defaults.
        match basic_ty {
            Basic::Void => Ok(TypeBuilder::void()),
            // An unknown type of unspecified size has no integer representation; treat it as void.
            Basic::Unknown { bytes: 0 } => Ok(TypeBuilder::void()),
            Basic::Unknown { bytes } => {
                // Preserve both the descriptive IDA placeholder name and its integer storage.
                // Constructing an unbacked named-type reference here would lose the width during
                // layout until some unrelated type definition happened to resolve that name.
                let name = format!("__unk_u{}", bytes * 8);
                let storage = Type::int(*bytes as usize, false);
                Ok(TypeBuilder::named_type_from_type(name, &storage))
            }
            Basic::Bool if self.bool_size == 1 => Ok(TypeBuilder::bool()),
            // Binary Ninja's `bool` is always a single byte; a wider `bool` is represented as an
            // unsigned integer of the requested size.
            Basic::Bool => Ok(TypeBuilder::int(self.bool_size, false)),
            Basic::BoolSized { bytes } if bytes.get() == 1 => Ok(TypeBuilder::bool()),
            Basic::BoolSized { bytes } => Ok(TypeBuilder::int(bytes.get() as usize, false)),
            Basic::Char => Ok(TypeBuilder::char()),
            Basic::SegReg => Err(anyhow::anyhow!("SegReg is not supported")),
            Basic::Short { is_signed } => {
                Ok(TypeBuilder::int(self.short_size, is_signed.unwrap_or(true)))
            }
            Basic::Long { is_signed } => {
                Ok(TypeBuilder::int(self.long_size, is_signed.unwrap_or(true)))
            }
            Basic::LongLong { is_signed } => Ok(TypeBuilder::int(
                self.long_long_size,
                is_signed.unwrap_or(true),
            )),
            Basic::Int { is_signed } => {
                Ok(TypeBuilder::int(self.int_size, is_signed.unwrap_or(true)))
            }
            Basic::IntSized { bytes, is_signed } => Ok(TypeBuilder::int(
                bytes.get() as usize,
                is_signed.unwrap_or(true),
            )),
            Basic::Float { bytes } => Ok(TypeBuilder::float(bytes.get() as usize)),
            Basic::LongDouble => Ok(TypeBuilder::float(self.long_double_size)),
        }
    }

    pub fn build_pointer_ty(
        &self,
        pointer_ty: &idb_rs::til::pointer::Pointer,
    ) -> anyhow::Result<TypeBuilder> {
        // A `__ptr32` / `__ptr64` modifier overrides the platform address size for this pointer
        // (e.g. a 32-bit pointer embedded in an otherwise 64-bit binary).
        // `shifted` pointers have no direct Binary Ninja representation; the pointee type and
        // width are preserved but the shift attribute is dropped.
        let pointer_width = match pointer_ty.modifier {
            Some(PointerModifier::Ptr32) => 4,
            Some(PointerModifier::Ptr64) => 8,
            Some(PointerModifier::Restricted) | None => self.address_size,
        };
        let inner_ty = self.translate_type_info(&pointer_ty.typ)?;
        let builder = TypeBuilder::pointer_of_width(
            &inner_ty,
            pointer_width,
            // NOTE: Set later in `translate_type_info`.
            false,
            // NOTE: Set later in `translate_type_info`.
            false,
            None,
        );
        // IDA `__based` pointers are relative to a variable address; wire up the BN pointer base
        // so the relationship is preserved. The base register index carried in the IDA type has no
        // direct equivalent in BN's type system, so only the base kind is recorded.
        if matches!(pointer_ty.closure, PointerType::PointerBased(_)) {
            builder.set_pointer_base(PointerBaseType::RelativeToVariableAddressPointerBaseType, 0);
        }
        Ok(builder)
    }

    pub fn build_function_ty(
        &self,
        function_ty: &idb_rs::til::function::Function,
    ) -> anyhow::Result<TypeBuilder> {
        let return_ty = self.translate_type_info(&function_ty.ret)?;
        // Recover the explicit return-value location (e.g. a non-default return register) when the
        // database records one; otherwise the calling convention derives it.
        let return_value = self.build_return_value(&return_ty, function_ty.retloc.as_ref());
        let params: Vec<FunctionParameter> = self.build_function_params(&function_ty.args)?;
        // An ellipsis calling convention is IDA's marker for a variadic function.
        let has_variable_args = matches!(
            function_ty.calling_convention,
            Some(CallingConvention::Ellipsis)
        );
        let stack_adjust = Conf::new(0, 0);

        let builder = match function_ty.calling_convention {
            Some(CallingConvention::Cdecl) | Some(CallingConvention::Thiscall)
                if self.cdecl_calling_convention.is_some() =>
            {
                let cc = self.cdecl_calling_convention.clone().unwrap();
                TypeBuilder::function_with_opts(
                    return_value,
                    &params,
                    has_variable_args,
                    cc,
                    stack_adjust,
                )
            }
            Some(CallingConvention::Stdcall) if self.stdcall_calling_convention.is_some() => {
                let cc = self.stdcall_calling_convention.clone().unwrap();
                TypeBuilder::function_with_opts(
                    return_value,
                    &params,
                    has_variable_args,
                    cc,
                    stack_adjust,
                )
            }
            Some(CallingConvention::Fastcall) if self.fastcall_calling_convention.is_some() => {
                let cc = self.fastcall_calling_convention.clone().unwrap();
                TypeBuilder::function_with_opts(
                    return_value,
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

    /// Build a [`ReturnValue`] for a function, attaching an explicit storage location when the
    /// database records a return location that we can resolve to registers/stack.
    fn build_return_value(&self, return_ty: &Ref<Type>, retloc: Option<&ArgLoc>) -> ReturnValue {
        let location = self
            .value_location_components(retloc)
            .map(|(components, indirect)| {
                Conf::new(
                    ValueLocation {
                        components,
                        indirect,
                        returned_pointer: None,
                    },
                    MAX_CONFIDENCE,
                )
            });
        ReturnValue {
            ty: Conf::new(return_ty.clone(), MAX_CONFIDENCE),
            location,
        }
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
                let location = self.value_location_from_arg_loc(arg.loc.as_ref());
                self.translate_type_info(&arg.ty)
                    .map(|ty| FunctionParameter::new(ty, arg_name, location))
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
        builder.packed(udt_ty.is_unaligned);
        if is_union {
            builder.structure_type(StructureType::UnionStructureType);
        }

        let (members, member_width, member_alignment) = self.build_udt_members(udt_ty, is_union)?;
        for member in members {
            builder.insert_member(member, false);
        }

        let alignment = if udt_ty.is_unaligned {
            1
        } else {
            member_alignment.max(udt_ty.alignment.map_or(1, |align| u64::from(align.get())))
        };
        builder.alignment(alignment as usize);

        // `extra_padding` records trailing padding bytes IDA stores for fixed-size UDTs; add it
        // to the member-derived width so the structure occupies its true storage size.
        let width = align_up(member_width, alignment) + udt_ty.extra_padding.unwrap_or(0);
        builder.width(width);
        Ok(TypeBuilder::structure(&builder.finalize()))
    }

    pub fn build_udt_members(
        &self,
        udt: &idb_rs::til::udt::UDT,
        is_union: bool,
    ) -> anyhow::Result<(Vec<StructureMember>, u64, u64)> {
        let mut current_bit_offset = 0u64;
        let mut active_bitfield: Option<(u64, u64, u64)> = None;
        let mut max_alignment = 1;
        let mut structure_members = Vec::new();
        for member in &udt.members {
            let member_ty = Conf::new(self.translate_type_info(&member.member_type)?, 255);
            let member_width = self.width_of_type(&member.member_type)? as u64;
            let natural_alignment = member_ty.contents.alignment().max(1) as u64;
            let mut member_alignment = member.alignment.map_or(natural_alignment, |align| {
                natural_alignment.max(align.get().into())
            });
            if udt.is_unaligned || member.is_unaligned {
                member_alignment = 1;
            } else if let Some(pack) = udt.effective_alignment {
                member_alignment = member_alignment.min(pack.get().into());
            }
            max_alignment = max_alignment.max(member_alignment);

            let (member_offset, bit_width) = match &member.member_type.type_variant {
                TypeVariant::Bitfield(bitfield) => {
                    let storage_bits = u64::from(bitfield.nbytes.get()) * 8;
                    let field_bits = u64::from(bitfield.width);
                    if field_bits == 0 {
                        // A zero-width bitfield is an alignment directive, not a real member.
                        active_bitfield = None;
                        if !is_union {
                            current_bit_offset =
                                align_up(current_bit_offset.div_ceil(8), member_alignment) * 8;
                        }
                        continue;
                    }
                    let field_width = u8::try_from(field_bits)
                        .map_err(|_| anyhow::anyhow!("Bitfield width {field_bits} is too large"))?;
                    if is_union {
                        current_bit_offset = current_bit_offset.max(storage_bits);
                        (0, Some(field_width))
                    } else if let Some((start, active_storage, used)) =
                        active_bitfield.filter(|(_, active_storage, used)| {
                            *active_storage == storage_bits && *used + field_bits <= storage_bits
                        })
                    {
                        active_bitfield = Some((start, active_storage, used + field_bits));
                        (start + used, Some(field_width))
                    } else {
                        let start = align_up(current_bit_offset.div_ceil(8), member_alignment) * 8;
                        current_bit_offset = start + storage_bits;
                        active_bitfield = Some((start, storage_bits, field_bits));
                        (start, Some(field_width))
                    }
                }
                _ => {
                    active_bitfield = None;
                    let offset = if is_union {
                        current_bit_offset = current_bit_offset.max(member_width * 8);
                        0
                    } else {
                        let offset = align_up(current_bit_offset.div_ceil(8), member_alignment);
                        current_bit_offset = (offset + member_width) * 8;
                        offset * 8
                    };
                    (offset, None)
                }
            };

            let member_name = member
                .name
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("field_{}", member_offset / 8));
            let bn_member = if let Some(bit_width) = bit_width {
                StructureMember::new_bitfield(
                    member_ty,
                    member_name,
                    member_offset,
                    bit_width,
                    MemberAccess::PublicAccess,
                    MemberScope::NoScope,
                )
            } else {
                StructureMember::new(
                    member_ty,
                    member_name,
                    member_offset / 8,
                    MemberAccess::PublicAccess,
                    MemberScope::NoScope,
                )
            };
            structure_members.push(bn_member);
        }

        // NTRs can be zero-sized until their definitions are installed in the view, so return the
        // width calculated from the IDA types instead of asking the temporary BN structure.
        Ok((
            structure_members,
            current_bit_offset.div_ceil(8),
            max_alignment,
        ))
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
                    // IDA's grouped (bitmask) enums partition the members into named bitmask
                    // groups. Binary Ninja enumerations are flat and have no equivalent grouping
                    // concept, so we flatten the groups, qualifying each member with its group
                    // name to keep the names unique and preserve the original grouping intent.
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
            // Keep these widths in lockstep with `build_basic_ty` so that NTR placeholder widths
            // match the types they stand in for.
            TypeVariant::Basic(basic) => match basic {
                Basic::Void => Ok(0),
                Basic::Unknown { bytes } => Ok(*bytes as usize),
                Basic::Bool => Ok(self.bool_size),
                Basic::BoolSized { bytes } => Ok(bytes.get() as usize),
                Basic::Char => Ok(1),
                Basic::SegReg => Ok(8),
                Basic::Short { .. } => Ok(self.short_size),
                Basic::Long { .. } => Ok(self.long_size),
                Basic::LongLong { .. } => Ok(self.long_long_size),
                Basic::Int { .. } => Ok(self.int_size),
                Basic::IntSized { bytes, .. } => Ok(bytes.get() as usize),
                Basic::Float { bytes } => Ok(bytes.get() as usize),
                Basic::LongDouble => Ok(self.long_double_size),
            },
            TypeVariant::Pointer(_) => Ok(self.address_size),
            TypeVariant::Function(_) => Err(anyhow::anyhow!("Function types do not have a width")),
            TypeVariant::Array(arr) => {
                let elem_width = self.width_of_type(&arr.elem_type)?;
                // A flexible array member (no element count) contributes no storage of its own;
                // it only names the tail of the containing structure. Treat it as zero-width to
                // mirror `build_array_ty`, rather than erroring, so structures ending in one can
                // still be sized.
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
            // Build the structure/union through the same path used for real translation and read
            // back its finalized width, so alignment padding, bitfield storage sharing and tail
            // padding are all accounted for instead of approximated. This recurses, but C types
            // can only nest by value finitely (self-reference is only possible through a pointer,
            // which is sized by `address_size`), so it always terminates.
            TypeVariant::Struct(s) => Ok(self.build_udt_ty(s, false)?.finalize().width() as usize),
            TypeVariant::Union(u) => Ok(self.build_udt_ty(u, true)?.finalize().width() as usize),
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

    /// Translate an IDA argument/return storage location into a Binary Ninja value location.
    ///
    /// Returns [`ValueLocationSource::Default`] for locations we cannot represent (or whose
    /// registers cannot be resolved), letting the calling convention derive the location.
    fn value_location_from_arg_loc(&self, loc: Option<&ArgLoc>) -> ValueLocationSource {
        match self.value_location_components(loc) {
            Some((components, indirect)) => ValueLocationSource::Custom(ValueLocation {
                components,
                indirect,
                returned_pointer: None,
            }),
            None => ValueLocationSource::Default,
        }
    }

    /// Resolve an IDA [`ArgLoc`] into Binary Ninja value-location components and whether the
    /// location is indirect (the value lives in memory at the component). Returns `None` for
    /// forms with no representation, or when a referenced register cannot be resolved.
    fn value_location_components(
        &self,
        loc: Option<&ArgLoc>,
    ) -> Option<(Vec<ValueLocationComponent>, bool)> {
        match loc? {
            ArgLoc::Stack(offset) => Some((vec![stack_component(*offset as i64)], false)),
            ArgLoc::Reg1(reg) => Some((vec![self.register_component(*reg, 0)?], false)),
            ArgLoc::Reg2(regs) => {
                // The low and high 16 bits each hold a register index; the value is split across
                // the two registers.
                let low = self.register_component(regs & 0xFFFF, 0)?;
                let high = self.register_component((regs >> 16) & 0xFFFF, 0)?;
                Some((vec![low, high], false))
            }
            ArgLoc::RRel { reg, off } => {
                // Register-relative: the value lives in memory at register + offset.
                Some((
                    vec![self.register_component(u32::from(*reg), *off as i64)?],
                    true,
                ))
            }
            // Distributed, static (global address) and none/custom forms have no direct mapping.
            ArgLoc::Dist(_) | ArgLoc::Static(_) | ArgLoc::None => None,
        }
    }

    /// Build a value-location component for an IDA register index, resolving it through the
    /// processor register names and the architecture.
    fn register_component(&self, reg_index: u32, offset: i64) -> Option<ValueLocationComponent> {
        let arch = self.arch.as_ref()?;
        let name = self.register_names.get(reg_index as usize)?;
        let register = arch.register_by_name(name)?;
        Some(ValueLocationComponent {
            variable: Variable::from_register(register),
            offset,
            size: None,
        })
    }
}

fn align_up(value: u64, alignment: u64) -> u64 {
    let alignment = alignment.max(1);
    let remainder = value % alignment;
    if remainder == 0 {
        value
    } else {
        value + alignment - remainder
    }
}

/// Build a value-location component for a stack offset.
fn stack_component(offset: i64) -> ValueLocationComponent {
    ValueLocationComponent {
        variable: Variable::from_stack_offset(offset),
        offset: 0,
        size: None,
    }
}
