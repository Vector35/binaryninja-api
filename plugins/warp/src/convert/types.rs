use crate::cache::{cached_type_reference, TypeRefID};
use binaryninja::architecture::Architecture as BNArchitecture;
use binaryninja::architecture::ArchitectureExt;
use binaryninja::binary_view::BinaryView;
use binaryninja::calling_convention::CoreCallingConvention as BNCallingConvention;
use binaryninja::confidence::Conf as BNConf;
use binaryninja::confidence::MAX_CONFIDENCE;
use binaryninja::rc::Ref as BNRef;
use binaryninja::types::BaseStructure as BNBaseStructure;
use binaryninja::types::EnumerationBuilder as BNEnumerationBuilder;
use binaryninja::types::FunctionParameter as BNFunctionParameter;
use binaryninja::types::MemberAccess as BNMemberAccess;
use binaryninja::types::MemberScope as BNMemberScope;
use binaryninja::types::NamedTypeReference as BNNamedTypeReference;
use binaryninja::types::StructureBuilder as BNStructureBuilder;
use binaryninja::types::StructureMember as BNStructureMember;
use binaryninja::types::StructureType as BNStructureType;
use binaryninja::types::Type as BNType;
use binaryninja::types::TypeClass as BNTypeClass;
use binaryninja::types::{NamedTypeReference, NamedTypeReferenceClass};
use std::collections::HashSet;
use warp::r#type::class::array::ArrayModifiers;
use warp::r#type::class::pointer::PointerAddressing;
use warp::r#type::class::structure::StructureMemberModifiers;
use warp::r#type::class::{
    ArrayClass, BooleanClass, CallingConvention, CharacterClass, EnumerationClass,
    EnumerationMember, FloatClass, FunctionClass, FunctionMember, IntegerClass, PointerClass,
    ReferrerClass, StructureClass, StructureMember, TypeClass,
};
use warp::r#type::{Type, TypeModifiers};

pub fn from_bn_type(view: &BinaryView, raw_ty: &BNType, confidence: u8) -> Type {
    from_bn_type_internal(view, &mut HashSet::new(), raw_ty, confidence)
}

pub fn from_bn_type_internal(
    view: &BinaryView,
    visited_refs: &mut HashSet<TypeRefID>,
    raw_ty: &BNType,
    confidence: u8,
) -> Type {
    let bytes_to_bits = |val| val * 8;
    let raw_ty_bit_width = bytes_to_bits(raw_ty.width());
    let type_class = match raw_ty.type_class() {
        BNTypeClass::VoidTypeClass => TypeClass::Void,
        BNTypeClass::BoolTypeClass => {
            let bool_class = BooleanClass { width: None };
            TypeClass::Boolean(bool_class)
        }
        BNTypeClass::IntegerTypeClass => {
            let signed = raw_ty.is_signed().contents;
            let width = Some(raw_ty_bit_width as u16);
            if signed && width == Some(8) {
                // NOTE: if its an i8, its a char.
                let char_class = CharacterClass { width: None };
                TypeClass::Character(char_class)
            } else {
                let int_class = IntegerClass { width, signed };
                TypeClass::Integer(int_class)
            }
        }
        BNTypeClass::FloatTypeClass => {
            let float_class = FloatClass {
                width: Some(raw_ty_bit_width as u16),
            };
            TypeClass::Float(float_class)
        }
        // TODO: Union?????
        BNTypeClass::StructureTypeClass => {
            let raw_struct = raw_ty.get_structure().unwrap();

            let mut members = raw_struct
                .members()
                .into_iter()
                .map(|raw_member| {
                    let bit_offset = bytes_to_bits(raw_member.offset);
                    let mut modifiers = StructureMemberModifiers::empty();
                    // If this member is not public mark it as internal.
                    modifiers.set(
                        StructureMemberModifiers::Internal,
                        !matches!(raw_member.access, BNMemberAccess::PublicAccess),
                    );
                    StructureMember {
                        name: Some(raw_member.name),
                        offset: bit_offset,
                        ty: Box::new(from_bn_type_internal(
                            view,
                            visited_refs,
                            &raw_member.ty.contents,
                            raw_member.ty.confidence,
                        )),
                        modifiers,
                    }
                })
                .collect::<Vec<_>>();

            // Add base structures as flattened members
            let base_to_member_iter = raw_struct.base_structures().into_iter().map(|base_struct| {
                let bit_offset = bytes_to_bits(base_struct.offset);
                let mut modifiers = StructureMemberModifiers::empty();
                modifiers.set(StructureMemberModifiers::Flattened, true);
                let base_struct_ty = from_bn_type_internal(
                    view,
                    visited_refs,
                    &BNType::named_type(&base_struct.ty),
                    MAX_CONFIDENCE,
                );
                StructureMember {
                    name: base_struct_ty.name.to_owned(),
                    offset: bit_offset,
                    ty: Box::new(base_struct_ty),
                    modifiers,
                }
            });
            members.extend(base_to_member_iter);

            // TODO: Check if union
            let struct_class = StructureClass::new(members);
            TypeClass::Structure(struct_class)
        }
        BNTypeClass::EnumerationTypeClass => {
            let raw_enum = raw_ty.get_enumeration().unwrap();

            let enum_ty_signed = raw_ty.is_signed().contents;
            let enum_ty = Type::builder::<String, _>()
                .class(TypeClass::Integer(IntegerClass {
                    width: Some(raw_ty_bit_width as u16),
                    signed: enum_ty_signed,
                }))
                .build();

            let members = raw_enum
                .members()
                .into_iter()
                .map(|raw_member| EnumerationMember {
                    name: Some(raw_member.name),
                    constant: raw_member.value,
                })
                .collect();

            let enum_class = EnumerationClass::new(enum_ty, members);
            TypeClass::Enumeration(enum_class)
        }
        BNTypeClass::PointerTypeClass => {
            let raw_child_ty = raw_ty.target().unwrap();
            let ptr_class = PointerClass {
                width: Some(raw_ty_bit_width as u16),
                child_type: Box::new(from_bn_type_internal(
                    view,
                    visited_refs,
                    &raw_child_ty.contents,
                    raw_child_ty.confidence,
                )),
                // TODO: Handle addressing.
                addressing: PointerAddressing::Absolute,
            };
            TypeClass::Pointer(ptr_class)
        }
        BNTypeClass::ArrayTypeClass => {
            let length = raw_ty.count();
            let raw_member_ty = raw_ty.element_type().unwrap();
            let array_class = ArrayClass {
                length: Some(length),
                member_type: Box::new(from_bn_type_internal(
                    view,
                    visited_refs,
                    &raw_member_ty.contents,
                    raw_member_ty.confidence,
                )),
                modifiers: ArrayModifiers::empty(),
            };
            TypeClass::Array(array_class)
        }
        BNTypeClass::FunctionTypeClass => {
            let in_members = raw_ty
                .parameters()
                .unwrap()
                .into_iter()
                .map(|raw_member| {
                    // TODO: Location...
                    // let _location = Location::Register(RegisterLocation);
                    FunctionMember {
                        name: Some(raw_member.name),
                        ty: Box::new(from_bn_type_internal(
                            view,
                            visited_refs,
                            &raw_member.ty.contents,
                            raw_member.ty.confidence,
                        )),
                        // TODO: Just omit location for now?
                        // TODO: Location should be optional...
                        location: None,
                    }
                })
                .collect();

            let mut out_members = Vec::new();
            if let Some(return_ty) = raw_ty.return_value() {
                out_members.push(FunctionMember {
                    name: None,
                    ty: Box::new(from_bn_type_internal(
                        view,
                        visited_refs,
                        &return_ty.contents,
                        return_ty.confidence,
                    )),
                    location: None,
                });
            }

            let calling_convention = raw_ty
                .calling_convention()
                .map(|bn_cc| from_bn_calling_convention(bn_cc.contents));

            let func_class = FunctionClass {
                calling_convention,
                in_members,
                out_members,
            };
            TypeClass::Function(func_class)
        }
        BNTypeClass::VarArgsTypeClass => TypeClass::Void,
        BNTypeClass::ValueTypeClass => {
            // What the is this.
            TypeClass::Void
        }
        BNTypeClass::NamedTypeReferenceClass => {
            let raw_ntr = raw_ty.get_named_type_reference().unwrap();
            let ref_id = TypeRefID::from(raw_ntr.as_ref());
            let mut ref_class = ReferrerClass::new(None, Some(raw_ntr.name().to_string()));
            if visited_refs.insert(ref_id) {
                // This ntr is NOT self-referential, meaning we can deduce a type GUID.
                if let Some(computed_ty) = cached_type_reference(view, visited_refs, &raw_ntr) {
                    // NOTE: The GUID here must always equal the same for any given type for this to work effectively.
                    ref_class.guid = Some(computed_ty.guid);
                }
                visited_refs.remove(&ref_id);
            }
            TypeClass::Referrer(ref_class)
        }
        BNTypeClass::WideCharTypeClass => {
            let char_class = CharacterClass {
                width: Some(raw_ty_bit_width as u16),
            };
            TypeClass::Character(char_class)
        }
    };

    let name = raw_ty.registered_name().map(|n| n.name().to_string());

    Type {
        name,
        class: type_class,
        confidence,
        // TODO: Fill these out...
        modifiers: TypeModifiers::empty(),
        metadata: vec![],
        alignment: Default::default(),
        // TODO: Filling this out is... weird.
        // TODO: we _do_ want this for networked types (this is the only way we can update type is if we fill this out)
        ancestors: vec![],
    }
}

pub fn from_bn_calling_convention(raw_cc: BNRef<BNCallingConvention>) -> CallingConvention {
    // NOTE: Currently calling convention just stores the name.
    CallingConvention::new(raw_cc.name().as_str())
}

pub fn to_bn_calling_convention<A: BNArchitecture>(
    arch: &A,
    calling_convention: &CallingConvention,
) -> BNRef<BNCallingConvention> {
    for cc in &arch.calling_conventions() {
        if cc.name().as_str() == calling_convention.name {
            return cc.clone();
        }
    }
    arch.get_default_calling_convention().unwrap()
}

// Always pass the architecture unless you know what you're doing!
pub fn to_bn_type<A: BNArchitecture + Copy>(arch: Option<A>, ty: &Type) -> BNRef<BNType> {
    let bits_to_bytes = |val: u64| (val / 8);
    let addr_size = arch.map(|a| a.address_size()).unwrap_or(8) as u64;
    match &ty.class {
        TypeClass::Void => BNType::void(),
        TypeClass::Boolean(_) => BNType::bool(),
        TypeClass::Integer(c) => {
            let width = c.width.map(|w| bits_to_bytes(w as _)).unwrap_or(4);
            BNType::int(width as usize, c.signed)
        }
        TypeClass::Character(c) => match c.width {
            Some(w) => BNType::wide_char(bits_to_bytes(w as _) as usize),
            None => BNType::char(),
        },
        TypeClass::Float(c) => {
            let width = c.width.map(|w| bits_to_bytes(w as _)).unwrap_or(4);
            BNType::float(width as usize)
        }
        TypeClass::Pointer(ref c) => {
            let child_type = to_bn_type(arch, &c.child_type);
            let ptr_width = c.width.map(|w| bits_to_bytes(w as _)).unwrap_or(addr_size);
            // TODO: Child type confidence
            let constant = ty.is_const();
            let volatile = ty.is_volatile();
            // TODO: If the pointer is to a null terminated array of chars, make it a pointer to char
            // TODO: Addressing mode
            BNType::pointer_of_width(&child_type, ptr_width as usize, constant, volatile, None)
        }
        TypeClass::Array(c) => {
            let member_type = to_bn_type(arch, &c.member_type);
            // TODO: How to handle DST array (length is None)
            BNType::array(&member_type, c.length.unwrap_or(0))
        }
        TypeClass::Structure(c) => {
            let mut builder = BNStructureBuilder::new();
            // TODO: Structure type class?
            // TODO: Alignment
            // TODO: Other modifiers?
            let mut base_structs: Vec<BNBaseStructure> = Vec::new();
            for member in &c.members {
                let member_type = BNConf::new(to_bn_type(arch, &member.ty), u8::MAX);
                let member_name = member.name.to_owned().unwrap_or("field_OFFSET".into());
                let member_offset = bits_to_bytes(member.offset);
                let member_access = if member
                    .modifiers
                    .contains(StructureMemberModifiers::Internal)
                {
                    BNMemberAccess::PrivateAccess
                } else {
                    BNMemberAccess::PublicAccess
                };
                // TODO: Member scope
                let member_scope = BNMemberScope::NoScope;
                if member
                    .modifiers
                    .contains(StructureMemberModifiers::Flattened)
                {
                    // Add member as a base structure to inherit its fields.
                    match &member.ty.class {
                        TypeClass::Referrer(c) => {
                            // We only support base structures with a referrer right now.
                            let base_struct_ntr_name =
                                c.name.to_owned().unwrap_or("base_UNKNOWN".into());
                            let base_struct_ntr = match c.guid {
                                Some(guid) => BNNamedTypeReference::new_with_id(
                                    NamedTypeReferenceClass::UnknownNamedTypeClass,
                                    &guid.to_string(),
                                    base_struct_ntr_name,
                                ),
                                None => BNNamedTypeReference::new(
                                    NamedTypeReferenceClass::UnknownNamedTypeClass,
                                    base_struct_ntr_name,
                                ),
                            };
                            base_structs.push(BNBaseStructure::new(
                                base_struct_ntr,
                                member_offset,
                                member.ty.size().unwrap_or(0),
                            ))
                        }
                        _ => {
                            log::error!(
                                "Adding base {:?} with invalid ty: {:?}",
                                ty.name,
                                member.ty
                            );
                        }
                    }
                } else {
                    builder.insert_member(
                        BNStructureMember::new(
                            member_type,
                            member_name,
                            member_offset,
                            member_access,
                            member_scope,
                        ),
                        false,
                    );
                }
            }
            builder.base_structures(&base_structs);
            BNType::structure(&builder.finalize())
        }
        TypeClass::Enumeration(c) => {
            let mut builder = BNEnumerationBuilder::new();
            for member in &c.members {
                // TODO: Add default name?
                let member_name = member.name.to_owned().unwrap_or("enum_VAL".into());
                let member_value = member.constant;
                builder.insert(&member_name, member_value);
            }
            // TODO: Warn if enumeration has no size.
            let width = bits_to_bytes(c.member_type.size().unwrap()) as usize;
            let signed = matches!(c.member_type.class, TypeClass::Integer(c) if c.signed);
            // TODO: Passing width like this is weird.
            BNType::enumeration(&builder.finalize(), width.try_into().unwrap(), signed)
        }
        TypeClass::Union(c) => {
            let mut builder = BNStructureBuilder::new();
            builder.structure_type(BNStructureType::UnionStructureType);
            for member in &c.members {
                let member_type = BNConf::new(to_bn_type(arch, &member.ty), u8::MAX);
                let member_name = member.name.to_owned();
                // TODO: Member access
                let member_access = BNMemberAccess::PublicAccess;
                // TODO: Member scope
                let member_scope = BNMemberScope::NoScope;
                let structure_member = BNStructureMember::new(
                    member_type,
                    member_name,
                    0, // Union members all exist at 0 right?
                    member_access,
                    member_scope,
                );
                builder.insert_member(structure_member, false);
            }
            BNType::structure(&builder.finalize())
        }
        TypeClass::Function(c) => {
            let return_type = if !c.out_members.is_empty() {
                // TODO: WTF
                to_bn_type(arch, &c.out_members[0].ty)
            } else {
                BNType::void()
            };
            let params: Vec<_> = c
                .in_members
                .iter()
                .map(|member| {
                    let member_type = to_bn_type(arch, &member.ty);
                    let name = member.name.clone();
                    // TODO: Location AND fix default param name
                    BNFunctionParameter::new(member_type, name.unwrap_or("param_IDK".into()), None)
                })
                .collect();
            // TODO: Variable arguments
            let variable_args = false;
            // If we have a calling convention we run the extended function type creation.
            match (c.calling_convention.as_ref(), arch.as_ref()) {
                (Some(cc), Some(arch)) => {
                    let calling_convention = to_bn_calling_convention(arch, cc);
                    BNType::function_with_opts(
                        &return_type,
                        &params,
                        variable_args,
                        BNConf::new(calling_convention, u8::MAX),
                        BNConf::new(0, 0),
                    )
                }
                (_, _) => BNType::function(&return_type, params, variable_args),
            }
        }
        TypeClass::Referrer(c) => {
            let ntr = match c.guid {
                Some(guid) => {
                    let guid_str = guid.to_string();
                    let ntr_name = c.name.to_owned().unwrap_or(guid_str.clone());
                    NamedTypeReference::new_with_id(
                        NamedTypeReferenceClass::TypedefNamedTypeClass,
                        &guid_str,
                        ntr_name,
                    )
                }
                None => match c.name.as_ref() {
                    Some(ntr_name) => NamedTypeReference::new(
                        NamedTypeReferenceClass::UnknownNamedTypeClass,
                        ntr_name,
                    ),
                    None => {
                        log::error!("Referrer with no reference! {:?}", c);
                        NamedTypeReference::new(
                            NamedTypeReferenceClass::UnknownNamedTypeClass,
                            "AHHHHHH",
                        )
                    }
                },
            };
            BNType::named_type(&ntr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binaryninja::binary_view::BinaryViewExt;
    use binaryninja::headless::Session;
    use std::path::PathBuf;
    use warp::r#type::guid::TypeGUID;

    #[test]
    fn type_conversion() {
        let session = Session::new().expect("Failed to initialize session");
        let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
        for entry in std::fs::read_dir(out_dir).expect("Failed to read OUT_DIR") {
            let entry = entry.expect("Failed to read directory entry");
            let path = entry.path();
            if path.is_file() {
                if let Some(bv) = session.load(path) {
                    let types_len = bv.types().len();
                    let converted_types: Vec<_> = bv
                        .types()
                        .iter()
                        .map(|qualified_name_and_type| {
                            let ty = from_bn_type(&bv, &qualified_name_and_type.ty, u8::MAX);
                            (TypeGUID::from(&ty), ty)
                        })
                        .collect();
                    assert_eq!(types_len, converted_types.len());
                }
            }
        }
    }
}
