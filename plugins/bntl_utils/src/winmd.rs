//! Import windows metadata types into a Binary Ninja type library.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use thiserror::Error;

use binaryninja::architecture::Architecture;
use binaryninja::platform::Platform;
use binaryninja::qualified_name::QualifiedName;
use binaryninja::rc::Ref;
use binaryninja::types::{
    EnumerationBuilder, FunctionParameter, MemberAccess, MemberScope, NamedTypeReference,
    NamedTypeReferenceClass, StructureBuilder, StructureType, Type, TypeBuilder, TypeLibrary,
};

use info::{LibraryName, MetadataFunctionInfo, MetadataInfo, MetadataTypeInfo, MetadataTypeKind};

pub mod info;
pub mod translate;

#[derive(Error, Debug)]
pub enum ImportError {
    #[error("no files were provided")]
    NoFiles,
    #[error("the type name '{0}' is not handled")]
    UnhandledType(String),
    #[error("failed to translate windows metadata")]
    TransactionError(#[from] translate::TranslationError),
    #[error("the type '{0}' has an unhandled size")]
    UnhandledTypeSize(&'static str),
}

#[derive(Debug)]
pub struct WindowsMetadataImporter {
    info: MetadataInfo,
    // TODO: If we can replace / add this with type libraries we can make multi-pass importer.
    type_lookup: HashMap<(String, String), MetadataTypeInfo>,
    address_size: usize,
    integer_size: usize,
}

impl WindowsMetadataImporter {
    pub fn new() -> Self {
        Self {
            info: MetadataInfo::default(),
            type_lookup: HashMap::new(),
            address_size: 8,
            integer_size: 8,
        }
    }

    #[allow(dead_code)]
    pub fn new_with_info(info: MetadataInfo) -> Self {
        let mut res = Self::new();
        res.info = info;
        res.build_type_lookup();
        res
    }

    pub fn with_files(mut self, paths: &[PathBuf]) -> Result<Self, ImportError> {
        let mut files = Vec::new();
        for path in paths {
            let file = windows_metadata::reader::File::read(path).expect("Failed to read file");
            files.push(file);
        }
        self.info = translate::WindowsMetadataTranslator::new().translate(files)?;
        // We updated info, so we must rebuild the lookup table.
        self.build_type_lookup();
        Ok(self)
    }

    #[allow(dead_code)]
    pub fn with_platform(mut self, platform: &Platform) -> Self {
        // TODO: platform.address_size()
        self.address_size = platform.arch().address_size();
        self.integer_size = platform.arch().default_integer_size();
        self
    }

    /// Build the lookup table for us to use when referencing types.
    ///
    /// Should be called anytime we update `self.info`.
    fn build_type_lookup(&mut self) {
        for ty in &self.info.types {
            if let Some(_existing) = self
                .type_lookup
                .insert((ty.namespace.clone(), ty.name.clone()), ty.clone())
            {
                tracing::warn!(
                    "Duplicate type name '{}' found when building type lookup",
                    ty.name
                );
            }
        }
    }

    pub fn import(&self, platform: &Platform) -> Result<Vec<Ref<TypeLibrary>>, ImportError> {
        // TODO: We need to take all of these enums and figure out where to put them.
        let mut test = self.info.clone();
        let constant_enums = test.create_constant_enums();
        // TODO: Creating zero width enums
        test.types.extend(constant_enums);
        let partitioned_info = test.partitioned();

        let mut type_libs = Vec::new();
        for (name, info) in partitioned_info.libraries {
            let type_lib_name = match name {
                LibraryName::Module(module_name) => module_name.clone(),
                LibraryName::Namespace(ns_name) => {
                    // TODO: We might need to do something different for namespaced type libraries in the future.
                    ns_name.clone()
                }
            };
            let til = TypeLibrary::new(platform.arch(), &type_lib_name);
            til.add_platform(platform);
            til.set_dependency_name(&type_lib_name);
            for ty in &info.metadata.types {
                self.import_type(&til, ty)?;
            }
            for func in &info.metadata.functions {
                self.import_function(&til, func)?;
            }
            for (name, library_name) in &info.external_references {
                let qualified_name = QualifiedName::from(name.clone());
                match library_name {
                    LibraryName::Namespace(source) => {
                        // TODO: We might need to do something different for namespaced type libraries in the future.
                        til.add_type_source(qualified_name, source);
                    }
                    LibraryName::Module(source) => {
                        til.add_type_source(qualified_name, source);
                    }
                }
            }

            type_libs.push(til);
        }

        Ok(type_libs)
    }

    pub fn import_function(
        &self,
        til: &TypeLibrary,
        func: &MetadataFunctionInfo,
    ) -> Result<(), ImportError> {
        // TODO: Handle ordinals? Ordinals exist in binaries that need to be parsed, maybe we
        // TODO: make another handler for that
        let qualified_name = QualifiedName::from(func.name.clone());
        let ty = self.convert_type_kind(&func.ty)?;
        til.add_named_object(qualified_name, &ty);
        Ok(())
    }

    pub fn import_type(
        &self,
        til: &TypeLibrary,
        type_info: &MetadataTypeInfo,
    ) -> Result<(), ImportError> {
        let qualified_name = QualifiedName::from(type_info.name.clone());
        let ty = self.convert_type_kind(&type_info.kind)?;
        til.add_named_type(qualified_name, &ty);
        Ok(())
    }

    pub fn convert_type_kind(&self, kind: &MetadataTypeKind) -> Result<Ref<Type>, ImportError> {
        match kind {
            MetadataTypeKind::Void => Ok(Type::void()),
            MetadataTypeKind::Bool { size: None } => Ok(Type::bool()),
            MetadataTypeKind::Bool { size: Some(size) } => {
                Ok(TypeBuilder::bool().set_width(*size).finalize())
            }
            MetadataTypeKind::Integer { size, is_signed } => {
                Ok(Type::int(size.unwrap_or(self.integer_size), *is_signed))
            }
            MetadataTypeKind::Character { size: 1 } => Ok(Type::int(1, true)),
            MetadataTypeKind::Character { size } => Ok(Type::wide_char(*size)),
            MetadataTypeKind::Float { size } => Ok(Type::float(*size)),
            MetadataTypeKind::Pointer {
                is_const,
                is_pointee_const: _is_pointee_const,
                target,
            } => {
                let target_ty = self.convert_type_kind(target)?;
                Ok(Type::pointer_of_width(
                    &target_ty,
                    self.address_size,
                    *is_const,
                    false,
                    None,
                ))
            }
            MetadataTypeKind::Array { element, count } => {
                let element_ty = self.convert_type_kind(element)?;
                Ok(Type::array(&element_ty, *count as u64))
            }
            MetadataTypeKind::Struct { fields, is_packed } => {
                let mut structure = StructureBuilder::new();
                // Current offset in bytes
                let mut current_byte_offset = 0usize;

                // TODO: Change how this operates now that we have an is_packed flag.
                // Used to add tail padding to satisfy alignment requirements.
                let mut max_alignment = 0usize;
                // We need to look ahead to figure out when bitfields end and adjust current_byte_offset accordingly.
                let mut field_iter = fields.iter().peekable();
                while let Some(field) = field_iter.next() {
                    let field_ty = self.convert_type_kind(&field.ty)?;
                    let field_size = self.type_kind_size(&field.ty)?;
                    let field_alignment = self.type_kind_alignment(&field.ty)?;
                    max_alignment = max_alignment.max(field_alignment);
                    if let Some((bit_pos, bit_width)) = field.bitfield {
                        let current_bit_offset = current_byte_offset * 8;
                        let field_bit_offset = current_bit_offset + bit_pos as usize;
                        // TODO: member access and member scope have definitions inside winmd we can use.
                        structure.insert_bitwise(
                            &field_ty,
                            &field.name,
                            field_bit_offset as u64,
                            Some(bit_width),
                            false,
                            MemberAccess::PublicAccess,
                            MemberScope::NoScope,
                        );

                        if let Some(next_field) = field_iter.peek() {
                            if next_field.bitfield.is_some() {
                                // Continue as if we are in the same storage unit (no alignment)
                                current_byte_offset = (current_bit_offset + bit_width as usize) / 8;
                            } else {
                                // Find the start of the storage unit.
                                // if we are at byte 1 of u32 (align 4), storage starts at 0.
                                // if we are at byte 5 of u32 (align 4), storage starts at 4.
                                let storage_start =
                                    (current_byte_offset / field_alignment) * field_alignment;
                                // Jump to the end of that storage unit.
                                current_byte_offset = storage_start + field_size;
                            }
                        }
                    } else {
                        // Align the field placement based on the current field alignment.
                        let aligned_current_offset =
                            align_up(current_byte_offset as u64, field_alignment as u64);
                        structure.insert(
                            &field_ty,
                            &field.name,
                            aligned_current_offset,
                            false,
                            MemberAccess::PublicAccess,
                            MemberScope::NoScope,
                        );
                        current_byte_offset = aligned_current_offset as usize + field_size;
                    }
                }
                structure.alignment(max_alignment);

                // TODO: Only add tail padding if we are not packed? I think we still need to do more.
                if *is_packed {
                    structure.packed(true);
                } else {
                    let total_size = align_up(current_byte_offset as u64, max_alignment as u64);
                    structure.width(total_size);
                }

                Ok(Type::structure(&structure.finalize()))
            }
            MetadataTypeKind::Enum { ty, variants } => {
                // NOTE: A void type may be returned by synthetic constant enums, which is why we
                // do not error when there is a zero width enum.
                let enum_ty = self.convert_type_kind(ty)?;
                let mut builder = EnumerationBuilder::new();
                for (name, value) in variants {
                    builder.insert(name, *value);
                }
                Ok(Type::enumeration(
                    &builder.finalize(),
                    NonZeroUsize::new(enum_ty.width() as usize)
                        .unwrap_or(NonZeroUsize::new(self.integer_size).unwrap()),
                    enum_ty.is_signed().contents,
                ))
            }
            MetadataTypeKind::Function {
                params,
                return_type,
                is_vararg,
            } => {
                let return_ty = self.convert_type_kind(return_type)?;
                let mut bn_params = Vec::new();
                for param in params {
                    let param_ty = self.convert_type_kind(&param.ty)?;
                    bn_params.push(FunctionParameter::new(param_ty, param.name.clone(), None));
                }
                Ok(Type::function(&return_ty, bn_params, *is_vararg))
            }
            MetadataTypeKind::Reference { name, namespace } => {
                // We are required to set the ID here since type libraries seem to only look up through
                // the ID, and never fall back to name lookup. This is strange considering you must also
                // set the types source to the given library, which seems counterintuitive.
                // TODO: Add kind to ntr.
                let ntr = NamedTypeReference::new_with_id(
                    NamedTypeReferenceClass::TypedefNamedTypeClass,
                    &format!("{}::{}", namespace, name),
                    name,
                );
                // TODO: Type alignment?
                let type_size = self.type_kind_size(kind)?;
                Ok(TypeBuilder::named_type(&ntr)
                    .set_width(type_size)
                    .set_alignment(type_size)
                    .finalize())
            }
            MetadataTypeKind::Union { fields } => {
                let mut union = StructureBuilder::new();
                union.structure_type(StructureType::UnionStructureType);

                let mut max_alignment = 0usize;
                for field in fields {
                    let field_ty = self.convert_type_kind(&field.ty)?;
                    let field_alignment = self.type_kind_alignment(&field.ty)?;
                    max_alignment = max_alignment.max(field_alignment);
                    union.insert(
                        &field_ty,
                        &field.name,
                        0,
                        false,
                        MemberAccess::PublicAccess,
                        MemberScope::NoScope,
                    );
                }

                union.alignment(max_alignment);
                Ok(Type::structure(&union.finalize()))
            }
        }
    }

    /// Retrieve the size of a type kind in bytes, references to types will be looked up
    /// such that we can determine the size of structures with references as fields.
    pub fn type_kind_size(&self, kind: &MetadataTypeKind) -> Result<usize, ImportError> {
        match kind {
            MetadataTypeKind::Void => Ok(0),
            MetadataTypeKind::Bool { size } => Ok(size.unwrap_or(self.integer_size)),
            MetadataTypeKind::Integer { size, .. } => Ok(size.unwrap_or(self.integer_size)),
            MetadataTypeKind::Character { size } => Ok(*size),
            MetadataTypeKind::Float { size } => Ok(*size),
            MetadataTypeKind::Pointer { .. } => Ok(self.address_size),
            MetadataTypeKind::Array { element, count } => {
                let elem_size = self.type_kind_size(element)?;
                Ok(elem_size * *count)
            }
            MetadataTypeKind::Struct { fields, is_packed } => {
                let mut current_offset = 0usize;
                let mut max_struct_alignment = 1usize;
                for field in fields {
                    let field_size = self.type_kind_size(&field.ty)?;
                    let field_alignment = if *is_packed {
                        1
                    } else {
                        self.type_kind_alignment(&field.ty)?
                    };
                    max_struct_alignment = max_struct_alignment.max(field_alignment);
                    current_offset =
                        align_up(current_offset as u64, field_alignment as u64) as usize;
                    current_offset += field_size;
                }
                // Tail padding is only needed if not packed.
                let final_alignment = if *is_packed { 1 } else { max_struct_alignment };
                let total_size = align_up(current_offset as u64, final_alignment as u64) as usize;
                Ok(total_size)
            }
            MetadataTypeKind::Union { fields } => {
                let mut largest_field_size = 0usize;
                for field in fields {
                    let field_size = self.type_kind_size(&field.ty)?;
                    largest_field_size = largest_field_size.max(field_size);
                }
                Ok(largest_field_size)
            }
            MetadataTypeKind::Enum { ty, .. } => self.type_kind_size(ty),
            MetadataTypeKind::Function { .. } => Err(ImportError::UnhandledTypeSize(
                "Function types are not sized",
            )),
            MetadataTypeKind::Reference { name, namespace } => {
                // Look up the type and return its size.
                let Some(ty_info) = self.type_lookup.get(&(namespace.clone(), name.clone())) else {
                    // This should really only happen if we did not specify all the required winmd files.
                    // tracing::error!(
                    //     "Failed to find type '{}' when looking up type size for reference",
                    //     name
                    // );
                    return Ok(1);
                };
                self.type_kind_size(&ty_info.kind)
            }
        }
    }

    pub fn type_kind_alignment(&self, kind: &MetadataTypeKind) -> Result<usize, ImportError> {
        match kind {
            MetadataTypeKind::Bool { size: None } => Ok(1),
            MetadataTypeKind::Bool { size } => Ok(size.unwrap_or(self.integer_size)),
            // TODO: Clean this stuff up.
            MetadataTypeKind::Character { size } => Ok(*size),
            MetadataTypeKind::Integer { size: Some(1), .. } => Ok(1),
            MetadataTypeKind::Integer { size: Some(2), .. } => Ok(2),
            MetadataTypeKind::Integer { size: Some(4), .. } => Ok(4),
            MetadataTypeKind::Integer { size: Some(8), .. }
            | MetadataTypeKind::Float { size: 8 }
            | MetadataTypeKind::Pointer { .. } => Ok(self.address_size), // 8 on x64
            MetadataTypeKind::Array { element, .. } => self.type_kind_alignment(element),
            MetadataTypeKind::Struct { fields, is_packed } => {
                if *is_packed {
                    return Ok(1);
                }
                let mut max_align = 1usize;
                for field in fields {
                    max_align = max_align.max(self.type_kind_alignment(&field.ty)?);
                }
                Ok(max_align)
            }
            MetadataTypeKind::Union { fields } => {
                let mut max_align = 1usize;
                for field in fields {
                    max_align = max_align.max(self.type_kind_alignment(&field.ty)?);
                }
                Ok(max_align)
            }
            MetadataTypeKind::Reference { name, namespace } => {
                let Some(ty_info) = self.type_lookup.get(&(namespace.clone(), name.clone())) else {
                    // TODO: Failed to find it in local type lookup, try type libraries?
                    // tracing::error!(
                    //     "Failed to find type '{}' when looking up type alignment for reference",
                    //     name
                    // );
                    return Ok(4);
                };
                self.type_kind_alignment(&ty_info.kind)
            }
            _ => Ok(4),
        }
    }
}

// Aligns an offset up to the nearest multiple of `align`.
fn align_up(offset: u64, align: u64) -> u64 {
    if align == 0 {
        return offset;
    }
    let mask = align - 1;
    (offset + mask) & !mask
}

#[cfg(test)]
mod tests {
    use super::info::{
        MetadataFieldInfo, MetadataImportInfo, MetadataImportMethod, MetadataModuleInfo,
    };
    use super::*;
    use binaryninja::architecture::CoreArchitecture;
    use binaryninja::types::TypeClass;

    #[test]
    fn test_import_type() {
        // We must initialize binary ninja to access architectures.
        let _session = binaryninja::headless::Session::new().expect("Failed to create session");

        let mut info = MetadataInfo::default();
        info.functions = vec![MetadataFunctionInfo {
            name: "MyFunction".to_string(),
            ty: MetadataTypeKind::Function {
                params: vec![],
                return_type: Box::new(MetadataTypeKind::Void),
                is_vararg: false,
            },
            namespace: "Win32.Test".to_string(),
            import_info: Some(MetadataImportInfo {
                method: MetadataImportMethod::ByName("MyFunction".to_string()),
                module: MetadataModuleInfo {
                    name: "TestModule.dll".to_string(),
                },
            }),
        }];
        info.types = vec![
            MetadataTypeInfo {
                name: "Bar".to_string(),
                kind: MetadataTypeKind::Integer {
                    size: Some(4),
                    is_signed: true,
                },
                namespace: "Win32.Test".to_string(),
            },
            MetadataTypeInfo {
                name: "TestType".to_string(),
                kind: MetadataTypeKind::Struct {
                    fields: vec![
                        MetadataFieldInfo {
                            name: "field1".to_string(),
                            ty: MetadataTypeKind::Integer {
                                size: Some(4),
                                is_signed: false,
                            },
                            is_const: false,
                            bitfield: None,
                        },
                        // TODO: Add more fields to verify bitfields, and const fields.
                        MetadataFieldInfo {
                            name: "field2_0".to_string(),
                            ty: MetadataTypeKind::Integer {
                                size: Some(4),
                                is_signed: true,
                            },
                            is_const: true,
                            bitfield: Some((0, 1)),
                        },
                        MetadataFieldInfo {
                            name: "field2_1".to_string(),
                            ty: MetadataTypeKind::Integer {
                                size: Some(4),
                                is_signed: true,
                            },
                            is_const: true,
                            bitfield: Some((1, 1)),
                        },
                        MetadataFieldInfo {
                            name: "field3".to_string(),
                            ty: MetadataTypeKind::Integer {
                                size: Some(2),
                                is_signed: true,
                            },
                            is_const: true,
                            bitfield: None,
                        },
                        MetadataFieldInfo {
                            name: "field4".to_string(),
                            ty: MetadataTypeKind::Pointer {
                                is_pointee_const: false,
                                is_const: false,
                                target: Box::new(MetadataTypeKind::Reference {
                                    namespace: "Win32.Test".to_string(),
                                    name: "Bar".to_string(),
                                }),
                            },
                            is_const: false,
                            bitfield: None,
                        },
                    ],
                    is_packed: false,
                },
                namespace: "Foo".to_string(),
            },
        ];
        let importer = WindowsMetadataImporter::new_with_info(info);
        let x86 = CoreArchitecture::by_name("x86").expect("No x86 architecture");
        let platform = Platform::by_name("windows-x86").expect("No windows-x86 platform");
        let type_libraries = importer.import(&platform).expect("Failed to import types");
        assert_eq!(type_libraries.len(), 1);
        let til = type_libraries.first().expect("No type libraries");
        assert_eq!(til.named_types().len(), 1);
        let first_ty = til
            .named_types()
            .iter()
            .next()
            .expect("No types in library");
        assert_eq!(first_ty.name.to_string(), "TestType");
        assert_eq!(first_ty.ty.type_class(), TypeClass::StructureTypeClass);
        let first_ty_struct = first_ty
            .ty
            .get_structure()
            .expect("Type is not a structure");
        assert_eq!(first_ty_struct.members().len(), 5);
        let mut structure_fields = first_ty_struct.members().iter();

        for member in first_ty_struct.members() {
            println!(" +{}: {}", member.offset, member.name.to_string())
        }

        // TODO: Finish this!
        assert!(false);
        // let first_member = structure_fields.next().expect("No fields in structure");
        // assert_eq!(first_member.name.to_string(), "field1");
        // assert_eq!(first_member.ty, TypeClass::IntegerTypeClass);
        // let second_member = structure_fields.next().expect("No fields in structure");
        // assert_eq!(second_member.name.to_string(), "field2_0");
        // assert_eq!(second_member.type.type_class(), TypeClass::IntegerTypeClass);
        // let third_member = structure_fields.next().expect("No fields in structure");
        // assert_eq!(third_member.name.to_string(), "field2_1");
        // assert_eq!(third_member.type.type_class(), TypeClass::IntegerTypeClass);
        // let fourth_member = structure_fields.next().expect("No fields in structure");
    }
}
