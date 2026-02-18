//! Translate windows metadata into a self-contained structure, for later use.

use super::info::{
    MetadataConstantInfo, MetadataFieldInfo, MetadataFunctionInfo, MetadataImportInfo,
    MetadataImportMethod, MetadataInfo, MetadataModuleInfo, MetadataParameterInfo,
    MetadataTypeInfo, MetadataTypeKind,
};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use windows_metadata::reader::TypeCategory;
use windows_metadata::{
    AsRow, FieldAttributes, HasAttributes, MethodCallAttributes, Type, TypeAttributes, Value,
};

pub const BITFIELD_ATTR: &str = "NativeBitfieldAttribute";
pub const CONST_ATTR: &str = "ConstAttribute";
pub const FNPTR_ATTR: &str = "UnmanagedFunctionPointerAttribute";
pub const _STRUCT_SIZE_ATTR: &str = "StructSizeFieldAttribute";
pub const API_CONTRACT_ATTR: &str = "ApiContractAttribute";

#[derive(Error, Debug)]
pub enum TranslationError {
    #[error("no files were provided")]
    NoFiles,
    #[error("the type name '{0}' is not handled")]
    UnhandledType(String),
    #[error("the attribute '{0}' is not supported")]
    UnsupportedAttribute(String),
}

pub struct WindowsMetadataTranslator {
    // TODO: Allow this to be customized by user.
    /// Replace references to a given name with a different one.
    ///
    /// This allows you to move types to a different namespace or rename them and be certain all
    /// references to that type are updated.
    remapped_references: HashMap<(&'static str, &'static str), (&'static str, &'static str)>,
}

impl WindowsMetadataTranslator {
    pub fn new() -> Self {
        // TODO: Move this to a static array.
        let mut remapped_references = HashMap::new();
        remapped_references.insert(("System", "Guid"), ("Windows.Win32.Foundation", "Guid"));
        Self {
            remapped_references,
        }
    }

    pub fn translate(
        &self,
        files: Vec<windows_metadata::reader::File>,
    ) -> Result<MetadataInfo, TranslationError> {
        if files.is_empty() {
            return Err(TranslationError::NoFiles);
        }
        let index = windows_metadata::reader::TypeIndex::new(files);
        self.translate_index(&index)
    }

    pub fn translate_index(
        &self,
        index: &windows_metadata::reader::TypeIndex,
    ) -> Result<MetadataInfo, TranslationError> {
        let mut functions = Vec::new();
        let mut types = Vec::new();
        let mut constants = Vec::new();

        // TODO: Move this somewhere else?
        // Add synthetic types here.
        types.extend([
            MetadataTypeInfo {
                name: "Guid".to_string(),
                kind: MetadataTypeKind::Struct {
                    fields: vec![
                        MetadataFieldInfo {
                            name: "Data1".to_string(),
                            ty: MetadataTypeKind::Integer {
                                size: Some(4),
                                is_signed: false,
                            },
                            is_const: false,
                            bitfield: None,
                        },
                        MetadataFieldInfo {
                            name: "Data2".to_string(),
                            ty: MetadataTypeKind::Integer {
                                size: Some(2),
                                is_signed: false,
                            },
                            is_const: false,
                            bitfield: None,
                        },
                        MetadataFieldInfo {
                            name: "Data3".to_string(),
                            ty: MetadataTypeKind::Integer {
                                size: Some(2),
                                is_signed: false,
                            },
                            is_const: false,
                            bitfield: None,
                        },
                        MetadataFieldInfo {
                            name: "Data4".to_string(),
                            ty: MetadataTypeKind::Array {
                                element: Box::new(MetadataTypeKind::Integer {
                                    size: Some(1),
                                    is_signed: false,
                                }),
                                count: 8,
                            },
                            is_const: false,
                            bitfield: None,
                        },
                    ],
                    is_packed: false,
                },
                namespace: "Windows.Win32.Foundation".to_string(),
            },
            MetadataTypeInfo {
                name: "HANDLE".to_string(),
                kind: MetadataTypeKind::Pointer {
                    is_const: false,
                    is_pointee_const: false,
                    target: Box::new(MetadataTypeKind::Void),
                },
                namespace: "Windows.Win32.Foundation".to_string(),
            },
            MetadataTypeInfo {
                name: "HINSTANCE".to_string(),
                kind: MetadataTypeKind::Pointer {
                    is_const: false,
                    is_pointee_const: false,
                    target: Box::new(MetadataTypeKind::Void),
                },
                namespace: "Windows.Win32.Foundation".to_string(),
            },
            MetadataTypeInfo {
                name: "HMODULE".to_string(),
                kind: MetadataTypeKind::Pointer {
                    is_const: false,
                    is_pointee_const: false,
                    target: Box::new(MetadataTypeKind::Void),
                },
                namespace: "Windows.Win32.Foundation".to_string(),
            },
            MetadataTypeInfo {
                name: "PCSTR".to_string(),
                kind: MetadataTypeKind::Pointer {
                    is_const: true,
                    is_pointee_const: false,
                    target: Box::new(MetadataTypeKind::Character { size: 1 }),
                },
                namespace: "Windows.Win32.Foundation".to_string(),
            },
            MetadataTypeInfo {
                name: "PCWSTR".to_string(),
                kind: MetadataTypeKind::Pointer {
                    is_const: true,
                    is_pointee_const: false,
                    target: Box::new(MetadataTypeKind::Character { size: 2 }),
                },
                namespace: "Windows.Win32.Foundation".to_string(),
            },
            MetadataTypeInfo {
                name: "PSTR".to_string(),
                kind: MetadataTypeKind::Pointer {
                    is_const: false,
                    is_pointee_const: false,
                    target: Box::new(MetadataTypeKind::Character { size: 1 }),
                },
                namespace: "Windows.Win32.Foundation".to_string(),
            },
            MetadataTypeInfo {
                name: "PWSTR".to_string(),
                kind: MetadataTypeKind::Pointer {
                    is_const: false,
                    is_pointee_const: false,
                    target: Box::new(MetadataTypeKind::Character { size: 2 }),
                },
                namespace: "Windows.Win32.Foundation".to_string(),
            },
            MetadataTypeInfo {
                name: "UNICODE_STRING".to_string(),
                kind: MetadataTypeKind::Struct {
                    fields: vec![
                        MetadataFieldInfo {
                            name: "Length".to_string(),
                            ty: MetadataTypeKind::Integer {
                                size: Some(2),
                                is_signed: false,
                            },
                            is_const: false,
                            bitfield: None,
                        },
                        MetadataFieldInfo {
                            name: "MaximumLength".to_string(),
                            ty: MetadataTypeKind::Integer {
                                size: Some(2),
                                is_signed: false,
                            },
                            is_const: false,
                            bitfield: None,
                        },
                        MetadataFieldInfo {
                            name: "Buffer".to_string(),
                            ty: MetadataTypeKind::Reference {
                                namespace: "Windows.Win32.Foundation".to_string(),
                                name: "PWSTR".to_string(),
                            },
                            is_const: false,
                            bitfield: None,
                        },
                    ],
                    is_packed: false,
                },
                namespace: "Windows.Win32.Foundation".to_string(),
            },
            MetadataTypeInfo {
                name: "BOOLEAN".to_string(),
                kind: MetadataTypeKind::Bool { size: Some(1) },
                namespace: "Windows.Win32.Security".to_string(),
            },
            MetadataTypeInfo {
                name: "BOOL".to_string(),
                // BOOL is integer sized, not char sized like a typical bool value.
                kind: MetadataTypeKind::Bool { size: None },
                namespace: "Windows.Win32.Security".to_string(),
            },
        ]);

        for entry in index.types() {
            match entry.category() {
                TypeCategory::Interface => {
                    let (interface_ty, interface_vtable_ty) = self.translate_interface(&entry)?;
                    types.push(interface_ty);
                    types.push(interface_vtable_ty);
                }
                TypeCategory::Class => {
                    let (cls_functions, cls_constants) = self.translate_class(&entry)?;
                    functions.extend(cls_functions);
                    constants.extend(cls_constants);
                }
                TypeCategory::Enum => {
                    types.push(self.translate_enum(&entry)?);
                }
                TypeCategory::Struct => {
                    // Skip marker type structures.
                    if entry.has_attribute(API_CONTRACT_ATTR) {
                        continue;
                    }
                    types.push(self.translate_struct(&entry)?);
                }
                TypeCategory::Delegate => {
                    types.push(self.translate_delegate(&entry)?);
                }
                TypeCategory::Attribute => {
                    // We will pull attributes directly from the other entries.
                }
            }
        }

        // Remove duplicate types within the same namespace, the first one wins. This is what allows
        // us to override types by placing the overrides in the type list before traversing the index.
        let mut tracked_names = HashSet::<(String, String)>::new();
        types.retain(|ty| {
            let ty_name = (ty.namespace.clone(), ty.name.clone());
            tracked_names.insert(ty_name)
        });

        Ok(MetadataInfo {
            types,
            functions,
            constants,
        })
    }

    pub fn translate_struct(
        &self,
        structure: &windows_metadata::reader::TypeDef,
    ) -> Result<MetadataTypeInfo, TranslationError> {
        let mut fields = Vec::new();

        let nested: Result<HashMap<String, _>, _> = structure
            .index()
            .nested(*structure)
            .map(|n| {
                // TODO: Are all nested fields a struct?
                let nested_ty = self.translate_struct(&n)?;
                Ok((n.name().to_string(), nested_ty))
            })
            .collect();
        let nested = nested?;

        for field in structure.fields() {
            let mut field_ty = self.translate_type(&field.ty())?;
            // TODO: This is kinda ugly.
            // Handle nested structures by unwrapping the reference.
            let mut nested_ty = None;
            field_ty.visit_references(&mut |_, name| {
                nested_ty = nested.get(name).cloned().map(|n| n.kind);
            });
            field_ty = nested_ty.unwrap_or(field_ty);

            // Bitfields are special, they are a "fake" field that we need to look at the attributes of
            // to unwrap the real fields that are contained within the storage type.
            if field.has_attribute(BITFIELD_ATTR) {
                for bitfield in field.attributes() {
                    let bitfield_values = bitfield.value();
                    let mut values = bitfield_values.iter();
                    let Some((_, Value::Utf8(bitfield_name))) = values.next() else {
                        continue;
                    };
                    let Some((_, Value::I64(bitfield_pos))) = values.next() else {
                        continue;
                    };
                    let Some((_, Value::I64(bitfield_width))) = values.next() else {
                        continue;
                    };
                    // is_private, is_public, is_virtual
                    fields.push(MetadataFieldInfo {
                        name: bitfield_name.clone(),
                        ty: field_ty.clone(),
                        is_const: field.has_attribute(CONST_ATTR),
                        bitfield: Some((*bitfield_pos as u8, *bitfield_width as u8)),
                    });
                }
            } else {
                fields.push(MetadataFieldInfo {
                    name: field.name().to_string(),
                    ty: field_ty,
                    is_const: field.has_attribute(CONST_ATTR),
                    bitfield: None,
                });
            }
        }

        let mut is_packed = false;
        if let Some(_layout) = structure.class_layout() {
            is_packed = _layout.packing_size() == 1;
        }

        // ExplicitLayout seems to denote a union layout.
        let kind = if structure.flags().contains(TypeAttributes::ExplicitLayout) {
            MetadataTypeKind::Union { fields }
        } else {
            MetadataTypeKind::Struct { fields, is_packed }
        };

        Ok(MetadataTypeInfo {
            name: structure.name().to_string(),
            kind,
            namespace: structure.namespace().to_string(),
        })
    }

    pub fn translate_class(
        &self,
        class: &windows_metadata::reader::TypeDef,
    ) -> Result<(Vec<MetadataFunctionInfo>, Vec<MetadataConstantInfo>), TranslationError> {
        let namespace = class.namespace().to_string();
        let mut functions = Vec::new();
        for method in class.methods() {
            match self.translate_method(&method) {
                Ok(mut func) => {
                    func.namespace = namespace.clone();
                    functions.push(func);
                }
                Err(e) => tracing::warn!("Failed to translate method {}: {}", method.name(), e),
            }
        }

        let mut constants = Vec::new();
        for field in class.fields() {
            if let Some(constant) = field.constant().and_then(|c| self.value_to_u64(&c.value())) {
                constants.push(MetadataConstantInfo {
                    name: field.name().to_string(),
                    namespace: namespace.clone(),
                    ty: self.translate_type(&field.ty())?,
                    value: constant,
                });
            } else {
                tracing::debug!("Field {} is not a constant, skipping...", field.name());
            }
        }

        Ok((functions, constants))
    }

    pub fn translate_method(
        &self,
        method: &windows_metadata::reader::MethodDef,
    ) -> Result<MetadataFunctionInfo, TranslationError> {
        // TODO: Pass generics here? generic_params seems always empty? Even windows-rs doesn't use it.
        let signature = method.signature(&[]);
        let func_params: Result<Vec<MetadataParameterInfo>, TranslationError> = method
            .params()
            .filter(|p| !p.name().is_empty())
            .zip(signature.types)
            .map(|(param, param_ty)| {
                Ok(MetadataParameterInfo {
                    name: param.name().to_string(),
                    ty: self.translate_type(&param_ty)?,
                })
            })
            .collect();
        let func_ty = MetadataTypeKind::Function {
            params: func_params?,
            return_type: Box::new(self.translate_type(&signature.return_type)?),
            is_vararg: signature.flags.contains(MethodCallAttributes::VARARG),
        };

        let import_info = method
            .impl_map()
            .map(|impl_map| self.import_info_from_map(&impl_map));

        Ok(MetadataFunctionInfo {
            name: method.name().to_string(),
            ty: func_ty,
            // NOTE: This will be set by the associated class entry once returned.
            namespace: "".to_string(),
            import_info,
        })
    }

    pub fn translate_delegate(
        &self,
        delegate: &windows_metadata::reader::TypeDef,
    ) -> Result<MetadataTypeInfo, TranslationError> {
        if !delegate.has_attribute(FNPTR_ATTR) {
            return Err(TranslationError::UnsupportedAttribute(
                FNPTR_ATTR.to_string(),
            ));
        }
        let invoke_method = delegate
            .methods()
            .find(|m| m.name() == "Invoke")
            .expect("Invoke method not found");
        let translated_invoke_method = self.translate_method(&invoke_method)?;
        Ok(MetadataTypeInfo {
            name: delegate.name().to_string(),
            kind: MetadataTypeKind::Pointer {
                is_const: false,
                is_pointee_const: false,
                target: Box::new(translated_invoke_method.ty),
            },
            namespace: delegate.namespace().to_string(),
        })
    }

    pub fn translate_interface(
        &self,
        interface: &windows_metadata::reader::TypeDef,
    ) -> Result<(MetadataTypeInfo, MetadataTypeInfo), TranslationError> {
        let mut vtable_fields = Vec::new();
        for meth in interface.methods() {
            let meth_ty = self.translate_method(&meth)?;
            vtable_fields.push(MetadataFieldInfo {
                name: meth.name().to_string(),
                ty: MetadataTypeKind::Pointer {
                    is_const: false,
                    is_pointee_const: false,
                    target: Box::new(meth_ty.ty),
                },
                is_const: false,
                bitfield: None,
            })
        }

        let interface_ns = interface.namespace();
        let interface_ty = MetadataTypeInfo {
            name: interface.name().to_string(),
            kind: MetadataTypeKind::Struct {
                fields: vec![MetadataFieldInfo {
                    name: "vtable".to_string(),
                    ty: MetadataTypeKind::Pointer {
                        is_const: false,
                        is_pointee_const: false,
                        target: Box::new(MetadataTypeKind::Reference {
                            namespace: interface_ns.to_string(),
                            name: format!("{}VTable", interface.name()),
                        }),
                    },
                    is_const: false,
                    bitfield: None,
                }],
                is_packed: false,
            },
            namespace: interface_ns.to_string(),
        };
        let interface_vtable_ty = MetadataTypeInfo {
            name: format!("{}VTable", interface.name()),
            kind: MetadataTypeKind::Struct {
                fields: Vec::new(),
                is_packed: false,
            },
            namespace: interface_ns.to_string(),
        };
        Ok((interface_ty, interface_vtable_ty))
    }

    pub fn translate_enum(
        &self,
        _enum: &windows_metadata::reader::TypeDef,
    ) -> Result<MetadataTypeInfo, TranslationError> {
        let mut variants = Vec::new();
        let mut last_constant = 0;
        let mut enum_ty = MetadataTypeKind::Integer {
            size: None,
            is_signed: true,
        };
        for variant in _enum.fields() {
            if variant.flags().contains(FieldAttributes::RTSpecialName) {
                // Skip the hidden "value__" field.
                continue;
            }
            // Pull the enums type from the constant if it exists.
            // Otherwise, we will fall back to void and use a default type when importing.
            if let Some(constant) = variant.constant() {
                enum_ty = self.translate_type(&constant.ty())?;
            }
            let variant_constant = variant
                .constant()
                .and_then(|c| self.value_to_u64(&c.value()))
                .unwrap_or(last_constant);
            let variant_name = variant.name().to_string();
            variants.push((variant_name, variant_constant));
            last_constant = variant_constant;
        }
        Ok(MetadataTypeInfo {
            name: _enum.name().to_string(),
            kind: MetadataTypeKind::Enum {
                ty: Box::new(enum_ty),
                variants,
            },
            namespace: _enum.namespace().to_string(),
        })
    }

    pub fn translate_type(&self, ty: &Type) -> Result<MetadataTypeKind, TranslationError> {
        match ty {
            Type::Void => Ok(MetadataTypeKind::Void),
            Type::Bool => Ok(MetadataTypeKind::Bool { size: Some(1) }),
            Type::Char => Ok(MetadataTypeKind::Character { size: 1 }),
            Type::I8 => Ok(MetadataTypeKind::Integer {
                size: Some(1),
                is_signed: true,
            }),
            Type::U8 => Ok(MetadataTypeKind::Integer {
                size: Some(1),
                is_signed: false,
            }),
            Type::I16 => Ok(MetadataTypeKind::Integer {
                size: Some(2),
                is_signed: true,
            }),
            Type::U16 => Ok(MetadataTypeKind::Integer {
                size: Some(2),
                is_signed: false,
            }),
            Type::I32 => Ok(MetadataTypeKind::Integer {
                size: Some(4),
                is_signed: true,
            }),
            Type::U32 => Ok(MetadataTypeKind::Integer {
                size: Some(4),
                is_signed: false,
            }),
            Type::I64 => Ok(MetadataTypeKind::Integer {
                size: Some(8),
                is_signed: true,
            }),
            Type::U64 => Ok(MetadataTypeKind::Integer {
                size: Some(8),
                is_signed: false,
            }),
            Type::F32 => Ok(MetadataTypeKind::Float { size: 4 }),
            Type::F64 => Ok(MetadataTypeKind::Float { size: 8 }),
            Type::ISize => Ok(MetadataTypeKind::Integer {
                size: None,
                is_signed: true,
            }),
            Type::USize => Ok(MetadataTypeKind::Integer {
                size: None,
                is_signed: false,
            }),
            Type::Name(name) => {
                if let Some((remapped_ns, remapped_name)) =
                    self.remapped_references.get(&(&name.namespace, &name.name))
                {
                    Ok(MetadataTypeKind::Reference {
                        namespace: remapped_ns.to_string(),
                        name: remapped_name.to_string(),
                    })
                } else {
                    Ok(MetadataTypeKind::Reference {
                        namespace: name.namespace.clone(),
                        name: name.name.clone(),
                    })
                }
            }
            Type::PtrMut(target, _) => Ok(MetadataTypeKind::Pointer {
                is_const: false,
                is_pointee_const: false,
                target: Box::new(self.translate_type(target)?),
            }),
            Type::PtrConst(target, _) => {
                Ok(MetadataTypeKind::Pointer {
                    is_const: false,
                    // TODO: I think this might be pointee const?
                    is_pointee_const: true,
                    target: Box::new(self.translate_type(target)?),
                })
            }
            Type::ArrayFixed(elem_ty, count) => Ok(MetadataTypeKind::Array {
                element: Box::new(self.translate_type(elem_ty)?),
                count: *count,
            }),
            other => Err(TranslationError::UnhandledType(format!("{:?}", other))),
        }
    }

    pub fn import_info_from_map(
        &self,
        map: &windows_metadata::reader::ImplMap,
    ) -> MetadataImportInfo {
        MetadataImportInfo {
            method: MetadataImportMethod::ByName(map.import_name().to_string()),
            module: MetadataModuleInfo {
                name: map.import_scope().name().to_string(),
            },
        }
    }

    pub fn value_to_u64(&self, value: &Value) -> Option<u64> {
        match value {
            Value::Bool(b) => Some(*b as u64),
            Value::U8(i) => Some(*i as u64),
            Value::I8(i) => Some(*i as u64),
            Value::U16(i) => Some(*i as u64),
            Value::I16(i) => Some(*i as u64),
            Value::U32(i) => Some(*i as u64),
            Value::I32(i) => Some(*i as u64),
            Value::U64(i) => Some(*i),
            Value::I64(i) => Some(*i as u64),
            _ => None,
        }
    }
}
