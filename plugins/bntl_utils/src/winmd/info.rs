//! Metadata information extracted from Windows metadata files.
//!
//! While we could use the direct representation, this is easier to work with.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Default, Clone)]
pub struct MetadataInfo {
    pub types: Vec<MetadataTypeInfo>,
    pub functions: Vec<MetadataFunctionInfo>,
    pub constants: Vec<MetadataConstantInfo>,
}

impl MetadataInfo {
    /// Partitions the metadata into a map of libraries, where each library contains types and functions
    /// that belong to that library. This is used when mapping metadata info to type libraries.
    pub fn partitioned(&self) -> PartitionedMetadataInfo {
        let mut result_map: HashMap<LibraryName, LibraryInfo> = HashMap::new();

        // Map of namespace to module names that use it.
        let mut namespace_dependencies: HashMap<String, HashSet<String>> = HashMap::new();
        for func in &self.functions {
            if let Some(import) = &func.import_info {
                namespace_dependencies
                    .entry(func.namespace.clone())
                    .or_default()
                    .insert(import.module.name.clone());
            }
        }

        let namespace_to_library_name = |ns: &str| -> LibraryName {
            match namespace_dependencies.get(ns) {
                Some(modules) if modules.len() == 1 => {
                    LibraryName::Module(modules.iter().next().unwrap().clone())
                }
                _ => LibraryName::Namespace(ns.to_string()),
            }
        };

        for func in &self.functions {
            let dest_lib = match &func.import_info {
                Some(info) => LibraryName::Module(info.module.name.clone()),
                None => LibraryName::Namespace(func.namespace.clone()),
            };
            let entry = result_map.entry(dest_lib.clone()).or_default();
            func.ty.visit_references(&mut |ns, name| {
                let library_name = namespace_to_library_name(ns);
                if dest_lib != library_name {
                    entry
                        .external_references
                        .insert(name.to_string(), library_name);
                }
            });
            entry.metadata.functions.push(func.clone());
        }

        for ty in &self.types {
            let dest_lib = namespace_to_library_name(&ty.namespace);
            let entry = result_map.entry(dest_lib.clone()).or_default();
            ty.kind.visit_references(&mut |ns, name| {
                let library_name = namespace_to_library_name(ns);
                if dest_lib != library_name {
                    entry
                        .external_references
                        .insert(name.to_string(), library_name);
                }
            });
            entry.metadata.types.push(ty.clone());
        }

        for constant in &self.constants {
            let dest_lib = namespace_to_library_name(&constant.namespace);
            let entry = result_map.entry(dest_lib.clone()).or_default();
            constant.ty.visit_references(&mut |ns, name| {
                let library_name = namespace_to_library_name(ns);
                if dest_lib != library_name {
                    entry
                        .external_references
                        .insert(name.to_string(), library_name);
                }
            });
            entry.metadata.constants.push(constant.clone());
        }

        PartitionedMetadataInfo {
            libraries: result_map,
        }
    }

    pub fn create_constant_enums(&self) -> Vec<MetadataTypeInfo> {
        // Group constants by their type, if there are multiple constants with the same type, we
        // will make an enum out of them, once that is done, we will take overlapping constants
        // and prioritize certain namespaces over others.
        // TODO: Add some more structured types here, this is a crazy map.
        let mut grouped_constants: HashMap<
            (String, String),
            HashMap<u64, Vec<MetadataConstantInfo>>,
        > = HashMap::new();
        for constant in &self.constants {
            let MetadataTypeKind::Reference { name, namespace } = &constant.ty else {
                // TODO: We should optionally provide a way to group constants like these into an enumeration.
                // Skipping constant `WDS_MC_TRACE_VERBOSE` with non-reference type `Integer { size: Some(4), is_signed: false }`
                // Skipping constant `WDS_MC_TRACE_INFO` with non-reference type `Integer { size: Some(4), is_signed: false }`
                // Skipping constant `WDS_MC_TRACE_WARNING` with non-reference type `Integer { size: Some(4), is_signed: false }`
                // Skipping constant `WDS_MC_TRACE_ERROR` with non-reference type `Integer { size: Some(4), is_signed: false }`
                // Skipping constant `WDS_MC_TRACE_FATAL` with non-reference type `Integer { size: Some(4), is_signed: false }`
                tracing::debug!(
                    "Skipping constant `{}` with non-reference type `{:?}`",
                    constant.name,
                    constant.ty
                );
                continue;
            };
            grouped_constants
                .entry((namespace.clone(), name.clone()))
                .or_default()
                .entry(constant.value)
                .or_default()
                .push(constant.clone());
        }

        let mut enums = Vec::new();
        for ((enum_namespace, enum_name), mapped_values) in grouped_constants {
            let mut variants = Vec::new();
            for (_, group_variants) in mapped_values {
                let sorted_group_variants =
                    sort_metadata_constants_by_proximity(&enum_namespace, group_variants);
                let enum_variants: Vec<_> = sorted_group_variants
                    .iter()
                    .map(|info| (info.name.clone(), info.value))
                    .collect();
                variants.extend(enum_variants);
            }

            let enum_kind = MetadataTypeKind::Enum {
                ty: Box::new(MetadataTypeKind::Void),
                variants,
            };

            enums.push(MetadataTypeInfo {
                name: enum_name,
                kind: enum_kind,
                namespace: enum_namespace,
            });
        }
        enums
    }

    #[allow(dead_code)]
    fn update_stale_references(&mut self) {
        let mut valid_type_map = HashMap::new();
        for ty in self.types.iter() {
            valid_type_map.insert(ty.name.clone(), ty.clone());
        }

        for ty in self.types.iter_mut() {
            ty.kind.visit_references_mut(&mut |node| {
                let MetadataTypeKind::Reference { name, namespace } = node else {
                    tracing::error!(
                        "`visit_references_mut` did not return a reference! {:?}",
                        node
                    );
                    return;
                };
                if let Some(survivor) = valid_type_map.get(name) {
                    if namespace != &survivor.namespace {
                        tracing::debug!(
                            "Updating stale namespace reference `{}` to `{}` for `{}`",
                            namespace,
                            survivor.namespace,
                            name
                        );
                        *namespace = survivor.namespace.clone();
                    }
                }
            });
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum LibraryName {
    /// A synthetic library with no associated module name.
    ///
    /// The shared library is "synthetic" in the sense that a binary view cannot reference it directly.
    Namespace(String),
    /// A real module with a name (e.g. "info.dll"), these libraries can be referenced directly by a binary view.
    Module(String),
}

#[derive(Debug, Clone, Default)]
pub struct LibraryInfo {
    pub metadata: MetadataInfo,
    /// A map of externally referenced names to their library names.
    ///
    /// This is required when resolving type references to other libraries.
    pub external_references: HashMap<String, LibraryName>,
}

#[derive(Debug, Default)]
pub struct PartitionedMetadataInfo {
    pub libraries: HashMap<LibraryName, LibraryInfo>,
}

// TODO: ModuleRef (computable from ModuleInfo and the underlying core module)
// TODO: Put a ModuleRef in all places where a module is associated.
#[derive(Debug, Clone)]
pub struct MetadataModuleInfo {
    /// The modules name on disk, this is used to determine the imported
    /// function name when loading type information from a type library.
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct MetadataTypeInfo {
    pub name: String,
    pub kind: MetadataTypeKind,
    /// The namespace of the type, e.x. "Windows.Win32.Foundation"
    ///
    /// This is used to help determine what library this information belongs to. When we go to import
    /// this information (along with others), we will build a tree of information where each node
    /// corresponds to the namespace, and each child node corresponds to a sub-namespace. Then import
    /// info will be enumerated to determine if the type can only ever belong to a single import module
    /// if the type is only used in a single module, we will place it in that type library. If the namespace
    /// can reference more than one module, we will place it in a common type library named after
    /// the namespace itself, it can only ever be referenced by another type library and as such should
    /// only contain types and no functions.
    ///
    /// For more information see [`PartitionedMetadataInfo`].
    pub namespace: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataTypeKind {
    Void,
    Bool {
        // NOTE: Weird optional, if None we actually default the size to integer size!
        size: Option<usize>,
    },
    Integer {
        size: Option<usize>,
        is_signed: bool,
    },
    Character {
        size: usize,
    },
    Float {
        size: usize,
    },
    Pointer {
        is_const: bool,
        is_pointee_const: bool,
        target: Box<MetadataTypeKind>,
    },
    Array {
        element: Box<MetadataTypeKind>,
        count: usize,
    },
    Struct {
        fields: Vec<MetadataFieldInfo>,
        is_packed: bool,
    },
    Union {
        fields: Vec<MetadataFieldInfo>,
    },
    Enum {
        ty: Box<MetadataTypeKind>,
        variants: Vec<(String, u64)>,
    },
    Function {
        params: Vec<MetadataParameterInfo>,
        return_type: Box<MetadataTypeKind>,
        is_vararg: bool,
    },
    Reference {
        // TODO: Generics may also be passed here.
        /// The namespace of the referenced type, e.x. "Windows.Win32.Foundation"
        namespace: String,
        /// The referenced type name, e.x. "BOOL"
        name: String,
    },
}

impl MetadataTypeKind {
    pub(crate) fn visit_references<F>(&self, callback: &mut F)
    where
        F: FnMut(&str, &str),
    {
        match self {
            MetadataTypeKind::Reference { namespace, name } => {
                callback(namespace, name);
            }
            MetadataTypeKind::Pointer { target, .. } => {
                target.visit_references(callback);
            }
            MetadataTypeKind::Array { element, .. } => {
                element.visit_references(callback);
            }
            MetadataTypeKind::Struct { fields, .. } => {
                for field in fields {
                    field.ty.visit_references(callback);
                }
            }
            MetadataTypeKind::Enum { ty, .. } => {
                ty.visit_references(callback);
            }
            MetadataTypeKind::Function {
                params,
                return_type,
                ..
            } => {
                for param in params {
                    param.ty.visit_references(callback);
                }
                return_type.visit_references(callback);
            }
            _ => {}
        }
    }

    #[allow(dead_code)]
    pub(crate) fn visit_references_mut<F>(&mut self, callback: &mut F)
    where
        F: FnMut(&mut MetadataTypeKind),
    {
        match self {
            MetadataTypeKind::Reference { .. } => {
                callback(self);
            }
            MetadataTypeKind::Pointer { target, .. } => {
                target.visit_references_mut(callback);
            }
            MetadataTypeKind::Array { element, .. } => {
                element.visit_references_mut(callback);
            }
            MetadataTypeKind::Struct { fields, .. } | MetadataTypeKind::Union { fields, .. } => {
                for field in fields {
                    field.ty.visit_references_mut(callback);
                }
            }
            MetadataTypeKind::Enum { ty, .. } => {
                ty.visit_references_mut(callback);
            }
            MetadataTypeKind::Function {
                params,
                return_type,
                ..
            } => {
                for param in params {
                    param.ty.visit_references_mut(callback);
                }
                return_type.visit_references_mut(callback);
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataFieldInfo {
    pub name: String,
    pub ty: MetadataTypeKind,
    pub is_const: bool,
    /// This is only set for bitfields, The first value is the bit position within the associated byte,
    /// and the second is the bit width.
    ///
    /// NOTE: The bit position can never be greater than `7`.
    pub bitfield: Option<(u8, u8)>,
    // TODO: Attributes ( virtual, static, etc...)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataParameterInfo {
    pub name: String,
    pub ty: MetadataTypeKind,
    // TODO: Attributes (in, out, etc...)
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum MetadataImportMethod {
    ByName(String),
    ByOrdinal(u32),
}

#[derive(Debug, Clone)]
pub struct MetadataImportInfo {
    #[allow(dead_code)]
    pub method: MetadataImportMethod,
    pub module: MetadataModuleInfo,
}

#[derive(Debug, Clone)]
pub struct MetadataFunctionInfo {
    pub name: String,
    /// This will only ever be [`MetadataTypeKind::Function`].
    pub ty: MetadataTypeKind,
    pub namespace: String,
    pub import_info: Option<MetadataImportInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataConstantInfo {
    pub name: String,
    pub namespace: String,
    pub ty: MetadataTypeKind,
    pub value: u64,
}

pub fn sort_metadata_constants_by_proximity(
    reference: &str,
    mut candidates: Vec<MetadataConstantInfo>,
) -> Vec<MetadataConstantInfo> {
    let ref_parts: Vec<&str> = reference.split('.').collect();
    candidates.sort_by_cached_key(|info| {
        // Extract the namespace string from the metadata info
        let ns = &info.namespace;
        let cand_parts = ns.split('.');

        let score = ref_parts
            .iter()
            .zip(cand_parts)
            .take_while(|(a, b)| *a == b)
            .count();

        // Sort by highest score first, then alphabetically by namespace
        (std::cmp::Reverse(score), ns.clone())
    });
    candidates
}
