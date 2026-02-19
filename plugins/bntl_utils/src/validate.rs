use crate::schema::BntlSchema;
use binaryninja::platform::Platform;
use binaryninja::qualified_name::QualifiedName;
use binaryninja::rc::Ref;
use binaryninja::types::TypeLibrary;
use minijinja::{context, Environment};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::env::temp_dir;
use std::fmt::Display;

#[derive(Debug, PartialEq, PartialOrd, Clone, Eq, Hash, Serialize)]
pub enum ValidateIssue {
    DuplicateGUID {
        guid: String,
        existing_library: String,
    },
    DuplicateDependencyName {
        name: String,
        existing_library: String,
    },
    InvalidMetadata {
        key: String,
        issue: String,
    },
    DuplicateOrdinal {
        ordinal: u64,
        existing_name: String,
        duplicate_name: String,
    },
    NoPlatform,
    UnresolvedExternalReference {
        name: String,
        container: String,
    },
    UnresolvedSourceReference {
        name: String,
        source: String,
    },
    UnresolvedTypeLibrary {
        name: String,
    }, // TODO: Overlapping type name of platform?
       // TODO: E.g. a type is found in the type library, and also in the platform.
}

impl Display for ValidateIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidateIssue::DuplicateGUID {
                guid,
                existing_library,
            } => {
                write!(
                    f,
                    "Duplicate GUID: '{}' is already used by library '{}'",
                    guid, existing_library
                )
            }
            ValidateIssue::DuplicateDependencyName {
                name,
                existing_library,
            } => {
                write!(
                    f,
                    "Duplicate Dependency Name: '{}' is already provided by '{}'",
                    name, existing_library
                )
            }
            ValidateIssue::InvalidMetadata { key, issue } => {
                write!(f, "Invalid Metadata: Key '{}' - {}", key, issue)
            }
            ValidateIssue::DuplicateOrdinal {
                ordinal,
                existing_name,
                duplicate_name,
            } => {
                write!(
                    f,
                    "Duplicate Ordinal: #{} is assigned to both '{}' and '{}'",
                    ordinal, existing_name, duplicate_name
                )
            }
            ValidateIssue::NoPlatform => {
                write!(
                    f,
                    "Missing Platform: The type library has no target platform associated with it"
                )
            }
            ValidateIssue::UnresolvedExternalReference { name, container } => {
                write!(
                    f,
                    "Unresolved External Reference: Type '{}' referenced inside '{}' is marked as external but has no source",
                    name, container
                )
            }
            ValidateIssue::UnresolvedSourceReference { name, source } => {
                write!(
                    f,
                    "Unresolved Source Reference: Type '{}' expects source '{}', but it wasn't found there",
                    name, source
                )
            }
            ValidateIssue::UnresolvedTypeLibrary { name } => {
                write!(
                    f,
                    "Unresolved Type Library: Could not find dependency library file for '{}'",
                    name
                )
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct ValidateResult {
    pub issues: Vec<ValidateIssue>,
}

impl ValidateResult {
    /// Render the validation report as HTML.
    pub fn render_report(&self) -> Result<String, minijinja::Error> {
        let mut environment = Environment::new();
        // Remove trailing lines for blocks, this is required for Markdown tables.
        environment.set_trim_blocks(true);
        minijinja_embed::load_templates!(&mut environment);
        let tmpl = environment.get_template("validate.html")?;
        tmpl.render(context!(issues => self.issues))
    }
}

#[derive(Debug, Default, Clone)]
pub struct TypeLibValidater {
    pub seen_guids: HashMap<String, String>,
    // TODO: This needs to be by platform as well.
    pub seen_dependency_names: HashMap<String, String>,
    /// These are the type libraries that are accessible to the type library under validation.
    ///
    /// Used to validate external references.
    pub type_libraries: Vec<Ref<TypeLibrary>>,
    /// Built from the available type libraries.
    pub valid_external_references: HashSet<QualifiedName>,
}

impl TypeLibValidater {
    pub fn new() -> Self {
        Self {
            seen_guids: HashMap::new(),
            seen_dependency_names: HashMap::new(),
            type_libraries: Vec::new(),
            valid_external_references: HashSet::new(),
        }
    }

    /// These are the type libraries that are accessible to the type library under validation.
    ///
    /// Used to validate external references.
    pub fn with_type_libraries(mut self, type_libraries: Vec<Ref<TypeLibrary>>) -> Self {
        self.type_libraries = type_libraries;
        for type_lib in &self.type_libraries {
            for ty in &type_lib.named_types() {
                self.valid_external_references.insert(ty.name);
            }
            for obj in &type_lib.named_objects() {
                self.valid_external_references.insert(obj.name);
            }
        }
        self
    }

    /// The platform that is accessible to the type library under validation.
    ///
    /// Used to validate external references.
    pub fn with_platform(mut self, platform: &Platform) -> Self {
        for ty in &platform.types() {
            self.valid_external_references.insert(ty.name);
        }
        self
    }

    pub fn validate(&mut self, type_lib: &TypeLibrary) -> ValidateResult {
        let mut result = ValidateResult::default();

        if type_lib.platform_names().is_empty() {
            result.issues.push(ValidateIssue::NoPlatform);
        }

        if let Some(issue) = self.validate_guid(type_lib) {
            result.issues.push(issue);
        }

        if let Some(issue) = self.validate_dependency_name(type_lib) {
            result.issues.push(issue);
        }

        result.issues.extend(self.validate_ordinals(type_lib));
        result
            .issues
            .extend(self.validate_external_references(type_lib));

        // TODO: This is currently disabled because it's too slow.
        result.issues.extend(self.validate_source_files(type_lib));

        result
    }

    pub fn validate_guid(&mut self, type_lib: &TypeLibrary) -> Option<ValidateIssue> {
        match self.seen_guids.insert(type_lib.guid(), type_lib.name()) {
            None => None,
            Some(existing_library) => Some(ValidateIssue::DuplicateGUID {
                guid: type_lib.guid(),
                existing_library,
            }),
        }
    }

    pub fn validate_dependency_name(&mut self, type_lib: &TypeLibrary) -> Option<ValidateIssue> {
        match self
            .seen_dependency_names
            .insert(type_lib.dependency_name(), type_lib.name())
        {
            None => None,
            Some(existing_library) => Some(ValidateIssue::DuplicateDependencyName {
                name: type_lib.dependency_name(),
                existing_library,
            }),
        }
    }

    pub fn validate_source_files(&self, type_lib: &TypeLibrary) -> Vec<ValidateIssue> {
        let mut issues = Vec::new();
        let tmp_type_lib_path = temp_dir().join(type_lib.name());
        if !type_lib.decompress_to_file(&tmp_type_lib_path) {
            tracing::error!(
                "Failed to decompress type library to temporary file: {}",
                type_lib.name()
            );
            return issues;
        }
        let schema = BntlSchema::from_path(&tmp_type_lib_path);
        for (src, types) in schema.to_source_map() {
            let Some(dep_type_lib) = self.type_libraries.iter().find(|tl| tl.name() == src) else {
                issues.push(ValidateIssue::UnresolvedTypeLibrary {
                    name: src.to_string(),
                });
                continue;
            };

            for ty in &types {
                let qualified_name = QualifiedName::from(ty);
                let is_named_ty = dep_type_lib
                    .get_named_type(qualified_name.clone())
                    .is_none();
                let is_named_obj = dep_type_lib.get_named_object(qualified_name).is_none();
                if !is_named_ty && !is_named_obj {
                    issues.push(ValidateIssue::UnresolvedSourceReference {
                        name: ty.to_string(),
                        source: src.to_string(),
                    });
                }
            }
        }
        issues
    }

    pub fn validate_external_references(&self, type_lib: &TypeLibrary) -> Vec<ValidateIssue> {
        let mut issues = Vec::new();
        for ty in &type_lib.named_types() {
            crate::helper::visit_type_reference(&ty.ty, &mut |ntr| {
                if !self.valid_external_references.contains(&ntr.name()) {
                    issues.push(ValidateIssue::UnresolvedExternalReference {
                        name: ntr.name().to_string(),
                        container: ty.name.to_string(),
                    });
                }
            })
        }
        for obj in &type_lib.named_objects() {
            crate::helper::visit_type_reference(&obj.ty, &mut |ntr| {
                if !self.valid_external_references.contains(&ntr.name()) {
                    issues.push(ValidateIssue::UnresolvedExternalReference {
                        name: ntr.name().to_string(),
                        container: obj.name.to_string(),
                    });
                }
            })
        }
        issues
    }

    pub fn validate_ordinals(&self, type_lib: &TypeLibrary) -> Vec<ValidateIssue> {
        let Some(metadata_key_md) = type_lib.query_metadata("metadata") else {
            return vec![];
        };
        let Some(metadata_key_str) = metadata_key_md.get_string() else {
            return vec![ValidateIssue::InvalidMetadata {
                key: "metadata".to_owned(),
                issue: "Expected string".to_owned(),
            }];
        };

        let Some(metadata_map_md) = type_lib.query_metadata(&metadata_key_str.to_string_lossy())
        else {
            return vec![ValidateIssue::InvalidMetadata {
                key: metadata_key_str.to_string_lossy().to_string(),
                issue: "Missing metadata map key".to_owned(),
            }];
        };

        let Some(metadata_map) = metadata_map_md.get_value_store() else {
            return vec![ValidateIssue::InvalidMetadata {
                key: metadata_key_str.to_string_lossy().to_string(),
                issue: "Expected value store".to_owned(),
            }];
        };

        let mut discovered_ordinals = HashMap::new();
        let mut issues = Vec::new();
        for (key, value) in metadata_map.iter() {
            let Ok(ordinal_num) = key.parse::<u64>() else {
                issues.push(ValidateIssue::InvalidMetadata {
                    key: key.to_string(),
                    issue: "Expected ordinal number".to_owned(),
                });
                continue;
            };

            let Some(value_bn_str) = value.get_string() else {
                issues.push(ValidateIssue::InvalidMetadata {
                    key: key.to_string(),
                    issue: "Expected string".to_owned(),
                });
                continue;
            };
            let value_str = value_bn_str.to_string_lossy().to_string();

            match discovered_ordinals.insert(ordinal_num, value_str.clone()) {
                None => (),
                Some(existing_ordinal) => issues.push(ValidateIssue::DuplicateOrdinal {
                    ordinal: ordinal_num,
                    existing_name: existing_ordinal,
                    duplicate_name: value_str,
                }),
            }
        }
        issues
    }
}
