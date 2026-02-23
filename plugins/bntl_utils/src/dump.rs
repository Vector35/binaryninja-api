use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::file_metadata::FileMetadata;
use binaryninja::metadata::{Metadata, MetadataType};
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::types::printer::TokenEscapingType;
use binaryninja::types::{CoreTypePrinter, TypeLibrary};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TILDumpError {
    #[error("Failed to create empty BinaryView")]
    ViewCreationFailed,

    #[error("Type library has no associated platforms")]
    NoPlatformFound,

    #[error("Platform '{0}' not found in Binary Ninja")]
    PlatformNotFound(String),

    #[error("Failed to print types from library")]
    PrinterError,

    #[error("Metadata error: {0}")]
    MetadataError(String),

    #[error("Unexpected metadata type for 'ordinals': {0:?}")]
    UnexpectedMetadataType(MetadataType),
}

pub struct TILDump {
    /// The type libraries that are accessible to the type printer.
    available_type_libs: Vec<Ref<TypeLibrary>>,
}

impl TILDump {
    pub fn new() -> Self {
        Self {
            available_type_libs: Vec::new(),
        }
    }

    pub fn with_type_libs(mut self, type_libs: Vec<Ref<TypeLibrary>>) -> Self {
        self.available_type_libs = type_libs;
        self
    }

    pub fn dump(&self, type_lib: &TypeLibrary) -> Result<String, TILDumpError> {
        let empty_file = FileMetadata::new();
        let empty_bv = BinaryView::from_data(&empty_file, &[]);

        let type_lib_plats = type_lib.platform_names();
        let platform_name = type_lib_plats
            .iter()
            .next()
            .ok_or(TILDumpError::NoPlatformFound)?;

        let platform_name_str = platform_name.to_string();
        let platform = Platform::by_name(&platform_name_str)
            .ok_or(TILDumpError::PlatformNotFound(platform_name_str))?;

        empty_bv.set_default_platform(&platform);

        for dependency in &self.available_type_libs {
            empty_bv.add_type_library(dependency);
        }
        empty_bv.add_type_library(type_lib);

        for ty in &type_lib.named_types() {
            empty_bv.import_type_library_type(ty.name, None);
        }
        for obj in &type_lib.named_objects() {
            empty_bv.import_type_library_object(obj.name, None);
        }

        let dep_sorted_types = empty_bv.dependency_sorted_types();
        let unsorted_functions = type_lib.named_objects();
        let mut all_types: Vec<_> = dep_sorted_types
            .iter()
            .chain(unsorted_functions.iter())
            .collect();
        all_types.sort_by_key(|t| t.name.clone());

        let type_printer = CoreTypePrinter::default();
        let printed_types = type_printer
            .print_all_types(
                all_types,
                &empty_bv,
                4,
                TokenEscapingType::NoTokenEscapingType,
            )
            .ok_or(TILDumpError::PrinterError)?;

        let mut printed_types_str = printed_types.to_string_lossy().to_string();
        printed_types_str.push_str("\n// TYPE LIBRARY INFORMATION\n");

        let metadata_lines = type_library_metadata_to_string(type_lib)?;
        printed_types_str.push_str(&metadata_lines.join("\n"));

        empty_file.close();
        Ok(printed_types_str)
    }
}

fn type_library_metadata_to_string(type_lib: &TypeLibrary) -> Result<Vec<String>, TILDumpError> {
    let mut result = Vec::new();
    for alt_name in &type_lib.alternate_names() {
        result.push(format!("// ALTERNATE NAME: {}", alt_name));
    }

    let mut add_ordinals = |metadata: Ref<Metadata>| -> Result<(), TILDumpError> {
        if let Some(map) = metadata.get_value_store() {
            let mut list = map.iter().collect::<Vec<_>>();
            list.sort_by_key(|&(key, _)| key.parse::<u64>().unwrap_or_default());
            for (key, value) in list {
                result.push(format!("// ORDINAL {}: {}", key, value));
            }
        }
        Ok(())
    };

    if let Some(ordinal_key) = type_lib.query_metadata("ordinals") {
        match ordinal_key.get_type() {
            MetadataType::StringDataType => {
                let queried_key = ordinal_key.get_string().ok_or_else(|| {
                    TILDumpError::MetadataError("Failed to get ordinal key string".into())
                })?;

                let queried_key_str = queried_key.to_string_lossy();
                let queried_md = type_lib.query_metadata(&queried_key_str).ok_or_else(|| {
                    TILDumpError::MetadataError(format!(
                        "Failed to query metadata for key: {}",
                        queried_key_str
                    ))
                })?;

                add_ordinals(queried_md)?;
            }
            MetadataType::KeyValueDataType => add_ordinals(ordinal_key)?,
            ty => return Err(TILDumpError::UnexpectedMetadataType(ty)),
        }
    }

    Ok(result)
}
