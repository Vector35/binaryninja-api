use binaryninja::interaction::{Form, FormInputField};
use binaryninja::user_directory;
use std::path::PathBuf;

pub mod create;
pub mod diff;
pub mod dump;
pub mod validate;
// TODO: Load?

pub struct InputFileField;

impl InputFileField {
    pub fn field() -> FormInputField {
        FormInputField::OpenFileName {
            prompt: "File Path".to_string(),
            // TODO: This is called extension but is really a filter.
            extension: None,
            default: None,
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("File Path")?;
        let field_value = field.try_value_string()?;
        Some(PathBuf::from(field_value))
    }
}

pub struct OutputDirectoryField;

impl OutputDirectoryField {
    pub fn field() -> FormInputField {
        let type_lib_dir = user_directory().join("typelib");
        FormInputField::DirectoryName {
            prompt: "Output Directory".to_string(),
            default: Some(type_lib_dir.to_string_lossy().to_string()),
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("Output Directory")?;
        let field_value = field.try_value_string()?;
        Some(PathBuf::from(field_value))
    }
}

pub struct InputDirectoryField;

impl InputDirectoryField {
    pub fn field() -> FormInputField {
        FormInputField::DirectoryName {
            prompt: "Input Directory".to_string(),
            default: None,
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("Input Directory")?;
        let field_value = field.try_value_string()?;
        Some(PathBuf::from(field_value))
    }
}
