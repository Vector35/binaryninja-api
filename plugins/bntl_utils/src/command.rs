use binaryninja::interaction::{Form, FormInputField};
use binaryninja::user_directory;
use std::path::PathBuf;

pub mod create;
pub mod diff;
pub mod dump;
pub mod validate;
// TODO: Load?

pub struct OutputDirectoryField;

impl OutputDirectoryField {
    pub fn field() -> FormInputField {
        let type_lib_dir = user_directory().join("typelib");
        FormInputField::DirectoryName {
            prompt: "Output Directory".to_string(),
            default_name: Some(type_lib_dir.clone()),
            default: Some(type_lib_dir),
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("Output Directory")?;
        field.try_value_path()
    }
}

pub struct InputDirectoryField;

impl InputDirectoryField {
    pub fn field() -> FormInputField {
        FormInputField::DirectoryName {
            prompt: "Input Directory".to_string(),
            default_name: None,
            default: None,
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("Input Directory")?;
        field.try_value_path()
    }
}
