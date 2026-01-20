use binaryninja::interaction::{Form, FormInputField};
use std::path::PathBuf;

pub mod load_file;

pub struct LoadFileField {
    filter: String,
    default: Option<String>,
}

impl LoadFileField {
    #[allow(unused)]
    pub fn new(filter: &str) -> Self {
        Self {
            filter: filter.to_string(),
            default: None,
        }
    }

    pub fn with_default(filter: &str, default: &str) -> Self {
        Self {
            filter: filter.to_string(),
            default: Some(default.to_string()),
        }
    }

    pub fn field(&self) -> FormInputField {
        FormInputField::OpenFileName {
            prompt: "File Path".to_string(),
            // TODO: This is called extension but is really a filter.
            extension: Some(self.filter.clone()),
            default: self.default.clone(),
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("File Path")?;
        let field_value = field.try_value_string()?;
        Some(PathBuf::from(field_value))
    }
}
