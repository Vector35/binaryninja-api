use crate::command::OutputDirectoryField;
use crate::diff::TILDiff;
use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::BinaryView;
use binaryninja::command::Command;
use binaryninja::interaction::{Form, FormInputField};
use binaryninja::types::TypeLibrary;
use std::path::PathBuf;
use std::thread;

pub struct InputFileAField;

impl InputFileAField {
    pub fn field() -> FormInputField {
        FormInputField::OpenFileName {
            prompt: "Library A".to_string(),
            // TODO: This is called extension but is really a filter.
            extension: Some("*.bntl".to_string()),
            default: None,
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("Library A")?;
        let field_value = field.try_value_string()?;
        Some(PathBuf::from(field_value))
    }
}

pub struct InputFileBField;

impl InputFileBField {
    pub fn field() -> FormInputField {
        FormInputField::OpenFileName {
            prompt: "Library B".to_string(),
            // TODO: This is called extension but is really a filter.
            extension: Some("*.bntl".to_string()),
            default: None,
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("Library B")?;
        let field_value = field.try_value_string()?;
        Some(PathBuf::from(field_value))
    }
}

pub struct Diff;

impl Diff {
    pub fn execute() {
        let mut form = Form::new("Diff type libraries");
        form.add_field(InputFileAField::field());
        form.add_field(InputFileBField::field());
        form.add_field(OutputDirectoryField::field());
        if !form.prompt() {
            return;
        }
        let a_path = InputFileAField::from_form(&form).unwrap();
        let b_path = InputFileBField::from_form(&form).unwrap();
        let output_dir = OutputDirectoryField::from_form(&form).unwrap();

        let _bg_task = BackgroundTask::new("Diffing type libraries...", false).enter();
        let Some(type_lib_a) = TypeLibrary::load_from_file(&a_path) else {
            tracing::error!("Failed to load type library: {}", a_path.display());
            return;
        };
        let Some(type_lib_b) = TypeLibrary::load_from_file(&b_path) else {
            tracing::error!("Failed to load type library: {}", b_path.display());
            return;
        };

        let diff_result = match TILDiff::new().diff((&a_path, &type_lib_a), (&b_path, &type_lib_b))
        {
            Ok(diff_result) => diff_result,
            Err(err) => {
                tracing::error!("Failed to diff type libraries: {}", err);
                return;
            }
        };
        tracing::info!("Similarity Ratio: {}", diff_result.ratio);
        let output_path = output_dir
            .join(type_lib_a.dependency_name())
            .with_extension("diff");
        std::fs::write(&output_path, diff_result.diff).unwrap();
        tracing::info!("Diff written to: {}", output_path.display());
    }
}

impl Command for Diff {
    fn action(&self, _view: &BinaryView) {
        thread::spawn(move || {
            Diff::execute();
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
