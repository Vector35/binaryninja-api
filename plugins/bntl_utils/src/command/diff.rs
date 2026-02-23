use crate::command::OutputDirectoryField;
use crate::diff::TILDiff;
use crate::helper::path_to_type_libraries;
use binaryninja::background_task::BackgroundTask;
use binaryninja::command::GlobalCommand;
use binaryninja::interaction::{Form, FormInputField};
use std::path::PathBuf;
use std::thread;

pub struct InputFileAField;

impl InputFileAField {
    pub fn field() -> FormInputField {
        FormInputField::DirectoryName {
            prompt: "Directory A".to_string(),
            default: None,
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("Directory A")?;
        let field_value = field.try_value_string()?;
        Some(PathBuf::from(field_value))
    }
}

pub struct InputFileBField;

impl InputFileBField {
    pub fn field() -> FormInputField {
        FormInputField::DirectoryName {
            prompt: "Directory B".to_string(),
            default: None,
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("Directory B")?;
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

        let bg_task = BackgroundTask::new("Diffing type libraries...", true).enter();

        let b_libraries = path_to_type_libraries(&a_path);
        let a_libraries = path_to_type_libraries(&b_path);
        // TODO: Make this parallel
        for a_lib in &a_libraries {
            for b_lib in &b_libraries {
                if bg_task.is_cancelled() {
                    return;
                }

                if a_lib.name() != b_lib.name() {
                    continue;
                }

                bg_task.set_progress_text(&format!("Diffing '{}'...", a_lib.name()));
                let diff_result = match TILDiff::new().diff_with_dependencies(
                    (&a_lib, a_libraries.clone()),
                    (&b_lib, b_libraries.clone()),
                ) {
                    Ok(diff_result) => diff_result,
                    Err(err) => {
                        tracing::error!("Failed to diff type libraries: {}", err);
                        continue;
                    }
                };
                tracing::info!("Similarity Ratio: {}", diff_result.ratio);

                let output_path = output_dir.join(a_lib.name()).with_extension("diff");
                std::fs::write(&output_path, diff_result.diff).unwrap();
                tracing::info!("Diff written to: {}", output_path.display());
            }
        }
    }
}

impl GlobalCommand for Diff {
    fn action(&self) {
        thread::spawn(move || {
            Diff::execute();
        });
    }

    fn valid(&self) -> bool {
        true
    }
}
