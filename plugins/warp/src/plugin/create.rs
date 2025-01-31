use crate::processor::{
    CompressionTypeField, FileDataKindField, IncludedFunctionsField, WarpFileProcessor,
};
use crate::report::{ReportGenerator, ReportKindField};
use crate::{user_signature_dir, INCLUDE_TAG_NAME};
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use binaryninja::interaction::form::{Form, FormInputField};
use binaryninja::interaction::{MessageBoxButtonResult, MessageBoxButtonSet, MessageBoxIcon};
use binaryninja::rc::Ref;
use std::path::PathBuf;
use std::thread;
use warp::WarpFile;

pub struct SaveFileField;

impl SaveFileField {
    pub fn field(view: &BinaryView) -> FormInputField {
        let default_name = view
            .file()
            .filename()
            .split('/')
            .last()
            .unwrap_or("file")
            .to_string();
        let signature_dir = user_signature_dir();
        let default_file_path = signature_dir.join(&default_name).with_extension("warp");
        FormInputField::SaveFileName {
            prompt: "File Path".to_string(),
            // TODO: This is called extension but is really a filter.
            extension: Some("*.warp".to_string()),
            default_name: Some(default_name),
            default: Some(default_file_path.to_string_lossy().to_string()),
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("File Path")?;
        let field_value = field.try_value_string()?;
        Some(PathBuf::from(field_value))
    }
}

pub struct CreateSignatureFile;

impl CreateSignatureFile {
    pub fn execute(view: Ref<BinaryView>) -> Option<()> {
        // Prompt the user first so that they can go do other things and not worry about a popup.
        let mut form = Form::new("Create Signature File");
        form.add_field(SaveFileField::field(&view));

        let fd_field = FileDataKindField::default();
        form.add_field(fd_field.to_field());

        let compression_field = CompressionTypeField::default();
        form.add_field(compression_field.to_field());

        let mut included_field = IncludedFunctionsField::default();
        // If the view has the include tag, we better set the default to the selected functions.
        if view.tag_type_by_name(INCLUDE_TAG_NAME).is_some() {
            included_field = IncludedFunctionsField::Selected;
        }
        form.add_field(included_field.to_field());

        let report_field = ReportKindField::default();
        form.add_field(report_field.to_field());

        if !form.prompt() {
            return None;
        }
        let compression_type = CompressionTypeField::from_form(&form).unwrap_or_default();
        let file_path = SaveFileField::from_form(&form)?;
        let file_data_kind = FileDataKindField::from_form(&form).unwrap_or_default();
        let file_included_functions = IncludedFunctionsField::from_form(&form).unwrap_or_default();
        let report_kind = ReportKindField::from_form(&form).unwrap_or_default();

        // If we already have a file, prompt the user if they want to add the data.
        let mut existing_chunks = Vec::new();
        if file_path.exists() {
            let prompt_result = binaryninja::interaction::show_message_box(
                "Keep existing file data?",
                "The file already exists. Do you want to keep the existing data?",
                MessageBoxButtonSet::YesNoCancelButtonSet,
                MessageBoxIcon::QuestionIcon,
            );

            match prompt_result {
                MessageBoxButtonResult::NoButton => {
                    // User wants to overwrite the file.
                }
                MessageBoxButtonResult::YesButton | MessageBoxButtonResult::OKButton => {
                    // User wants to keep the existing data.
                    let data = std::fs::read(&file_path).ok()?;
                    let existing_file = WarpFile::from_owned_bytes(data)?;
                    existing_chunks.extend(existing_file.chunks);
                }
                MessageBoxButtonResult::CancelButton => {
                    log::info!(
                        "User cancelled signature file creation, no operations were performed."
                    );
                    return None;
                }
            }
        }

        let file_builder = WarpFileProcessor::new()
            .with_compression_type(compression_type)
            .with_file_data(file_data_kind)
            .with_included_functions(file_included_functions);

        // Reference path is just used for the state tracking. Does not need to be readable.
        let reference_path = file_path.clone();
        let Ok(mut file) = file_builder.process_view(reference_path, &view) else {
            log::error!("Failed to create signature file!");
            return None;
        };

        // Add back the existing chunks if the user selected to keep them.
        // TODO: Optionally merge the chunks?
        file.chunks.extend(existing_chunks);

        if std::fs::write(&file_path, file.to_bytes()).is_err() {
            log::error!("Failed to write data to signature file!");
        }

        // Show the report if desired.
        match report_kind {
            ReportKindField::None => {}
            ReportKindField::Html => {
                let report_generator = ReportGenerator::new();
                if let Some(html_string) = report_generator.html_report(&file) {
                    view.show_html_report("Generated WARP File", html_string.as_str(), "");
                }
            }
            ReportKindField::Markdown => {
                let report_generator = ReportGenerator::new();
                if let Some(md_string) = report_generator.markdown_report(&file) {
                    view.show_markdown_report("Generated WARP File", md_string.as_str(), "");
                }
            }
            ReportKindField::Json => {
                let report_generator = ReportGenerator::new();
                if let Some(json_string) = report_generator.json_report(&file) {
                    view.show_plaintext_report("Generated WARP File", json_string.as_str());
                }
            }
        }

        Some(())
    }
}

impl Command for CreateSignatureFile {
    fn action(&self, view: &BinaryView) {
        let view = view.to_owned();
        thread::spawn(move || {
            CreateSignatureFile::execute(view);
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
