use crate::processor::{
    new_processing_state_background_thread, CompressionTypeField, FileDataKindField,
    IncludedFunctionsField, SaveReportToDiskField, WarpFileProcessor,
};
use crate::report::{ReportGenerator, ReportKindField};
use crate::{user_signature_dir, INCLUDE_TAG_NAME};
use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use binaryninja::interaction::form::{Form, FormInputField};
use binaryninja::interaction::{MessageBoxButtonResult, MessageBoxButtonSet, MessageBoxIcon};
use binaryninja::rc::Ref;
use std::path::PathBuf;
use std::thread;
use warp::chunk::Chunk;
use warp::WarpFile;

pub struct SaveFileField;

impl SaveFileField {
    pub fn field(view: &BinaryView) -> FormInputField {
        let file = view.file();
        let default_name = match file.project_file() {
            None => {
                // Not in a project, use the file name directly.
                file.filename()
                    .split('/')
                    .last()
                    .unwrap_or("file")
                    .to_string()
            }
            Some(project_file) => project_file.name(),
        };
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

pub struct OpenFileField;

impl OpenFileField {
    pub fn field() -> FormInputField {
        FormInputField::OpenFileName {
            prompt: "Input File Path".to_string(),
            extension: None,
            default: None,
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("Input File Path")?;
        let field_value = field.try_value_string()?;
        Some(PathBuf::from(field_value))
    }
}

pub struct CreateFromCurrentView;

impl CreateFromCurrentView {
    pub fn execute(view: Ref<BinaryView>, external_file: bool) -> Option<()> {
        // Prompt the user first so that they can go do other things and not worry about a popup.
        let mut form = Form::new("Create From View");

        if external_file {
            form.add_field(OpenFileField::field());
        }

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
        let report_to_disk_field = SaveReportToDiskField::default();
        form.add_field(report_to_disk_field.to_field());

        if !form.prompt() {
            return None;
        }
        let compression_type = CompressionTypeField::from_form(&form).unwrap_or_default();
        let file_path = SaveFileField::from_form(&form)?;
        let file_data_kind = FileDataKindField::from_form(&form).unwrap_or_default();
        let file_included_functions = IncludedFunctionsField::from_form(&form).unwrap_or_default();
        let report_kind = ReportKindField::from_form(&form).unwrap_or_default();
        let save_report_to_disk = SaveReportToDiskField::from_form(&form).unwrap_or_default();
        let open_file_path = OpenFileField::from_form(&form);

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

        let processor = WarpFileProcessor::new()
            .with_compression_type(compression_type)
            .with_file_data(file_data_kind)
            .with_included_functions(file_included_functions);

        let file = match open_file_path {
            None => {
                // We are processing the current view. NOT an external file.
                // Reference path is just used for the state tracking. Does not need to be readable.
                let reference_path = file_path.clone();
                processor.process_view(reference_path, &view)
            }
            Some(open_file_path) => {
                // This thread will show the state in a background task.
                let background_task = BackgroundTask::new("Processing started...", true);
                new_processing_state_background_thread(background_task.clone(), processor.state());
                let file = processor.process(open_file_path);
                background_task.finish();
                file
            }
        };

        if let Err(err) = file {
            binaryninja::interaction::show_message_box(
                "Failed to create signature file",
                &err.to_string(),
                MessageBoxButtonSet::OKButtonSet,
                MessageBoxIcon::ErrorIcon,
            );
            log::error!("Failed to create signature file: {}", err);
            return None;
        }

        let background_task = BackgroundTask::new("Creating WARP File...", false);
        let mut file = file.unwrap();
        // Add back the existing chunks if the user selected to keep them.
        if !existing_chunks.is_empty() {
            file.chunks.extend(existing_chunks);
            // TODO: Make merging optional?
            // TODO: Merging can lose chunk data if it goes above the maximum table count.
            // TODO: We should probably solve that in the warp crate itself?
            file.chunks = Chunk::merge(&file.chunks, compression_type.into());

            // After merging, we should have at least one chunk. If not, merging actually removed data.
            if file.chunks.len() < 1 {
                log::error!("Failed to merge chunks! Please report this, it should not happen.");
                return None;
            }
        }

        let file_bytes = file.to_bytes();
        let file_size = file_bytes.len();
        if std::fs::write(&file_path, file_bytes).is_err() {
            log::error!("Failed to write data to signature file!");
        }
        log::info!("Saved signature file to: '{}'", file_path.display());
        background_task.finish();

        // Show a report of the generate signatures, if desired.
        let report_generator = ReportGenerator::new();
        if let Some(report_string) = report_generator.report(&report_kind, &file) {
            if save_report_to_disk == SaveReportToDiskField::Yes {
                let report_ext = report_generator
                    .report_extension(&report_kind)
                    .unwrap_or_default();
                let report_path = file_path.with_extension(report_ext);
                let _ = std::fs::write(report_path, &report_string);
            }

            // The ReportWidget uses a QTextBrowser, which cannot render large files very well.
            if file_size > 10000000 {
                log::warn!("WARP report file is too large to show in the UI. Please see the report file on disk.");
            } else {
                match report_kind {
                    ReportKindField::None => {}
                    ReportKindField::Html => {
                        view.show_html_report("Generated WARP File", report_string.as_str(), "");
                    }
                    ReportKindField::Markdown => {
                        view.show_markdown_report(
                            "Generated WARP File",
                            report_string.as_str(),
                            "",
                        );
                    }
                    ReportKindField::Json => {
                        view.show_plaintext_report("Generated WARP File", report_string.as_str());
                    }
                }
            }
        }

        Some(())
    }
}

impl Command for CreateFromCurrentView {
    fn action(&self, view: &BinaryView) {
        let view = view.to_owned();
        thread::spawn(move || {
            CreateFromCurrentView::execute(view, false);
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

pub struct CreateFromFiles;

impl Command for CreateFromFiles {
    fn action(&self, view: &BinaryView) {
        let view = view.to_owned();
        thread::spawn(move || {
            CreateFromCurrentView::execute(view, true);
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
