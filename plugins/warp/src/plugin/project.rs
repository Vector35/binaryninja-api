use crate::processor::{
    new_processing_state_background_thread, CompressionTypeField, FileDataKindField,
    FileFilterField, WarpFileProcessor,
};
use crate::report::{ReportGenerator, ReportKindField};
use binaryninja::background_task::BackgroundTask;
use binaryninja::command::ProjectCommand;
use binaryninja::interaction::{Form, FormInputField};
use binaryninja::project::folder::ProjectFolder;
use binaryninja::project::Project;
use binaryninja::rc::Ref;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;
use warp::WarpFile;

pub struct CreateSignaturesForm {
    form: Form,
}

impl CreateSignaturesForm {
    pub fn new(_project: &Project) -> CreateSignaturesForm {
        let mut form = Form::new("Create Signature File");
        form.add_field(Self::file_data_field());
        form.add_field(Self::file_filter_field());
        form.add_field(Self::generated_report_field());
        form.add_field(Self::compression_type_field());
        form.add_field(Self::save_individual_files_field());
        form.add_field(Self::skip_existing_warp_files_field());
        // TODO: Threads (we run the analysis in the background)
        Self { form }
    }

    pub fn file_data_field() -> FormInputField {
        FileDataKindField::default().to_field()
    }

    pub fn file_data_kind(&self) -> FileDataKindField {
        FileDataKindField::from_form(&self.form).unwrap_or_default()
    }

    pub fn file_filter_field() -> FormInputField {
        FileFilterField::to_field()
    }

    pub fn file_filter(&self) -> Option<Regex> {
        FileFilterField::from_form(&self.form)
    }

    pub fn generated_report_field() -> FormInputField {
        ReportKindField::default().to_field()
    }

    pub fn generated_report_kind(&self) -> ReportKindField {
        ReportKindField::from_form(&self.form).unwrap_or_default()
    }

    pub fn compression_type_field() -> FormInputField {
        CompressionTypeField::default().to_field()
    }

    pub fn compression_type(&self) -> CompressionTypeField {
        CompressionTypeField::from_form(&self.form).unwrap_or_default()
    }

    pub fn save_individual_files_field() -> FormInputField {
        FormInputField::Checkbox {
            prompt: "Save individual files".to_string(),
            default: None,
            value: false,
        }
    }

    pub fn save_individual_files(&self) -> bool {
        let field = self.form.get_field_with_name("Save individual files");
        let field_value = field.and_then(|f| f.try_value_int()).unwrap_or(0);
        match field_value {
            1 => true,
            _ => false,
        }
    }

    pub fn skip_existing_warp_files_field() -> FormInputField {
        FormInputField::Checkbox {
            prompt: "Skip existing WARP files".to_string(),
            default: Some(true),
            value: false,
        }
    }

    pub fn skip_existing_warp_files(&self) -> bool {
        let field = self.form.get_field_with_name("Skip existing WARP files");
        let field_value = field.and_then(|f| f.try_value_int()).unwrap_or(0);
        match field_value {
            1 => true,
            _ => false,
        }
    }

    pub fn prompt(&mut self) -> bool {
        self.form.prompt()
    }
}

pub struct CreateSignatures;

impl CreateSignatures {
    pub fn execute(project: Ref<Project>) {
        let mut form = CreateSignaturesForm::new(&project);
        if !form.prompt() {
            return;
        }
        let file_data_kind = form.file_data_kind();
        let report_kind = form.generated_report_kind();
        let compression_type = form.compression_type();
        let save_individual_files = form.save_individual_files();

        // Save the warp file to the project.
        let save_warp_file = move |project: &Project,
                                   folder: Option<&ProjectFolder>,
                                   name: &str,
                                   warp_file: &WarpFile| {
            if project
                .create_file(&warp_file.to_bytes(), folder, name, "")
                .is_err()
            {
                log::error!("Failed to create project file!");
            }

            let report = ReportGenerator::new();
            if let Some(generated) = report.report(&report_kind, &warp_file) {
                let ext = report.report_extension(&report_kind).unwrap_or_default();
                let file_name = format!("{}_report.{}", name, ext);
                if project
                    .create_file(&generated.into_bytes(), folder, &file_name, "Warp file")
                    .is_err()
                {
                    log::error!("Failed to create project file!");
                }
            }
        };

        // Optional callback for saving off the individual project files.
        let callback_project = project.clone();
        let save_individual_files_cb = move |path: &Path, file: &WarpFile| {
            if file.chunks.is_empty() {
                log::debug!("Skipping empty file: {}", path.display());
                return;
            }
            // The path returned will be the one on disk, so we will go and grab the project for it.
            let Some(project_file) = callback_project.file_by_path(path) else {
                log::error!("Failed to find project file for path: {}", path.display());
                return;
            };
            let project_file = project_file.to_owned();
            let file_name = format!("{}.warp", project_file.name());
            let project_folder = project_file.folder();
            save_warp_file(
                &callback_project,
                project_folder.as_deref(),
                &file_name,
                file,
            );
        };

        let mut processor = WarpFileProcessor::new()
            .with_file_data(file_data_kind)
            .with_compression_type(compression_type);

        if save_individual_files {
            processor = processor.with_processed_file_callback(save_individual_files_cb);
        }

        // Construct the user-supplied file filter, we also have an appended filter for warp files.
        let mut filter = form.file_filter();
        // This checkbox is here as this is very common to filter for.
        // And we want to do it by default.
        if form.skip_existing_warp_files() {
            let warp_filter = Regex::new(".*\\.warp").unwrap();
            filter = match filter {
                Some(existing) => {
                    let combined = format!("{}|.*\\.warp", existing.as_str());
                    Some(Regex::new(&combined).unwrap())
                }
                None => Some(warp_filter),
            };
        }
        if let Some(filter) = form.file_filter() {
            processor = processor.with_file_filter(filter);
        }

        // This thread will show the state in a background task.
        let background_task = BackgroundTask::new("Processing started...", true);
        new_processing_state_background_thread(background_task.clone(), processor.state());

        let start = Instant::now();
        match processor.process_project(&project) {
            Ok(warp_file) => {
                save_warp_file(&project, None, "generated.warp", &warp_file);
            }
            Err(e) => {
                log::error!("Failed to process project: {}", e);
            }
        }
        log::info!("Processing project files took: {:?}", start.elapsed());

        // Tells the processing state thread to finish.
        background_task.finish();
    }
}

impl ProjectCommand for CreateSignatures {
    fn action(&self, project: &Project) {
        let project = project.to_owned();
        thread::spawn(move || {
            CreateSignatures::execute(project);
        });
    }

    fn valid(&self, _view: &Project) -> bool {
        true
    }
}
