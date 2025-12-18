use crate::processor::{
    new_processing_state_background_thread, CompressionTypeField, FileDataKindField,
    FileFilterField, ProcessingFileState, RequestAnalysisField, WarpFileProcessor,
};
use crate::report::{ReportGenerator, ReportKindField};
use binaryninja::background_task::BackgroundTask;
use binaryninja::command::ProjectCommand;
use binaryninja::interaction::{Form, FormInputField};
use binaryninja::project::folder::ProjectFolder;
use binaryninja::project::Project;
use binaryninja::rc::Ref;
use binaryninja::worker_thread::{set_worker_thread_count, worker_thread_count};
use rayon::ThreadPoolBuilder;
use regex::Regex;
use std::path::Path;
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
        form.add_field(Self::request_analysis_field());
        form.add_field(Self::processing_thread_count_field());
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

    pub fn file_filter(&self) -> Option<Result<Regex, regex::Error>> {
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

    pub fn request_analysis_field() -> FormInputField {
        RequestAnalysisField::default().to_field()
    }

    pub fn request_analysis(&self) -> RequestAnalysisField {
        RequestAnalysisField::from_form(&self.form).unwrap_or_default()
    }

    pub fn processing_thread_count_field() -> FormInputField {
        let default = rayon::current_num_threads();
        FormInputField::Integer {
            prompt: "Processing threads".to_string(),
            default: Some(default as i64),
            value: 0,
        }
    }

    pub fn processing_thread_count(&self) -> usize {
        let field = self.form.get_field_with_name("Processing threads");
        let worker_thread_count = worker_thread_count();
        field
            .and_then(|f| f.try_value_int())
            .unwrap_or(worker_thread_count as i64)
            .abs() as usize
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
        let skip_existing_warp_files = form.skip_existing_warp_files();
        let request_analysis = form.request_analysis();
        let processing_thread_count = form.processing_thread_count();

        // Save the warp file to the project.
        let save_warp_file = move |project: &Project,
                                   folder: Option<&ProjectFolder>,
                                   name: &str,
                                   warp_file: &WarpFile| {
            if project
                .create_file(&warp_file.to_bytes(), folder, name, "")
                .is_err()
            {
                tracing::error!("Failed to create project file!");
            }

            let report = ReportGenerator::new();
            if let Some(generated) = report.report(&report_kind, &warp_file) {
                let ext = report.report_extension(&report_kind).unwrap_or_default();
                let file_name = format!("{}_report.{}", name, ext);
                if project
                    .create_file(&generated.into_bytes(), folder, &file_name, "Warp file")
                    .is_err()
                {
                    tracing::error!("Failed to create project file!");
                }
            }
        };

        // Optional callback for saving off the individual project files.
        let callback_project = project.clone();
        let save_individual_files_cb = move |path: &Path, file: &WarpFile| {
            if file.chunks.is_empty() {
                tracing::debug!("Skipping empty file: {}", path.display());
                return;
            }
            // The path returned will be the one on disk, so we will go and grab the project for it.
            let Some(project_file) = callback_project.file_by_path(path) else {
                tracing::error!("Failed to find project file for path: {}", path.display());
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
            .with_compression_type(compression_type)
            .with_skip_warp_files(skip_existing_warp_files)
            .with_request_analysis(request_analysis == RequestAnalysisField::Yes);

        if save_individual_files {
            processor = processor.with_processed_file_callback(save_individual_files_cb);
        }

        // Construct the user-supplied file filter. This will filter files in the project only, files
        // in an archive will be considered a part of the archive file.
        if let Some(filter) = form.file_filter() {
            match filter {
                Ok(f) => {
                    processor = processor.with_file_filter(f);
                }
                Err(err) => {
                    tracing::error!("Failed to parse file filter: {}", err);
                    tracing::error!(
                        "Consider using a substring instead of a glob pattern, e.g. *.exe => exe"
                    );
                    return;
                }
            }
        }

        // This thread will show the state in a background task.
        let background_task = BackgroundTask::new("Processing started...", true);
        new_processing_state_background_thread(background_task.clone(), processor.state());

        let Ok(thread) = ThreadPoolBuilder::new()
            .num_threads(processing_thread_count)
            .build()
        else {
            tracing::error!("Failed to create processing thread pool!");
            return;
        };

        // We have to bump the number of worker threads up so that view destruction's and analysis
        // does not halt, using a multiple of three seems good. This is only temporary.
        let previous_worker_thread_count = worker_thread_count();
        let upgraded_thread_count = previous_worker_thread_count * 3;
        if upgraded_thread_count > previous_worker_thread_count {
            tracing::info!(
                "Setting worker thread count to {} for the duration of processing...",
                upgraded_thread_count
            );
            set_worker_thread_count(upgraded_thread_count);
        }

        let start = Instant::now();
        thread.scope(|_| match processor.process_project(&project) {
            Ok(warp_file) => {
                save_warp_file(&project, None, "generated.warp", &warp_file);
            }
            Err(e) => {
                tracing::error!("Failed to process project: {}", e);
            }
        });

        let processed_file_count = processor
            .state()
            .files_with_state(ProcessingFileState::Processed);
        tracing::info!(
            "Processing {} project files took: {:?}",
            processed_file_count,
            start.elapsed()
        );
        // Reset the worker thread count to the user specified; either way it will not persist.
        set_worker_thread_count(previous_worker_thread_count);
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
