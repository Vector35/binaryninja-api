use binaryninja::background_task::BackgroundTask;
use binaryninja::command::ProjectCommand;
use binaryninja::interaction::{Form, FormInputField};
use binaryninja::project::Project;
use binaryninja::rc::Ref;
use regex::Regex;
use std::thread;
use std::time::Instant;

use crate::processor::{
    new_processing_state_background_thread, FileDataKindField, FileFilterField, WarpFileProcessor,
};
use crate::report::{ReportGenerator, ReportKindField};

pub struct CreateSignaturesForm {
    form: Form,
}

impl CreateSignaturesForm {
    pub fn new(_project: &Project) -> CreateSignaturesForm {
        let mut form = Form::new("Create Signature File");
        form.add_field(Self::file_data_field());
        form.add_field(Self::file_filter_field());
        form.add_field(Self::generated_report_field());
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

        let mut processor = WarpFileProcessor::new().with_file_data(file_data_kind);

        // This thread will show the state in a background task.
        let background_task = BackgroundTask::new("Processing started...", true);
        new_processing_state_background_thread(background_task.clone(), processor.state());

        if let Some(filter) = form.file_filter() {
            processor = processor.with_file_filter(filter);
        }

        let start = Instant::now();
        match processor.process_project(&project) {
            Ok(warp_file) => {
                // Print the processor string into the description of the file, so we know how it was generated.
                let processor_str = format!("{:#?}", &processor);

                // TODO: File name needs to be configurable.
                if project
                    .create_file(
                        &warp_file.to_bytes(),
                        None,
                        "generated.warp",
                        &processor_str,
                    )
                    .is_err()
                {
                    log::error!("Failed to create project file!");
                }

                let report = ReportGenerator::new();
                if let Some(generated) = report.report(&report_kind, &warp_file) {
                    let ext = report.report_extension(&report_kind).unwrap_or_default();
                    let file_name = format!("report.{}", ext);
                    if project
                        .create_file(&generated.into_bytes(), None, &file_name, "Warp file")
                        .is_err()
                    {
                        log::error!("Failed to create project file!");
                    }
                }
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
