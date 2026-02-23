use crate::command::{InputDirectoryField, OutputDirectoryField};
use crate::process::{new_processing_state_background_thread, TypeLibProcessor};
use crate::validate::TypeLibValidater;
use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::{Command, GlobalCommand, ProjectCommand};
use binaryninja::interaction::{Form, FormInputField, MessageBoxButtonSet, MessageBoxIcon};
use binaryninja::platform::Platform;
use binaryninja::project::Project;
use std::thread;

pub struct CreateFromCurrentView;

impl Command for CreateFromCurrentView {
    fn action(&self, view: &BinaryView) {
        let mut form = Form::new("Create From View");
        // TODO: The choice to select what types to include
        form.add_field(OutputDirectoryField::field());
        if !form.prompt() {
            return;
        }
        let output_dir = OutputDirectoryField::from_form(&form).unwrap();
        let Some(default_platform) = view.default_platform() else {
            tracing::error!("No default platform set for view");
            return;
        };

        let file_path = view.file().file_path();
        let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
        let processor = TypeLibProcessor::new(&file_name, &default_platform.name());
        let data = match processor.process_view(file_path, view) {
            Ok(data) => data,
            Err(err) => {
                tracing::error!("Failed to process view: {}", err);
                return;
            }
        }
        .prune();

        let attached_libraries = view
            .type_libraries()
            .iter()
            .map(|t| t.to_owned())
            .chain(data.type_libraries.iter().map(|t| t.to_owned()))
            .collect::<Vec<_>>();
        let mut validator = TypeLibValidater::new()
            .with_platform(&default_platform)
            .with_type_libraries(attached_libraries);

        for type_library in data.type_libraries {
            let output_path = output_dir.join(format!("{}.bntl", type_library.name()));

            let validation_result = validator.validate(&type_library);
            if !validation_result.issues.is_empty() {
                tracing::error!(
                    "Found {} issues in type library '{}'",
                    validation_result.issues.len(),
                    type_library.name()
                );
                match validation_result.render_report() {
                    Ok(rendered) => {
                        view.show_html_report(&type_library.name(), &rendered, "");
                        if let Err(e) = std::fs::write(output_path.with_extension("html"), rendered)
                        {
                            tracing::error!(
                                "Failed to write validation report to {}: {}",
                                output_path.display(),
                                e
                            );
                        }
                    }
                    Err(err) => tracing::error!("Failed to render validation report: {}", err),
                }
            }

            if type_library.write_to_file(&output_path) {
                tracing::info!(
                    "Created type library '{}': {}",
                    type_library.name(),
                    output_path.display()
                );
            } else {
                tracing::error!("Failed to write type library to {}", output_path.display());
            }
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

pub struct NameField;

impl NameField {
    pub fn field() -> FormInputField {
        FormInputField::TextLine {
            prompt: "Dependency Name".to_string(),
            default: Some("foo.dll".to_string()),
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<String> {
        let field = form.get_field_with_name("Dependency Name")?;
        field.try_value_string()
    }
}

pub struct PlatformField;

impl PlatformField {
    pub fn field() -> FormInputField {
        FormInputField::TextLine {
            prompt: "Platform Name".to_string(),
            default: Some("windows-x86_64".to_string()),
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<String> {
        let field = form.get_field_with_name("Platform Name")?;
        field.try_value_string()
    }
}

pub struct CreateFromDirectory;

impl CreateFromDirectory {
    pub fn execute() {
        let mut form = Form::new("Create From Directory");
        // TODO: The choice to select what types to include
        form.add_field(InputDirectoryField::field());
        form.add_field(PlatformField::field());
        form.add_field(NameField::field());
        form.add_field(OutputDirectoryField::field());
        if !form.prompt() {
            return;
        }
        let input_dir = InputDirectoryField::from_form(&form).unwrap();
        let platform_name = PlatformField::from_form(&form).unwrap();
        let default_name = NameField::from_form(&form).unwrap();
        let output_dir = OutputDirectoryField::from_form(&form).unwrap();

        let Some(default_platform) = Platform::by_name(&platform_name) else {
            tracing::error!("Invalid platform name: {}", platform_name);
            return;
        };

        let processor = TypeLibProcessor::new(&default_name, &default_platform.name());

        let background_task = BackgroundTask::new("Processing started...", true);
        new_processing_state_background_thread(background_task.clone(), processor.state());
        let data = processor.process_directory(&input_dir);
        background_task.finish();

        let pruned_data = match data {
            // Prune off empty type libraries, no need to save them.
            Ok(data) => data.prune(),
            Err(err) => {
                binaryninja::interaction::show_message_box(
                    "Failed to process directory",
                    &err.to_string(),
                    MessageBoxButtonSet::OKButtonSet,
                    MessageBoxIcon::ErrorIcon,
                );
                tracing::error!("Failed to process directory: {}", err);
                return;
            }
        };

        for type_library in pruned_data.type_libraries {
            // Place the type libraries in a folder with the architecture name, as that is necessary
            // information for the user to correctly place the following type libraries in the user directory.
            let arch_output_path = output_dir.join(type_library.arch().name());
            let _ = std::fs::create_dir_all(&arch_output_path);
            let output_path = arch_output_path.join(format!("{}.bntl", type_library.name()));
            if type_library.write_to_file(&output_path) {
                tracing::info!(
                    "Created type library '{}': {}",
                    type_library.name(),
                    output_path.display()
                );
            } else {
                tracing::error!("Failed to write type library to {}", output_path.display());
            }
        }
    }
}

impl GlobalCommand for CreateFromDirectory {
    fn action(&self) {
        thread::spawn(move || {
            CreateFromDirectory::execute();
        });
    }

    fn valid(&self) -> bool {
        true
    }
}

pub struct CreateFromProject;

impl CreateFromProject {
    pub fn execute(project: &Project) {
        let mut form = Form::new("Create From Project");
        // TODO: The choice to select what types to include
        form.add_field(PlatformField::field());
        form.add_field(NameField::field());
        form.add_field(OutputDirectoryField::field());
        if !form.prompt() {
            return;
        }
        let platform_name = PlatformField::from_form(&form).unwrap();
        let default_name = NameField::from_form(&form).unwrap();
        let output_dir = OutputDirectoryField::from_form(&form).unwrap();

        let Some(default_platform) = Platform::by_name(&platform_name) else {
            tracing::error!("Invalid platform name: {}", platform_name);
            return;
        };

        let processor = TypeLibProcessor::new(&default_name, &default_platform.name());

        let background_task = BackgroundTask::new("Processing started...", true);
        new_processing_state_background_thread(background_task.clone(), processor.state());
        let data = processor.process_project(project);
        background_task.finish();

        let finalized_data = match data {
            // Prune off empty type libraries, no need to save them.
            Ok(data) => data.finalized(&default_name),
            Err(err) => {
                binaryninja::interaction::show_message_box(
                    "Failed to process project",
                    &err.to_string(),
                    MessageBoxButtonSet::OKButtonSet,
                    MessageBoxIcon::ErrorIcon,
                );
                tracing::error!("Failed to process project: {}", err);
                return;
            }
        };

        for type_library in finalized_data.type_libraries {
            // Place the type libraries in a folder with the architecture name, as that is necessary
            // information for the user to correctly place the following type libraries in the user directory.
            let arch_output_path = output_dir.join(type_library.arch().name());
            let _ = std::fs::create_dir_all(&arch_output_path);
            let output_path = arch_output_path.join(format!("{}.bntl", type_library.name()));
            if type_library.write_to_file(&output_path) {
                tracing::info!(
                    "Created type library '{}': {}",
                    type_library.name(),
                    output_path.display()
                );
            } else {
                tracing::error!("Failed to write type library to {}", output_path.display());
            }
        }
    }
}

impl ProjectCommand for CreateFromProject {
    fn action(&self, project: &Project) {
        let owned_project = project.to_owned();
        thread::spawn(move || {
            CreateFromProject::execute(&owned_project);
        });
    }

    fn valid(&self, _project: &Project) -> bool {
        true
    }
}
