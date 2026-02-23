use crate::input::{Input, ResolvedInput};
use binaryninja::platform::Platform;
use bntl_utils::process::TypeLibProcessor;
use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// The name of the type library to create.
    ///
    /// TODO: Note that this wont be used for inputs which provide a name
    pub name: String,
    /// TODO: Note that this wont be used for inputs which provide a platform
    pub platform: String,
    pub input: Input,
    pub output_directory: Option<PathBuf>,
    /// A list of directories to use for include paths when parsing C header files.
    #[clap(long)]
    pub include_directories: Vec<PathBuf>,
    #[clap(long)]
    pub dry_run: bool,
}

impl CreateArgs {
    pub fn execute(&self) {
        let Some(_platform) = Platform::by_name(&self.platform) else {
            tracing::error!("Failed to find platform: {}", self.platform);
            let platforms: Vec<_> = Platform::list_all().iter().map(|p| p.name()).collect();
            tracing::error!("Available platforms: {}", platforms.join(", "));
            panic!("Platform not found");
        };

        let output_path = self
            .output_directory
            .clone()
            .unwrap_or(PathBuf::from("./output/"));
        if output_path.exists() && !output_path.is_dir() {
            tracing::error!("Output path {} is not a directory", output_path.display());
            return;
        }
        std::fs::create_dir_all(&output_path).expect("Failed to create output directory");

        let processor = TypeLibProcessor::new(&self.name, &self.platform)
            .with_include_directories(self.include_directories.clone());
        // TODO: Need progress indicator here, when downloading files.
        let resolved_input = self.input.resolve().expect("Failed to resolve input");

        let data = match resolved_input {
            ResolvedInput::Path(path) => processor.process(&path),
            ResolvedInput::Project(project) => processor.process_project(&project),
            ResolvedInput::ProjectFolder(project_folder) => {
                processor.process_project_folder(&project_folder)
            }
            ResolvedInput::ProjectFile(project_file) => {
                processor.process_project_file(&project_file)
            }
        }
        .expect("Failed to process input");

        if self.dry_run {
            tracing::info!("Dry run enabled, skipping actual type library creation");
            return;
        }

        for type_library in data.type_libraries {
            // Place the type libraries in a folder with the architecture name, as that is necessary
            // information for the user to correctly place the following type libraries in the user directory.
            let arch_output_path = output_path.join(type_library.arch().name());
            std::fs::create_dir_all(&arch_output_path)
                .expect("Failed to create architecture directory");
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
