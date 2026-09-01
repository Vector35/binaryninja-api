use crate::input::{Input, ResolvedInput};
use binaryninja::platform::Platform;
use bntl_utils::process::ImportLibProcessor;
use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// The name of the import library to create.
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
    /// A list of additional compiler options to pass to the compiler when parsing C header files.
    #[arg(last = true, allow_hyphen_values = true, num_args = 0..)]
    pub compiler_options: Vec<String>,
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

        let processor = ImportLibProcessor::new(&self.name, &self.platform)
            .with_include_directories(self.include_directories.clone())
            .with_compiler_options(self.compiler_options.clone());
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
            tracing::info!("Dry run enabled, skipping actual import library creation");
            return;
        }

        for import_library in data.import_libraries {
            // Place the import libraries in a folder with the architecture name, as that is necessary
            // information for the user to correctly place the following import libraries in the user directory.
            let arch_output_path = output_path.join(import_library.arch().name());
            std::fs::create_dir_all(&arch_output_path)
                .expect("Failed to create architecture directory");
            let output_path = arch_output_path.join(format!("{}.bntl", import_library.name()));
            if import_library.write_to_file(&output_path) {
                tracing::info!(
                    "Created import library '{}': {}",
                    import_library.name(),
                    output_path.display()
                );
            } else {
                tracing::error!(
                    "Failed to write import library to {}",
                    output_path.display()
                );
            }
        }
    }
}
