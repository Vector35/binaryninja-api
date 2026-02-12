use binaryninja::types::TypeLibrary;
use bntl_utils::diff::TILDiff;
use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct DiffArgs {
    pub file_a: PathBuf,
    pub file_b: PathBuf,
    /// Path to write the `.diff` file to.
    pub output_path: PathBuf,
    /// Timeout in seconds for the diff operation to complete, if provided the diffing will begin
    /// to approximate after the deadline has passed.
    #[clap(long)]
    pub timeout: Option<u64>,
}

impl DiffArgs {
    pub fn execute(&self) {
        let type_lib_a =
            TypeLibrary::load_from_file(&self.file_a).expect("Failed to load type library");
        let type_lib_b =
            TypeLibrary::load_from_file(&self.file_b).expect("Failed to load type library");

        let diff_result =
            match TILDiff::new().diff((&self.file_a, &type_lib_a), (&self.file_b, &type_lib_b)) {
                Ok(diff_result) => diff_result,
                Err(err) => {
                    tracing::error!("Failed to diff type libraries: {}", err);
                    return;
                }
            };
        tracing::info!("Similarity Ratio: {}", diff_result.ratio);
        std::fs::write(&self.output_path, diff_result.diff).unwrap();
        tracing::info!("Diff written to: {}", self.output_path.display());
    }
}
