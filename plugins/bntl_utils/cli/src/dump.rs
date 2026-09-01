use binaryninja::types::ImportLibrary;
use bntl_utils::dump::TILDump;
use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct DumpArgs {
    pub input: PathBuf,
    pub output_path: Option<PathBuf>,
}

impl DumpArgs {
    pub fn execute(&self) {
        let type_lib =
            ImportLibrary::load_from_file(&self.input).expect("Failed to load import library");
        let default_output_path = self.input.with_extension("h");
        let output_path = self.output_path.as_ref().unwrap_or(&default_output_path);
        let dependencies =
            bntl_utils::helper::path_to_import_libraries(&self.input.parent().unwrap());
        let printed_types = TILDump::new()
            .with_import_libs(dependencies)
            .dump(&type_lib)
            .expect("Failed to dump import library");
        std::fs::write(output_path, printed_types).expect("Failed to write import library header");
    }
}
