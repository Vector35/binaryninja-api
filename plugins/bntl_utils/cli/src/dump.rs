use binaryninja::types::TypeLibrary;
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
            TypeLibrary::load_from_file(&self.input).expect("Failed to load type library");
        let default_output_path = self.input.with_extension("h");
        let output_path = self.output_path.as_ref().unwrap_or(&default_output_path);
        let dependencies =
            bntl_utils::helper::path_to_type_libraries(&self.input.parent().unwrap());
        let printed_types = TILDump::new()
            .with_type_libs(dependencies)
            .dump(&type_lib)
            .expect("Failed to dump type library");
        std::fs::write(output_path, printed_types).expect("Failed to write type library header");
    }
}
