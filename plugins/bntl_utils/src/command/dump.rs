use crate::command::{InputFileField, OutputDirectoryField};
use crate::dump::TILDump;
use crate::helper::path_to_type_libraries;
use binaryninja::binary_view::BinaryView;
use binaryninja::command::Command;
use binaryninja::interaction::Form;
use binaryninja::types::TypeLibrary;

pub struct Dump;

impl Command for Dump {
    // TODO: We need a command type that does not require a binary view.
    fn action(&self, _view: &BinaryView) {
        let mut form = Form::new("Dump to C Header");
        // TODO: The choice to select what to include?
        form.add_field(InputFileField::field());
        form.add_field(OutputDirectoryField::field());
        if !form.prompt() {
            return;
        }
        let output_dir = OutputDirectoryField::from_form(&form).unwrap();
        let input_path = InputFileField::from_form(&form).unwrap();

        let type_lib = match TypeLibrary::load_from_file(&input_path) {
            Some(type_lib) => type_lib,
            None => {
                tracing::error!("Failed to load type library from {}", input_path.display());
                return;
            }
        };

        // TODO: Currently we collect input path dependencies from the platform and the parent directory.
        let dependencies = path_to_type_libraries(input_path.parent().unwrap());
        let dump = match TILDump::new().with_type_libs(dependencies).dump(&type_lib) {
            Ok(dump) => dump,
            Err(err) => {
                tracing::error!("Failed to dump type library: {}", err);
                return;
            }
        };

        let output_path = output_dir.join(format!("{}.h", type_lib.name()));
        if let Err(e) = std::fs::write(&output_path, dump) {
            tracing::error!("Failed to write dump to {}: {}", output_path.display(), e);
        }
        tracing::info!("Dump written to {}", output_path.display());
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
