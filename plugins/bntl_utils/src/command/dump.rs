use crate::command::{InputDirectoryField, OutputDirectoryField};
use crate::dump::TILDump;
use crate::helper::path_to_type_libraries;
use binaryninja::background_task::BackgroundTask;
use binaryninja::command::GlobalCommand;
use binaryninja::interaction::Form;

pub struct Dump;

impl Dump {
    pub fn execute() {
        let mut form = Form::new("Dump to C Header");
        // TODO: The choice to select what to include?
        form.add_field(InputDirectoryField::field());
        form.add_field(OutputDirectoryField::field());
        if !form.prompt() {
            return;
        }
        let output_dir = OutputDirectoryField::from_form(&form).unwrap();
        let input_path = InputDirectoryField::from_form(&form).unwrap();

        let bg_task = BackgroundTask::new("Dumping type libraries...", true).enter();

        let type_libraries = path_to_type_libraries(&input_path);
        for type_lib in &type_libraries {
            if bg_task.is_cancelled() {
                return;
            }
            bg_task.set_progress_text(&format!("Dumping '{}'...", type_lib.name()));
            let dump = match TILDump::new()
                .with_type_libs(type_libraries.clone())
                .dump(&type_lib)
            {
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
    }
}

impl GlobalCommand for Dump {
    fn action(&self) {
        std::thread::spawn(move || {
            Dump::execute();
        });
    }

    fn valid(&self) -> bool {
        true
    }
}
