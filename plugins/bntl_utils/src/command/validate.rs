use crate::command::{InputDirectoryField, OutputDirectoryField};
use crate::helper::path_to_type_libraries;
use crate::validate::TypeLibValidater;
use binaryninja::command::GlobalCommand;
use binaryninja::interaction::Form;
use binaryninja::platform::Platform;

pub struct Validate;

impl Validate {
    pub fn execute() {
        let mut form = Form::new("Validate Type Libraries");
        form.add_field(InputDirectoryField::field());
        form.add_field(OutputDirectoryField::field());
        if !form.prompt() {
            return;
        }
        let output_dir = OutputDirectoryField::from_form(&form).unwrap();
        let input_path = InputDirectoryField::from_form(&form).unwrap();

        let type_libraries = path_to_type_libraries(&input_path);
        // TODO: Run this in parallel.
        for type_lib in &type_libraries {
            // Type libraries should always have at least one platform associated with them.
            if type_lib.platform_names().is_empty() {
                tracing::error!("Type library {} has no platforms!", input_path.display());
                continue;
            }

            // TODO: Currently we collect input path dependencies from the platform and the parent directory.
            let validator = TypeLibValidater::new().with_type_libraries(type_libraries.clone());
            // Validate for every platform so that we can find issues in lesser used platforms.
            for platform_name in &type_lib.platform_names() {
                let Some(platform) = Platform::by_name(platform_name) else {
                    tracing::error!("Failed to find platform with name {}", platform_name);
                    continue;
                };
                let results = validator
                    .clone()
                    .with_platform(&platform)
                    .validate(&type_lib);
                if results.issues.is_empty() {
                    tracing::info!(
                        "No issues found for type library {} on platform {}",
                        type_lib.name(),
                        platform_name
                    );
                    continue;
                }
                let rendered = match results.render_report() {
                    Ok(rendered) => rendered,
                    Err(err) => {
                        tracing::error!("Failed to render validation report: {}", err);
                        continue;
                    }
                };
                let out_path = output_dir.with_extension(format!("{}.html", platform_name));
                if let Err(e) = std::fs::write(out_path, rendered) {
                    tracing::error!(
                        "Failed to write validation report to {}: {}",
                        output_dir.display(),
                        e
                    );
                }
            }
        }
    }
}

impl GlobalCommand for Validate {
    fn action(&self) {
        std::thread::spawn(move || {
            Validate::execute();
        });
    }

    fn valid(&self) -> bool {
        true
    }
}
