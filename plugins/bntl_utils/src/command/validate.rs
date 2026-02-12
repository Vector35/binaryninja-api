use crate::helper::path_to_type_libraries;
use crate::validate::TypeLibValidater;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use binaryninja::interaction::get_open_filename_input;
use binaryninja::platform::Platform;
use binaryninja::types::TypeLibrary;

pub struct Validate;

impl Command for Validate {
    fn action(&self, _view: &BinaryView) {
        let Some(input_path) =
            get_open_filename_input("Select a type library to validate", "*.bntl")
        else {
            return;
        };

        let type_lib = match TypeLibrary::load_from_file(&input_path) {
            Some(type_lib) => type_lib,
            None => {
                tracing::error!("Failed to load type library from {}", input_path.display());
                return;
            }
        };

        // Type libraries should always have at least one platform associated with them.
        if type_lib.platform_names().is_empty() {
            tracing::error!("Type library {} has no platforms!", input_path.display());
            return;
        }

        // TODO: Currently we collect input path dependencies from the platform and the parent directory.
        let dependencies = path_to_type_libraries(input_path.parent().unwrap());

        let validator = TypeLibValidater::new().with_type_libraries(dependencies);
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
            let out_path = input_path.with_extension(format!("{}.html", platform_name));
            let out_name = format!("{} ({})", type_lib.name(), platform_name);
            _view.show_html_report(&out_name, &rendered, "");
            if let Err(e) = std::fs::write(out_path, rendered) {
                tracing::error!(
                    "Failed to write validation report to {}: {}",
                    input_path.display(),
                    e
                );
            }
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
