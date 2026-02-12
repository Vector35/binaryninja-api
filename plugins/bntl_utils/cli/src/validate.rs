use binaryninja::platform::Platform;
use bntl_utils::validate::{TypeLibValidater, ValidateIssue};
use clap::Args;
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Path to the directory containing the type libraries to validate.
    ///
    /// This must contain all the type libraries referencable.
    pub input: PathBuf,
    /// Dump validation results to the directory specified.
    #[clap(short, long)]
    pub output: Option<PathBuf>,
}

impl ValidateArgs {
    pub fn execute(&self) {
        if let Some(output_dir) = &self.output {
            std::fs::create_dir_all(output_dir).expect("Failed to create output directory");
        }

        // TODO: For now we just pass all the type libraries in the containing input directory.
        let type_libs = bntl_utils::helper::path_to_type_libraries(&self.input);
        type_libs.par_iter().for_each(|type_lib| {
            // We run validation per platform. This is to make sure that if we depend on platform
            // types that they exist in each one of the specified platforms, not just one of them.
            let mut platform_mapped_issues: HashMap<ValidateIssue, Vec<String>> = HashMap::new();
            let available_platforms = type_lib.platform_names();

            for platform in &available_platforms {
                let platform = Platform::by_name(platform).expect("Failed to load platform");
                let mut ctx = TypeLibValidater::new()
                    .with_type_libraries(type_libs.clone())
                    .with_platform(&platform);
                let result = ctx.validate(&type_lib);
                for issue in &result.issues {
                    platform_mapped_issues
                        .entry(issue.clone())
                        .or_default()
                        .push(platform.name().to_string());
                }

                if let Some(output_dir) = &self.output
                    && !result.issues.is_empty()
                {
                    let dump_path = output_dir
                        .join(type_lib.name())
                        .with_extension(format!("{}.problems.json", platform.name()));
                    let result = serde_json::to_string_pretty(&result.issues)
                        .expect("Failed to serialize result");
                    std::fs::write(dump_path, result).expect("Failed to write validation result");
                }
            }

            for (issue, platforms) in platform_mapped_issues {
                match (available_platforms.len(), platforms.len()) {
                    (1, _) => tracing::error!("{}", issue),
                    _ => tracing::error!("{}: {}", platforms.join(", "), issue),
                }
            }
        });
    }
}
