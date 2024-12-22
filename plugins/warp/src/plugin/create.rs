use crate::cache::{cached_function, cached_type_references};
use crate::matcher::invalidate_function_matcher_cache;
use crate::user_signature_dir;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use binaryninja::function::Function;
use binaryninja::rc::Guard;
use rayon::prelude::*;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::thread;
use std::time::Instant;

pub struct CreateSignatureFile;

// TODO: Prompt the user to add the newly created signature file to the signature blacklist (so that it doesn't keep getting applied)

impl Command for CreateSignatureFile {
    fn action(&self, view: &BinaryView) {
        let is_function_named = |f: &Guard<Function>| {
            !f.symbol().short_name().as_str().contains("sub_") || f.has_user_annotations()
        };
        let mut signature_dir = user_signature_dir();
        if let Some(default_plat) = view.default_platform() {
            // If there is a default platform, put the signature in there.
            // TODO: We should instead use the platform of the function.
            signature_dir.push(default_plat.name().to_string());
        }
        let view = view.to_owned();
        thread::spawn(move || {
            let total_functions = view.functions().len();
            let done_functions = AtomicUsize::default();
            let background_task = binaryninja::background_task::BackgroundTask::new(
                format!("Generating signatures... ({}/{})", 0, total_functions),
                true,
            );

            let start = Instant::now();

            let mut data = warp::signature::Data::default();
            data.functions.par_extend(
                view.functions()
                    .par_iter()
                    .inspect(|_| {
                        done_functions.fetch_add(1, Relaxed);
                        background_task.set_progress_text(format!(
                            "Generating signatures... ({}/{})",
                            done_functions.load(Relaxed),
                            total_functions
                        ))
                    })
                    .filter(is_function_named)
                    .filter(|f| !f.analysis_skipped())
                    .filter_map(|func| {
                        let llil = func.low_level_il().ok()?;
                        Some(cached_function(&func, &llil))
                    }),
            );

            if let Some(ref_ty_cache) = cached_type_references(&view) {
                let referenced_types = ref_ty_cache
                    .cache
                    .iter()
                    .filter_map(|t| t.to_owned())
                    .collect::<Vec<_>>();

                data.types.extend(referenced_types);
            }

            log::info!("Signature generation took {:?}", start.elapsed());
            background_task.finish();

            // NOTE: Because we only can consume signatures from a specific directory, we don't need to use the interaction API.
            // If we did need to save signature files to a project than this would need to change.
            let Some(save_file) = rfd::FileDialog::new()
                .add_filter("Signature Files", &["sbin"])
                .set_file_name(format!("{}.sbin", view.file().filename()))
                .set_directory(signature_dir)
                .save_file()
            else {
                return;
            };

            match std::fs::write(&save_file, data.to_bytes()) {
                Ok(_) => {
                    log::info!("Signature file saved successfully.");
                    // Force rebuild platform matcher.
                    invalidate_function_matcher_cache();
                }
                Err(e) => log::error!("Failed to write data to signature file: {:?}", e),
            }
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
