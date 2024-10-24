use crate::cache::cached_function;
use crate::convert::from_bn_type;
use binaryninja::binaryview::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use rayon::prelude::*;
use std::io::Write;
use std::thread;
use std::time::Instant;
use warp::r#type::ComputedType;

pub struct CreateSignatureFile;

// TODO: Prompt the user to add the newly created signature file to the signature blacklist (so that it doesn't keep getting applied)

impl Command for CreateSignatureFile {
    fn action(&self, view: &BinaryView) {
        let mut signature_dir = binaryninja::user_directory().unwrap().join("signatures/");
        // TODO: This needs to split out each platform into its own bucket...
        if let Some(default_plat) = view.default_platform() {
            // If there is a default platform, put the signature in there.
            signature_dir.push(default_plat.name().to_string());
        }
        let view = view.to_owned();
        thread::spawn(move || {
            let background_task = binaryninja::backgroundtask::BackgroundTask::new(
                format!("Generating {} signatures... ", view.functions().len()),
                true,
            )
            .unwrap();

            let start = Instant::now();

            let mut data = warp::signature::Data::default();
            data.functions.par_extend(
                view.functions()
                    .par_iter()
                    .filter_map(|func| cached_function(&func, func.low_level_il().ok()?.as_ref())),
            );
            data.types.extend(view.types().iter().map(|ty| {
                let ref_ty = ty.type_object().to_owned();
                ComputedType::new(from_bn_type(&view, ref_ty, u8::MAX))
            }));

            // And type generation :3
            log::info!("Signature generation took {:?}", start.elapsed());

            if let Some(sig_file_name) = binaryninja::interaction::get_text_line_input(
                "Signature File",
                "Create Signature File",
            ) {
                let save_file = signature_dir.join(sig_file_name + ".sbin");
                log::info!("Saving to signatures to {:?}...", &save_file);
                // TODO: Should we overwrite? Prompt user.
                if let Ok(mut file) = std::fs::File::create(&save_file) {
                    match file.write_all(&data.to_bytes()) {
                        Ok(_) => log::info!("Signature file saved successfully."),
                        Err(e) => log::error!("Failed to write data to signature file: {:?}", e),
                    }
                } else {
                    log::error!("Could not create signature file: {:?}", save_file);
                }
            }

            background_task.finish();
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
