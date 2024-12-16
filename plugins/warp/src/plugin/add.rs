use crate::cache::{cached_function, cached_type_references};
use crate::matcher::invalidate_function_matcher_cache;
use crate::user_signature_dir;
use binaryninja::binaryview::BinaryView;
use binaryninja::command::FunctionCommand;
use binaryninja::function::Function;
use std::thread;

pub struct AddFunctionSignature;

impl FunctionCommand for AddFunctionSignature {
    fn action(&self, view: &BinaryView, func: &Function) {
        let func_plat_name = func.platform().name().to_string();
        let signature_dir = user_signature_dir().join(func_plat_name);
        let view = view.to_owned();
        let func = func.to_owned();
        thread::spawn(move || {
            let Ok(llil) = func.low_level_il() else {
                log::error!("Could not get low level IL for function.");
                return;
            };

            // NOTE: Because we only can consume signatures from a specific directory, we don't need to use the interaction API.
            // If we did need to save signature files to a project than this would need to change.
            let Some(save_file) = rfd::FileDialog::new()
                .add_filter("Signature Files", &["sbin"])
                .set_file_name("user.sbin")
                .set_directory(signature_dir)
                .save_file()
            else {
                return;
            };

            let mut data = warp::signature::Data::default();
            if let Ok(file_bytes) = std::fs::read(&save_file) {
                // If the file we are adding the function to already has data we should preserve it!
                log::info!("Signature file already exists, preserving data...");
                let Some(file_data) = warp::signature::Data::from_bytes(&file_bytes) else {
                    log::error!("Could not get data from signature file: {:?}", save_file);
                    return;
                };
                data = file_data;
            };

            // Now add our function to the data.
            data.functions.push(cached_function(&func, &llil));

            if let Some(ref_ty_cache) = cached_type_references(&view) {
                let referenced_types = ref_ty_cache
                    .cache
                    .iter()
                    .filter_map(|t| t.to_owned())
                    .collect::<Vec<_>>();

                data.types.extend(referenced_types);
            }

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

    fn valid(&self, _view: &BinaryView, _func: &Function) -> bool {
        true
    }
}
