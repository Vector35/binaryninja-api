use std::collections::HashMap;
use std::time::Instant;

use crate::cache::cached_function_guid;
use crate::plugin::on_matched_function;
use binaryninja::binaryview::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use rayon::prelude::*;
use warp::signature::function::{Function, FunctionGUID};

pub struct ApplySignatureFile;

// TODO: All this should do is insert data into the Matcher. this is leftover code.
impl Command for ApplySignatureFile {
    fn action(&self, view: &BinaryView) {
        // TODO: Start bulk modification
        // TODO: view.begin_bulk_modify_symbols();
        let Some(file) =
            binaryninja::interaction::get_open_filename_input("Apply Signature File", "*.sbin")
        else {
            return;
        };

        // TODO: signature files also need to store type information.

        let Ok(data) = std::fs::read(&file) else {
            log::error!("Could not read signature file: {:?}", file);
            return;
        };

        let Some(data) = warp::signature::Data::from_bytes(&data) else {
            log::error!("Could not get data from signature file: {:?}", file);
            return;
        };

        // TODO: Turn Vec<Function> to HashSet so that functions with the same symbol and type get eliminated.
        let data_functions: HashMap<FunctionGUID, Vec<Function>> =
            data.functions
                .into_iter()
                .fold(HashMap::new(), |mut acc, func| {
                    #[allow(clippy::unwrap_or_default)]
                    acc.entry(func.guid).or_insert_with(Vec::new).push(func);
                    acc
                });

        let background_task = binaryninja::backgroundtask::BackgroundTask::new(
            format!("Applying signatures from {:?}", file),
            true,
        )
        .unwrap();

        let funcs = view.functions();
        let start = Instant::now();

        background_task
            .set_progress_text(format!("Building {} patterns to lookup...", funcs.len()));

        // TODO: Redo this.
        let single_matched = funcs
            .par_iter()
            .filter_map(|func| {
                let llil = func.low_level_il_if_available()?;
                let pattern = cached_function_guid(&func, &llil)?;
                Some((func, data_functions.get(&pattern)?))
            })
            .filter(|(_, sig)| sig.len() == 1)
            .collect::<Vec<_>>();

        background_task.set_progress_text(format!("Applying {} matches...", single_matched.len()));
        for (func, matched) in single_matched {
            on_matched_function(&func, &matched[0]);
        }

        log::info!("Signature application took {:?}", start.elapsed());

        background_task.finish();
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
