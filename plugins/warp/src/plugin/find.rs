use crate::cache::try_cached_function_guid;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use binaryninja::function::Function as BNFunction;
use binaryninja::rc::Guard as BNGuard;
use rayon::prelude::*;
use std::thread;
use warp::signature::function::FunctionGUID;

pub struct FindFunctionFromGUID;

impl Command for FindFunctionFromGUID {
    fn action(&self, view: &BinaryView) {
        let Some(guid_str) = binaryninja::interaction::get_text_line_input(
            "Function GUID",
            "Find Function from GUID",
        ) else {
            return;
        };

        let Ok(searched_guid) = guid_str.parse::<FunctionGUID>() else {
            log::error!("Failed to parse function guid... {}", guid_str);
            return;
        };

        log::info!("Searching functions for GUID... {}", searched_guid);
        let funcs = view.functions();
        thread::spawn(move || {
            let background_task = binaryninja::background_task::BackgroundTask::new(
                format!("Searching functions for GUID... {}", searched_guid),
                false,
            );

            // Only run this for functions which have already generated a GUID.
            let matched = funcs
                .par_iter()
                .filter(|func| {
                    try_cached_function_guid(func).is_some_and(|guid| guid == searched_guid)
                })
                .collect::<Vec<BNGuard<BNFunction>>>();

            if matched.is_empty() {
                log::info!("No matches found for GUID... {}", searched_guid);
            } else {
                for func in matched {
                    log::info!("Match found at function... 0x{:0x}", func.start());
                }
            }

            background_task.finish();
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
