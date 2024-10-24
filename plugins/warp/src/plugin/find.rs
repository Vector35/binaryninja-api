use binaryninja::binaryview::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use rayon::prelude::*;
use std::thread;
use warp::signature::function::FunctionGUID;

use crate::cache::cached_function_guid;

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
            let background_task = binaryninja::backgroundtask::BackgroundTask::new(
                format!("Searching functions for GUID... {}", searched_guid),
                true,
            )
            .unwrap();

            // TODO: While background_task has not finished.
            let matched = funcs
                .par_iter()
                .filter_map(|func| {
                    Some((
                        func.clone(),
                        cached_function_guid(&func, func.low_level_il_if_available()?.as_ref())?,
                    ))
                })
                .filter(|(_func, guid)| guid.eq(&searched_guid))
                .collect::<Vec<_>>();

            for (func, _) in matched {
                log::info!("Match found at function... 0x{:0x}", func.start());
            }

            background_task.finish();
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
