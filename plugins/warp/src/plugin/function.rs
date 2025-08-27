use crate::cache::{cached_function_guid, try_cached_function_guid};
use crate::{get_warp_include_tag_type, INCLUDE_TAG_NAME};
use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::{Command, FunctionCommand};
use binaryninja::function::Function;
use binaryninja::rc::Guard;
use rayon::iter::ParallelIterator;
use std::thread;
use warp::signature::function::FunctionGUID;

pub struct IncludeFunction;

impl FunctionCommand for IncludeFunction {
    fn action(&self, view: &BinaryView, func: &Function) {
        let sym_name = func.symbol().short_name();
        let sym_name_str = sym_name.to_string_lossy();
        let should_add_tag = func.function_tags(None, Some(INCLUDE_TAG_NAME)).is_empty();
        let insert_tag_type = get_warp_include_tag_type(view);
        match should_add_tag {
            true => {
                log::info!(
                    "Including selected function '{}' at 0x{:x}",
                    sym_name_str,
                    func.start()
                );
                func.add_tag(&insert_tag_type, "", None, false, None);
            }
            false => {
                log::info!(
                    "Removing included function '{}' at 0x{:x}",
                    sym_name_str,
                    func.start()
                );
                func.remove_tags_of_type(&insert_tag_type, None, false, None);
            }
        }
    }

    fn valid(&self, _view: &BinaryView, _func: &Function) -> bool {
        // TODO: Only allow if the function is named?
        true
    }
}

pub struct CopyFunctionGUID;

impl FunctionCommand for CopyFunctionGUID {
    fn action(&self, _view: &BinaryView, func: &Function) {
        let Some(guid) = cached_function_guid(func, || func.lifted_il().ok()) else {
            log::error!("Could not get guid for copied function");
            return;
        };
        log::info!(
            "Function GUID for {:?}... {}",
            func.symbol().short_name(),
            guid
        );
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            let _ = clipboard.set_text(guid.to_string());
        }
    }

    fn valid(&self, _view: &BinaryView, _func: &Function) -> bool {
        true
    }
}

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
        let view = view.to_owned();
        thread::spawn(move || {
            let background_task = BackgroundTask::new(
                &format!("Searching functions for GUID... {}", searched_guid),
                false,
            );

            // Only run this for functions which have already generated a GUID.
            let matched: Vec<Guard<Function>> = funcs
                .par_iter()
                .filter(|func| {
                    try_cached_function_guid(func).is_some_and(|guid| guid == searched_guid)
                })
                .collect();

            if matched.is_empty() {
                log::info!("No matches found for GUID... {}", searched_guid);
            } else {
                for func in &matched {
                    // Also navigate the user, as that is probably what they want.
                    if matched.len() == 1 {
                        let current_view = view.file().current_view();
                        if view
                            .file()
                            .navigate_to(&current_view, func.start())
                            .is_err()
                        {
                            log::error!(
                                "Failed to navigate to found function 0x{:0x} in view {}",
                                func.start(),
                                current_view
                            );
                        }
                    }
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
