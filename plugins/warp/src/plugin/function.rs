use crate::cache::{insert_cached_function_match, try_cached_function_match};
use crate::{
    get_warp_ignore_tag_type, get_warp_include_tag_type, IGNORE_TAG_NAME, INCLUDE_TAG_NAME,
};
use binaryninja::binary_view::BinaryView;
use binaryninja::command::FunctionCommand;
use binaryninja::function::{Function, FunctionUpdateType};

pub struct IncludeFunction;

impl FunctionCommand for IncludeFunction {
    fn action(&self, view: &BinaryView, func: &Function) {
        let sym_name = func.symbol().short_name();
        let sym_name_str = sym_name.to_string_lossy();
        let should_add_tag = func.function_tags(None, Some(INCLUDE_TAG_NAME)).is_empty();
        let insert_tag_type = get_warp_include_tag_type(view);
        match should_add_tag {
            true => {
                tracing::info!(
                    "Including selected function '{}' at 0x{:x}",
                    sym_name_str,
                    func.start()
                );
                func.add_tag(&insert_tag_type, "", None, false, None);
            }
            false => {
                tracing::info!(
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

pub struct IgnoreFunction;

impl FunctionCommand for IgnoreFunction {
    fn action(&self, view: &BinaryView, func: &Function) {
        let sym_name = func.symbol().short_name();
        let sym_name_str = sym_name.to_string_lossy();
        let should_add_tag = func.function_tags(None, Some(IGNORE_TAG_NAME)).is_empty();
        let ignore_tag_type = get_warp_ignore_tag_type(view);
        match should_add_tag {
            true => {
                tracing::info!(
                    "Ignoring function for matching '{}' at 0x{:x}",
                    sym_name_str,
                    func.start()
                );
                func.add_tag(&ignore_tag_type, "", None, false, None);
            }
            false => {
                tracing::info!(
                    "Including function for matching '{}' at 0x{:x}",
                    sym_name_str,
                    func.start()
                );
                func.remove_tags_of_type(&ignore_tag_type, None, false, None);
            }
        }
    }

    fn valid(&self, _view: &BinaryView, _func: &Function) -> bool {
        true
    }
}

pub struct RemoveFunction;

impl FunctionCommand for RemoveFunction {
    fn action(&self, _view: &BinaryView, func: &Function) {
        let sym_name = func.symbol().short_name();
        let sym_name_str = sym_name.to_string_lossy();
        tracing::info!(
            "Removing matched function '{}' at 0x{:x}",
            sym_name_str,
            func.start()
        );
        insert_cached_function_match(func, None);
        func.reanalyze(FunctionUpdateType::UserFunctionUpdate);
    }

    fn valid(&self, _view: &BinaryView, func: &Function) -> bool {
        // Only allow if the function actually has a match.
        try_cached_function_match(func).is_some()
    }
}
