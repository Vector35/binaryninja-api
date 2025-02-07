use binaryninja::binary_view::BinaryView;
use binaryninja::command::FunctionCommand;
use binaryninja::function::Function;

use crate::cache::cached_function_guid;

pub struct CopyFunctionGUID;

impl FunctionCommand for CopyFunctionGUID {
    fn action(&self, _view: &BinaryView, func: &Function) {
        let Ok(llil) = func.low_level_il() else {
            log::error!("Could not get low level il for copied function");
            return;
        };
        let guid = cached_function_guid(func, &llil);
        log::info!(
            "Function GUID for {}... {}",
            func.symbol().short_name().to_string(),
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
