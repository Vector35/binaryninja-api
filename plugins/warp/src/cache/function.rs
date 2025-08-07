use crate::convert::{comment_to_bn_comment, to_bn_symbol_at_address};
use binaryninja::binary_view::BinaryViewExt;
use binaryninja::function::{Function as BNFunction, FunctionUpdateType};
use binaryninja::symbol::SymbolType;
use warp::signature::function::Function;

// TODO: Rename this?
/// Inserts a function match into the cache. This also has the side effect of setting persisted function
/// information, such as the matched function symbol.
///
/// IMPORTANT: This will mark the function as needing updates, if you intend to fill in functions with
/// no match (i.e. `None`), then you must change this function to prevent marking that as needing updates.
/// However, it's perfectly valid to remove a match and need to update the function still, so be careful.
pub fn insert_cached_function_match(function: &BNFunction, matched_function: Option<Function>) {
    let view = function.view();
    let function_start = function.start();
    // NOTE: If we expect to run match_function multiple times on a function, we should move this elsewhere.
    // Mark the function as needing updates so that reanalysis occurs on the function, and we apply the match.
    function.mark_updates_required(FunctionUpdateType::FullAutoFunctionUpdate);
    if let Some(auto_sym) = view.symbol_by_address(function_start) {
        // TODO: If we ever create non library function symbols we will need to remove this check (see: `to_bn_symbol_at_address`).
        if auto_sym.sym_type() == SymbolType::LibraryFunction {
            // NOTE: This will also mark for full auto function update, one thing to note is that the
            // requirement to call this is that this function not be called in the associated function's analysis.
            view.undefine_auto_symbol(&auto_sym);
        }
    }
    match matched_function {
        Some(matched_function) => {
            // Define the new matched function symbol, this can safely be done here as the symbol itself
            // will be persisted, unlike function type information or variable information.
            let new_sym = to_bn_symbol_at_address(&view, &matched_function.symbol, function_start);
            view.define_auto_symbol(&new_sym);
            // TODO: How to clear the comments? They are just persisted.
            // TODO: Also they generate an undo action, i hate implicit undo actions so much.
            for comment in &matched_function.comments {
                let bn_comment = comment_to_bn_comment(&function, comment.clone());
                function.set_comment_at(bn_comment.addr, &bn_comment.comment);
            }
            function.store_metadata("warp_matched_function", &matched_function.to_bytes(), false);
        }
        None => {
            function.remove_metadata("warp_matched_function");
        }
    }
}

// TODO: This does allocations, and for every reanalysis.
pub fn try_cached_function_match(function: &BNFunction) -> Option<Function> {
    let metadata = function.query_metadata("warp_matched_function")?;
    let raw_metadata = metadata.get_raw()?;
    Function::from_bytes(&raw_metadata)
}
