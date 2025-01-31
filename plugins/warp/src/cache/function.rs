use binaryninja::function::{Function as BNFunction, FunctionUpdateType};
use warp::signature::function::Function;

/// Inserts a function match into the cache.
///
/// IMPORTANT: This will mark the function as needing updates, if you intend to fill in functions with
/// no match (i.e. `None`), then you must change this function to prevent marking that as needing updates.
/// However, it's perfectly valid to remove a match and need to update the function still, so be careful.
pub fn insert_cached_function_match(function: &BNFunction, matched_function: Option<Function>) {
    // NOTE: If we expect to run match_function multiple times on a function, we should move this elsewhere.
    // Mark the function as needing updates so that reanalysis occurs on the function, and we apply the match.
    function.mark_updates_required(FunctionUpdateType::FullAutoFunctionUpdate);
    match matched_function {
        Some(matched_function) => {
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
