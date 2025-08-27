use crate::cache::FunctionID;
use crate::convert::from_bn_symbol;
use crate::function_guid;
use binaryninja::binary_view::BinaryViewExt;
use binaryninja::function::Function as BNFunction;
use binaryninja::low_level_il::function::{FunctionMutability, LowLevelILFunction, NonSSA};
use binaryninja::rc::Ref as BNRef;
use binaryninja::symbol::Symbol as BNSymbol;
use std::collections::HashSet;
use uuid::Uuid;
use warp::signature::constraint::Constraint;
use warp::signature::function::FunctionGUID;

/// Try to get the cached function GUID from the metadata.
///
/// If not cached, we will use `lifted_il_accessor` to retrieve the lifted IL and create the GUID.
///
/// `lifted_il_accessor` exists as it is to allow the retrieval of a cached GUID without incurring
/// the cost of building the IL (if it no longer exists).
pub fn cached_function_guid<M: FunctionMutability>(
    function: &BNFunction,
    lifted_il_accessor: impl Fn() -> Option<BNRef<LowLevelILFunction<M, NonSSA>>>,
) -> Option<FunctionGUID> {
    let cached_guid = try_cached_function_guid(function);
    if let Some(cached_guid) = cached_guid {
        return Some(cached_guid);
    }

    let function_guid = function_guid(function, lifted_il_accessor()?.as_ref());
    function.store_metadata(
        "warp_function_guid",
        &function_guid.as_bytes().to_vec(),
        false,
    );
    Some(function_guid)
}

pub fn try_cached_function_guid(function: &BNFunction) -> Option<FunctionGUID> {
    let metadata = function.query_metadata("warp_function_guid")?;
    let raw_metadata = metadata.get_raw()?;
    let uuid = Uuid::from_slice(raw_metadata.as_slice()).ok()?;
    Some(FunctionGUID::from(uuid))
}

pub fn cached_constraints<F>(function: &BNFunction, filter: F) -> HashSet<Constraint>
where
    F: Fn(&BNFunction) -> bool,
{
    // TODO: Implied constraints, symbol name, image offset
    let cs_constraints = cached_call_site_constraints(function);
    let adj_constraints = cached_adjacency_constraints(function, filter);
    cs_constraints.union(&adj_constraints).cloned().collect()
}

pub fn cached_call_site_constraints(function: &BNFunction) -> HashSet<Constraint> {
    let cache = ConstraintBuilder;
    cache.call_site_constraints(function)
}

pub fn cached_adjacency_constraints<F>(function: &BNFunction, filter: F) -> HashSet<Constraint>
where
    F: Fn(&BNFunction) -> bool,
{
    let cache = ConstraintBuilder;
    cache.adjacency_constraints(function, filter)
}

#[derive(Clone, Debug, Default)]
pub struct ConstraintBuilder;

impl ConstraintBuilder {
    pub fn call_site_constraints(&self, function: &BNFunction) -> HashSet<Constraint> {
        let view = function.view();
        let func_id = FunctionID::from(function);
        let func_start = function.start();
        let func_platform = function.platform();
        let mut constraints = HashSet::new();
        for call_site in &function.call_sites() {
            for cs_ref_addr in view.code_refs_from_addr(call_site.address, Some(function)) {
                match view.function_at(&func_platform, cs_ref_addr) {
                    Some(cs_ref_func) => {
                        // Call site is a function, constrain on it.
                        let cs_ref_func_id = FunctionID::from(cs_ref_func.as_ref());
                        if cs_ref_func_id != func_id {
                            let call_site_offset: i64 =
                                call_site.address.wrapping_sub(func_start) as i64;
                            // TODO: If the function is thunk we should also insert the called function.
                            constraints.extend(
                                self.related_function_constraint(&cs_ref_func, call_site_offset),
                            );
                        }
                    }
                    None => {
                        // We could be dealing with an extern symbol, get the symbol as a constraint.
                        let call_site_offset: i64 =
                            call_site.address.wrapping_sub(func_start) as i64;
                        if let Some(call_site_sym) = view.symbol_by_address(cs_ref_addr) {
                            constraints.insert(
                                self.related_symbol_constraint(&call_site_sym, call_site_offset),
                            );
                        }
                    }
                }
            }
        }
        constraints
    }

    pub fn adjacency_constraints<F>(&self, function: &BNFunction, filter: F) -> HashSet<Constraint>
    where
        F: Fn(&BNFunction) -> bool,
    {
        let view = function.view();
        let func_id = FunctionID::from(function);
        let func_start = function.start();
        let mut constraints = HashSet::new();

        let mut func_addr_constraint = |func_start_addr| {
            // NOTE: We could potentially have dozens of functions all at the same start address.
            for curr_func in &view.functions_at(func_start_addr) {
                let curr_func_id = FunctionID::from(curr_func.as_ref());
                if curr_func_id != func_id && filter(curr_func.as_ref()) {
                    // NOTE: For this to work the GUID has to have already been cached. If not it will just be the symbol.
                    // Function adjacent to another function, constrain on the pattern.
                    let curr_addr_offset = (func_start_addr as i64) - func_start as i64;
                    constraints
                        .extend(self.related_function_constraint(&curr_func, curr_addr_offset));
                }
            }
        };

        let mut before_func_start = func_start;
        for _ in 0..2 {
            before_func_start = view.function_start_before(before_func_start);
            func_addr_constraint(before_func_start);
        }

        let mut after_func_start = func_start;
        for _ in 0..2 {
            after_func_start = view.function_start_after(after_func_start);
            func_addr_constraint(after_func_start);
        }

        constraints
    }

    /// Construct a function constraint, must pass the offset at which it is located.
    pub fn related_function_constraint(
        &self,
        function: &BNFunction,
        offset: i64,
    ) -> Vec<Constraint> {
        let mut constraints = vec![];
        if let Some(guid) = try_cached_function_guid(function) {
            let guid_constraint = Constraint::from_function(&guid, Some(offset));
            constraints.push(guid_constraint);
        }
        let symbol_constraint = self.related_symbol_constraint(&function.symbol(), offset);
        constraints.push(symbol_constraint);
        constraints
    }

    /// Construct a symbol constraint, must pass the offset at which it is located.
    pub fn related_symbol_constraint(&self, symbol: &BNSymbol, offset: i64) -> Constraint {
        let mut symbol = from_bn_symbol(symbol);
        symbol.name = clean_symbol_name(&symbol.name);
        Constraint::from_symbol(&symbol, Some(offset))
    }
}

/// Cleans various internal symbol prefixes and suffixes for consistency.
///
/// This is very important for getting matching symbol constraints.
///
/// Examples:
/// - "__imp__RemoveDirectoryW@4" -> "RemoveDirectoryW"
/// - "__free_base" -> "free_base"
/// - "__impl__free_base" -> "free_base"
/// - "j___free_base" -> "free_base"
/// - "j_free_base" -> "free_base"
/// - "_free_base" -> "free_base"
pub fn clean_symbol_name(symbol_name: &str) -> String {
    // Handle MSVC-style imported symbols
    let without_imp = symbol_name.strip_prefix("__imp__").unwrap_or(symbol_name);

    // Handle jump thunk prefix
    let without_jump = without_imp.strip_prefix("j_").unwrap_or(without_imp);

    // Strip all remaining leading underscores
    let mut result = without_jump;
    while result.starts_with('_') {
        result = &result[1..];
    }

    // Remove stdcall decoration (@N suffix)
    match result.find('@') {
        Some(pos) => result[..pos].to_string(),
        None => result.to_string(),
    }
}
