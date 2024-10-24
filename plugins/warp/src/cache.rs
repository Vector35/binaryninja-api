use binaryninja::architecture::Architecture;
use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::function::Function as BNFunction;
use binaryninja::llil;
use binaryninja::llil::{FunctionMutability, NonSSA, NonSSAVariant};
use binaryninja::rc::Guard;
use binaryninja::rc::Ref as BNRef;
use dashmap::try_result::TryResult;
use dashmap::DashMap;
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::OnceLock;
use warp::signature::function::constraints::FunctionConstraint;
use warp::signature::function::{Function, FunctionGUID};

use crate::convert::from_bn_symbol;
use crate::{build_function, function_guid};

pub static FUNCTION_CACHE: OnceLock<DashMap<ViewID, FunctionCache>> = OnceLock::new();
pub static GUID_CACHE: OnceLock<DashMap<ViewID, GUIDCache>> = OnceLock::new();

pub fn cached_function<A: Architecture, M: FunctionMutability, V: NonSSAVariant>(
    function: &BNFunction,
    llil: &llil::Function<A, M, NonSSA<V>>,
) -> Option<Function> {
    let view = function.view();
    let view_id = ViewID::from(view.as_ref());
    let function_cache = FUNCTION_CACHE.get_or_init(Default::default);
    match function_cache.get(&view_id) {
        Some(cache) => cache.function(function, llil),
        None => {
            let cache = FunctionCache::default();
            let function = cache.function(function, llil);
            function_cache.insert(view_id, cache);
            function
        }
    }
}

pub fn cached_call_site_constraints(function: &BNFunction) -> HashSet<FunctionConstraint> {
    let view = function.view();
    let view_id = ViewID::from(view);
    let guid_cache = GUID_CACHE.get_or_init(Default::default);
    match guid_cache.get(&view_id) {
        Some(cache) => cache.call_site_constraints(function),
        None => {
            let cache = GUIDCache::default();
            let constraints = cache.call_site_constraints(function);
            guid_cache.insert(view_id, cache);
            constraints
        }
    }
}

pub fn cached_adjacency_constraints(function: &BNFunction) -> HashSet<FunctionConstraint> {
    let view = function.view();
    let view_id = ViewID::from(view);
    let guid_cache = GUID_CACHE.get_or_init(Default::default);
    match guid_cache.get(&view_id) {
        Some(cache) => cache.adjacency_constraints(function),
        None => {
            let cache = GUIDCache::default();
            let constraints = cache.adjacency_constraints(function);
            guid_cache.insert(view_id, cache);
            constraints
        }
    }
}

pub fn cached_function_guid<A: Architecture, M: FunctionMutability, V: NonSSAVariant>(
    function: &BNFunction,
    llil: &llil::Function<A, M, NonSSA<V>>,
) -> Option<FunctionGUID> {
    let view = function.view();
    let view_id = ViewID::from(view);
    let guid_cache = GUID_CACHE.get_or_init(Default::default);
    match guid_cache.get(&view_id) {
        Some(cache) => cache.function_guid(function, llil),
        None => {
            let cache = GUIDCache::default();
            let guid = cache.function_guid(function, llil);
            guid_cache.insert(view_id, cache);
            guid
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FunctionCache {
    pub cache: DashMap<FunctionID, Option<Function>>,
}

impl FunctionCache {
    pub fn function<A: Architecture, M: FunctionMutability, V: NonSSAVariant>(
        &self,
        function: &BNFunction,
        llil: &llil::Function<A, M, NonSSA<V>>,
    ) -> Option<Function> {
        let function_id = FunctionID::from(function);
        match self.cache.try_get_mut(&function_id) {
            TryResult::Present(function) => function.value().to_owned(),
            TryResult::Absent => {
                let function = build_function(function, llil);
                self.cache.insert(function_id, function.clone());
                function
            }
            TryResult::Locked => build_function(function, llil),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GUIDCache {
    pub cache: DashMap<FunctionID, Option<FunctionGUID>>,
}

impl GUIDCache {
    pub fn call_site_constraints(&self, function: &BNFunction) -> HashSet<FunctionConstraint> {
        let view = function.view();
        let func_id = FunctionID::from(function);
        let func_start = function.start();
        let mut constraints = HashSet::new();
        for call_site in &function.call_sites() {
            for cs_ref in &view.get_code_refs(call_site.address) {
                let cs_ref_func = cs_ref.function();
                let cs_ref_func_id = FunctionID::from(cs_ref_func);
                if cs_ref_func_id != func_id {
                    if let Some(cs_ref_func_llil) = cs_ref_func.low_level_il_if_available() {
                        // Function references another function, constrain on the pattern.
                        // TODO: If function is trivial thunk we should _also_ insert the tailcall target as a constraint.
                        let call_site_offset: i64 = func_start as i64 - call_site.address as i64;
                        constraints.insert(self.function_constraint(
                            cs_ref_func,
                            &cs_ref_func_llil,
                            call_site_offset,
                        ));
                    }
                }
            }
        }
        constraints
    }

    pub fn adjacency_constraints(&self, function: &BNFunction) -> HashSet<FunctionConstraint> {
        let view = function.view();
        let func_id = FunctionID::from(function);
        let func_start = function.start();
        let mut constraints = HashSet::new();

        let mut func_addr_constraint = |func_start_addr| {
            // NOTE: We could potentially have dozens of functions all at the same start address.
            for curr_func in &view.functions_at(func_start_addr) {
                let curr_func_id = FunctionID::from(curr_func.as_ref());
                if curr_func_id != func_id {
                    // NOTE: We have to get the llil here for the function which is problematic for running
                    // NOTE: within a workflow (before analysis has finished)
                    if let Some(curr_func_llil) = curr_func.low_level_il_if_available() {
                        // Function adjacent to another function, constrain on the pattern.
                        let curr_addr_offset = (func_start_addr as i64) - func_start as i64;
                        constraints.insert(self.function_constraint(
                            &curr_func,
                            &curr_func_llil,
                            curr_addr_offset,
                        ));
                    }
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
    pub fn function_constraint<A: Architecture, M: FunctionMutability, V: NonSSAVariant>(
        &self,
        function: &BNFunction,
        llil: &llil::Function<A, M, NonSSA<V>>,
        offset: i64,
    ) -> FunctionConstraint {
        let guid = self.function_guid(function, llil);
        let symbol = from_bn_symbol(&function.symbol());
        FunctionConstraint {
            guid,
            symbol: Some(symbol),
            offset,
        }
    }

    pub fn function_guid<A: Architecture, M: FunctionMutability, V: NonSSAVariant>(
        &self,
        function: &BNFunction,
        llil: &llil::Function<A, M, NonSSA<V>>,
    ) -> Option<FunctionGUID> {
        let function_id = FunctionID::from(function);
        match self.cache.try_get_mut(&function_id) {
            TryResult::Present(function_guid) => function_guid.value().to_owned(),
            TryResult::Absent => {
                let function_guid = function_guid(function, llil);
                self.cache.insert(function_id, function_guid);
                function_guid
            }
            TryResult::Locked => function_guid(function, llil),
        }
    }
}

/// A unique view ID, used for caching.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ViewID(u64);

impl From<&BinaryView> for ViewID {
    fn from(value: &BinaryView) -> Self {
        let mut hasher = DefaultHasher::new();
        hasher.write_u64(value.original_image_base());
        hasher.write(value.view_type().to_bytes());
        hasher.write_u64(value.entry_point());
        hasher.write(value.file().filename().to_bytes());
        Self(hasher.finish())
    }
}

impl From<BNRef<BinaryView>> for ViewID {
    fn from(value: BNRef<BinaryView>) -> Self {
        Self::from(value.as_ref())
    }
}

impl From<Guard<'_, BinaryView>> for ViewID {
    fn from(value: Guard<'_, BinaryView>) -> Self {
        Self::from(value.as_ref())
    }
}

/// A unique function ID, used for caching.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct FunctionID(u64);

impl From<&BNFunction> for FunctionID {
    fn from(value: &BNFunction) -> Self {
        let mut hasher = DefaultHasher::new();
        hasher.write_u64(value.start());
        hasher.write_u64(value.lowest_address());
        hasher.write_u64(value.highest_address());
        Self(hasher.finish())
    }
}

impl From<BNRef<BNFunction>> for FunctionID {
    fn from(value: BNRef<BNFunction>) -> Self {
        Self::from(value.as_ref())
    }
}

impl From<Guard<'_, BNFunction>> for FunctionID {
    fn from(value: Guard<'_, BNFunction>) -> Self {
        Self::from(value.as_ref())
    }
}
