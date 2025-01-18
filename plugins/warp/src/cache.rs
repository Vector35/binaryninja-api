use crate::convert::{from_bn_symbol, from_bn_type_internal};
use crate::{build_function, function_guid};
use binaryninja::architecture::Architecture;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::confidence::MAX_CONFIDENCE;
use binaryninja::function::Function as BNFunction;
use binaryninja::low_level_il::function::{
    FunctionMutability, LowLevelILFunction, NonSSA, RegularNonSSA,
};
use binaryninja::low_level_il::RegularLowLevelILFunction;
use binaryninja::rc::Guard;
use binaryninja::rc::Ref as BNRef;
use binaryninja::symbol::Symbol as BNSymbol;
use binaryninja::types::NamedTypeReference as BNNamedTypeReference;
use binaryninja::ObjectDestructor;
use dashmap::mapref::one::Ref;
use dashmap::DashMap;
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::OnceLock;
use warp::r#type::ComputedType;
use warp::signature::function::constraints::FunctionConstraint;
use warp::signature::function::{Function, FunctionGUID};

pub static MATCHED_FUNCTION_CACHE: OnceLock<DashMap<ViewID, MatchedFunctionCache>> =
    OnceLock::new();
pub static FUNCTION_CACHE: OnceLock<DashMap<ViewID, FunctionCache>> = OnceLock::new();
pub static GUID_CACHE: OnceLock<DashMap<ViewID, GUIDCache>> = OnceLock::new();
pub static TYPE_REF_CACHE: OnceLock<DashMap<ViewID, TypeRefCache>> = OnceLock::new();

pub fn register_cache_destructor() {
    pub static mut CACHE_DESTRUCTOR: CacheDestructor = CacheDestructor;
    #[allow(static_mut_refs)]
    // SAFETY: This can be done as the backing data is an opaque ZST.
    unsafe {
        CACHE_DESTRUCTOR.register()
    };
}

pub fn cached_function_match<F>(function: &BNFunction, f: F) -> Option<Function>
where
    F: Fn() -> Option<Function>,
{
    let view = function.view();
    let view_id = ViewID::from(view.as_ref());
    let function_id = FunctionID::from(function);
    let function_cache = MATCHED_FUNCTION_CACHE.get_or_init(Default::default);
    match function_cache.get(&view_id) {
        Some(cache) => cache.get_or_insert(&function_id, f).to_owned(),
        None => {
            let cache = MatchedFunctionCache::default();
            let matched = cache.get_or_insert(&function_id, f).to_owned();
            function_cache.insert(view_id, cache);
            matched
        }
    }
}

pub fn try_cached_function_match(function: &BNFunction) -> Option<Function> {
    let view = function.view();
    let view_id = ViewID::from(view);
    let function_id = FunctionID::from(function);
    let function_cache = MATCHED_FUNCTION_CACHE.get_or_init(Default::default);
    function_cache
        .get(&view_id)?
        .get(&function_id)?
        .value()
        .to_owned()
}

pub fn cached_function<A: Architecture>(
    function: &BNFunction,
    llil: &RegularLowLevelILFunction<A>,
) -> Function {
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

pub fn cached_adjacency_constraints<F>(
    function: &BNFunction,
    filter: F,
) -> HashSet<FunctionConstraint>
where
    F: Fn(&BNFunction) -> bool,
{
    let view = function.view();
    let view_id = ViewID::from(view);
    let guid_cache = GUID_CACHE.get_or_init(Default::default);
    match guid_cache.get(&view_id) {
        Some(cache) => cache.adjacency_constraints(function, filter),
        None => {
            let cache = GUIDCache::default();
            let constraints = cache.adjacency_constraints(function, filter);
            guid_cache.insert(view_id, cache);
            constraints
        }
    }
}

pub fn cached_function_guid<A: Architecture, M: FunctionMutability>(
    function: &BNFunction,
    llil: &LowLevelILFunction<A, M, NonSSA<RegularNonSSA>>,
) -> FunctionGUID {
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

pub fn try_cached_function_guid(function: &BNFunction) -> Option<FunctionGUID> {
    let view = function.view();
    let view_id = ViewID::from(view);
    let guid_cache = GUID_CACHE.get_or_init(Default::default);
    guid_cache.get(&view_id)?.try_function_guid(function)
}

pub fn cached_type_reference(
    view: &BinaryView,
    visited_refs: &mut HashSet<TypeRefID>,
    type_ref: &BNNamedTypeReference,
) -> Option<ComputedType> {
    let view_id = ViewID::from(view);
    let type_ref_cache = TYPE_REF_CACHE.get_or_init(Default::default);
    match type_ref_cache.get(&view_id) {
        Some(cache) => cache.cached_type_reference(view, visited_refs, type_ref),
        None => {
            let cache = TypeRefCache::default();
            let ntr = cache.cached_type_reference(view, visited_refs, type_ref);
            type_ref_cache.insert(view_id, cache);
            ntr
        }
    }
}

pub fn cached_type_references(view: &BinaryView) -> Option<Ref<ViewID, TypeRefCache>> {
    let view_id = ViewID::from(view);
    let type_ref_cache = TYPE_REF_CACHE.get_or_init(Default::default);
    type_ref_cache.get(&view_id)
}

#[derive(Clone, Debug, Default)]
pub struct MatchedFunctionCache {
    pub cache: DashMap<FunctionID, Option<Function>>,
}

impl MatchedFunctionCache {
    pub fn get_or_insert<F>(
        &self,
        function_id: &FunctionID,
        f: F,
    ) -> Ref<'_, FunctionID, Option<Function>>
    where
        F: FnOnce() -> Option<Function>,
    {
        self.cache.get(function_id).unwrap_or_else(|| {
            self.cache.insert(*function_id, f());
            self.cache.get(function_id).unwrap()
        })
    }

    pub fn get(&self, function_id: &FunctionID) -> Option<Ref<'_, FunctionID, Option<Function>>> {
        self.cache.get(function_id)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FunctionCache {
    pub cache: DashMap<FunctionID, Function>,
}

impl FunctionCache {
    pub fn function<A: Architecture>(
        &self,
        function: &BNFunction,
        llil: &RegularLowLevelILFunction<A>,
    ) -> Function {
        let function_id = FunctionID::from(function);
        match self.cache.get(&function_id) {
            Some(function) => function.value().to_owned(),
            None => {
                let function = build_function(function, llil);
                self.cache.insert(function_id, function.clone());
                function
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GUIDCache {
    pub cache: DashMap<FunctionID, FunctionGUID>,
}

impl GUIDCache {
    pub fn call_site_constraints(&self, function: &BNFunction) -> HashSet<FunctionConstraint> {
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
                            constraints
                                .insert(self.function_constraint(&cs_ref_func, call_site_offset));
                        }
                    }
                    None => {
                        // We could be dealing with an extern symbol, get the symbol as a constraint.
                        let call_site_offset: i64 =
                            call_site.address.wrapping_sub(func_start) as i64;
                        if let Some(call_site_sym) = view.symbol_by_address(cs_ref_addr) {
                            constraints.insert(
                                self.function_constraint_from_symbol(
                                    &call_site_sym,
                                    call_site_offset,
                                ),
                            );
                        }
                    }
                }
            }
        }
        constraints
    }

    pub fn adjacency_constraints<F>(
        &self,
        function: &BNFunction,
        filter: F,
    ) -> HashSet<FunctionConstraint>
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
                    constraints.insert(self.function_constraint(&curr_func, curr_addr_offset));
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
    pub fn function_constraint(&self, function: &BNFunction, offset: i64) -> FunctionConstraint {
        let guid = self.try_function_guid(function);
        let symbol = from_bn_symbol(&function.symbol());
        FunctionConstraint {
            guid,
            symbol: Some(symbol),
            offset,
        }
    }

    /// Construct a function constraint from a symbol, typically used for extern function call sites, must pass the offset at which it is located.
    pub fn function_constraint_from_symbol(
        &self,
        symbol: &BNSymbol,
        offset: i64,
    ) -> FunctionConstraint {
        let symbol = from_bn_symbol(symbol);
        FunctionConstraint {
            guid: None,
            symbol: Some(symbol),
            offset,
        }
    }

    pub fn function_guid<A: Architecture, M: FunctionMutability>(
        &self,
        function: &BNFunction,
        llil: &LowLevelILFunction<A, M, NonSSA<RegularNonSSA>>,
    ) -> FunctionGUID {
        let function_id = FunctionID::from(function);
        match self.cache.get(&function_id) {
            Some(function_guid) => function_guid.value().to_owned(),
            None => {
                let function_guid = function_guid(function, llil);
                self.cache.insert(function_id, function_guid);
                function_guid
            }
        }
    }

    pub fn try_function_guid(&self, function: &BNFunction) -> Option<FunctionGUID> {
        let function_id = FunctionID::from(function);
        self.cache
            .get(&function_id)
            .map(|function_guid| function_guid.value().to_owned())
    }
}

#[derive(Clone, Debug, Default)]
pub struct TypeRefCache {
    pub cache: DashMap<TypeRefID, Option<ComputedType>>,
}

impl TypeRefCache {
    /// NOTE: No self-referential type must be used on this function.
    pub fn cached_type_reference(
        &self,
        view: &BinaryView,
        visited_refs: &mut HashSet<TypeRefID>,
        type_ref: &BNNamedTypeReference,
    ) -> Option<ComputedType> {
        let ntr_id = TypeRefID::from(type_ref);
        match self.cache.get(&ntr_id) {
            Some(cache) => cache.to_owned(),
            None => match type_ref.target(view) {
                Some(raw_ty) => {
                    let computed_ty = ComputedType::new(from_bn_type_internal(
                        view,
                        visited_refs,
                        &raw_ty,
                        MAX_CONFIDENCE,
                    ));
                    self.cache
                        .entry(ntr_id)
                        .insert(Some(computed_ty))
                        .to_owned()
                }
                None => self.cache.entry(ntr_id).insert(None).to_owned(),
            },
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
        hasher.write_usize(value.file().session_id());
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

/// A unique named type reference ID, used for caching.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypeRefID(u64);

impl From<&BNNamedTypeReference> for TypeRefID {
    fn from(value: &BNNamedTypeReference) -> Self {
        let mut hasher = DefaultHasher::new();
        hasher.write(value.id().as_bytes());
        Self(hasher.finish())
    }
}

impl From<BNRef<BNNamedTypeReference>> for TypeRefID {
    fn from(value: BNRef<BNNamedTypeReference>) -> Self {
        Self::from(value.as_ref())
    }
}

impl From<Guard<'_, BNNamedTypeReference>> for TypeRefID {
    fn from(value: Guard<'_, BNNamedTypeReference>) -> Self {
        Self::from(value.as_ref())
    }
}

pub struct CacheDestructor;

impl ObjectDestructor for CacheDestructor {
    fn destruct_view(&self, view: &BinaryView) {
        // Clear caches as the view is no longer alive.
        let view_id = ViewID::from(view);
        if let Some(cache) = MATCHED_FUNCTION_CACHE.get() {
            cache.remove(&view_id);
        }
        if let Some(cache) = FUNCTION_CACHE.get() {
            cache.remove(&view_id);
        }
        if let Some(cache) = GUID_CACHE.get() {
            cache.remove(&view_id);
        }
        if let Some(cache) = TYPE_REF_CACHE.get() {
            cache.remove(&view_id);
        }
        log::debug!("Removed WARP caches for {:?}", view.file().filename());
    }
}
