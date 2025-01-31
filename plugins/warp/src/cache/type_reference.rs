use crate::cache::ViewID;
use crate::convert::from_bn_type_internal;
use binaryninja::binary_view::BinaryView;
use binaryninja::confidence::MAX_CONFIDENCE;
use binaryninja::rc::Guard;
use binaryninja::rc::Ref as BNRef;
use binaryninja::types::NamedTypeReference as BNNamedTypeReference;
use dashmap::mapref::one::Ref;
use dashmap::DashMap;
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hasher};
use std::sync::OnceLock;
use warp::r#type::ComputedType;

pub static TYPE_REF_CACHE: OnceLock<DashMap<ViewID, TypeRefCache>> = OnceLock::new();

pub fn clear_type_ref_cache(view: &BinaryView) {
    let view_id = ViewID::from(view);
    if let Some(cache) = TYPE_REF_CACHE.get() {
        cache.remove(&view_id);
    }
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
