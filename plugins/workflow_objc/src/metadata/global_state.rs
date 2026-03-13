use binaryninja::file_metadata::SessionId;
use binaryninja::object_destructor::register_object_destructor;
use binaryninja::{
    binary_view::{BinaryView, BinaryViewBase, BinaryViewExt},
    file_metadata::FileMetadata,
    metadata::Metadata,
    object_destructor::ObjectDestructor,
    rc::Ref,
    settings::{QueryOptions, Settings},
};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::{
    collections::{HashMap, HashSet},
    ops::Range,
    sync::{Arc, RwLock},
};

pub struct AnalysisInfo {
    pub image_base: u64,
    pub objc_stubs: Option<Range<u64>>,
    pub should_rewrite_to_direct_calls: bool,
    selector_impls: RwLock<SelectorImplsState>,
}

enum SelectorImplsState {
    NotLoaded,
    Loaded(Option<SelectorImplementations>),
}

struct SelectorImplementations {
    sel_ref_to_impl: HashMap<u64, Vec<u64>>,
    sel_to_impl: HashMap<u64, Vec<u64>>,
}

static VIEW_INFOS: Lazy<DashMap<SessionId, Arc<AnalysisInfo>>> = Lazy::new(DashMap::new);
static IGNORED_VIEWS: Lazy<DashMap<SessionId, bool>> = Lazy::new(DashMap::new);

struct ObjectLifetimeObserver;

impl ObjectDestructor for ObjectLifetimeObserver {
    fn destruct_file_metadata(&self, metadata: &FileMetadata) {
        let id = metadata.session_id();
        VIEW_INFOS.remove(&id);
        IGNORED_VIEWS.remove(&id);
    }
}

static SUPPORTED_ARCHS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut m = HashSet::new();
    m.insert("aarch64");
    m.insert("x86_64");
    m.insert("armv7");
    m.insert("thumb2");
    m
});

fn is_supported_arch(bv: &BinaryView) -> bool {
    let arch_name = bv
        .default_arch()
        .map(|arch| arch.name())
        .unwrap_or_default();
    SUPPORTED_ARCHS.contains(&arch_name as &str)
}

pub struct GlobalState;

impl GlobalState {
    pub fn register_cleanup() {
        let destructor = register_object_destructor(ObjectLifetimeObserver);
        std::mem::forget(destructor);
    }

    fn id(bv: &BinaryView) -> SessionId {
        bv.file().session_id()
    }

    pub fn analysis_info(bv: &BinaryView) -> Option<Arc<AnalysisInfo>> {
        let id = Self::id(bv);

        if let Some(info) = VIEW_INFOS.get(&id) {
            if bv.start() == info.image_base {
                return Some(info.clone());
            }
        }

        let info = Arc::new(AnalysisInfo::from_view(bv)?);
        VIEW_INFOS.insert(id, info.clone());
        Some(info)
    }

    pub fn should_ignore_view(bv: &BinaryView) -> bool {
        if let Some(ignore) = IGNORED_VIEWS.get(&Self::id(bv)) {
            return *ignore;
        }

        let ignore = !(is_supported_arch(bv) && AnalysisInfo::has_metadata(bv));
        IGNORED_VIEWS.insert(Self::id(bv), ignore);
        ignore
    }
}

impl AnalysisInfo {
    fn from_view(bv: &BinaryView) -> Option<Self> {
        let should_rewrite_to_direct_calls = Settings::new().get_bool_with_opts(
            "analysis.objectiveC.resolveDynamicDispatch",
            &mut QueryOptions::new_with_view(bv),
        );
        let info = AnalysisInfo {
            image_base: bv.start(),
            objc_stubs: bv
                .section_by_name("__objc_stubs")
                .map(|section| section.start()..section.end()),
            should_rewrite_to_direct_calls,
            selector_impls: RwLock::new(SelectorImplsState::NotLoaded),
        };
        if !Self::has_metadata(bv) {
            return None;
        }
        Some(info)
    }

    fn has_metadata(bv: &BinaryView) -> bool {
        bv.query_metadata("Objective-C").is_some()
    }

    pub fn get_selector_impl(&self, bv: &BinaryView, selector_addr: u64) -> Option<u64> {
        let get = |impls: &SelectorImplementations| {
            impls
                .sel_ref_to_impl
                .get(&selector_addr)
                .or_else(|| impls.sel_to_impl.get(&selector_addr))
                .and_then(|v| v.first().copied())
                .filter(|&addr| addr != 0)
        };

        let cache = self.selector_impls.read().unwrap();
        match &*cache {
            SelectorImplsState::Loaded(Some(impls)) => return get(impls),
            SelectorImplsState::Loaded(None) => return None,
            SelectorImplsState::NotLoaded => {}
        }
        drop(cache);

        let mut cache = self.selector_impls.write().unwrap();
        if let SelectorImplsState::NotLoaded = &*cache {
            *cache = SelectorImplsState::Loaded(self.load_selector_impls(bv));
        }

        if let SelectorImplsState::Loaded(Some(impls)) = &*cache {
            get(impls)
        } else {
            None
        }
    }

    fn load_selector_impls(&self, bv: &BinaryView) -> Option<SelectorImplementations> {
        let Some(Ok(meta)) = bv.get_metadata::<HashMap<String, Ref<Metadata>>>("Objective-C")
        else {
            return None;
        };
        let version_meta = meta.get("version")?;
        if version_meta.get_unsigned_integer()? != 1 {
            tracing::error!(
                "workflow_objc: Unexpected Objective-C metadata version. Expected 1, got {}.",
                version_meta.get_unsigned_integer()?
            );
            return None;
        }

        let mut sel_ref_to_impl = HashMap::new();
        if let Some(sel_ref_to_impl_meta) = meta.get("selRefImplementations") {
            if let Some(map) = Self::parse_selector_impls(sel_ref_to_impl_meta) {
                sel_ref_to_impl = map;
            }
        }

        let mut sel_to_impl = HashMap::new();
        if let Some(sel_to_impl_meta) = meta.get("selImplementations") {
            if let Some(map) = Self::parse_selector_impls(sel_to_impl_meta) {
                sel_to_impl = map;
            }
        }

        Some(SelectorImplementations {
            sel_ref_to_impl,
            sel_to_impl,
        })
    }

    fn parse_selector_impls(meta: &Metadata) -> Option<HashMap<u64, Vec<u64>>> {
        let array = meta.get_array()?;
        let mut result = HashMap::new();
        for item in &array {
            let item = item.get_array()?;
            if item.len() != 2 {
                tracing::warn!(
                    "Expected selector implementation metadata to have 2 items, found {}",
                    item.len()
                );
                return None;
            }
            let selector = item.get(0).get_unsigned_integer()?;
            let impls_meta = item.get(1).get_unsigned_integer_list()?;
            result.insert(selector, impls_meta);
        }
        Some(result)
    }
}
