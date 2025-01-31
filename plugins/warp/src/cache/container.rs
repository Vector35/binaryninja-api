use crate::container::Container;
use dashmap::DashMap;
use std::ops::Deref;
use std::sync::{Arc, OnceLock, RwLock};

pub static CONTAINER_CACHE: OnceLock<DashMap<String, Arc<RwLock<Box<dyn Container>>>>> =
    OnceLock::new();

pub fn for_cached_containers(f: impl Fn(&dyn Container)) {
    let containers_cache = CONTAINER_CACHE.get_or_init(Default::default);
    for container in containers_cache.iter() {
        if let Ok(guarded_container) = container.read() {
            f(guarded_container.deref().as_ref());
        }
    }
}

// TODO: The static lifetime here is a little wierd... (we need it to Box)
pub fn add_cached_container(container: impl Container + 'static) {
    let containers_cache = CONTAINER_CACHE.get_or_init(Default::default);
    let container_name = container.to_string();
    containers_cache.insert(container_name, Arc::new(RwLock::new(Box::new(container))));
}

pub fn cached_containers() -> Vec<Arc<RwLock<Box<dyn Container>>>> {
    let containers_cache = CONTAINER_CACHE.get_or_init(Default::default);
    containers_cache.iter().map(|c| c.clone()).collect()
}
