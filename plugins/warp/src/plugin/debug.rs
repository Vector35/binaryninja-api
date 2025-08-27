use crate::cache::container::for_cached_containers;
use crate::{build_function, cache};
use binaryninja::binary_view::BinaryView;
use binaryninja::command::{Command, FunctionCommand};
use binaryninja::function::Function;
use binaryninja::ObjectDestructor;

pub struct DebugFunction;

impl FunctionCommand for DebugFunction {
    fn action(&self, _view: &BinaryView, func: &Function) {
        log::info!(
            "{:#?}",
            build_function(func, || func.lifted_il().ok(), false)
        );
    }

    fn valid(&self, _view: &BinaryView, _func: &Function) -> bool {
        true
    }
}

pub struct DebugCache;

impl Command for DebugCache {
    fn action(&self, _view: &BinaryView) {
        for_cached_containers(|c| {
            log::info!("Container: {:#?}", c);
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

pub struct DebugInvalidateCache;

impl Command for DebugInvalidateCache {
    fn action(&self, view: &BinaryView) {
        let destructor = cache::CacheDestructor {};
        destructor.destruct_view(view);
        log::info!("Invalidated all WARP caches...");
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
