use log::LevelFilter;

use binaryninja::binaryview::{BinaryView, BinaryViewExt};
use binaryninja::command::{Command, FunctionCommand};
use binaryninja::function::Function;
use binaryninja::rc::Ref;
use binaryninja::tags::TagType;
use warp::signature::function::Function as WarpFunction;

use crate::build_function;
use crate::cache::{ViewID, FUNCTION_CACHE, GUID_CACHE};
use crate::convert::{to_bn_symbol_at_address, to_bn_type};
use crate::matcher::{PlatformID, PLAT_MATCHER_CACHE};

mod apply;
mod copy;
mod create;
mod find;
mod types;
mod workflow;

// TODO: This icon is a little much
const TAG_ICON: &str = "🌏";
const TAG_NAME: &str = "WARP";

fn get_warp_tag_type(view: &BinaryView) -> Ref<TagType> {
    view.get_tag_type(TAG_NAME)
        .unwrap_or_else(|| view.create_tag_type(TAG_NAME, TAG_ICON))
}

// What happens to the function when it is matched.
// TODO: add user: bool
// TODO: Rename to markup_function or something.
pub fn on_matched_function(function: &Function, matched: &WarpFunction) {
    let view = function.view();
    view.define_auto_symbol(&to_bn_symbol_at_address(
        &view,
        &matched.symbol,
        function.symbol().address(),
    ));
    function.set_auto_type(&to_bn_type(&function.arch(), &matched.ty));
    // TODO: Add metadata. (both binja metadata and warp metadata)
    function.add_tag(
        &get_warp_tag_type(&view),
        matched.guid.to_string(),
        None,
        true,
        None,
    );
}

struct DebugFunction;

impl FunctionCommand for DebugFunction {
    fn action(&self, _view: &BinaryView, func: &Function) {
        if let Ok(llil) = func.low_level_il() {
            if let Some(function) = build_function(func, &llil) {
                log::info!("{:#?}", function);
            }
        }
    }

    fn valid(&self, _view: &BinaryView, _func: &Function) -> bool {
        true
    }
}

struct DebugCache;

impl Command for DebugCache {
    fn action(&self, view: &BinaryView) {
        let function_cache = FUNCTION_CACHE.get_or_init(Default::default);
        let view_id = ViewID::from(view);
        if let Some(cache) = function_cache.get(&view_id) {
            log::info!("View functions: {}", cache.cache.len());
        }

        let function_guid_cache = GUID_CACHE.get_or_init(Default::default);
        if let Some(cache) = function_guid_cache.get(&view_id) {
            log::info!("View function guids: {}", cache.cache.len());
        }

        let plat_cache = PLAT_MATCHER_CACHE.get_or_init(Default::default);
        if let Some(plat) = view.default_platform() {
            let platform_id = PlatformID::from(plat);
            if let Some(cache) = plat_cache.get(&platform_id) {
                log::info!("Platform functions: {}", cache.functions.len());
                log::info!("Platform types: {}", cache.types.len());
                log::info!(
                    "Platform matched functions: {}",
                    cache.matched_functions.len()
                );
            }
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    binaryninja::logger::init(LevelFilter::Debug).unwrap();

    workflow::insert_matcher_workflow();

    binaryninja::command::register(
        "WARP\\Apply Signature File Types",
        "Load all types from a signature file and ignore functions",
        types::LoadTypesCommand {},
    );

    binaryninja::command::register(
        "WARP\\Debug Cache",
        "Debug cache sizes... because...",
        DebugCache {},
    );

    binaryninja::command::register_for_function(
        "WARP\\Debug Signature",
        "Print the entire signature for the function",
        DebugFunction {},
    );

    binaryninja::command::register_for_function(
        "WARP\\Copy Pattern",
        "Copy the computed pattern for the function",
        copy::CopyFunctionGUID {},
    );

    binaryninja::command::register(
        "WARP\\Find Function From GUID",
        "Locate the function in the view using a GUID",
        find::FindFunctionFromGUID {},
    );

    binaryninja::command::register(
        "WARP\\Generate Signature File",
        "Generates a signature file containing all binary view functions",
        create::CreateSignatureFile {},
    );

    binaryninja::command::register(
        "WARP\\Apply Signature File",
        "Applies a signature file to the current view",
        apply::ApplySignatureFile {},
    );

    true
}
