use crate::cache::{
    register_cache_destructor, ViewID, FUNCTION_CACHE, GUID_CACHE, MATCHED_FUNCTION_CACHE,
};
use crate::convert::{to_bn_symbol_at_address, to_bn_type};
use crate::matcher::{
    invalidate_function_matcher_cache, Matcher, MatcherSettings, PlatformID, PLAT_MATCHER_CACHE,
};
use crate::{build_function, cache};
use binaryninja::binaryview::{BinaryView, BinaryViewExt};
use binaryninja::command::{Command, FunctionCommand};
use binaryninja::function::{Function, FunctionUpdateType};
use binaryninja::logger::Logger;
use binaryninja::rc::Ref;
use binaryninja::tags::TagType;
use binaryninja::ObjectDestructor;
use log::LevelFilter;
use warp::signature::function::constraints::FunctionConstraint;
use warp::signature::function::Function as WarpFunction;

mod add;
mod copy;
mod create;
mod find;
mod load;
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
    view.define_user_symbol(&to_bn_symbol_at_address(
        &view,
        &matched.symbol,
        function.symbol().address(),
    ));
    function.set_user_type(&to_bn_type(&function.arch(), &matched.ty));
    // TODO: Add metadata. (both binja metadata and warp metadata)
    function.add_tag(
        &get_warp_tag_type(&view),
        matched.guid.to_string(),
        None,
        true,
        None,
    );
    // Seems to be the only way to get the analysis update to work correctly.
    function.mark_updates_required(FunctionUpdateType::FullAutoFunctionUpdate);
}

struct DebugFunction;

impl FunctionCommand for DebugFunction {
    fn action(&self, _view: &BinaryView, func: &Function) {
        if let Ok(llil) = func.low_level_il() {
            log::info!("{:#?}", build_function(func, &llil));
        }
    }

    fn valid(&self, _view: &BinaryView, _func: &Function) -> bool {
        true
    }
}

struct DebugMatcher;

impl FunctionCommand for DebugMatcher {
    fn action(&self, _view: &BinaryView, function: &Function) {
        let Ok(llil) = function.low_level_il() else {
            log::error!("No LLIL for function 0x{:x}", function.start());
            return;
        };
        let platform = function.platform();
        // Build the matcher every time this is called to make sure we aren't in a bad state.
        let matcher = Matcher::from_platform(platform);
        let func = build_function(function, &llil);
        // TODO: Clean this up.
        if let Some(possible_matches) = matcher.functions.get(&func.guid) {
            let print_constraint = |prefix: &str, constraint: &FunctionConstraint| {
                log::info!(
                    "    {} {} ({})",
                    prefix,
                    constraint
                        .to_owned()
                        .symbol
                        .map(|s| s.name)
                        .unwrap_or("*".to_string()),
                    constraint
                        .guid
                        .map(|g| g.to_string())
                        .unwrap_or("*".to_string())
                );
            };
            for possible_match in possible_matches.value() {
                log::info!("{} ({})", possible_match.symbol.name, possible_match.guid);
                for constraint in &possible_match.constraints.call_sites {
                    print_constraint("CS", constraint);
                }
                for constraint in &possible_match.constraints.call_sites {
                    print_constraint("ADJ", constraint);
                }
            }
        } else {
            log::error!(
                "No possible matches found for the function 0x{:x}",
                function.start()
            );
        };
    }

    fn valid(&self, _view: &BinaryView, _function: &Function) -> bool {
        true
    }
}

struct DebugCache;

impl Command for DebugCache {
    fn action(&self, view: &BinaryView) {
        let view_id = ViewID::from(view);
        let function_cache = FUNCTION_CACHE.get_or_init(Default::default);
        if let Some(cache) = function_cache.get(&view_id) {
            log::info!("View functions: {}", cache.cache.len());
        }

        let matched_function_cache = MATCHED_FUNCTION_CACHE.get_or_init(Default::default);
        if let Some(cache) = matched_function_cache.get(&view_id) {
            log::info!("View matched functions: {}", cache.cache.len());
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
                log::info!("Platform settings: {:?}", cache.settings);
            }
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

struct DebugInvalidateCache;

impl Command for DebugInvalidateCache {
    fn action(&self, view: &BinaryView) {
        invalidate_function_matcher_cache();
        let destructor = cache::CacheDestructor {};
        destructor.destruct_view(view);
        log::info!("Invalidated all WARP caches...");
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("WARP").with_level(LevelFilter::Debug).init();

    // Register our matcher settings.
    MatcherSettings::register();

    // Make sure caches are flushed when the views get destructed.
    register_cache_destructor();

    workflow::insert_workflow();

    binaryninja::command::register(
        "WARP\\Run Matcher",
        "Run the matcher manually",
        workflow::RunMatcher {},
    );

    binaryninja::command::register(
        "WARP\\Debug\\Cache",
        "Debug cache sizes... because...",
        DebugCache {},
    );

    binaryninja::command::register(
        "WARP\\Debug\\Invalidate Caches",
        "Invalidate all WARP caches",
        DebugInvalidateCache {},
    );

    binaryninja::command::register_for_function(
        "WARP\\Debug\\Function Signature",
        "Print the entire signature for the function",
        DebugFunction {},
    );

    binaryninja::command::register_for_function(
        "WARP\\Debug\\Function Matcher",
        "Print all possible matches for the function",
        DebugMatcher {},
    );

    binaryninja::command::register(
        "WARP\\Debug\\Apply Signature File Types",
        "Load all types from a signature file and ignore functions",
        types::LoadTypes {},
    );

    binaryninja::command::register(
        "WARP\\Load Signature File",
        "Load file into the matcher, this does NOT kick off matcher analysis",
        load::LoadSignatureFile {},
    );

    binaryninja::command::register_for_function(
        "WARP\\Copy Function GUID",
        "Copy the computed GUID for the function",
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

    binaryninja::command::register_for_function(
        "WARP\\Add Function Signature to File",
        "Stores the signature for the function in the signature file",
        add::AddFunctionSignature {},
    );

    true
}
