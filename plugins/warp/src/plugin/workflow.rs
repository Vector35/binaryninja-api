use crate::cache::container::for_cached_containers;
use crate::cache::{
    cached_function_guid, insert_cached_function_match, try_cached_function_guid,
    try_cached_function_match,
};
use crate::convert::{
    comment_to_bn_comment, platform_to_target, to_bn_symbol_at_address, to_bn_type,
};
use crate::matcher::{Matcher, MatcherSettings};
use crate::{get_warp_tag_type, relocatable_regions};
use binaryninja::architecture::RegisterId;
use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use binaryninja::settings::{QueryOptions, Settings};
use binaryninja::workflow::{Activity, AnalysisContext, Workflow};
use itertools::Itertools;
use std::collections::HashMap;
use std::time::Instant;
use warp::r#type::class::function::{Location, RegisterLocation, StackLocation};
use warp::signature::function::{Function, FunctionGUID};
use warp::target::Target;

pub const APPLY_ACTIVITY_NAME: &str = "analysis.warp.apply";
const APPLY_ACTIVITY_CONFIG: &str = r#"{
    "name": "analysis.warp.apply",
    "title" : "WARP Apply Matched",
    "description": "This analysis step applies WARP info to matched functions...",
    "eligibility": {
        "auto": {},
        "runOnce": false
    }
}"#;

pub const MATCHER_ACTIVITY_NAME: &str = "analysis.warp.matcher";
const MATCHER_ACTIVITY_CONFIG: &str = r#"{
    "name": "analysis.warp.matcher",
    "title" : "WARP Matcher",
    "description": "This analysis step attempts to find matching WARP functions after the initial analysis is complete...",
    "eligibility": {
        "auto": {},
        "runOnce": true
    }
}"#;

pub const GUID_ACTIVITY_NAME: &str = "analysis.warp.guid";
const GUID_ACTIVITY_CONFIG: &str = r#"{
    "name": "analysis.warp.guid",
    "title" : "WARP GUID Generator",
    "description": "This analysis step generates the GUID for all analyzed functions...",
    "eligibility": {
        "auto": {},
        "runOnce": false
    }
}"#;

pub struct RunMatcher;

impl Command for RunMatcher {
    fn action(&self, view: &BinaryView) {
        let view = view.to_owned();
        std::thread::spawn(move || {
            // For embedded targets the user may not have set the sections up.
            // Alert the user if we have no actual regions (+1 comes from the synthetic section).
            let regions = relocatable_regions(&view);
            if regions.len() <= 1 && view.memory_map().is_activated() {
                log::warn!(
                    "No relocatable regions found, for best results please define sections for the binary!"
                );
            }

            run_matcher(&view);
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

pub fn run_matcher(view: &BinaryView) {
    // TODO: Create the tag type so we dont have UB in the apply function workflow.
    let undo_id = view.file().begin_undo_actions(false);
    let _ = get_warp_tag_type(view);
    view.file().forget_undo_actions(&undo_id);

    // Then we want to actually find matching functions.
    let background_task = BackgroundTask::new("Matching on WARP functions...", true);
    let start = Instant::now();

    // Build matcher
    let view_settings = Settings::new();
    let mut query_opts = QueryOptions::new_with_view(view);
    let matcher_settings = MatcherSettings::from_settings(&view_settings, &mut query_opts);
    let matcher = Matcher::new(matcher_settings);

    // TODO: Par iter this? Using dashmap
    let functions_by_target_and_guid: HashMap<(FunctionGUID, Target), Vec<_>> = view
        .functions()
        .iter()
        .filter_map(|f| {
            let guid = try_cached_function_guid(&f)?;
            let target = platform_to_target(&f.platform());
            Some(((guid, target), f.to_owned()))
        })
        .into_group_map();

    if functions_by_target_and_guid.is_empty() && !view.functions().is_empty() {
        // The user is likely trying to run the matcher on a database before guids were automatically
        // generated, we should alert them and ask if they would like to reanalyze.
        // TODO: Call reanalyze for them?
        log::error!("Trying to match with an older database, please reanalyze the database.");
        background_task.finish();
        return;
    }

    // TODO: Par iter this? Using dashmap
    let guids_by_target: HashMap<Target, Vec<FunctionGUID>> = functions_by_target_and_guid
        .keys()
        .map(|(guid, target)| (target.clone(), *guid))
        .into_group_map();

    // TODO: Target gets cloned a lot.
    // TODO: Containers might both match on the same function. What should we do?
    for_cached_containers(|container| {
        if background_task.is_cancelled() {
            return;
        }

        for (target, guids) in &guids_by_target {
            let function_guid_with_sources = container
                .sources_with_function_guids(target, guids)
                .unwrap_or_default();

            for (guid, sources) in &function_guid_with_sources {
                let matched_functions: Vec<Function> = sources
                    .iter()
                    .flat_map(|source| {
                        container
                            .functions_with_guid(target, source, guid)
                            .unwrap_or_default()
                    })
                    .collect();

                let functions = functions_by_target_and_guid
                    .get(&(*guid, target.clone()))
                    .expect("Function guid not found");

                for function in functions {
                    // Match on all the possible functions
                    if let Some(matched_function) =
                        matcher.match_function_from_constraints(function, &matched_functions)
                    {
                        // We were able to find a match, add it to the match cache and then mark the function
                        // as requiring updates; this is so that we know about it in the applier activity.
                        insert_cached_function_match(function, Some(matched_function.clone()));
                    }
                }
            }
        }
    });

    if background_task.is_cancelled() {
        log::info!("Matcher was cancelled by user, you may run it again by running the 'Run Matcher' command.");
    }

    // It is noisy to show this every time, so we only show it in cases where a user can reasonably perceive.
    let elapsed = start.elapsed();
    if elapsed > std::time::Duration::from_secs(1) {
        log::info!("Function matching took {:?}", elapsed);
    }
    background_task.finish();

    // Now we want to trigger re-analysis.
    view.update_analysis();
}

pub fn insert_workflow() {
    // "Hey look, it's a plier" ~ Josh 2025
    let apply_activity = |ctx: &AnalysisContext| {
        let view = ctx.view();
        let function = ctx.function();
        if let Some(matched_function) = try_cached_function_match(&function) {
            view.define_auto_symbol(&to_bn_symbol_at_address(
                &view,
                &matched_function.symbol,
                function.symbol().address(),
            ));
            if let Some(func_ty) = &matched_function.ty {
                function.set_auto_type(&to_bn_type(&function.arch(), func_ty));
            }
            // TODO: How to clear the comments? They are just persisted.
            // TODO: Also they generate an undo action, i hate implicit undo actions so much.
            for comment in matched_function.comments {
                let bn_comment = comment_to_bn_comment(&function, comment);
                function.set_comment_at(bn_comment.addr, &bn_comment.comment);
            }
            if let Some(mlil) = ctx.mlil_function() {
                for variable in matched_function.variables {
                    let decl_addr = ((function.start() as i64) + variable.offset) as u64;
                    if let Some(decl_instr) = mlil.instruction_at(decl_addr) {
                        let decl_var = match variable.location {
                            Location::Register(RegisterLocation { id, .. }) => {
                                decl_instr.variable_for_register_after(RegisterId(id as u32))
                            }
                            Location::Stack(StackLocation { offset, .. }) => {
                                decl_instr.variable_for_stack_location_after(offset)
                            }
                        };
                        let decl_ty = match variable.ty {
                            Some(decl_ty) => to_bn_type(&function.arch(), &decl_ty),
                            None => {
                                let Some(existing_var) = function.variable_type(&decl_var) else {
                                    continue;
                                };
                                existing_var.contents
                            }
                        };
                        let decl_name = variable
                            .name
                            .unwrap_or_else(|| function.variable_name(&decl_var));
                        mlil.create_auto_var(&decl_var, &decl_ty, &decl_name, false)
                    }
                }
            }
            function.add_tag(
                &get_warp_tag_type(&view),
                &matched_function.guid.to_string(),
                None,
                false,
                None,
            );
        }
    };

    let matcher_activity = |ctx: &AnalysisContext| {
        let view = ctx.view();
        run_matcher(&view);
    };

    let guid_activity = |ctx: &AnalysisContext| {
        let function = ctx.function();
        if let Some(lifted_il) = unsafe { ctx.lifted_il_function() } {
            cached_function_guid(&function, &lifted_il);
        }
    };

    let old_function_meta_workflow = Workflow::instance("core.function.metaAnalysis");
    let function_meta_workflow = old_function_meta_workflow.clone_to("core.function.metaAnalysis");
    let guid_activity = Activity::new_with_action(GUID_ACTIVITY_CONFIG, guid_activity);
    let apply_activity = Activity::new_with_action(APPLY_ACTIVITY_CONFIG, apply_activity);
    function_meta_workflow
        .register_activity(&guid_activity)
        .unwrap();
    // Because we are going to impact analysis with application we must make sure the function update is triggered to continue to update analysis.
    function_meta_workflow
        .register_activity(&apply_activity)
        .unwrap();
    function_meta_workflow
        .insert_after("core.function.runFunctionRecognizers", [GUID_ACTIVITY_NAME]);
    function_meta_workflow
        .insert_after("core.function.generateMediumLevelIL", [APPLY_ACTIVITY_NAME]);
    function_meta_workflow.register().unwrap();

    let old_module_meta_workflow = Workflow::instance("core.module.metaAnalysis");
    let module_meta_workflow = old_module_meta_workflow.clone_to("core.module.metaAnalysis");
    let matcher_activity = Activity::new_with_action(MATCHER_ACTIVITY_CONFIG, matcher_activity);
    // Matcher activity must have core.module.update as subactivity otherwise analysis will sometimes never retrigger.
    module_meta_workflow
        .register_activity_with_subactivities(&matcher_activity, vec!["core.module.update"])
        .unwrap();
    module_meta_workflow.insert(
        "core.module.deleteUnusedAutoFunctions",
        [MATCHER_ACTIVITY_NAME],
    );
    module_meta_workflow.register().unwrap();
}
