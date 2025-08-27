use crate::cache::container::for_cached_containers;
use crate::cache::{
    cached_function_guid, insert_cached_function_match, try_cached_function_guid,
    try_cached_function_match,
};
use crate::convert::{platform_to_target, to_bn_type};
use crate::matcher::{Matcher, MatcherSettings};
use crate::{get_warp_tag_type, relocatable_regions};
use binaryninja::architecture::RegisterId;
use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use binaryninja::settings::{QueryOptions, Settings};
use binaryninja::workflow::{activity, Activity, AnalysisContext, Workflow, WorkflowBuilder};
use itertools::Itertools;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use std::collections::HashMap;
use std::time::Instant;
use warp::r#type::class::function::{Location, RegisterLocation, StackLocation};
use warp::signature::function::{Function, FunctionGUID};
use warp::target::Target;

pub const GUID_ACTIVITY_NAME: &str = "analysis.warp.guid";

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
        // NOTE: We only alert if we actually have the GUID activity enabled.
        if let Some(sample_function) = view.functions().iter().next() {
            let function_workflow = sample_function
                .workflow()
                .expect("Function has no workflow");
            if function_workflow.contains(GUID_ACTIVITY_NAME) {
                log::error!("No function guids in database, please reanalyze the database.");
            } else {
                log::error!(
                    "Activity '{}' is not in workflow '{}', create function guids manually to run matcher...",
                    GUID_ACTIVITY_NAME,
                    function_workflow.name()
                )
            }
        }
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

            function_guid_with_sources
                .into_par_iter()
                .for_each(|(guid, sources)| {
                    let matched_functions: Vec<Function> = sources
                        .iter()
                        .flat_map(|source| {
                            container
                                .functions_with_guid(target, source, &guid)
                                .unwrap_or_default()
                        })
                        .collect();

                    // NOTE: See the comment in `match_function_from_constraints` about this fast fail.
                    if matcher
                        .settings
                        .maximum_possible_functions
                        .is_some_and(|max| max < matched_functions.len() as u64)
                    {
                        log::warn!(
                            "Skipping {}, too many possible functions: {}",
                            guid,
                            matched_functions.len()
                        );
                        return;
                    }

                    let functions = functions_by_target_and_guid
                        .get(&(guid, target.clone()))
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
                });
        }
    });

    if background_task.is_cancelled() {
        log::info!("Matcher was cancelled by user, you may run it again by running the 'Run Matcher' command.");
    }

    log::info!("Function matching took {:?}", start.elapsed());
    background_task.finish();

    // Now we want to trigger re-analysis.
    view.update_analysis();
}

pub fn insert_workflow() -> Result<(), ()> {
    // TODO: Note: because of symbol persistence function symbol is applied in `insert_cached_function_match`.
    // TODO: Comments are also applied there, they are "user" like, persisted and make undo actions.
    // "Hey look, it's a plier" ~ Josh 2025
    let apply_activity = |ctx: &AnalysisContext| {
        let view = ctx.view();
        let function = ctx.function();
        if let Some(matched_function) = try_cached_function_match(&function) {
            // core.function.propagateAnalysis will assign user type info to auto, so we must not apply
            // otherwise we will wipe over user type info.
            if !function.has_user_type() {
                if let Some(func_ty) = &matched_function.ty {
                    function.set_auto_type(&to_bn_type(Some(function.arch()), func_ty));
                }
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
                        if function.is_var_user_defined(&decl_var) {
                            // Internally, analysis will just assign user vars to auto vars and consult only that.
                            // So we must skip if there is a user-defined var at the decl.
                            continue;
                        }
                        let decl_ty = match variable.ty {
                            Some(decl_ty) => to_bn_type(Some(function.arch()), &decl_ty),
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
                        function.create_auto_var(&decl_var, &decl_ty, &decl_name, false)
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
        cached_function_guid(&function, || unsafe { ctx.lifted_il_function() });
    };

    let guid_config = activity::Config::action(
        GUID_ACTIVITY_NAME,
        "WARP GUID Generator",
        "This analysis step generates the GUID for all analyzed functions...",
    )
    .eligibility(activity::Eligibility::auto().run_once(false));
    let guid_activity = Activity::new_with_action(&guid_config, guid_activity);

    let apply_config = activity::Config::action(
        "analysis.warp.apply",
        "WARP Apply Matched",
        "This analysis step applies WARP info to matched functions...",
    )
    .eligibility(activity::Eligibility::auto().run_once(false));
    let apply_activity = Activity::new_with_action(&apply_config, apply_activity);

    let add_function_activities = |workflow: Option<WorkflowBuilder>| -> Result<(), ()> {
        let Some(workflow) = workflow else {
            return Ok(());
        };

        workflow
            .activity_after(&guid_activity, "core.function.runFunctionRecognizers")?
            .activity_after(&apply_activity, "core.function.generateMediumLevelIL")?
            .register()?;
        Ok(())
    };

    add_function_activities(Workflow::cloned("core.function.metaAnalysis"))?;
    // TODO: Remove this once the objectivec workflow is registered on the meta workflow.
    add_function_activities(Workflow::cloned("core.function.objectiveC"))?;

    let matcher_config = activity::Config::action(
        "analysis.warp.matcher",
        "WARP Matcher",
        "This analysis step attempts to find matching WARP functions after the initial analysis is complete...",
    )
    .eligibility(activity::Eligibility::auto().run_once(true))
    // Matcher activity must have core.module.update as subactivity otherwise analysis will sometimes never retrigger.
    .downstream_dependencies(["core.module.update"]);
    let matcher_activity = Activity::new_with_action(&matcher_config, matcher_activity);
    Workflow::cloned("core.module.metaAnalysis")
        .ok_or(())?
        .activity_before(&matcher_activity, "core.module.finishUpdate")?
        .register()?;

    Ok(())
}
