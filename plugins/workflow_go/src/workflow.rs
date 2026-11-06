use crate::activities::calling_convention::GoCallingConventionWorkflow;
use crate::activities::string_argument::NarrowStringsAction;
use crate::go::detect::GoDetector;
use anyhow::{Result, anyhow};
use binaryninja::workflow::{Activity, AnalysisContext, Workflow, activity};

const FUNCTION_WF: &str = "core.function.metaAnalysis";
const MODULE_WF: &str = "core.module.metaAnalysis";
const MLIL_ANCHOR: &str = "core.function.generateMediumLevelIL";
const MODULE_ANCHOR: &str = "core.module.loadDebugInfo";

const ACT_APPLY_CC: &str = "analysis.plugins.goWorkflow.applyCallingConvention";
const ACT_NARROW: &str = "analysis.plugins.goWorkflow.narrowStrings";
const HLIL_ANCHOR: &str = "core.function.commitAnalysisData";

/// Registers the necessary workflow for golang analyses
pub fn register_activities() -> Result<()> {
    register_module_workflow()?;
    register_function_workflow()?;
    Ok(())
}

fn register_function_workflow() -> Result<()> {
    let apply_cc = Activity::new_with_action(
        activity::Config::action(
            ACT_APPLY_CC,
            "Go ABIInternal: Apply Calling Convention",
            "Set the correct calling convention for golang binaries.",
        )
        .eligibility(activity::Eligibility::auto()),
        GoCallingConventionWorkflow::apply,
    );

    let narrow = Activity::new_with_action(
        activity::Config::action(
            ACT_NARROW,
            "Go: Narrow String Literals",
            "Adjust the size of the strings passed as arguments",
        )
        .eligibility(activity::Eligibility::auto()),
        NarrowStringsAction::apply,
    );

    Workflow::cloned(FUNCTION_WF)
        .ok_or_else(|| anyhow!("failed to clone {FUNCTION_WF}"))?
        .activity_before(&apply_cc, MLIL_ANCHOR)
        .map_err(|_| anyhow!("activity_before failed: anchor '{MLIL_ANCHOR}' missing?"))?
        .activity_before(&narrow, HLIL_ANCHOR)
        .map_err(|_| anyhow!("activity_after failed: anchor '{HLIL_ANCHOR}'"))?
        .register()
        .map_err(|_| anyhow!("register failed: {FUNCTION_WF}"))?;

    Ok(())
}

fn register_module_workflow() -> Result<()> {
    const ACT_ANNOTATE: &str = "analysis.plugins.goWorkflow.annotate";

    let annotate = Activity::new_with_action(
        activity::Config::action(
            ACT_ANNOTATE,
            "Go: identify golang binary",
            "Identify if the binary is golang, pclntab presence and version.",
        )
        .eligibility(activity::Eligibility::auto()),
        annotate_action,
    );

    Workflow::cloned(MODULE_WF)
        .ok_or_else(|| anyhow!("failed clone for : {MODULE_WF}"))?
        .activity_after(&annotate, MODULE_ANCHOR)
        .map_err(|_| anyhow!("activity_after annotate: anchor '{MODULE_ANCHOR}'"))?
        .register()
        .map_err(|_| anyhow!("failed workflow registration: {MODULE_WF}"))?;

    Ok(())
}

fn annotate_action(ctx: &AnalysisContext) {
    let view = ctx.view();
    let info = GoDetector::analyze(&view);

    if !info.is_go {
        tracing::info!("golang: non-go binary detected, workflows for golang will be skipped.");
        return;
    }

    view.store_metadata("go_workflow.is_go", info.is_go, true);
    view.store_metadata("go_workflow.has_pclntab", info.has_pclntab, true);
    view.store_metadata("go_workflow.go_version", info.version.as_str(), true);
}
