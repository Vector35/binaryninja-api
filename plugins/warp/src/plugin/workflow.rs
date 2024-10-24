use crate::matcher::cached_function_match;
use binaryninja::llil;
use binaryninja::workflow::{Activity, AnalysisContext, Workflow};

const MATCHER_ACTIVITY_NAME: &str = "analysis.plugins.WARPMatcher";
// NOTE: runOnce is off because previously matched functions need info applied.
const MATCHER_ACTIVITY_CONFIG: &str = r#"{
    "name": "analysis.plugins.WARPMatcher",
    "title" : "WARP Matcher",
    "description": "This analysis step applies WARP info to matched functions...",
    "eligibility": {
        "auto": { "default": true },
        "runOnce": false
    }
}"#;

pub fn insert_matcher_workflow() {
    let matcher_activity = |ctx: &AnalysisContext| {
        let function = ctx.function();
        if function.has_user_annotations() {
            // User has touched the function, stop trying to match on it!
            return;
        }

        if let Some(llil) = unsafe { ctx.llil_function::<llil::NonSSA<llil::RegularNonSSA>>() } {
            cached_function_match(&function, &llil);
        }
    };

    let meta_workflow = Workflow::new_from_copy("core.function.metaAnalysis");
    let activity = Activity::new_with_action(MATCHER_ACTIVITY_CONFIG, matcher_activity);
    meta_workflow.register_activity(&activity).unwrap();
    meta_workflow.insert(
        "core.function.runFunctionRecognizers",
        [MATCHER_ACTIVITY_NAME],
    );
    meta_workflow.register().unwrap();
}
