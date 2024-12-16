use binaryninja::llil::{
    ExprInfo, LiftedNonSSA, NonSSA, VisitorAction,
};
use binaryninja::workflow::{Activity, AnalysisContext, Workflow};
use log::LevelFilter;
use binaryninja::logger::Logger;

const RUST_ACTIVITY_NAME: &'static str = "analysis.plugins.rustexample";
const RUST_ACTIVITY_CONFIG: &'static str = r#"{
    "name": "analysis.plugins.rustexample",
    "title" : "Rust Example",
    "description": "This analysis step logs out some information about the function...",
    "eligibility": {
        "auto": { "default": true },
        "runOnce": false
    }
}"#;

fn example_activity(analysis_context: &AnalysisContext) {
    let func = analysis_context.function();
    log::info!(
        "Activity `{}` called in function {} with workflow {:?}!",
        RUST_ACTIVITY_NAME,
        func.start(),
        func.workflow().map(|wf| wf.name())
    );
    // If we have llil available, replace that as well.
    if let Some(llil) = unsafe { analysis_context.llil_function::<NonSSA<LiftedNonSSA>>() } {
        for basic_block in &func.basic_blocks() {
            for instr in basic_block.iter() {
                if let Some(llil_instr) = llil.instruction_at(instr) {
                    llil_instr.visit_tree(&mut |expr, info| {
                        match info {
                            ExprInfo::Const(_op) => {
                                // Replace all consts with 0x1337.
                                log::info!(
                                    "Replacing llil expression @ 0x{:x} : {}",
                                    instr,
                                    expr.index()
                                );
                                unsafe {
                                    llil.replace_expression(expr.index(), llil.const_int(4, 0x1337))
                                };
                            }
                            _ => {}
                        }
                        VisitorAction::Descend
                    });
                }
            }
        }
        analysis_context.set_lifted_il_function(&llil);
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("Workflow Example").with_level(LevelFilter::Info).init();

    log::info!("Initialized the plugin");

    let meta_workflow = Workflow::new_from_copy("core.function.metaAnalysis");
    let activity = Activity::new_with_action(RUST_ACTIVITY_CONFIG, example_activity);
    meta_workflow.register_activity(&activity).unwrap();
    meta_workflow.insert("core.function.runFunctionRecognizers", [RUST_ACTIVITY_NAME]);
    // Re-register the meta workflow with our changes.
    meta_workflow.register().unwrap();
    true
}
