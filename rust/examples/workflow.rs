use binaryninja::binary_view::BinaryViewExt;
use binaryninja::low_level_il::expression::{ExpressionHandler, LowLevelILExpressionKind};
use binaryninja::low_level_il::instruction::InstructionHandler;
use binaryninja::low_level_il::VisitorAction;
use binaryninja::tracing::TracingLogListener;
use binaryninja::workflow::{Activity, AnalysisContext, Workflow};

const RUST_ACTIVITY_NAME: &str = "analysis.plugins.rustexample";
const RUST_ACTIVITY_CONFIG: &str = r#"{
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
    println!(
        "Activity `{}` called in function {} with workflow {:?}!",
        RUST_ACTIVITY_NAME,
        func.start(),
        func.workflow().map(|wf| wf.name())
    );
    // If we have llil available, replace that as well.
    if let Some(llil) = unsafe { analysis_context.llil_function() } {
        for basic_block in &func.basic_blocks() {
            for instr in basic_block.iter() {
                if let Some(llil_instr) = llil.instruction_at(instr) {
                    llil_instr.visit_tree(&mut |expr| {
                        if let LowLevelILExpressionKind::Const(_op) = expr.kind() {
                            // Replace all consts with 0x1337.
                            tracing::debug!(
                                "Replacing llil expression @ 0x{:x} : {}",
                                instr,
                                expr.index
                            );
                            unsafe {
                                llil.replace_expression(expr.index, llil.const_int(4, 0x1337))
                            };
                        }
                        VisitorAction::Descend
                    });
                }
            }
        }
        analysis_context.set_llil_function(&llil.finalized());
    }
}

pub fn main() {
    tracing_subscriber::fmt::init();
    let _listener = TracingLogListener::new().register();

    // This loads all the core architecture, platform, etc plugins
    let headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    tracing::info!("Registering workflow...");
    let activity = Activity::new_with_action(RUST_ACTIVITY_CONFIG, example_activity);
    // Update the meta-workflow with our new activity.
    Workflow::cloned("core.function.metaAnalysis")
        .expect("Couldn't find meta workflow")
        .activity_after(&activity, "core.function.runFunctionRecognizers")
        .expect("Couldn't find runFunctionRecognizers")
        .register()
        .expect("Couldn't register activity");

    tracing::info!("Loading binary...");
    let bv = headless_session
        .load("/bin/cat")
        .expect("Couldn't open `/bin/cat`");

    // traverse all llil expressions and look for the constant 0x1337
    for func in &bv.functions() {
        if let Ok(llil) = func.low_level_il() {
            for block in &llil.basic_blocks() {
                for instr in block.iter() {
                    instr.visit_tree(&mut |expr| {
                        if let LowLevelILExpressionKind::Const(value) = expr.kind() {
                            if value.value() == 0x1337 {
                                tracing::info!(
                                    "Found constant 0x1337 at instruction 0x{:x} in function {}",
                                    instr.address(),
                                    func.start()
                                );
                            }
                        }
                        VisitorAction::Descend
                    });
                }
            }
        }
    }
}
