use log::*;

use binaryninja::activity::register_activity;
use binaryninja::analysiscontext::AnalysisContext;
use binaryninja::workflow::{register_workflow, Workflow};

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    binaryninja::logger::init(LevelFilter::Warn).unwrap();

    let ww = Workflow::instance().duplicate("TestWorkflow");

    let aa = register_activity("extension.test", move |_: &AnalysisContext| error!("hello from test workflow"));

    ww.register_activity(aa);
    ww.insert("core.function.translateTailCalls", &["extension.test"]);

    register_workflow(ww);

    true
}
