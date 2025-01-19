use binaryninja::headless::Session;
use binaryninja::settings::Settings;
use binaryninja::workflow::Workflow;
use rstest::*;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

// TODO: Test running a workflow activity
// TODO: Test activity insertion and removal

#[rstest]
fn test_workflow_clone(_session: &Session) {
    let original_workflow = Workflow::new("core.function.baseAnalysis");
    let mut cloned_workflow = original_workflow.clone("clone_workflow");

    assert_eq!(cloned_workflow.name().as_str(), "clone_workflow");
    assert_eq!(
        cloned_workflow.configuration(),
        original_workflow.configuration()
    );

    cloned_workflow = original_workflow.clone("");
    assert_eq!(
        cloned_workflow.name().as_str(),
        "core.function.baseAnalysis"
    );
}

#[rstest]
fn test_workflow_registration(_session: &Session) {
    // Validate NULL workflows cannot be registered
    let workflow = Workflow::new("null");
    assert_eq!(workflow.name().as_str(), "null");
    assert!(!workflow.registered());
    workflow
        .register()
        .expect_err("Re-registration of null is allowed");

    // Validate new workflows can be registered
    let test_workflow = Workflow::instance("core.function.baseAnalysis").clone("test_workflow");

    assert_eq!(test_workflow.name().as_str(), "test_workflow");
    assert!(!test_workflow.registered());
    test_workflow
        .register()
        .expect("Failed to register workflow");
    assert!(test_workflow.registered());
    assert_eq!(
        test_workflow.size(),
        Workflow::instance("core.function.baseAnalysis").size()
    );
    Workflow::list()
        .iter()
        .find(|w| w.name() == test_workflow.name())
        .expect("Workflow not found in list");
    Settings::new()
        .get_property_string_list("analysis.workflows.functionWorkflow", "enum")
        .iter()
        .find(|&w| w == "test_workflow")
        .expect("Workflow not found in settings");

    // Validate that registered workflows are immutable
    let immutable_workflow = Workflow::instance("test_workflow");
    assert!(!immutable_workflow.clear());
    assert!(immutable_workflow.contains("core.function.advancedAnalysis"));
    assert!(!immutable_workflow.remove("core.function.advancedAnalysis"));
    assert!(!Workflow::instance("core.function.baseAnalysis").clear());

    // Validate re-registration of baseAnalysis is not allowed
    let base_workflow_clone = Workflow::instance("core.function.baseAnalysis").clone("");

    assert_eq!(
        base_workflow_clone.name().as_str(),
        "core.function.baseAnalysis"
    );
    assert!(!base_workflow_clone.registered());
    base_workflow_clone
        .register()
        .expect_err("Re-registration of baseAnalysis is allowed");
    assert_eq!(
        base_workflow_clone.size(),
        Workflow::instance("core.function.baseAnalysis").size()
    );
    assert_eq!(
        base_workflow_clone.configuration(),
        Workflow::instance("core.function.baseAnalysis").configuration()
    );
    assert!(!base_workflow_clone.registered());
}
