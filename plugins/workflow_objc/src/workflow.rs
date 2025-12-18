use binaryninja::workflow::{activity, Activity, AnalysisContext, Workflow};

use crate::{activities, error::WorkflowRegistrationError};

/// Base confidence levels for types applied by each of the activities in this workflow.
/// These are ordered such that later activities can override types applied by earlier activities.
#[repr(u8)]
pub enum Confidence {
    ObjCMsgSend = 96,
    SuperInit = 100,
}

fn run<E: std::fmt::Debug>(
    func: impl Fn(&AnalysisContext) -> Result<(), E>,
) -> impl Fn(&AnalysisContext) {
    move |ac| {
        if let Err(err) = func(ac) {
            tracing::debug!("Error occurred while running activity: {err:#x?}");
        }
    }
}

pub fn register_activities() -> Result<(), WorkflowRegistrationError> {
    let workflow =
        Workflow::cloned("core.function.metaAnalysis").ok_or(WorkflowRegistrationError)?;

    let objc_msg_send_calls_activity = Activity::new_with_action(
        activity::Config::action(
            "core.function.objectiveC.analyzeMessageSends",
            "Obj-C: Analyze Message Sends",
            "Analyze inline objc_msgSend calls, including applying call type adjustments and resolving to direct calls (if enabled)",
        ).eligibility(
            activity::Eligibility::auto().predicate(
                activity::ViewType::in_(["Mach-O", "DSCView"]),
        )),
        run(activities::objc_msg_send_calls::process),
    );

    let inline_stubs_activity = Activity::new_with_action(
        activity::Config::action(
            "core.function.objectiveC.inlineStubs",
            "Obj-C: Inline Message Send Stubs",
            "Inline Objective-C selector stubs, such as _objc_msgSend$foo, into their callers",
        )
        .eligibility(
            activity::Eligibility::without_setting()
                // The shared cache view does its own inlining of stub functions.
                .predicate(activity::ViewType::in_(["Mach-O"])),
        ),
        run(activities::inline_stubs::process),
    );

    let super_init_activity = Activity::new_with_action(
        activity::Config::action(
            "core.function.objectiveC.types.superInit",
            "Obj-C: Adjust return types of [super init…] calls",
            "Adjust the return type of calls to objc_msgSendSuper2 where the selector is in the init family.",
        )
        .eligibility(
            activity::Eligibility::auto().predicate(
                activity::ViewType::in_(["Mach-O", "DSCView"]),
        )),
        run(activities::super_init::process),
    );

    let remove_memory_management_activity = Activity::new_with_action(
        activity::Config::action(
            "core.function.objectiveC.removeMemoryManagement",
            "Obj-C: Remove reference counting calls",
            "Remove calls to objc_retain / objc_release / objc_autorelease to simplify the resulting higher-level ILs",
        )
        .eligibility(
            activity::Eligibility::auto_with_default(false).matching_all_predicates(&[
                activity::ViewType::in_(["Mach-O", "DSCView"]).into(),
                activity::Platform::in_(["mac-aarch64", "ios-aarch64"]).into()
            ])
        ),
        run(activities::remove_memory_management::process),
    );

    workflow
        .activity_after(&inline_stubs_activity, "core.function.translateTailCalls")?
        .activity_after(&objc_msg_send_calls_activity, &inline_stubs_activity.name())?
        .activity_before(
            &remove_memory_management_activity,
            "core.function.generateMediumLevelIL",
        )?
        .activity_after(&super_init_activity, "core.function.generateMediumLevelIL")?
        .register()?;

    Ok(())
}
