use binaryninja::background_task::*;
use binaryninja::headless::Session;
use rstest::*;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_background_task_registered(_session: &Session) {
    let task_progress = "test registered";
    let task = BackgroundTask::new(task_progress, false);
    BackgroundTask::running_tasks()
        .iter()
        .find(|t| t.progress_text().as_str() == task_progress)
        .expect("Task not running");
    task.finish();
    let still_running = BackgroundTask::running_tasks()
        .iter()
        .find(|t| t.progress_text().as_str() == task_progress)
        .is_some();
    assert!(!still_running, "Task still running");
}

#[rstest]
fn test_background_task_cancellable(_session: &Session) {
    let task_progress = "test cancellable";
    let task = BackgroundTask::new(task_progress, false);
    BackgroundTask::running_tasks()
        .iter()
        .find(|t| t.progress_text().as_str() == task_progress)
        .expect("Task not running");
    task.cancel();
    assert!(task.is_cancelled());
    task.finish();
}

#[rstest]
fn test_background_task_progress(_session: &Session) {
    let task = BackgroundTask::new("test progress", false);
    let first_progress = task.progress_text().to_string();
    assert_eq!(first_progress, "test progress");
    task.set_progress_text("new progress");
    let second_progress = task.progress_text().to_string();
    assert_eq!(second_progress, "new progress");
    task.finish();
}
