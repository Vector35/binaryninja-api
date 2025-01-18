use binaryninja::headless::Session;
use rstest::*;
use std::sync::{Arc, Barrier};

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_setting_worker_thread(_session: &Session) {
    let original_count = binaryninja::worker_thread::worker_thread_count();
    binaryninja::worker_thread::set_worker_thread_count(original_count - 1);
    assert_eq!(
        binaryninja::worker_thread::worker_thread_count(),
        original_count - 1
    );
    binaryninja::worker_thread::set_worker_thread_count(original_count);
    assert_eq!(
        binaryninja::worker_thread::worker_thread_count(),
        original_count
    );
}

#[rstest]
fn test_worker_thread_different(_session: &Session) {
    let calling_thread = std::thread::current();

    // We need both (2) threads to synchronize
    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = Arc::clone(&barrier);
    binaryninja::worker_thread::execute_on_worker_thread("test", move || {
        let worker_thread = std::thread::current();
        assert_ne!(
            calling_thread.id(),
            worker_thread.id(),
            "Expected calling thread to be different from the worker thread"
        );
        barrier_clone.wait();
    });

    // Wait until worker thread has finished.
    barrier.wait();
}
