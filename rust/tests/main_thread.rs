use binaryninja::headless::Session;
use rstest::*;

// TODO: Add a test for MainThreadHandler

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_not_main_thread(_session: &Session) {
    // We should never be the main thread.
    assert!(!binaryninja::is_main_thread())
}

#[rstest]
fn test_main_thread_different(_session: &Session) {
    let calling_thread = std::thread::current();
    binaryninja::main_thread::execute_on_main_thread_and_wait(move || {
        let main_thread = std::thread::current();
        assert_ne!(
            calling_thread.id(),
            main_thread.id(),
            "Expected calling thread to be the different from the main thread"
        )
    });
}
