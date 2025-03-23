use binaryninja::headless::Session;

// TODO: Add a test for MainThreadHandler

#[test]
fn test_not_main_thread() {
    // We should never be the main thread.
    assert!(!binaryninja::is_main_thread())
}

#[test]
fn test_main_thread_different() {
    let _session = Session::new().expect("Failed to initialize session");
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
