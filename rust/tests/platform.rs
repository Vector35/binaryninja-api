use binaryninja::headless::Session;
use binaryninja::platform::Platform;

#[test]
fn test_platform_lifetime() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform_0 = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let platform_types_0 = platform_0.types();
    let platform_1 = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let platform_types_1 = platform_1.types();
    assert_eq!(platform_types_0.len(), platform_types_1.len());
    assert_ne!(platform_types_1.len(), 0);
}

#[test]
fn test_platform_types() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let platform_types = platform.types();
    // windows-x86_64 has a few thousand, not zero.
    assert_ne!(platform_types.len(), 0);
}

#[test]
fn test_platform_calling_conventions() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    assert_eq!(platform.calling_conventions().len(), 1);
}
