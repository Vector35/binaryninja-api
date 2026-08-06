use binaryninja::confidence::Conf;
use binaryninja::format_string_resolution_provider::{
    CustomFormatStringResolutionProvider, FormatStringResolutionProvider,
};
use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::types::Type;
use serial_test::serial;

struct TestProvider;

impl CustomFormatStringResolutionProvider for TestProvider {
    fn is_valid(&self, format: &str, platform: Option<&Platform>) -> Option<Vec<Conf<Ref<Type>>>> {
        match format {
            "platform" => {
                let platform = platform?;
                Some(vec![
                    Conf::new(Type::int(platform.address_size(), true), 173),
                    Conf::new(Type::float(8), 91),
                ])
            }
            "empty" => Some(Vec::new()),
            _ => None,
        }
    }
}

#[test]
#[serial]
fn register_list_and_lookup_provider() {
    let _session = Session::new().expect("Failed to initialize session");
    let provider = FormatStringResolutionProvider::register(
        "RustFormatStringResolutionProvider.List",
        TestProvider,
    );
    assert_eq!(provider.name(), "RustFormatStringResolutionProvider.List");

    let provider =
        FormatStringResolutionProvider::by_name("RustFormatStringResolutionProvider.List")
            .expect("registered provider is available by name");
    assert_eq!(provider.name(), "RustFormatStringResolutionProvider.List");
    assert!(FormatStringResolutionProvider::all()
        .iter()
        .any(|candidate| candidate.name() == "RustFormatStringResolutionProvider.List"));
}

#[test]
#[serial]
fn custom_provider_round_trip_preserves_platform_types_and_confidence() {
    let _session = Session::new().expect("Failed to initialize session");
    let provider = FormatStringResolutionProvider::register(
        "RustFormatStringResolutionProvider.RoundTrip",
        TestProvider,
    );
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");

    let types = provider
        .is_valid("platform", Some(&platform))
        .expect("format is valid");
    assert_eq!(types.len(), 2);
    assert_eq!(types[0].contents.width(), platform.address_size() as u64);
    assert_eq!(types[0].confidence, 173);
    assert_eq!(types[1].contents.width(), 8);
    assert_eq!(types[1].confidence, 91);

    assert!(provider
        .is_valid("empty", Some(&platform))
        .expect("empty format is valid")
        .is_empty());
    assert!(provider.is_valid("invalid", Some(&platform)).is_none());
    assert!(provider.is_valid("platform", None).is_none());
}

#[test]
#[serial]
fn native_c_style_provider_is_loaded_in_headless_sessions() {
    let _session = Session::new().expect("Failed to initialize session");
    let provider = FormatStringResolutionProvider::by_name("CStyleFormatString")
        .expect("native C-style provider is loaded without explicit registration");
    let windows = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let linux = Platform::by_name("linux-x86_64").expect("linux-x86_64 exists");

    let windows_types = provider
        .is_valid("%ld", Some(&windows))
        .expect("%ld is a valid Windows format string");
    assert_eq!(windows_types.len(), 1);
    assert_eq!(windows_types[0].contents.width(), 4);
    assert_eq!(windows_types[0].confidence, u8::MAX);

    let linux_types = provider
        .is_valid("%ld", Some(&linux))
        .expect("%ld is a valid Linux format string");
    assert_eq!(linux_types.len(), 1);
    assert_eq!(linux_types[0].contents.width(), 8);
    assert_eq!(linux_types[0].confidence, u8::MAX);
}
