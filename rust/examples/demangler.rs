use binaryninja::architecture::{ArchitectureExt, CoreArchitecture};
use binaryninja::demangle::{CustomDemangler, Demangler, DemanglerConfig, DemanglerResult};
use binaryninja::tracing::TracingLogListener;
use binaryninja::types::{QualifiedName, Type};

struct TestDemangler;

impl CustomDemangler for TestDemangler {
    fn is_mangled_string(&self, name: &str) -> bool {
        name == "test_name" || name == "test_name2"
    }

    fn demangle(&self, name: &str, _config: &DemanglerConfig) -> Option<DemanglerResult> {
        match name {
            "test_name" => Some(DemanglerResult::new(
                QualifiedName::from(vec!["test_name"]),
                Some(Type::bool()),
            )),
            "test_name2" => Some(DemanglerResult::new(
                QualifiedName::from(vec!["test_name2", "aaa"]),
                None,
            )),
            _ => None,
        }
    }
}

fn main() {
    tracing_subscriber::fmt::init();
    let _listener = TracingLogListener::new().register();

    tracing::info!("Registering demangler...");
    assert!(Demangler::register("Test", TestDemangler));

    // This loads all the core architecture, platform, etc plugins
    let _headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    let placeholder_arch = CoreArchitecture::by_name("x86_64").expect("x86 exists");
    let platform = placeholder_arch
        .standalone_platform()
        .expect("x86 standalone platform exists");
    let config = DemanglerConfig::for_platform(&platform, false);

    for d in Demangler::list().iter() {
        tracing::info!("{}", d.name());

        tracing::info!(
            "  \"__ZN1AC2Ei\" is mangled? {}",
            d.is_mangled_string("__ZN1AC2Ei")
        );
        tracing::info!("  \"__ZN1AC2Ei\" : {:?}", d.demangle("__ZN1AC2Ei", &config));
        tracing::info!("  \"test_name\" : {:?}", d.demangle("test_name", &config));
        tracing::info!("  \"test_name2\" : {:?}", d.demangle("test_name2", &config));
    }
}
