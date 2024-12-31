use binaryninja::architecture::CoreArchitecture;
use binaryninja::binaryview::BinaryView;
use binaryninja::demangle::{CustomDemangler, Demangler};
use binaryninja::rc::Ref;
use binaryninja::types::{QualifiedName, Type};

struct TestDemangler;

impl CustomDemangler for TestDemangler {
    fn is_mangled_string(&self, name: &str) -> bool {
        name == "test_name" || name == "test_name2"
    }

    fn demangle(
        &self,
        _arch: &CoreArchitecture,
        name: &str,
        _view: Option<Ref<BinaryView>>,
    ) -> Result<(Option<Ref<Type>>, QualifiedName), ()> {
        match name {
            "test_name" => Ok((Some(Type::bool()), QualifiedName::from(vec!["test_name"]))),
            "test_name2" => Ok((None, QualifiedName::from(vec!["test_name2", "aaa"]))),
            _ => Err(()),
        }
    }
}

fn main() {
    println!("Starting session...");
    // This loads all the core architecture, platform, etc plugins
    let _headless_session = binaryninja::headless::Session::new();

    println!("Registering demangler...");
    Demangler::register("Test", TestDemangler);

    let placeholder_arch = CoreArchitecture::by_name("x86_64").expect("x86 exists");

    for d in Demangler::list().iter() {
        println!("{}", d.name());

        println!("  \"__ZN1AC2Ei\" is mangled? {}", d.is_mangled_string("__ZN1AC2Ei"));
        println!("  \"__ZN1AC2Ei\" : {:?}", d.demangle(&placeholder_arch, "__ZN1AC2Ei", None));
        println!("  \"test_name\" : {:?}", d.demangle(&placeholder_arch, "test_name", None));
        println!("  \"test_name2\" : {:?}", d.demangle(&placeholder_arch, "test_name2", None));
    }
}
