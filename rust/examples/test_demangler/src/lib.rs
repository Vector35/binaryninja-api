use log::{info, LevelFilter};
use binaryninja::architecture::CoreArchitecture;
use binaryninja::binaryview::BinaryView;
use binaryninja::command;
use binaryninja::command::Command;
use binaryninja::demangle::{Demangler, CustomDemangler};
use binaryninja::logger::Logger;
use binaryninja::rc::Ref;
use binaryninja::types::{QualifiedName, Type};

struct TestDemangler;

impl CustomDemangler for TestDemangler {
    fn is_mangled_string(&self, name: &str) -> bool {
        name == "test_name" || name == "test_name2"
    }

    fn demangle(&self, _arch: &CoreArchitecture, name: &str, _view: Option<Ref<BinaryView>>) -> Result<(Option<Ref<Type>>, QualifiedName), ()> {
        match name {
            "test_name" => Ok((Some(Type::bool()), QualifiedName::from(vec!["test_name"]))),
            "test_name2" => Ok((None, QualifiedName::from(vec!["test_name2", "aaa"]))),
            _ => Err(()),
        }

    }
}

struct DemangleCommand;

impl Command for DemangleCommand {
    fn action(&self, view: &BinaryView) {
        for d in Demangler::list().iter() {
            info!("{}", d.name());

            info!("{}", d.is_mangled_string("__ZN1AC2Ei"));
            info!("{:?}", d.demangle(
                &CoreArchitecture::by_name("x86_64").expect("x86 exists"),
                "__ZN1AC2Ei",
                Some(view)
            ));
            info!("{:?}", d.demangle(
                &CoreArchitecture::by_name("x86_64").expect("x86 exists"),
                "test_name",
                None
            ));
            info!("{:?}", d.demangle(
                &CoreArchitecture::by_name("x86_64").expect("x86 exists"),
                "test_name2",
                None
            ));
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("Demangle Test").with_level(LevelFilter::Info).init();
    Demangler::register("Test", TestDemangler {});
    command::register("Demangle Test", "Test", DemangleCommand {});
    true
}
