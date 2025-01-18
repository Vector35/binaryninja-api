use binaryninja::architecture::CoreArchitecture;
use binaryninja::binary_view::BinaryView;
use binaryninja::demangle::{
    demangle_generic, demangle_gnu3, demangle_llvm, demangle_ms, CustomDemangler, Demangler,
};
use binaryninja::headless::Session;
use binaryninja::rc::Ref;
use binaryninja::types::{QualifiedName, Type};
use rstest::*;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_demangler_simple(_session: &Session) {
    let placeholder_arch = CoreArchitecture::by_name("x86").expect("x86 exists");
    // Example LLVM-style mangled name
    let llvm_mangled = "_Z3fooi"; // "foo(int)" in LLVM mangling
    let llvm_demangled = demangle_llvm(llvm_mangled, true).unwrap();
    assert_eq!(llvm_demangled, "foo(int)".into());

    // Example GNU-style mangled name
    let gnu_mangled = "_Z3bari"; // "bar(int)" in GNU mangling
    let (gnu_demangled_name, gnu_demangled_type) =
        demangle_gnu3(&placeholder_arch, gnu_mangled, true).unwrap();
    assert_eq!(gnu_demangled_name, "bar".into());
    // TODO: We check the type display because other means include things such as confidence which is hard to get 1:1
    assert_eq!(
        gnu_demangled_type.unwrap().to_string(),
        "int32_t(int32_t)".to_string()
    );

    // Example MSVC-style mangled name
    let msvc_mangled = "?baz@@YAHH@Z"; // "int __cdecl baz(int)" in MSVC mangling
    let (msvc_demangled_name, msvc_demangled_type) =
        demangle_ms(&placeholder_arch, msvc_mangled, true).unwrap();
    assert_eq!(msvc_demangled_name, "baz".into());
    // TODO: We check the type display because other means include things such as confidence which is hard to get 1:1
    assert_eq!(
        msvc_demangled_type.unwrap().to_string(),
        "int32_t __cdecl(int32_t)".to_string()
    );
}

#[rstest]
fn test_custom_demangler(_session: &Session) {
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
        ) -> Option<(QualifiedName, Option<Ref<Type>>)> {
            match name {
                "test_name" => Some((QualifiedName::from(vec!["test_name"]), Some(Type::bool()))),
                "test_name2" => Some((QualifiedName::from(vec!["test_name2", "aaa"]), None)),
                _ => None,
            }
        }
    }

    Demangler::register("Test", TestDemangler);

    let placeholder_arch = CoreArchitecture::by_name("x86_64").expect("x86_64 exists");

    let demangled = demangle_generic(&placeholder_arch, "test_name", None, true).unwrap();
    assert_eq!(
        demangled,
        (QualifiedName::from(vec!["test_name"]), Some(Type::bool()))
    );
    let demangled2 = demangle_generic(&placeholder_arch, "test_name2", None, true).unwrap();
    assert_eq!(
        demangled2,
        (QualifiedName::from(vec!["test_name2", "aaa"]), None)
    );
}
