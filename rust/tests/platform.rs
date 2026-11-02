use binaryninja::architecture::{ArchitectureExt, CoreArchitecture};
use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::types::Type;

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
fn test_platform_function_by_name() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    let platform_functions = platform.functions();
    assert_ne!(platform_functions.len(), 0);

    let function = platform_functions.get(0);
    assert!(platform.function_by_name(function.name, true).is_some());
}

#[test]
fn test_platform_calling_conventions() {
    let _session = Session::new().expect("Failed to initialize session");
    let platform = Platform::by_name("windows-x86_64").expect("windows-x86_64 exists");
    assert_eq!(platform.calling_conventions().len(), 1);
}

#[test]
fn test_platform_register_calling_convention() {
    let _session = Session::new().expect("Failed to initialize session");
    let arch = CoreArchitecture::by_name("x86_64").expect("x86_64 exists");
    let platform = Platform::new(&arch, "test-register-cc-x86_64");
    assert_eq!(platform.calling_conventions().len(), 0);

    let cc = arch
        .calling_convention_by_name("win64")
        .expect("win64 calling convention exists");
    platform.register_calling_convention(&cc);

    let calling_conventions = platform.calling_conventions();
    assert_eq!(calling_conventions.len(), 1);
    assert_eq!(calling_conventions.get(0).name(), "win64");
}

#[test]
fn test_syscall_namespaces() {
    let _session = Session::new().expect("Failed to initialize session");
    let arch = CoreArchitecture::by_name("x86_64").unwrap();
    let p = Platform::new(&arch, "test-syscall-namespaces");
    let os = arch.calling_convention_by_name("win64").unwrap();
    let hyper = arch.calling_convention_by_name("sysv").unwrap();
    assert_eq!(p.syscall_namespaces().len(), 1);
    assert_eq!(p.syscall_namespaces()[0].name, "default");
    p.set_syscall_convention(&os);
    assert_eq!(
        p.syscall_convention_in_namespace(0).unwrap().name(),
        "win64"
    );
    assert!(p.set_syscall_convention_in_namespace(0, Some(&hyper)));
    assert_eq!(p.get_syscall_convention().unwrap().name(), "sysv");
    assert!(p.register_syscall_namespace(1, "hypervisor", Some(&hyper)));
    assert!(p.register_syscall_namespace(2, "monitor", Some(&os)));
    assert!(!p.register_syscall_namespace(0, "duplicate", None));
    assert!(!p.register_syscall_namespace(1, "duplicate", None));
    assert!(!p.register_syscall_namespace(3, "monitor", None));
    assert!(!p.set_syscall_convention_in_namespace(999, None));
    let snapshot = p.syscall_namespaces();
    assert!(p.set_syscall_convention_in_namespace(1, None));
    assert_eq!(
        snapshot[1].calling_convention.as_ref().unwrap().name(),
        "sysv"
    );
    assert!(p.syscall_convention_in_namespace(1).is_none());
    assert!(p.calling_conventions().is_empty());
}

#[test]
fn test_namespaced_syscall_services() {
    let _session = Session::new().expect("Failed to initialize session");
    let arch = CoreArchitecture::by_name("x86_64").unwrap();
    let p = Platform::new(&arch, "test-syscall-namespace-services");
    assert!(p.register_syscall_namespace(1, "hypervisor", None));
    assert!(p.register_syscall_namespace(2, "monitor", None));
    let small = Type::function(Type::int(4, false), vec![], false);
    let large = Type::function(Type::int(8, false), vec![], false);
    assert!(p.define_syscall_in_namespace(0, 7, "os_service", &small));
    assert!(p.define_syscall_in_namespace(1, 7, "hyper_service", &large));
    assert!(p.define_syscall_in_namespace(2, 7, "monitor_service", &small));
    assert_eq!(
        p.syscall_name_in_namespace(0, 7).to_string_lossy(),
        "os_service"
    );
    assert_eq!(
        p.syscall_name_in_namespace(1, 7).to_string_lossy(),
        "hyper_service"
    );
    assert_eq!(
        p.syscall_name_in_namespace(2, 7).to_string_lossy(),
        "monitor_service"
    );
    assert_eq!(p.syscall_type_in_namespace(1, 7).unwrap(), large);
    assert_eq!(p.syscalls_in_namespace(1).len(), 1);
    assert!(p.syscall_name_in_namespace(999, 7).to_bytes().is_empty());
    assert!(p.syscall_type_in_namespace(999, 7).is_none());
    assert!(p.syscalls_in_namespace(999).is_empty());
    assert!(!p.define_syscall_in_namespace(999, 7, "invalid", &small));
    assert!(!p.define_syscall_in_namespace(1, 7, "invalid", &Type::int(4, false)));
    assert!(p.define_syscall_in_namespace(1, 7, "updated", &small));
    assert_eq!(p.syscall_type_in_namespace(1, 7).unwrap(), small);
}

#[test]
fn test_declarative_exception_models() {
    use binaryninja::platform::{
        ExceptionContinuation::*, ExceptionModel, ExceptionModelKind::*, ExceptionModelRule,
    };
    let _session = Session::new().expect("Failed to initialize session");
    let arch = CoreArchitecture::by_name("x86_64").unwrap();
    let platform = Platform::new(&arch, "test-exception-models");
    assert!(platform.register_syscall_namespace(1, "hypervisor", None));
    let kind = 2u64 << 32;
    let mask = 0xffffffff00000000;
    assert!(platform.exception_model(kind | 7).is_none());
    assert!(platform.set_exception_model(ExceptionModelRule {
        discriminator: kind,
        mask,
        model: ExceptionModel {
            kind: SystemCallExceptionModel,
            nameSpace: 1,
            continuation: ContinueAfterException
        },
    }));
    assert_eq!(platform.exception_model(kind | 7).unwrap().nameSpace, 1);
    assert!(platform.set_exception_model(ExceptionModelRule {
        discriminator: kind | 7,
        mask: u64::MAX,
        model: ExceptionModel {
            kind: TrapExceptionModel,
            nameSpace: 0,
            continuation: TerminateAfterException
        },
    }));
    assert_eq!(
        platform.exception_model(kind | 7).unwrap().kind,
        TrapExceptionModel
    );
    let snapshot = platform.exception_models();
    assert_eq!(snapshot.len(), 2);
    assert!(platform.remove_exception_model(kind | 7, u64::MAX));
    assert_eq!(
        platform.exception_model(kind | 7).unwrap().kind,
        SystemCallExceptionModel
    );
    assert_eq!(snapshot.len(), 2);
}

#[test]
fn test_exception_display_registry_owns_names_and_preserves_models() {
    use binaryninja::platform::{ExceptionDisplay, ExceptionDisplayRule};
    let _session = Session::new().expect("Failed to initialize session");
    let arch = CoreArchitecture::by_name("x86_64").unwrap();
    let p = Platform::new(&arch, "test-exception-displays");
    let event = (2u64 << 32) | 7;
    assert!(p.exception_display(event).is_none());
    let broad = ExceptionDisplayRule {
        discriminator: 2u64 << 32,
        mask: 0xffffffff00000000,
        display: ExceptionDisplay {
            name: "hvc".into(),
            value_mask: Some(0xffff),
            value_shift: 0,
        },
    };
    assert!(p.set_exception_display(&broad));
    let exact = ExceptionDisplayRule {
        discriminator: event,
        mask: u64::MAX,
        display: ExceptionDisplay {
            name: "warn_once".into(),
            value_mask: None,
            value_shift: 0,
        },
    };
    assert!(p.set_exception_display(&exact));
    let snapshot = p.exception_displays();
    let resolved = p.exception_display(event).unwrap();
    assert_eq!(resolved, exact.display);
    assert!(p.remove_exception_display(event, u64::MAX));
    assert_eq!(p.exception_display(event).unwrap(), broad.display);
    assert_eq!(snapshot[0].display, exact.display);
    assert_eq!(resolved, exact.display);
    assert!(p.exception_model(event).is_none());
    let invalid = ExceptionDisplayRule {
        display: ExceptionDisplay {
            name: "bad\0name".into(),
            value_mask: None,
            value_shift: 0,
        },
        ..exact
    };
    assert!(!p.set_exception_display(&invalid));
}

#[test]
fn test_exception_convention_eligibility() {
    let _session = Session::new().expect("Failed to initialize session");
    let arch = CoreArchitecture::by_name("armv7").unwrap();
    let smccc = arch.calling_convention_by_name("smccc32").unwrap();
    assert!(arch.is_exception_calling_convention_eligible(&smccc, 2 << 32));
    assert!(arch.is_exception_calling_convention_eligible(&smccc, 3 << 32));
    assert!(!arch.is_exception_calling_convention_eligible(&smccc, (2 << 32) | 7));
    assert!(!arch.is_exception_calling_convention_eligible(&smccc, 1 << 32));
    let conventions = arch.eligible_exception_calling_conventions(2 << 32);
    assert_eq!(conventions.len(), 1);
    assert_eq!(conventions.get(0).name(), "smccc32");
    let event = 0xfedcba9800000000;
    assert!(arch.register_exception_calling_convention(&smccc, event, u64::MAX));
    let snapshot = arch.eligible_exception_calling_conventions(event);
    assert!(arch.unregister_exception_calling_convention(&smccc, event, u64::MAX));
    assert!(!arch.is_exception_calling_convention_eligible(&smccc, event));
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot.get(0).name(), "smccc32");
}
