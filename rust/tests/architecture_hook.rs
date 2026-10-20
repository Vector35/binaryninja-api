//! Hooks permanently modify global architectures. Run all regressions sequentially in one session.
use binaryninja::architecture::{
    register_architecture_hook, Architecture, ArchitectureHook, CoreArchitecture, CoreFlag,
    CoreFlagWrite, CoreRegister, Flag, FlagWrite, Intrinsic, IntrinsicId,
};
use binaryninja::disassembly::{InstructionTextToken, InstructionTextTokenKind};
use binaryninja::headless::Session;
use binaryninja::low_level_il::expression::ValueExpr;
use binaryninja::low_level_il::lifting::LowLevelILFlagWriteOp;
use binaryninja::low_level_il::{LowLevelILMutableExpression, LowLevelILMutableFunction};
use binaryninjacore_sys::*;
use std::ffi::{c_void, CString};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn test_architecture_hook() {
    let _session = Session::new().expect("Failed to initialize session");
    check_instruction_text();
    check_floating_point_flags();
    check_intrinsic_class_override();
    check_associated_arch_by_addr();
}

struct AddressHook;

impl ArchitectureHook for AddressHook {
    fn associated_arch_by_addr(&self, base: &CoreArchitecture, addr: &mut u64) -> CoreArchitecture {
        *addr += 0x1000;
        let arch = base.associated_arch_by_addr(addr);
        *addr += 0x2000;
        arch
    }
}

fn check_associated_arch_by_addr() {
    let arch = CoreArchitecture::by_name("armv7").expect("Failed to get architecture");
    let mut address = 0x1001;
    assert_eq!(arch.associated_arch_by_addr(&mut address).name(), "thumb2");
    assert_eq!(address, 0x1000);

    register_architecture_hook(arch, AddressHook);
    let mut address = 0x1001;
    assert_eq!(arch.associated_arch_by_addr(&mut address).name(), "thumb2");
    assert_eq!(address, 0x4000);

    register_architecture_hook(arch, PassThroughHook);
    let mut address = 0x1001;
    assert_eq!(arch.associated_arch_by_addr(&mut address).name(), "thumb2");
    assert_eq!(address, 0x4000);
}

struct TextHook;

impl ArchitectureHook for TextHook {
    fn instruction_text(
        &self,
        _base: &CoreArchitecture,
        _data: &[u8],
        _addr: u64,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        Some((
            1,
            vec![InstructionTextToken::new(
                "hooked",
                InstructionTextTokenKind::Text,
            )],
        ))
    }

    fn instruction_text_with_context(
        &self,
        base: &CoreArchitecture,
        data: &[u8],
        addr: u64,
        _context: Option<NonNull<c_void>>,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        self.instruction_text(base, data, addr)
    }
}

struct PassThroughHook;
impl ArchitectureHook for PassThroughHook {}

fn check_instruction_text() {
    let arch = CoreArchitecture::by_name("x86_64").expect("Failed to get architecture");
    let data = [0x90]; // nop
    let address = 0x1000;
    let original = arch.instruction_text(&data, address).unwrap();
    let expected = Some((
        1,
        vec![InstructionTextToken::new(
            "hooked",
            InstructionTextTokenKind::Text,
        )],
    ));
    assert_ne!(Some(original), expected);

    // Match the Python hook regressions: replace text, then stack empty hooks.
    register_architecture_hook(arch, TextHook);
    assert_eq!(arch.instruction_text(&data, address), expected);
    assert_eq!(
        arch.instruction_text_with_context(&data, address, None),
        expected
    );

    register_architecture_hook(arch, PassThroughHook);
    register_architecture_hook(arch, PassThroughHook);
    assert_eq!(arch.instruction_text(&data, address), expected);
    assert_eq!(
        arch.instruction_text_with_context(&data, address, None),
        expected
    );
}

struct TypedFlagHook;
impl ArchitectureHook for TypedFlagHook {
    fn flag_write_llil<'a>(
        &self,
        _base: &CoreArchitecture,
        _flag: CoreFlag,
        _write: CoreFlagWrite,
        _op: LowLevelILFlagWriteOp<CoreRegister>,
        il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>> {
        Some(il.const_int(0, 1))
    }
}

// Compare the full expression, including operand values and sizes, rather than just its root op.
type Expression = (BNLowLevelILOperation, usize, u32, [u64; 4]);

fn flag_write_il(
    arch: CoreArchitecture,
    write: u32,
    flag: u32,
    operation: BNLowLevelILOperation,
) -> (usize, Vec<Expression>) {
    let name = CString::new(arch.name()).unwrap();
    let mut operands = [1.25f64.to_bits(), 2.5f64.to_bits()].map(|value| BNRegisterOrConstant {
        constant: true,
        reg: 0,
        value,
    });
    // Use the core API because LLIL_FSUB has no LowLevelILFlagWriteOp variant.
    unsafe {
        let arch = BNGetArchitectureByName(name.as_ptr());
        let il = BNCreateLowLevelILFunction(arch, std::ptr::null_mut());
        assert!(!il.is_null());
        let root = BNGetArchitectureFlagWriteLowLevelIL(
            arch,
            operation,
            8,
            write,
            flag,
            operands.as_mut_ptr(),
            operands.len(),
            il,
        );
        let expressions = (0..BNGetLowLevelILExprCount(il))
            .map(|index| {
                let expr = BNGetLowLevelILByIndex(il, index);
                (expr.operation, expr.size, expr.flags, expr.operands)
            })
            .collect();
        BNFreeLowLevelILFunction(il);
        (root, expressions)
    }
}

fn check_floating_point_flags() {
    use BNLowLevelILOperation::*;
    for (name, write_name, flags) in [
        (
            "armv7",
            "fcmp",
            vec![("n", LLIL_FCMP_LT), ("v", LLIL_FCMP_UO)],
        ),
        (
            "x86",
            "vcomi",
            vec![("s", LLIL_CONST), ("o", LLIL_CONST), ("a", LLIL_CONST)],
        ),
        (
            "x86_64",
            "vcomi",
            vec![("s", LLIL_CONST), ("o", LLIL_CONST), ("a", LLIL_CONST)],
        ),
    ] {
        let arch = CoreArchitecture::by_name(name).unwrap();
        let write = arch
            .flag_write_types()
            .into_iter()
            .find(|write| write.name() == write_name)
            .unwrap()
            .id()
            .0;
        let originals: Vec<_> = flags
            .into_iter()
            .map(|(flag_name, operation)| {
                let flag = arch
                    .flags()
                    .into_iter()
                    .find(|flag| flag.name() == flag_name)
                    .unwrap()
                    .id()
                    .0;
                let original = flag_write_il(arch, write, flag, LLIL_FSUB);
                assert_eq!(original.1[original.0].0, operation, "{name}: {flag_name}");
                (flag, original)
            })
            .collect();

        register_architecture_hook(arch, PassThroughHook);
        for (flag, expected) in &originals {
            assert_eq!(
                flag_write_il(arch, write, *flag, LLIL_FSUB),
                *expected,
                "{name}"
            );
        }

        register_architecture_hook(arch, TypedFlagHook);
        // An unsupported operation delegates through both hooks with its raw arguments intact.
        for (flag, expected) in &originals {
            assert_eq!(
                flag_write_il(arch, write, *flag, LLIL_FSUB),
                *expected,
                "{name}"
            );
        }
        // Supported operations must still call the typed hook override.
        let (root, expressions) = flag_write_il(arch, write, originals[0].0, LLIL_ADD);
        assert_eq!(expressions[root].0, LLIL_CONST);
        assert_eq!(expressions[root].3[0], 1);
    }
}

fn opposite_class(class: BNIntrinsicClass) -> BNIntrinsicClass {
    match class {
        BNIntrinsicClass::GeneralIntrinsicClass => BNIntrinsicClass::MemoryIntrinsicClass,
        BNIntrinsicClass::MemoryIntrinsicClass => BNIntrinsicClass::GeneralIntrinsicClass,
    }
}

#[derive(Default)]
struct IntrinsicClassHook {
    calls: AtomicUsize,
}

impl ArchitectureHook for IntrinsicClassHook {
    fn intrinsic_class(&self, base: &CoreArchitecture, id: IntrinsicId) -> BNIntrinsicClass {
        self.calls.fetch_add(1, Ordering::Relaxed);
        opposite_class(base.intrinsic_class(id))
    }
}

fn check_intrinsic_class_override() {
    for name in ["x86_64", "armv7"] {
        let arch = CoreArchitecture::by_name(name).unwrap();
        let intrinsic = arch.intrinsics().into_iter().next().unwrap();
        let id = intrinsic.id();
        let original = arch.intrinsic_class(id);

        register_architecture_hook(arch, PassThroughHook);
        assert_eq!(arch.intrinsic_class(id), original, "{name}");

        let hook = register_architecture_hook(arch, IntrinsicClassHook::default());
        let calls = hook.calls.load(Ordering::Relaxed);
        assert_eq!(arch.intrinsic_class(id), opposite_class(original), "{name}");
        assert_eq!(hook.calls.load(Ordering::Relaxed), calls + 1, "{name}");
        assert_eq!(intrinsic.class(), opposite_class(original), "{name}");

        // Default forwarding through another hook must retain the override.
        register_architecture_hook(arch, PassThroughHook);
        assert_eq!(arch.intrinsic_class(id), opposite_class(original), "{name}");

        // Delegation should reach the earlier override, so flipping twice restores the class.
        register_architecture_hook(arch, IntrinsicClassHook::default());
        assert_eq!(arch.intrinsic_class(id), original, "{name}");
    }
}
