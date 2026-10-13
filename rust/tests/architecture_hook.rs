//! Hook registration is permanent, so these checks run in a separate integration-test process.
use binaryninja::architecture::{
    register_architecture_hook, Architecture, ArchitectureHook, CoreArchitecture,
};
use binaryninja::disassembly::{InstructionTextToken, InstructionTextTokenKind};
use binaryninja::headless::Session;
use std::ffi::c_void;
use std::ptr::NonNull;

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

#[test]
fn test_architecture_hook() {
    let _session = Session::new().expect("Failed to initialize session");
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
