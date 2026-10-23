//! Rust architecture hook plugin that annotates ARM/thumb writes to PRIMASK

use binaryninja::architecture::{
    register_architecture_hook, Architecture, ArchitectureHook, CoreArchitecture,
};
use binaryninja::disassembly::{InstructionTextToken, InstructionTextTokenKind};
use binaryninja::logger::{bn_log, BnLogLevel};
use std::ffi::c_void;
use std::ptr::NonNull;

struct InterruptHook;

impl ArchitectureHook for InterruptHook {
    fn instruction_text_with_context(
        &self,
        base: &CoreArchitecture,
        data: &[u8],
        addr: u64,
        _context: Option<NonNull<c_void>>,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        let (length, mut tokens) = base.instruction_text(data, addr)?;
        if tokens.first().is_some_and(|token| token.text == "msr")
            && tokens.get(2).is_some_and(|token| token.text == "primask")
        {
            tokens.push(InstructionTextToken::new(
                " ; Toggling interrupts",
                InstructionTextTokenKind::Annotation,
            ));
        }
        Some((length, tokens))
    }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "C" fn CorePluginDependencies() {
    binaryninja::add_required_plugin_dependency("arch_armv7");
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "C" fn CorePluginInit() -> bool {
    let Some(thumb2) = CoreArchitecture::by_name("thumb2") else {
        bn_log(
            "interrupts_arch_hook",
            BnLogLevel::ErrorLog,
            "thumb2 architecture unavailable",
        );
        return false;
    };
    register_architecture_hook(thumb2, InterruptHook);
    bn_log(
        "interrupts_arch_hook",
        BnLogLevel::InfoLog,
        "Registered Rust interrupt annotation hook on thumb2",
    );
    true
}
