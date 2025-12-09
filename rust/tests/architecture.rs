use binaryninja::architecture::{Architecture, CoreArchitecture};
use binaryninja::disassembly::{
    InstructionTextToken, InstructionTextTokenContext, InstructionTextTokenKind,
};
use binaryninja::headless::Session;

#[test]
fn test_architecture_info() {
    let _session = Session::new().expect("Failed to initialize session");
    let arch = CoreArchitecture::by_name("x86_64").expect("Failed to get architecture");
    assert_eq!(arch.name(), "x86_64");
    assert_eq!(arch.endianness(), binaryninja::Endianness::LittleEndian);
    assert_eq!(arch.address_size(), 8);
}

#[test]
fn test_architecture_disassembly() {
    let _session = Session::new().expect("Failed to initialize session");
    let arch = CoreArchitecture::by_name("x86_64").expect("Failed to get architecture");

    // mov rax, 0x10
    let data = b"\x48\xC7\xC0\x10\x00\x00\x00";
    let address = 0x1000;

    let (instr_len, tokens) = arch
        .instruction_text(data, address)
        .expect("Failed to disassemble instruction");
    assert_eq!(instr_len, 7);

    let expected_tokens: Vec<InstructionTextToken> = vec![
        InstructionTextToken {
            address: 0,
            text: "mov".to_string(),
            confidence: 255,
            context: InstructionTextTokenContext::Normal,
            expr_index: None,
            kind: InstructionTextTokenKind::Instruction,
        },
        InstructionTextToken {
            address: 0,
            text: "     ".to_string(),
            confidence: 255,
            context: InstructionTextTokenContext::Normal,
            expr_index: None,
            kind: InstructionTextTokenKind::Text,
        },
        InstructionTextToken {
            address: 0,
            text: "rax".to_string(),
            confidence: 255,
            context: InstructionTextTokenContext::Normal,
            expr_index: None,
            kind: InstructionTextTokenKind::Register,
        },
        InstructionTextToken {
            address: 0,
            text: ", ".to_string(),
            confidence: 255,
            context: InstructionTextTokenContext::Normal,
            expr_index: None,
            kind: InstructionTextTokenKind::OperandSeparator,
        },
        InstructionTextToken {
            address: 0,
            text: "0x10".to_string(),
            confidence: 255,
            context: InstructionTextTokenContext::Normal,
            expr_index: None,
            kind: InstructionTextTokenKind::PossibleAddress {
                value: 16,
                size: Some(8),
            },
        },
    ];

    assert_eq!(tokens, expected_tokens);
}
