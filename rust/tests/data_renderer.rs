use std::path::PathBuf;

use binaryninja::binary_view::BinaryView;
use binaryninja::data_renderer::{
    register_specific_data_renderer, CustomDataRenderer, TypeContext,
};
use binaryninja::disassembly::{
    DisassemblyTextLine, InstructionTextToken, InstructionTextTokenKind,
};
use binaryninja::types::Type;

#[test]
fn test_data_renderer_basic() {
    struct StructRenderer {}
    impl CustomDataRenderer for StructRenderer {
        fn is_valid_for_data(
            &self,
            _view: &BinaryView,
            _addr: u64,
            type_: &Type,
            _types: &[TypeContext],
        ) -> bool {
            type_.get_structure().is_some()
        }

        fn lines_for_data(
            &self,
            _view: &BinaryView,
            addr: u64,
            type_: &Type,
            _prefix: &InstructionTextToken,
            _prefix_count: usize,
            width: usize,
            _types_ctx: &[TypeContext],
            _language: &str,
        ) -> Vec<DisassemblyTextLine> {
            let name = type_.registered_name().map(|name| name.name().to_string());
            let Some(type_) = type_.get_structure() else {
                unreachable!();
            };

            let mut output = vec![
                DisassemblyTextLine::new(vec![InstructionTextToken::new(
                    format!(
                        "Struct{}{} width {} or {width} {addr}",
                        name.as_ref().map(|_| " ").unwrap_or(""),
                        name.as_ref().map(String::as_str).unwrap_or(""),
                        type_.width()
                    ),
                    InstructionTextTokenKind::Comment { target: addr },
                )]),
                DisassemblyTextLine::new(vec![InstructionTextToken::new(
                    "{",
                    InstructionTextTokenKind::Text,
                )]),
            ];
            let members = type_.members();
            let offset_size =
                usize::try_from(members.last().map(|last| last.offset.ilog(16)).unwrap_or(0) + 3)
                    .unwrap();
            for member in members {
                let line = [
                    InstructionTextToken::new(
                        format!("{:#0width$x}", member.offset, width = offset_size),
                        InstructionTextTokenKind::StructOffset {
                            offset: member.offset,
                            type_names: vec![member.name.clone()],
                        },
                    ),
                    InstructionTextToken::new("|", InstructionTextTokenKind::Text),
                    InstructionTextToken::new(
                        member.name.clone(),
                        InstructionTextTokenKind::FieldName {
                            offset: member.offset,
                            type_names: vec![member.name.clone()],
                        },
                    ),
                    InstructionTextToken::new(",", InstructionTextTokenKind::Text),
                ];
                output.push(DisassemblyTextLine::new(line.to_vec()));
            }
            output.push(DisassemblyTextLine::new(vec![InstructionTextToken::new(
                "}",
                InstructionTextTokenKind::Text,
            )]));
            output
        }
    }

    let _renderer = register_specific_data_renderer(StructRenderer {});
    // TODO render a Type
}
