use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::data_renderer::{
    register_data_renderer, render_lines_for_data, CustomDataRenderer, RegistrationType,
    TypeContext,
};
use binaryninja::disassembly::{
    DisassemblyTextLine, InstructionTextToken, InstructionTextTokenKind,
};
use binaryninja::headless::Session;
use binaryninja::types::Type;
use std::path::PathBuf;

struct StructRenderer {}
impl CustomDataRenderer for StructRenderer {
    const REGISTRATION_TYPE: RegistrationType = RegistrationType::Specific;

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
        _prefix: Vec<InstructionTextToken>,
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

#[test]
fn test_data_renderer_basic() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let _ = register_data_renderer(StructRenderer {});

    // This will use all available data renderers, so we are also verifying that our custom renderer is being used.
    let lines = render_lines_for_data(
        &view,
        0x362e9,
        &view.type_by_name("_ABC").unwrap(),
        vec![],
        100,
        &[],
        None,
    );

    // TODO: This is not really checking all possible issues that could occur with round-tripping.
    // TODO: But it is a good start to just make sure it visually is what we expect.
    let lines_str = lines.iter().map(ToString::to_string).collect::<Vec<_>>();
    assert_eq!(
        lines_str,
        vec![
            "Struct _ABC width 12 or 100 221929",
            "{",
            "0x0|abcA,",
            "0x4|abcB,",
            "0x8|abcC,",
            "}"
        ]
    )
}
