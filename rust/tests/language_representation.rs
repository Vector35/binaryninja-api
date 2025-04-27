use std::path::PathBuf;

use binaryninja::architecture::CoreArchitecture;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::disassembly::{
    DisassemblySettings, DisassemblyTextLine, InstructionTextToken, InstructionTextTokenKind,
};
use binaryninja::function::Function;
use binaryninja::headless::Session;
use binaryninja::high_level_il::token_emitter::HighLevelILTokenEmitter;
use binaryninja::high_level_il::{HighLevelILFunction, HighLevelInstructionIndex};
use binaryninja::language_representation::{
    register_language_representation_function_type, CoreLanguageRepresentationFunction,
    CoreLanguageRepresentationFunctionType, LanguageRepresentationFunction,
    LanguageRepresentationFunctionType, OperatorPrecedence,
};
use binaryninja::rc::Ref;

struct MyLangReprType {
    core: CoreLanguageRepresentationFunctionType,
}

impl LanguageRepresentationFunctionType for MyLangReprType {
    fn create(
        &self,
        arch: &CoreArchitecture,
        func: &Function,
        high_level_il: &HighLevelILFunction,
    ) -> Ref<CoreLanguageRepresentationFunction> {
        CoreLanguageRepresentationFunction::new(
            &self.core,
            MyLangRepr {},
            arch,
            func,
            high_level_il,
        )
    }

    fn is_valid(&self, _view: &BinaryView) -> bool {
        true
    }

    fn function_type_tokens(
        &self,
        _func: &Function,
        _settings: &DisassemblySettings,
    ) -> Vec<DisassemblyTextLine> {
        todo!()
    }
}

unsafe impl Send for MyLangReprType {}
unsafe impl Sync for MyLangReprType {}

struct MyLangRepr;

impl LanguageRepresentationFunction for MyLangRepr {
    fn on_token_emitter_init(&self, _tokens: &HighLevelILTokenEmitter) {}

    fn expr_text(
        &self,
        il: &HighLevelILFunction,
        expr_index: HighLevelInstructionIndex,
        tokens: &HighLevelILTokenEmitter,
        _settings: &DisassemblySettings,
        _as_full_ast: bool,
        _precedence: OperatorPrecedence,
        _statement: bool,
    ) {
        let instr = il.instruction_from_expr_index(expr_index).unwrap();
        let instr = instr.lift();
        use binaryninja::high_level_il::HighLevelILLiftedInstructionKind::*;
        match &instr.kind {
            Block(block) => {
                tokens.append(InstructionTextToken::new(
                    format!("block {}\n", block.body.len()),
                    InstructionTextTokenKind::Text,
                ));
                for block_inst in &block.body {
                    self.expr_text(
                        il,
                        block_inst.expr_index,
                        tokens,
                        _settings,
                        _as_full_ast,
                        _precedence,
                        _statement,
                    );
                }
            }
            Unimpl | Unreachable | Undef => panic!(),
            _kind => {
                tokens.append(InstructionTextToken::new(
                    format!("other instr {:x}\n", instr.address),
                    InstructionTextTokenKind::Text,
                ));
            }
        }
    }

    fn begin_lines(
        &self,
        _il: &HighLevelILFunction,
        _expr_index: HighLevelInstructionIndex,
        _tokens: &HighLevelILTokenEmitter,
    ) {
    }

    fn end_lines(
        &self,
        _il: &HighLevelILFunction,
        _expr_index: HighLevelInstructionIndex,
        _tokens: &HighLevelILTokenEmitter,
    ) {
    }

    fn comment_start_string(&self) -> &str {
        "/* "
    }

    fn comment_end_string(&self) -> &str {
        " */"
    }

    fn annotation_start_string(&self) -> &str {
        "{"
    }

    fn annotation_end_string(&self) -> &str {
        "}"
    }
}

#[test]
fn test_custom_language_representation() {
    const LANG_REPR_NAME: &str = "test_lang_repr";
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();

    let my_repr = register_language_representation_function_type(
        |core| MyLangReprType { core },
        LANG_REPR_NAME,
    );
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let func = view
        .function_at(&view.default_platform().unwrap(), 0x36760)
        .unwrap();
    let _repr = my_repr.create(&func);
    let il = func.high_level_il(false).unwrap();

    let settings = DisassemblySettings::new();
    let root_idx = il.root_instruction_index();
    let result = _repr.linear_lines(&il, root_idx, &settings, false);
    let output: String = result.iter().map(|dis| dis.to_string()).collect();
    assert_eq!(
        format!("{output}"),
        "block 26
other instr 36775
other instr 3679e
other instr 3679e
other instr 367ba
other instr 367e6
other instr 3682f
other instr 3682f
other instr 36834
other instr 3683e
other instr 3684e
other instr 36867
other instr 36881
other instr 36881
other instr 36881
other instr 36896
other instr 368a0
other instr 368bb
other instr 368d2
other instr 3694a
other instr 36960
other instr 369e1
other instr 369ec
other instr 36a2e
other instr 36ab5
other instr 36abd
other instr 36ac2
"
    );
}
