use std::path::PathBuf;

use binaryninja::architecture::CoreArchitecture;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::disassembly::{
    DisassemblySettings, DisassemblyTextLine, InstructionTextToken, InstructionTextTokenKind,
};
use binaryninja::function::Function;
use binaryninja::headless::Session;
use binaryninja::high_level_il::{HighLevelILFunction, HighLevelInstructionIndex};
use binaryninja::language_representation::{
    create_language_representation_function, register_language_representation_function_type,
    register_line_formatter, CoreLanguageRepresentationFunction,
    CoreLanguageRepresentationFunctionType, CoreLineFormatter,
    CustomLanguageRepresentationFunction, CustomLanguageRepresentationFunctionType,
    CustomLineFormater, HighLevelILTokenEmitter, LineFormatterSettings, OperatorPrecedence,
};
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::type_container::TypeContainer;
use binaryninja::type_parser::{
    register_type_parser, CoreTypeParser, TypeParser, TypeParserError, TypeParserOption,
};
use binaryninja::type_printer::{
    register_type_printer, CoreTypePrinter, TokenEscapingType, TypeDefinitionLine, TypePrinter,
};
use binaryninja::types::{QualifiedName, QualifiedNameAndType, Type};

struct MyLangRepr {}
struct MyLangReprType {
    core: CoreLanguageRepresentationFunctionType,
    printer: CoreTypePrinter,
    parser: CoreTypeParser,
    line_formatter: CoreLineFormatter,
}
struct MyTypePrinter {}
struct MyTypeParser {}
struct MyLineFormatter {}

impl CustomLanguageRepresentationFunction for MyLangRepr {
    fn init_token_emitter(&self, _tokens: &HighLevelILTokenEmitter) {}

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

impl CustomLanguageRepresentationFunctionType for MyLangReprType {
    fn create(
        &self,
        arch: &CoreArchitecture,
        func: &Function,
        high_level_il: &HighLevelILFunction,
    ) -> CoreLanguageRepresentationFunction {
        create_language_representation_function(
            MyLangRepr {},
            &self.core,
            arch,
            func,
            high_level_il,
        )
    }

    fn is_valid(&self, _view: &BinaryView) -> bool {
        true
    }

    fn type_printer(&self) -> &CoreTypePrinter {
        &self.printer
    }

    fn type_parser(&self) -> &CoreTypeParser {
        &self.parser
    }

    fn line_formatter(&self) -> &CoreLineFormatter {
        &self.line_formatter
    }

    fn function_type_tokens(
        &self,
        _func: &Function,
        _settings: &DisassemblySettings,
    ) -> Vec<DisassemblyTextLine> {
        todo!()
    }
}

impl TypePrinter for MyTypePrinter {
    fn get_type_tokens<T: Into<QualifiedName>>(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _name: T,
        _base_confidence: u8,
        _escaping: TokenEscapingType,
    ) -> Option<Vec<InstructionTextToken>> {
        Some(vec![InstructionTextToken::new(
            "SomeType",
            InstructionTextTokenKind::Text,
        )])
    }

    fn get_type_tokens_before_name(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _base_confidence: u8,
        _parent_type: Option<Ref<Type>>,
        _escaping: TokenEscapingType,
    ) -> Option<Vec<InstructionTextToken>> {
        Some(vec![InstructionTextToken::new(
            "<name>",
            InstructionTextTokenKind::Text,
        )])
    }

    fn get_type_tokens_after_name(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _base_confidence: u8,
        _parent_type: Option<Ref<Type>>,
        _escaping: TokenEscapingType,
    ) -> Option<Vec<binaryninja::disassembly::InstructionTextToken>> {
        Some(vec![InstructionTextToken::new(
            "</name>",
            InstructionTextTokenKind::Text,
        )])
    }

    fn get_type_string<T: Into<QualifiedName>>(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _name: T,
        _escaping: TokenEscapingType,
    ) -> Option<String> {
        None
    }

    fn get_type_string_before_name(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _escaping: TokenEscapingType,
    ) -> Option<String> {
        None
    }

    fn get_type_string_after_name(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _escaping: TokenEscapingType,
    ) -> Option<String> {
        None
    }

    fn get_type_lines<T: Into<QualifiedName>>(
        &self,
        _type_: Ref<Type>,
        _types: &TypeContainer,
        _name: T,
        _padding_cols: isize,
        _collapsed: bool,
        _escaping: TokenEscapingType,
    ) -> Option<Vec<TypeDefinitionLine>> {
        None
    }

    fn print_all_types(
        &self,
        _names: Vec<QualifiedName>,
        _types: Vec<Ref<Type>>,
        _data: Ref<BinaryView>,
        _padding_cols: isize,
        _escaping: TokenEscapingType,
    ) -> Option<String> {
        None
    }
}

impl TypeParser for MyTypeParser {
    fn get_option_text(&self, _option: TypeParserOption, _value: &str) -> Option<String> {
        None
    }

    fn preprocess_source(
        &self,
        _source: &str,
        _file_name: &str,
        _platform: &binaryninja::platform::Platform,
        _existing_types: &TypeContainer,
        _options: &[String],
        _include_dirs: &[String],
    ) -> Result<String, Vec<binaryninja::type_parser::TypeParserError>> {
        todo!()
    }

    fn parse_types_from_source(
        &self,
        _source: &str,
        _file_name: &str,
        _platform: &binaryninja::platform::Platform,
        _existing_types: &TypeContainer,
        _options: &[String],
        _include_dirs: &[String],
        _auto_type_source: &str,
    ) -> Result<
        binaryninja::type_parser::TypeParserResult,
        Vec<binaryninja::type_parser::TypeParserError>,
    > {
        todo!()
    }

    fn parse_type_string(
        &self,
        _source: &str,
        _platform: &binaryninja::platform::Platform,
        _existing_types: &TypeContainer,
    ) -> Result<QualifiedNameAndType, Vec<TypeParserError>> {
        todo!()
    }
}

impl CustomLineFormater for MyLineFormatter {
    fn format_lines(
        &self,
        lines: &[DisassemblyTextLine],
        _settings: &LineFormatterSettings,
    ) -> Vec<DisassemblyTextLine> {
        lines.to_vec()
    }
}

#[test]
fn test_custom_language_representation() {
    const LANG_REPR_NAME: &str = "test_lang_repr";
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let (_, printer) = register_type_printer("my_type_printer", MyTypePrinter {});
    let (_, parser) = register_type_parser("my_type_parser", MyTypeParser {});
    let line_formatter = register_line_formatter("my_line_formatter", MyLineFormatter {});
    let my_repr = register_language_representation_function_type(
        |core| MyLangReprType {
            core,
            printer,
            parser,
            line_formatter,
        },
        LANG_REPR_NAME,
    );
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let func = view
        .function_at(&view.default_platform().unwrap(), 0x36760)
        .unwrap();
    let _repr = my_repr.create(
        &view.default_arch().unwrap().as_ref(),
        &func,
        &func.high_level_il(false).unwrap(),
    );
    let il = func.high_level_il(false).unwrap();

    let settings = DisassemblySettings::new();
    let root_idx = il.root_instruction_index();
    let result = _repr.linear_lines(&il, root_idx, &settings, false);
    let output: String = result.iter().map(|dis| dis.to_string()).collect();
    let _repr = binaryninja::language_representation::get_function_language_representation(
        &func,
        LANG_REPR_NAME,
    )
    .unwrap();
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
