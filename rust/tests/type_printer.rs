use binaryninja::binary_view::BinaryView;
use binaryninja::disassembly::InstructionTextToken;
use binaryninja::headless::Session;
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use binaryninja::type_container::TypeContainer;
use binaryninja::type_printer::{
    register_type_printer, CoreTypePrinter, TokenEscapingType, TypeDefinitionLine, TypePrinter,
};
use binaryninja::types::{
    MemberAccess, MemberScope, QualifiedName, Structure, StructureMember, Type,
};
use std::path::PathBuf;

#[test]
fn test_type_printer() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");

    let type_printer = CoreTypePrinter::default();
    let my_structure = Type::structure(
        &Structure::builder()
            .insert_member(
                StructureMember::new(
                    Type::int(4, false).into(),
                    "my_field".to_string(),
                    0,
                    MemberAccess::PublicAccess,
                    MemberScope::NoScope,
                ),
                false,
            )
            .finalize(),
    );

    let printed_types = type_printer
        .print_all_types(
            [("my_struct", my_structure)],
            &view,
            4,
            TokenEscapingType::NoTokenEscapingType,
        )
        .expect("Failed to print types");

    // TODO: Assert this
    /*
    // "my_struct"
    struct my_struct
    {
        uint32_t my_field;
    };
    */

    println!("{:#?}", printed_types);
}

struct MyTypePrinter;

impl TypePrinter for MyTypePrinter {
    fn get_type_tokens<T: Into<QualifiedName>>(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _name: T,
        _base_confidence: u8,
        _escaping: TokenEscapingType,
    ) -> Option<Vec<InstructionTextToken>> {
        todo!()
    }

    fn get_type_tokens_before_name(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _base_confidence: u8,
        _parent_type: Option<Ref<Type>>,
        _escaping: TokenEscapingType,
    ) -> Option<Vec<InstructionTextToken>> {
        todo!()
    }

    fn get_type_tokens_after_name(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _base_confidence: u8,
        _parent_type: Option<Ref<Type>>,
        _escaping: TokenEscapingType,
    ) -> Option<Vec<InstructionTextToken>> {
        todo!()
    }

    fn get_type_string<T: Into<QualifiedName>>(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _name: T,
        _escaping: TokenEscapingType,
    ) -> Option<String> {
        todo!()
    }

    fn get_type_string_before_name(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _escaping: TokenEscapingType,
    ) -> Option<String> {
        todo!()
    }

    fn get_type_string_after_name(
        &self,
        _type_: Ref<Type>,
        _platform: Option<Ref<Platform>>,
        _escaping: TokenEscapingType,
    ) -> Option<String> {
        todo!()
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
        todo!()
    }

    fn print_all_types(
        &self,
        names: Vec<QualifiedName>,
        types: Vec<Ref<Type>>,
        _data: Ref<BinaryView>,
        padding_cols: isize,
        escaping: TokenEscapingType,
    ) -> Option<String> {
        let printed = format!("{:?}, {:?}, {}, {:?}", names, types, padding_cols, escaping);
        Some(printed)
    }
}

#[test]
fn test_custom_type_printer() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");

    let type_printer = MyTypePrinter;
    register_type_printer("my_type_printer", type_printer);

    let core_type_printer = CoreTypePrinter::printer_by_name("my_type_printer")
        .expect("Failed to get core type printer");
    let printed_types = core_type_printer
        .print_all_types(
            vec![("test", Type::int(4, false))],
            &view,
            0,
            TokenEscapingType::NoTokenEscapingType,
        )
        .expect("Failed to print types");

    // TODO: Assert this
    println!("{:#?}", printed_types);
}
