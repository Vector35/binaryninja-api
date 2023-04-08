use gimli::{
    constants,
    write::{
        Address, AttributeValue, DwarfUnit, EndianVec, Expression, Range, RangeList, Sections,
        UnitEntryId,
    },
};
use object::{write, Architecture, BinaryFormat, SectionKind};
use std::fs;

use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    command::{register, Command},
    interaction,
    interaction::{FormResponses, FormResponses::Index},
    logger::init,
    rc::Ref,
    settings::Settings,
    symbol::SymbolType,
    types::{Conf, MemberAccess, StructureType, Type, TypeClass},
};
use log::{error, LevelFilter};

fn export_type(
    t: &Type,
    bv: &BinaryView,
    defined_types: &mut Vec<(Ref<Type>, UnitEntryId)>,
    dwarf: &mut DwarfUnit,
) -> UnitEntryId {
    if let Some((_, die)) = defined_types
        .iter()
        .find(|(defined_type, _)| defined_type.as_ref() == t)
    {
        return *die;
    }

    let root = dwarf.unit.root();
    match t.type_class() {
        TypeClass::VoidTypeClass => {
            let void_die_uid = dwarf.unit.add(root, constants::DW_TAG_unspecified_type);
            defined_types.push((t.to_owned(), void_die_uid));

            dwarf.unit.get_mut(void_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String("void".as_bytes().to_vec()),
            );
            void_die_uid
        }
        TypeClass::BoolTypeClass => {
            let bool_die_uid = dwarf.unit.add(root, constants::DW_TAG_base_type);
            defined_types.push((t.to_owned(), bool_die_uid));

            dwarf.unit.get_mut(bool_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(format!("{}", t).as_bytes().to_vec()),
            );
            dwarf.unit.get_mut(bool_die_uid).set(
                gimli::DW_AT_byte_size,
                AttributeValue::Data1(t.width() as u8),
            );
            dwarf.unit.get_mut(bool_die_uid).set(
                gimli::DW_AT_encoding,
                AttributeValue::Encoding(constants::DW_ATE_float),
            );
            bool_die_uid
        }
        TypeClass::IntegerTypeClass => {
            let int_die_uid = dwarf.unit.add(root, constants::DW_TAG_base_type);
            defined_types.push((t.to_owned(), int_die_uid));

            dwarf.unit.get_mut(int_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(format!("{}", t).as_bytes().to_vec()),
            );
            dwarf.unit.get_mut(int_die_uid).set(
                gimli::DW_AT_byte_size,
                AttributeValue::Data1(t.width() as u8),
            );
            dwarf.unit.get_mut(int_die_uid).set(
                gimli::DW_AT_encoding,
                if t.is_signed().contents {
                    AttributeValue::Encoding(constants::DW_ATE_signed)
                } else {
                    AttributeValue::Encoding(constants::DW_ATE_unsigned)
                },
            );
            int_die_uid
        }
        TypeClass::FloatTypeClass => {
            let float_die_uid = dwarf.unit.add(root, constants::DW_TAG_base_type);
            defined_types.push((t.to_owned(), float_die_uid));

            dwarf.unit.get_mut(float_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(format!("{}", t).as_bytes().to_vec()),
            );
            dwarf.unit.get_mut(float_die_uid).set(
                gimli::DW_AT_byte_size,
                AttributeValue::Data1(t.width() as u8),
            );
            dwarf.unit.get_mut(float_die_uid).set(
                gimli::DW_AT_encoding,
                AttributeValue::Encoding(constants::DW_ATE_float),
            );
            float_die_uid
        }
        TypeClass::StructureTypeClass => {
            let structure_die_uid = match t.get_structure().unwrap().structure_type() {
                StructureType::ClassStructureType => {
                    dwarf.unit.add(root, constants::DW_TAG_class_type)
                }
                StructureType::StructStructureType => {
                    dwarf.unit.add(root, constants::DW_TAG_structure_type)
                }
                StructureType::UnionStructureType => {
                    dwarf.unit.add(root, constants::DW_TAG_union_type)
                }
            };
            defined_types.push((t.to_owned(), structure_die_uid));

            // TODO : I think I should technically get the NTR for this type and pull the name from that? Not sure if this will fail spectacularly with anonymous structs
            dwarf.unit.get_mut(structure_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(format!("{}", t).as_bytes().to_vec()),
            );
            dwarf.unit.get_mut(structure_die_uid).set(
                gimli::DW_AT_byte_size,
                AttributeValue::Data1(t.width() as u8),
            );

            for struct_member in t.get_structure().unwrap().members().unwrap() {
                let struct_member_die_uid =
                    dwarf.unit.add(structure_die_uid, constants::DW_TAG_member);
                dwarf.unit.get_mut(struct_member_die_uid).set(
                    gimli::DW_AT_name,
                    AttributeValue::String(struct_member.name.as_bytes().to_vec()),
                );
                match struct_member.access {
                    MemberAccess::PrivateAccess => {
                        dwarf.unit.get_mut(struct_member_die_uid).set(
                            gimli::DW_AT_accessibility,
                            AttributeValue::Accessibility(gimli::DW_ACCESS_private),
                        );
                    }
                    MemberAccess::ProtectedAccess => {
                        dwarf.unit.get_mut(struct_member_die_uid).set(
                            gimli::DW_AT_accessibility,
                            AttributeValue::Accessibility(gimli::DW_ACCESS_protected),
                        );
                    }
                    MemberAccess::PublicAccess => {
                        dwarf.unit.get_mut(struct_member_die_uid).set(
                            gimli::DW_AT_accessibility,
                            AttributeValue::Accessibility(gimli::DW_ACCESS_public),
                        );
                    }
                    _ => (),
                };
                dwarf.unit.get_mut(struct_member_die_uid).set(
                    gimli::DW_AT_data_bit_offset,
                    AttributeValue::Data8(struct_member.offset * 8),
                );

                let target_die_uid = AttributeValue::UnitRef(export_type(
                    struct_member.ty.contents.as_ref(),
                    bv,
                    defined_types,
                    dwarf,
                ));
                dwarf
                    .unit
                    .get_mut(struct_member_die_uid)
                    .set(gimli::DW_AT_type, target_die_uid);
            }

            structure_die_uid
        }
        TypeClass::EnumerationTypeClass => {
            let enum_die_uid = dwarf.unit.add(root, constants::DW_TAG_enumeration_type);
            defined_types.push((t.to_owned(), enum_die_uid));

            dwarf.unit.get_mut(enum_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(format!("{}", t).as_bytes().to_vec()),
            );
            dwarf.unit.get_mut(enum_die_uid).set(
                gimli::DW_AT_byte_size,
                AttributeValue::Data1(t.width() as u8),
            );

            for enum_field in t.get_enumeration().unwrap().members() {
                let enum_field_die_uid = dwarf.unit.add(enum_die_uid, constants::DW_TAG_enumerator);
                dwarf.unit.get_mut(enum_field_die_uid).set(
                    gimli::DW_AT_name,
                    AttributeValue::String(enum_field.name.as_bytes().to_vec()),
                );
                dwarf.unit.get_mut(enum_field_die_uid).set(
                    gimli::DW_AT_const_value,
                    AttributeValue::Data4(enum_field.value as u32),
                );
            }

            enum_die_uid
        }
        TypeClass::PointerTypeClass => {
            let pointer_die_uid = dwarf.unit.add(root, constants::DW_TAG_pointer_type);
            defined_types.push((t.to_owned(), pointer_die_uid));

            dwarf.unit.get_mut(pointer_die_uid).set(
                gimli::DW_AT_byte_size,
                AttributeValue::Data1(t.width() as u8),
            );
            if let Ok(Conf {
                contents: target_type,
                ..
            }) = t.target()
            {
                let target_die_uid =
                    AttributeValue::UnitRef(export_type(&target_type, bv, defined_types, dwarf));
                dwarf
                    .unit
                    .get_mut(pointer_die_uid)
                    .set(gimli::DW_AT_type, target_die_uid);
            }
            pointer_die_uid
        }
        TypeClass::ArrayTypeClass => {
            let array_die_uid = dwarf.unit.add(root, constants::DW_TAG_array_type);
            defined_types.push((t.to_owned(), array_die_uid));

            dwarf.unit.get_mut(array_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(format!("{}", t).as_bytes().to_vec()),
            );
            if let Ok(Conf {
                contents: element_type,
                ..
            }) = t.element_type()
            {
                let target_die_uid =
                    AttributeValue::UnitRef(export_type(&element_type, bv, defined_types, dwarf));
                dwarf
                    .unit
                    .get_mut(array_die_uid)
                    .set(gimli::DW_AT_type, target_die_uid);
            }
            dwarf
                .unit
                .get_mut(array_die_uid)
                .set(gimli::DW_AT_byte_size, AttributeValue::Data8(t.width()));
            array_die_uid
        }
        TypeClass::FunctionTypeClass => dwarf.unit.add(root, constants::DW_TAG_unspecified_type),
        TypeClass::VarArgsTypeClass => dwarf.unit.add(root, constants::DW_TAG_unspecified_type),
        TypeClass::ValueTypeClass => dwarf.unit.add(root, constants::DW_TAG_unspecified_type),
        TypeClass::NamedTypeReferenceClass => {
            let typedef_die_uid = dwarf.unit.add(root, constants::DW_TAG_typedef);
            defined_types.push((t.to_owned(), typedef_die_uid));

            dwarf.unit.get_mut(typedef_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(format!("{}", t).as_bytes().to_vec()),
            );
            let t = t.get_named_type_reference().unwrap();
            if let Some(target_type) = t.target(bv) {
                let target_die_uid =
                    AttributeValue::UnitRef(export_type(&target_type, bv, defined_types, dwarf));
                dwarf
                    .unit
                    .get_mut(typedef_die_uid)
                    .set(gimli::DW_AT_type, target_die_uid);
            }
            typedef_die_uid
        }
        TypeClass::WideCharTypeClass => {
            let wide_char_die_uid = dwarf.unit.add(root, constants::DW_TAG_base_type);
            defined_types.push((t.to_owned(), wide_char_die_uid));

            dwarf.unit.get_mut(wide_char_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(format!("{}", t).as_bytes().to_vec()),
            );
            dwarf.unit.get_mut(wide_char_die_uid).set(
                gimli::DW_AT_byte_size,
                AttributeValue::Data1(t.width() as u8),
            );
            dwarf.unit.get_mut(wide_char_die_uid).set(
                gimli::DW_AT_encoding,
                if t.is_signed().contents {
                    AttributeValue::Encoding(constants::DW_ATE_signed_char)
                } else {
                    AttributeValue::Encoding(constants::DW_ATE_unsigned_char)
                },
            );
            wide_char_die_uid
        }
    }
}

fn export_types(
    bv: &BinaryView,
    dwarf: &mut DwarfUnit,
    defined_types: &mut Vec<(Ref<Type>, UnitEntryId)>,
) {
    for t in &bv.types() {
        export_type(&t.type_object(), bv, defined_types, dwarf);
    }
}

fn export_functions(
    bv: &BinaryView,
    dwarf: &mut DwarfUnit,
    defined_types: &mut Vec<(Ref<Type>, UnitEntryId)>,
) {
    let entry_point = bv.entry_point_function();

    for function in &bv.functions() {
        // Create function DIE as child of the compilation unit DIE
        let root = dwarf.unit.root();
        let function_die_uid = dwarf.unit.add(root, constants::DW_TAG_subprogram);
        // let function_die = dwarf.unit.get_mut(function_die_uid);

        // Set subprogram DIE attributes
        dwarf.unit.get_mut(function_die_uid).set(
            gimli::DW_AT_name,
            AttributeValue::String(function.symbol().full_name().as_bytes().to_vec()), // TODO: Which name to use?
        );

        // TODO : (DW_AT_main_subprogram VS DW_TAG_entry_point)
        // TODO : This attribute seems maybe usually unused?
        if let Ok(entry_point_function) = &entry_point {
            if entry_point_function.as_ref() == function.as_ref() {
                dwarf
                    .unit
                    .get_mut(function_die_uid)
                    .set(gimli::DW_AT_main_subprogram, AttributeValue::Flag(true));
                dwarf.unit.get_mut(function_die_uid).set(
                    gimli::DW_AT_low_pc,
                    AttributeValue::Address(Address::Constant(function.start())), // TODO: Relocations
                );
            }
        }

        let address_ranges = function.address_ranges();
        if address_ranges.len() == 1 {
            let address_range = address_ranges.get(0);
            dwarf.unit.get_mut(function_die_uid).set(
                gimli::DW_AT_low_pc,
                AttributeValue::Address(Address::Constant(address_range.start() - bv.start())), // TODO: Relocations
            );
            dwarf.unit.get_mut(function_die_uid).set(
                gimli::DW_AT_high_pc,
                AttributeValue::Address(Address::Constant(
                    address_range.end() - address_range.start(),
                )),
            );
        } else {
            let range_list = RangeList(
                address_ranges
                    .into_iter()
                    .map(|range| Range::StartLength {
                        begin: Address::Constant(range.start() - bv.start()), // TODO: Relocations?
                        length: range.end() - range.start(),
                    })
                    .collect(),
            );
            let range_list_id = dwarf.unit.ranges.add(range_list);
            dwarf.unit.get_mut(function_die_uid).set(
                gimli::DW_AT_ranges,
                AttributeValue::RangeListRef(range_list_id),
            );
        }

        // DWARFv4 2.18: " If no DW_AT_entry_pc attribute is present, then the entry address is assumed to be the same as the value of the DW_AT_low_pc attribute"
        if address_ranges.get(0).start() != function.start() {
            dwarf.unit.get_mut(function_die_uid).set(
                gimli::DW_AT_entry_pc,
                AttributeValue::Address(Address::Constant(function.start() - bv.start())),
            );
        }

        if function.return_type().contents.type_class() != TypeClass::VoidTypeClass {
            let return_type_die_uid = AttributeValue::UnitRef(export_type(
                function.return_type().contents.as_ref(),
                bv,
                defined_types,
                dwarf,
            ));
            dwarf
                .unit
                .get_mut(function_die_uid)
                .set(gimli::DW_AT_type, return_type_die_uid);
        }

        for parameter in function.function_type().parameters().unwrap() {
            let param_die_uid = dwarf
                .unit
                .add(function_die_uid, constants::DW_TAG_formal_parameter);

            dwarf.unit.get_mut(param_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(parameter.name.as_bytes().to_vec()),
            );

            let target_die_uid = AttributeValue::UnitRef(export_type(
                &parameter.t.contents,
                bv,
                defined_types,
                dwarf,
            ));
            dwarf
                .unit
                .get_mut(param_die_uid)
                .set(gimli::DW_AT_type, target_die_uid);
        }

        if function.function_type().has_variable_arguments().contents {
            dwarf
                .unit
                .add(function_die_uid, constants::DW_TAG_unspecified_parameters);
        }

        if function.symbol().external() {
            dwarf
                .unit
                .get_mut(function_die_uid)
                .set(gimli::DW_AT_external, AttributeValue::Flag(true));
        }

        // TODO : calling convention attr
        // TODO : local vars
    }
}

fn export_data_vars(
    bv: &BinaryView,
    dwarf: &mut DwarfUnit,
    defined_types: &mut Vec<(Ref<Type>, UnitEntryId)>,
) {
    let root = dwarf.unit.root();

    for data_variable in &bv.data_variables() {
        if let Some(symbol) = data_variable.symbol(bv) {
            if symbol.sym_type() == SymbolType::External {
                continue;
            }
        }

        let var_die_uid = dwarf.unit.add(root, constants::DW_TAG_variable);

        if let Some(symbol) = data_variable.symbol(bv) {
            dwarf.unit.get_mut(var_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(symbol.full_name().as_bytes().to_vec()),
            );

            if symbol.external() {
                dwarf
                    .unit
                    .get_mut(var_die_uid)
                    .set(gimli::DW_AT_external, AttributeValue::Flag(true));
            }
        } else {
            dwarf.unit.get_mut(var_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(
                    format!("data_{:x}", data_variable.address)
                        .as_bytes()
                        .to_vec(),
                ),
            );
        }

        let mut variable_location = Expression::new();
        variable_location.op_addr(Address::Constant(data_variable.address));
        dwarf.unit.get_mut(var_die_uid).set(
            gimli::DW_AT_location,
            AttributeValue::Exprloc(variable_location),
        );

        let target_die_uid = AttributeValue::UnitRef(export_type(
            data_variable.t.contents.as_ref(),
            bv,
            defined_types,
            dwarf,
        ));
        dwarf
            .unit
            .get_mut(var_die_uid)
            .set(gimli::DW_AT_type, target_die_uid);
    }
}

fn present_form() -> Vec<FormResponses> {
    // TODO : Verify inputs (like save location) so that we can fail early
    // TODO : Add Language field
    // TODO : Choose to export types/functions/etc
    interaction::FormInputBuilder::new()
        .save_file_field("Save Location", None, None, None)
        .choice_field(
            "Architecture",
            &[
                "Unknown",
                "Aarch64",
                "Aarch64_Ilp32",
                "Arm",
                "Avr",
                "Bpf",
                "I386",
                "X86_64",
                "X86_64_X32",
                "Hexagon",
                "LoongArch64",
                "Mips",
                "Mips64",
                "Msp430",
                "PowerPc",
                "PowerPc64",
                "Riscv32",
                "Riscv64",
                "S390x",
                "Sbf",
                "Sparc64",
                "Wasm32",
                "Xtensa",
            ],
            None,
        )
        .choice_field(
            "Container Format",
            &["Coff", "Elf", "MachO", "Pe", "Wasm", "Xcoff"],
            None,
        )
        .get_form_input("Export as DWARF")
}

fn write_dwarf<T: gimli::Endianity>(
    responses: Vec<FormResponses>,
    endian: T,
    dwarf: &mut DwarfUnit,
) {
    if responses.len() < 3 {
        return;
    }

    let arch = match responses[1] {
        Index(0) => Architecture::Unknown,
        Index(1) => Architecture::Aarch64,
        Index(2) => Architecture::Aarch64_Ilp32,
        Index(3) => Architecture::Arm,
        Index(4) => Architecture::Avr,
        Index(5) => Architecture::Bpf,
        Index(6) => Architecture::I386,
        Index(7) => Architecture::X86_64,
        Index(8) => Architecture::X86_64_X32,
        Index(9) => Architecture::Hexagon,
        Index(10) => Architecture::LoongArch64,
        Index(11) => Architecture::Mips,
        Index(12) => Architecture::Mips64,
        Index(13) => Architecture::Msp430,
        Index(14) => Architecture::PowerPc,
        Index(15) => Architecture::PowerPc64,
        Index(16) => Architecture::Riscv32,
        Index(17) => Architecture::Riscv64,
        Index(18) => Architecture::S390x,
        Index(19) => Architecture::Sbf,
        Index(20) => Architecture::Sparc64,
        Index(21) => Architecture::Wasm32,
        Index(22) => Architecture::Xtensa,
        _ => Architecture::Unknown,
    };

    let format = match responses[2] {
        Index(0) => BinaryFormat::Coff,
        Index(1) => BinaryFormat::Elf,
        Index(2) => BinaryFormat::MachO,
        Index(3) => BinaryFormat::Pe,
        Index(4) => BinaryFormat::Wasm,
        Index(5) => BinaryFormat::Xcoff,
        _ => BinaryFormat::Elf,
    };

    // TODO : Properly determine output format (without user input)
    // TODO : Properly determine architecture (without user input)
    // TODO : Look in to other options (mangling, flags, etc (see Object::new))
    let mut out_object = write::Object::new(
        format,
        arch,
        if endian.is_little_endian() {
            object::Endianness::Little
        } else {
            object::Endianness::Big
        },
    );

    // Finally, write the DWARF data to the sections.
    let mut sections = Sections::new(EndianVec::new(endian));
    dwarf.write(&mut sections).unwrap();

    sections
        .for_each(|input_id, input_data| {
            // Create section in output object
            let output_id = out_object.add_section(
                vec![], // Only machos have segment names? see object::write::Object::segment_name
                input_id
                    .dwo_name()
                    .unwrap_or_else(|| input_id.name())
                    .as_bytes()
                    .to_vec(),
                SectionKind::Debug, // TODO: Might be wrong
            );

            // Write data to section in output object
            let out_section = out_object.section_mut(output_id);
            if out_section.is_bss() {
                panic!("Please report this as a bug: output section is bss");
            } else {
                out_section.set_data(input_data.clone().into_vec(), 1);
            }
            // out_section.flags = in_section.flags(); // TODO

            Ok::<(), ()>(())
        })
        .unwrap();

    if let interaction::FormResponses::String(filename) = &responses[0] {
        if let Ok(out_data) = out_object.write() {
            if let Err(err) = fs::write(filename, out_data) {
                error!("Failed to write DWARF file: {}", err);
            }
        } else {
            error!("Failed to write DWARF with requested settings");
        }
    }
}

fn export_dwarf(bv: &BinaryView) {
    let responses = present_form();

    let encoding = gimli::Encoding {
        format: gimli::Format::Dwarf32,
        version: 4,
        address_size: bv.address_size() as u8,
    };

    // Create a container for a single compilation unit.
    // TODO : Add attributes to the compilation unit DIE?
    let mut dwarf = DwarfUnit::new(encoding);

    // Everything has types, so we need to track what is already defined globally as to not duplicate type entries
    let mut defined_types: Vec<(Ref<Type>, UnitEntryId)> = vec![];
    export_types(bv, &mut dwarf, &mut defined_types);
    export_functions(bv, &mut dwarf, &mut defined_types);
    export_data_vars(bv, &mut dwarf, &mut defined_types);
    // TODO: Export all symbols instead of just data vars?
    // TODO: Sections? Segments?

    if bv.default_endianness() == binaryninja::Endianness::LittleEndian {
        write_dwarf(responses, gimli::LittleEndian, &mut dwarf);
    } else {
        write_dwarf(responses, gimli::BigEndian, &mut dwarf);
    };
}

struct MyCommand;
impl Command for MyCommand {
    fn action(&self, view: &BinaryView) {
        export_dwarf(view)
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    init(LevelFilter::Info).expect("Unable to initialize logger");

    let settings = Settings::new("");
    settings.register_setting_json(
    "analysis.experimental.dwarfExport",
    r#"{
            "title" : "Enable the DWARF Export Plugin",
            "type" : "boolean",
            "default" : false,
            "description" : "Export current analysis state and annotations as DWARF for import into other tools. This is currently an experimental feature as integrations with tools that import DWARF information are limited."
        }"#,
    );

    if settings.get_bool("analysis.experimental.dwarfExport", None, None) {
        register(
            "Export as DWARF",
            "Export current analysis state and annotations as DWARF for import into other tools",
            MyCommand {},
        );
    }
    true
}
