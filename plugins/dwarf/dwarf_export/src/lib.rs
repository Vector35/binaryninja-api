mod edit_distance;

use gimli::{
    constants,
    write::{
        Address, AttributeValue, DwarfUnit, EndianVec, Expression, Range, RangeList, Sections,
        UnitEntryId,
    },
};
use object::{write, Architecture, BinaryFormat, SectionKind};
use std::fs;

use binaryninja::logger::Logger;
use binaryninja::{
    binary_view::{BinaryView, BinaryViewBase, BinaryViewExt},
    command::{register_command, Command},
    confidence::Conf,
    interaction,
    interaction::{FormResponses, FormResponses::Index},
    rc::Ref,
    string::BnString,
    symbol::SymbolType,
    types::{MemberAccess, StructureType, Type, TypeClass},
};
use log::{error, info, LevelFilter};

fn export_type(
    name: String,
    t: &Type,
    bv: &BinaryView,
    defined_types: &mut Vec<(Ref<Type>, UnitEntryId)>,
    dwarf: &mut DwarfUnit,
) -> Option<UnitEntryId> {
    if let Some((_, die)) = defined_types
        .iter()
        .find(|(defined_type, _)| defined_type.as_ref() == t)
    {
        return Some(*die);
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
            Some(void_die_uid)
        }
        TypeClass::BoolTypeClass => {
            let bool_die_uid = dwarf.unit.add(root, constants::DW_TAG_base_type);
            defined_types.push((t.to_owned(), bool_die_uid));

            dwarf.unit.get_mut(bool_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(name.as_bytes().to_vec()),
            );
            dwarf.unit.get_mut(bool_die_uid).set(
                gimli::DW_AT_byte_size,
                AttributeValue::Data1(t.width() as u8),
            );
            dwarf.unit.get_mut(bool_die_uid).set(
                gimli::DW_AT_encoding,
                AttributeValue::Encoding(constants::DW_ATE_float),
            );
            Some(bool_die_uid)
        }
        TypeClass::IntegerTypeClass => {
            let int_die_uid = dwarf.unit.add(root, constants::DW_TAG_base_type);
            defined_types.push((t.to_owned(), int_die_uid));

            dwarf.unit.get_mut(int_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(name.as_bytes().to_vec()),
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
            Some(int_die_uid)
        }
        TypeClass::FloatTypeClass => {
            let float_die_uid = dwarf.unit.add(root, constants::DW_TAG_base_type);
            defined_types.push((t.to_owned(), float_die_uid));

            dwarf.unit.get_mut(float_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(name.as_bytes().to_vec()),
            );
            dwarf.unit.get_mut(float_die_uid).set(
                gimli::DW_AT_byte_size,
                AttributeValue::Data1(t.width() as u8),
            );
            dwarf.unit.get_mut(float_die_uid).set(
                gimli::DW_AT_encoding,
                AttributeValue::Encoding(constants::DW_ATE_float),
            );
            Some(float_die_uid)
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

            dwarf.unit.get_mut(structure_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(name.as_bytes().to_vec()),
            );
            dwarf.unit.get_mut(structure_die_uid).set(
                gimli::DW_AT_byte_size,
                AttributeValue::Data2(t.width() as u16),
            );

            for struct_member in t.get_structure().unwrap().members() {
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
                    gimli::DW_AT_data_member_location,
                    AttributeValue::Data8(struct_member.offset),
                );

                if let Some(target_die_uid) = export_type(
                    format!("{}", struct_member.ty.contents),
                    struct_member.ty.contents.as_ref(),
                    bv,
                    defined_types,
                    dwarf,
                ) {
                    dwarf
                        .unit
                        .get_mut(struct_member_die_uid)
                        .set(gimli::DW_AT_type, AttributeValue::UnitRef(target_die_uid));
                }
            }

            Some(structure_die_uid)
        }
        TypeClass::EnumerationTypeClass => {
            let enum_die_uid = dwarf.unit.add(root, constants::DW_TAG_enumeration_type);
            defined_types.push((t.to_owned(), enum_die_uid));

            dwarf.unit.get_mut(enum_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(name.as_bytes().to_vec()),
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

            Some(enum_die_uid)
        }
        TypeClass::PointerTypeClass => {
            let pointer_die_uid = dwarf.unit.add(root, constants::DW_TAG_pointer_type);
            defined_types.push((t.to_owned(), pointer_die_uid));

            dwarf.unit.get_mut(pointer_die_uid).set(
                gimli::DW_AT_byte_size,
                AttributeValue::Data1(t.width() as u8),
            );
            if let Some(Conf {
                contents: target_type,
                ..
            }) = t.target()
            {
                // TODO : Passing through the name here might be wrong
                if let Some(target_die_uid) =
                    export_type(name, &target_type, bv, defined_types, dwarf)
                {
                    dwarf
                        .unit
                        .get_mut(pointer_die_uid)
                        .set(gimli::DW_AT_type, AttributeValue::UnitRef(target_die_uid));
                }
            }
            Some(pointer_die_uid)
        }
        TypeClass::ArrayTypeClass => {
            let array_die_uid = dwarf.unit.add(root, constants::DW_TAG_array_type);
            defined_types.push((t.to_owned(), array_die_uid));

            // Name
            dwarf.unit.get_mut(array_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(name.as_bytes().to_vec()),
            );

            // Element type
            if let Some(Conf {
                contents: element_type,
                ..
            }) = t.element_type()
            {
                // TODO : Passing through the name here might be wrong
                if let Some(target_die_uid) =
                    export_type(name, &element_type, bv, defined_types, dwarf)
                {
                    dwarf
                        .unit
                        .get_mut(array_die_uid)
                        .set(gimli::DW_AT_type, AttributeValue::UnitRef(target_die_uid));
                }
            }

            // For some reason subrange types have a 'type' field that is just "some type" that'll work to index this array
            //  We're hardcoding this to a uint64_t. This could be unsound.
            let array_accessor_type = export_type(
                "uint64_t".to_string(),
                &Type::named_int(8, false, "uint64_t"),
                bv,
                defined_types,
                dwarf,
            )
            .unwrap();

            // Array length and multidimensional arrays
            let mut current_t = t.to_owned();
            while let Some(Conf {
                contents: element_type,
                ..
            }) = current_t.element_type()
            {
                let array_dimension_die_uid = dwarf
                    .unit
                    .add(array_die_uid, constants::DW_TAG_subrange_type);

                dwarf.unit.get_mut(array_dimension_die_uid).set(
                    gimli::DW_AT_type,
                    AttributeValue::UnitRef(array_accessor_type),
                );

                dwarf.unit.get_mut(array_dimension_die_uid).set(
                    gimli::DW_AT_upper_bound,
                    AttributeValue::Data8(current_t.count() - 1),
                );

                if element_type.type_class() != TypeClass::ArrayTypeClass {
                    break;
                } else {
                    current_t = element_type;
                }
            }

            Some(array_die_uid)
        }
        TypeClass::FunctionTypeClass => {
            Some(dwarf.unit.add(root, constants::DW_TAG_unspecified_type))
        }
        TypeClass::VarArgsTypeClass => {
            Some(dwarf.unit.add(root, constants::DW_TAG_unspecified_type))
        }
        TypeClass::ValueTypeClass => Some(dwarf.unit.add(root, constants::DW_TAG_unspecified_type)),
        TypeClass::NamedTypeReferenceClass => {
            let ntr = t.get_named_type_reference().unwrap();
            if let Some(target_type) = ntr.target(bv) {
                if target_type.type_class() == TypeClass::StructureTypeClass {
                    export_type(
                        ntr.name().to_string(),
                        &target_type,
                        bv,
                        defined_types,
                        dwarf,
                    )
                } else {
                    let typedef_die_uid = dwarf.unit.add(root, constants::DW_TAG_typedef);
                    defined_types.push((t.to_owned(), typedef_die_uid));

                    dwarf.unit.get_mut(typedef_die_uid).set(
                        gimli::DW_AT_name,
                        AttributeValue::String(ntr.name().to_string().as_bytes().to_vec()),
                    );

                    if let Some(target_die_uid) = export_type(
                        ntr.name().to_string(),
                        &target_type,
                        bv,
                        defined_types,
                        dwarf,
                    ) {
                        dwarf
                            .unit
                            .get_mut(typedef_die_uid)
                            .set(gimli::DW_AT_type, AttributeValue::UnitRef(target_die_uid));
                    }
                    Some(typedef_die_uid)
                }
            } else {
                error!("Could not get target of typedef `{}`", ntr.name());
                None
            }
        }
        TypeClass::WideCharTypeClass => {
            let wide_char_die_uid = dwarf.unit.add(root, constants::DW_TAG_base_type);
            defined_types.push((t.to_owned(), wide_char_die_uid));

            dwarf.unit.get_mut(wide_char_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(name.as_bytes().to_vec()),
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
            Some(wide_char_die_uid)
        }
    }
}

fn export_types(
    bv: &BinaryView,
    dwarf: &mut DwarfUnit,
    defined_types: &mut Vec<(Ref<Type>, UnitEntryId)>,
) {
    for t in &bv.types() {
        export_type(t.name.to_string(), &t.ty, bv, defined_types, dwarf);
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
            AttributeValue::String(function.symbol().short_name().as_bytes().to_vec()),
        );

        // TODO : (DW_AT_main_subprogram VS DW_TAG_entry_point)
        // TODO : This attribute seems maybe usually unused?
        if let Some(entry_point_function) = &entry_point {
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
                AttributeValue::Address(Address::Constant(address_range.start)), // TODO: Relocations
            );
            dwarf.unit.get_mut(function_die_uid).set(
                gimli::DW_AT_high_pc,
                AttributeValue::Address(Address::Constant(address_range.end)),
            );
        } else {
            let range_list = RangeList(
                address_ranges
                    .into_iter()
                    .map(|range| Range::StartLength {
                        begin: Address::Constant(range.start), // TODO: Relocations?
                        length: range.end - range.start,
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
        if address_ranges.get(0).start != function.start() {
            dwarf.unit.get_mut(function_die_uid).set(
                gimli::DW_AT_entry_pc,
                AttributeValue::Address(Address::Constant(function.start())),
            );
        }

        if function.return_type().contents.type_class() != TypeClass::VoidTypeClass {
            if let Some(return_type_die_uid) = export_type(
                format!("{}", function.return_type().contents),
                function.return_type().contents.as_ref(),
                bv,
                defined_types,
                dwarf,
            ) {
                dwarf.unit.get_mut(function_die_uid).set(
                    gimli::DW_AT_type,
                    AttributeValue::UnitRef(return_type_die_uid),
                );
            }
        }

        for parameter in function.function_type().parameters().unwrap() {
            let param_die_uid = dwarf
                .unit
                .add(function_die_uid, constants::DW_TAG_formal_parameter);

            dwarf.unit.get_mut(param_die_uid).set(
                gimli::DW_AT_name,
                AttributeValue::String(parameter.name.as_bytes().to_vec()),
            );

            if let Some(target_die_uid) = export_type(
                format!("{}", parameter.ty.contents),
                &parameter.ty.contents,
                bv,
                defined_types,
                dwarf,
            ) {
                dwarf
                    .unit
                    .get_mut(param_die_uid)
                    .set(gimli::DW_AT_type, AttributeValue::UnitRef(target_die_uid));
            }
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
        let data_var_sym = bv.symbol_by_address(data_variable.address);
        if let Some(symbol) = &data_var_sym {
            if let SymbolType::External
            | SymbolType::Function
            | SymbolType::ImportedFunction
            | SymbolType::LibraryFunction = symbol.sym_type()
            {
                continue;
            }
        }

        let var_die_uid = dwarf.unit.add(root, constants::DW_TAG_variable);

        if let Some(symbol) = data_var_sym {
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

        if let Some(target_die_uid) = export_type(
            format!("{}", data_variable.ty),
            &data_variable.ty.contents,
            bv,
            defined_types,
            dwarf,
        ) {
            dwarf
                .unit
                .get_mut(var_die_uid)
                .set(gimli::DW_AT_type, AttributeValue::UnitRef(target_die_uid));
        }
    }
}

fn present_form(bv_arch: &str) -> Vec<FormResponses> {
    // TODO : Verify inputs (like save location) so that we can fail early
    // TODO : Add Language field
    // TODO : Choose to export types/functions/etc
    let archs = [
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
    ];
    interaction::FormInputBuilder::new()
        .save_file_field(
            "Save Location",
            Some("Debug Files (*.dwo *.debug);;All Files (*)"),
            None,
            None,
        )
        .choice_field(
            "Architecture",
            &archs,
            archs
                .iter()
                .enumerate()
                .min_by(|&(_, arch_name_1), &(_, arch_name_2)| {
                    edit_distance::distance(bv_arch, arch_name_1)
                        .cmp(&edit_distance::distance(bv_arch, arch_name_2))
                })
                .map(|(index, _)| index),
        )
        // Add actual / better support for formats other than elf?
        // .choice_field(
        //     "Container Format",
        //     &["Coff", "Elf", "MachO", "Pe", "Wasm", "Xcoff"],
        //     None,
        // )
        .get_form_input("Export as DWARF")
}

fn write_dwarf<T: gimli::Endianity>(
    responses: Vec<FormResponses>,
    endian: T,
    dwarf: &mut DwarfUnit,
) {
    if responses.len() < 2 {
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

    // let format = match responses[2] {
    //     Index(0) => BinaryFormat::Coff,
    //     Index(1) => BinaryFormat::Elf,
    //     Index(2) => BinaryFormat::MachO,
    //     Index(3) => BinaryFormat::Pe,
    //     Index(4) => BinaryFormat::Wasm,
    //     Index(5) => BinaryFormat::Xcoff,
    //     _ => BinaryFormat::Elf,
    // };

    // TODO : Look in to other options (mangling, flags, etc (see Object::new))
    let mut out_object = write::Object::new(
        BinaryFormat::Elf,
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
                input_id.name().as_bytes().to_vec(),
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
            } else {
                info!("Successfully saved as DWARF to `{}`", filename);
            }
        } else {
            error!("Failed to write DWARF with requested settings");
        }
    }
}

fn export_dwarf(bv: &BinaryView) {
    let arch_name = if let Some(arch) = bv.default_arch() {
        arch.name()
    } else {
        BnString::new("Unknown")
    };
    let responses = present_form(arch_name.as_str());

    let encoding = gimli::Encoding {
        format: gimli::Format::Dwarf32,
        version: 4,
        address_size: bv.address_size() as u8,
    };

    // Create a container for a single compilation unit.
    // TODO : Add attributes to the compilation unit DIE?
    let mut dwarf = DwarfUnit::new(encoding);
    dwarf.unit.get_mut(dwarf.unit.root()).set(
        gimli::DW_AT_producer,
        AttributeValue::String("Binary Ninja DWARF Export Plugin".as_bytes().to_vec()),
    );

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
    Logger::new("DWARF Export")
        .with_level(LevelFilter::Debug)
        .init();

    register_command(
        "Export as DWARF",
        "Export current analysis state and annotations as DWARF for import into other tools",
        MyCommand {},
    );

    true
}
