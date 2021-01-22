use crate::dwarfdebuginfo::DebugInfoBuilder;
use crate::helpers::*;

use binaryninja::{
    rc::*,
    types::{
        Enumeration, EnumerationBuilder, NamedTypeReference, NamedTypeReferenceClass,
        QualifiedName, Structure, StructureBuilder, Type,
    },
};

use gimli::{
    constants,
    AttributeValue::{Encoding, UnitRef},
    DebuggingInformationEntry, Dwarf, Reader, Unit, UnitOffset, UnitSectionOffset,
};

// Type tags in hello world:
//   DW_TAG_array_type
//   DW_TAG_base_type
//   DW_TAG_pointer_type
//   DW_TAG_structure_type
//   DW_TAG_typedef
//   DW_TAG_unspecified_type  // This one is done, but only for C/C++; Will not implement the generic case; Is always language specific (we just return void)
//   DW_TAG_enumeration_type
//   DW_TAG_const_type
//   *DW_TAG_subroutine_type
//   *DW_TAG_union_type
//   *DW_TAG_class_type

//   *DW_TAG_reference_type
//   *DW_TAG_rvalue_reference_type
//   *DW_TAG_subrange_type
//   *DW_TAG_template_type_parameter
//   *DW_TAG_template_value_parameter
// * = Not yet handled
// Other tags in hello world:
//   DW_TAG_compile_unit
//   DW_TAG_namespace
//   DW_TAG_subprogram
//   DW_TAG_formal_parameter
//   DW_TAG_enumerator
//   ?DW_TAG_member
//   *DW_TAG_imported_declaration
//   *DW_TAG_imported_module
//   *DW_TAG_inheritance
//   *DW_TAG_unspecified_parameters
//   *DW_TAG_variable

// This function iterates up through the dependency references, adding all the types along the way until there are no more or stopping at the first one already tracked, then returns the UID of the type of the given DIE
pub(crate) fn get_type<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    mut debug_info_builder: &mut DebugInfoBuilder<UnitOffset>,
) -> Option<UnitOffset> {
    // If this node (and thus all its referenced nodes) has already been processed, just return the offset
    if debug_info_builder.contains_type(entry.offset()) {
        return Some(entry.offset());
    }

    // Recurse
    // TODO : Need to consider specification and abstract origin?
    let mut result = None;
    if let Ok(Some(UnitRef(offset))) = entry.attr_value(constants::DW_AT_type) {
        let entry = unit.entry(offset).unwrap();
        result = get_type(&dwarf, &unit, &entry, &mut debug_info_builder);
    }
    let parent = result;

    // If this node (and thus all its referenced nodes) has already been processed (during recursion), just return the offset
    if debug_info_builder.contains_type(entry.offset()) {
        return Some(entry.offset());
    }

    // Collect the required information to create a type and add it to the type map. Also, add the dependencies of this type to the type's typeinfo
    // Create the type, make a typeinfo for it, and add it to the debug info
    // TODO : Add this type to the type map thing
    // TODO : Add this type's dependency to the type's info
    result = Some(entry.offset());
    let type_def: Option<Ref<Type>> = match entry.tag() {
        constants::DW_TAG_base_type => {
            // All base types have:
            //   DW_AT_name
            //   DW_AT_encoding (our concept of type_class)
            //   DW_AT_byte_size and/or DW_AT_bit_size
            //   *DW_AT_endianity (assumed default for arch)
            //   *DW_AT_data_bit_offset (assumed 0)
            //   *Some indication of signedness?
            //   * = Optional

            // TODO : Namespaces?
            // TODO : By spec base types need to have a name, what if it's spec non-conforming?
            let name = get_attr_string(&dwarf, &unit, &entry);

            // TODO : Handle other size specifiers (bits, offset, high_pc?, etc)
            let size: usize =
                get_attr_as_usize(entry.attr(constants::DW_AT_byte_size).unwrap().unwrap())
                    .unwrap();

            match entry.attr_value(constants::DW_AT_encoding) {
                // TODO : Need more binaries to see what's going on
                Ok(Some(Encoding(encoding))) => {
                    match encoding {
                        constants::DW_ATE_address => None,
                        constants::DW_ATE_boolean => Some(Type::bool()),
                        constants::DW_ATE_complex_float => None,
                        constants::DW_ATE_float => Some(Type::named_float(size, name)),
                        constants::DW_ATE_signed => Some(Type::named_int(size, true, name)),
                        constants::DW_ATE_signed_char => Some(Type::named_int(size, true, name)),
                        constants::DW_ATE_unsigned => Some(Type::named_int(size, false, name)),
                        constants::DW_ATE_unsigned_char => Some(Type::named_int(size, false, name)),
                        constants::DW_ATE_imaginary_float => None,
                        constants::DW_ATE_packed_decimal => None,
                        constants::DW_ATE_numeric_string => None,
                        constants::DW_ATE_edited => None,
                        constants::DW_ATE_signed_fixed => None,
                        constants::DW_ATE_unsigned_fixed => None,
                        constants::DW_ATE_decimal_float => Some(Type::named_float(size, name)), // TODO : How is this different from binary floating point, ie. DW_ATE_float?
                        constants::DW_ATE_UTF => Some(Type::named_int(size, false, name)), // TODO : Verify
                        constants::DW_ATE_UCS => None,
                        constants::DW_ATE_ASCII => None, // Some sort of array?
                        constants::DW_ATE_lo_user => None,
                        constants::DW_ATE_hi_user => None,
                        _ => None, // Anything else is invalid at time of writing (gimli v0.23.0)
                    }
                }
                _ => None,
            }
        }
        // bn::Types::Structure related things
        //  Steps to parsing a structure:
        //    Create a phony type representing the structure
        //    Parse the size of the structure and create a Structure instance
        //    Recurse on the DIE's children to create all their types (any references back to the the current DIE will be NamedTypeReferences to a phony type)
        //    Populate the members of the structure, create a structure_type, and register it with the DebugInfo
        constants::DW_TAG_structure_type => {
            // First things first, let's register a reference type for this struct for any children to grab while we're still building this type
            let name = get_attr_string(&dwarf, &unit, &entry);
            debug_info_builder.add_type(
                entry.offset(),
                Type::named_type(NamedTypeReference::new(
                    NamedTypeReferenceClass::StructNamedTypeClass,
                    Type::generate_auto_demangled_type_id(name.clone()),
                    QualifiedName::from(name),
                )),
            );

            // Create structure with proper size
            // TODO : Parse the size but properly
            let size =
                get_attr_as_u64(entry.attr(constants::DW_AT_byte_size).unwrap().unwrap()).unwrap();
            let mut structure_builder: StructureBuilder = StructureBuilder::new();
            structure_builder.set_width(size);

            // Get all the children and populate
            // TODO : Make in to its own function?
            let mut tree = unit.entries_tree(Some(entry.offset())).unwrap();
            let mut children = tree.root().unwrap().children();
            while let Ok(Some(child)) = children.next() {
                let label_value = match child.entry().offset().to_unit_section_offset(unit) {
                    UnitSectionOffset::DebugInfoOffset(o) => o.0,
                    UnitSectionOffset::DebugTypesOffset(o) => o.0,
                };
                // TODO : Remove `if let` guard; types will always exist once this plugin is complete
                if let Some(child_type_id) =
                    get_type(&dwarf, &unit, &child.entry(), &mut debug_info_builder)
                {
                    if child.entry().tag() == constants::DW_TAG_member {
                        let child_offset = get_attr_as_u64(
                            child
                                .entry()
                                .attr(constants::DW_AT_data_member_location)
                                .unwrap()
                                .unwrap(),
                        )
                        .unwrap();
                        let child_name = get_attr_string(&dwarf, &unit, &child.entry());

                        // TODO : Remove `if let` guard; types will always exist once this plugin is complete
                        if let Some(child_type) = debug_info_builder.get_type(child_type_id) {
                            structure_builder.insert(child_type.as_ref(), child_name, child_offset);
                        } else {
                            println!("Type for #0x{:08x} was not created!", label_value);
                        }
                    }
                } else {
                    println!("Type for #0x{:08x} could not be created!", label_value);
                }
            }
            // End children recursive block

            debug_info_builder.remove_type(entry.offset());

            // TODO : Figure out how to make this nicer:
            let structure = Structure::new(&structure_builder);
            Some(Type::structure(structure.as_ref()))
        }
        constants::DW_TAG_class_type => {
            // All class types will have:
            //   *DW_AT_name
            //   *DW_AT_byte_size or *DW_AT_bit_size
            //   *DW_AT_declaration
            //   *DW_AT_signature
            //   *DW_AT_specification
            //   ?DW_AT_abstract_origin
            //   ?DW_AT_accessibility
            //   ?DW_AT_allocated
            //   ?DW_AT_associated
            //   ?DW_AT_data_location
            //   ?DW_AT_description
            //   ?DW_AT_start_scope
            //   ?DW_AT_visibility
            //   * = Optional

            None
        }
        constants::DW_TAG_union_type => {
            // All union types will have:
            //   *DW_AT_name
            //   *DW_AT_byte_size or *DW_AT_bit_size
            //   *DW_AT_declaration
            //   *DW_AT_signature
            //   *DW_AT_specification
            //   ?DW_AT_abstract_origin
            //   ?DW_AT_accessibility
            //   ?DW_AT_allocated
            //   ?DW_AT_associated
            //   ?DW_AT_data_location
            //   ?DW_AT_description
            //   ?DW_AT_start_scope
            //   ?DW_AT_visibility
            //   * = Optional

            None
        }
        // Enum
        constants::DW_TAG_enumeration_type => {
            // All base types have:
            //   DW_AT_byte_size
            //   *DW_AT_name
            //   *DW_AT_enum_class
            //   *DW_AT_type
            //   ?DW_AT_abstract_origin
            //   ?DW_AT_accessibility
            //   ?DW_AT_allocated
            //   ?DW_AT_associated
            //   ?DW_AT_bit_size
            //   ?DW_AT_bit_stride
            //   ?DW_AT_byte_stride
            //   ?DW_AT_data_location
            //   ?DW_AT_declaration
            //   ?DW_AT_description
            //   ?DW_AT_sibling
            //   ?DW_AT_signature
            //   ?DW_AT_specification
            //   ?DW_AT_start_scope
            //   ?DW_AT_visibility
            //   * = Optional

            // Children of enumeration_types are enumerators which contain:
            //  DW_AT_name
            //  DW_AT_const_value
            //  *DW_AT_description

            let mut enumeration_builder = EnumerationBuilder::new();

            let mut tree = unit.entries_tree(Some(entry.offset())).unwrap();
            let mut children = tree.root().unwrap().children();
            while let Ok(Some(child)) = children.next() {
                if child.entry().tag() == constants::DW_TAG_enumerator {
                    let name = get_attr_string(&dwarf, &unit, &child.entry());
                    let value = get_attr_as_u64(
                        child
                            .entry()
                            .attr(constants::DW_AT_const_value)
                            .unwrap()
                            .unwrap(),
                    )
                    .unwrap();

                    enumeration_builder.insert(name, value);
                }
            }

            let enumeration = Enumeration::new(&enumeration_builder);

            Some(Type::enumeration(&enumeration))
        }
        // Basic types
        constants::DW_TAG_typedef => {
            // All base types have:
            //   DW_AT_name
            //   *DW_AT_type (TODO : Otherwise.....abstract origin?)
            //   * = Optional

            let name = get_attr_string(&dwarf, &unit, &entry);

            // TODO : Remove `if let` guard; types will always exist once this plugin is complete
            if let Some(thing) = debug_info_builder.get_type(parent.unwrap()) {
                Some(Type::named_type_from_type(name, thing.as_ref()))
            } else {
                let label_value = match entry.offset().to_unit_section_offset(unit) {
                    UnitSectionOffset::DebugInfoOffset(o) => o.0,
                    UnitSectionOffset::DebugTypesOffset(o) => o.0,
                };
                println!("Typedef for #0x{:08x} could not be created!", label_value);
                None
            }
        }
        constants::DW_TAG_pointer_type => {
            // All pointer types have:
            //   DW_AT_type
            //   *DW_AT_byte_size
            //   ?DW_AT_name
            //   ?DW_AT_address
            //   ?DW_AT_allocated
            //   ?DW_AT_associated
            //   ?DW_AT_data_location
            //   * = Optional

            // TODO : We assume the parent has a name?  Might we need to resolve it deeper?

            // TODO : Remove guards; types will always exist once this plugin is complete (except for void*)
            // TODO : use Type::pointer_of_width - BNCreatePointerTypeOfWidth instead, since pointers always give a width here
            let label_value = match entry.offset().to_unit_section_offset(unit) {
                UnitSectionOffset::DebugInfoOffset(o) => o.0,
                UnitSectionOffset::DebugTypesOffset(o) => o.0,
            };
            if let Some(parent) = parent {
                if let Some(parent_type) = debug_info_builder.get_type(parent) {
                    Some(Type::pointer_of_width(
                        Type::named_type_from_type(
                            get_attr_string(&dwarf, &unit, &unit.entry(parent).unwrap()),
                            parent_type.as_ref(),
                        )
                        .as_ref(),
                        get_attr_as_usize(entry.attr(constants::DW_AT_byte_size).unwrap().unwrap())
                            .unwrap(),
                        false,
                        false,
                        None,
                    ))
                } else {
                    println!("Pointer to #0x{:08x} could not be created!", label_value);
                    None
                }
            } else {
                Some(Type::pointer_of_width(
                    Type::void().as_ref(),
                    get_attr_as_usize(entry.attr(constants::DW_AT_byte_size).unwrap().unwrap())
                        .unwrap(),
                    false,
                    false,
                    None,
                ))
            }
        }
        constants::DW_TAG_array_type => {
            // All array types have:
            //    DW_AT_type
            //   *DW_AT_name
            //   *DW_AT_ordering
            //   *DW_AT_byte_stride or DW_AT_bit_stride
            //   *DW_AT_byte_size or DW_AT_bit_size
            //   *DW_AT_allocated
            //   *DW_AT_associated and
            //   *DW_AT_data_location
            //   * = Optional
            //   For multidimensional arrays, DW_TAG_subrange_type or DW_TAG_enumeration_type

            // TODO : How to do the name, if it has one?
            // TODO : size

            // TODO : Remove `if let` guard; types will always exist once this plugin is complete
            if let Some(thing) = debug_info_builder.get_type(parent.unwrap()) {
                Some(Type::array(thing.as_ref(), 0))
            } else {
                let label_value = match entry.offset().to_unit_section_offset(unit) {
                    UnitSectionOffset::DebugInfoOffset(o) => o.0,
                    UnitSectionOffset::DebugTypesOffset(o) => o.0,
                };
                println!("Array of #0x{:08x} could not be created!", label_value);
                None
            }
        }
        constants::DW_TAG_string_type => None,
        // Strange Types
        constants::DW_TAG_unspecified_type => Some(Type::void()),
        constants::DW_TAG_subroutine_type => {
            // All subroutine types have:
            //   *DW_AT_name
            //   *DW_AT_type (if not provided, void)
            //   *DW_AT_prototyped
            //   ?DW_AT_abstract_origin
            //   ?DW_AT_accessibility
            //   ?DW_AT_address_class
            //   ?DW_AT_allocated
            //   ?DW_AT_associated
            //   ?DW_AT_data_location
            //   ?DW_AT_declaration
            //   ?DW_AT_description
            //   ?DW_AT_sibling
            //   ?DW_AT_start_scope
            //   ?DW_AT_visibility
            //   * = Optional

            // May have children, including DW_TAG_formal_parameters, which all have:
            //   *DW_AT_type
            //   * = Optional
            // or is otherwise DW_TAG_unspecified_parameters

            None
        }
        // Unusual Types
        constants::DW_TAG_ptr_to_member_type => None,
        constants::DW_TAG_set_type => None,
        constants::DW_TAG_subrange_type => None,
        constants::DW_TAG_file_type => None,
        constants::DW_TAG_thrown_type => None,
        constants::DW_TAG_interface_type => None,
        // Weird types
        constants::DW_TAG_reference_type => None, // This is the l-value for the complimentary r-value following in the if-else chain
        constants::DW_TAG_rvalue_reference_type => None,
        constants::DW_TAG_restrict_type => None,
        constants::DW_TAG_shared_type => None,
        constants::DW_TAG_volatile_type => None,
        constants::DW_TAG_packed_type => None,
        constants::DW_TAG_const_type => {
            // All const types have:
            //   ?DW_AT_allocated
            //   ?DW_AT_associated
            //   ?DW_AT_data_location
            //   ?DW_AT_name
            //   ?DW_AT_sibling
            //   ?DW_AT_type

            // TODO : Maybe make helper function for parent offset -> Type
            if let Some(parent_offset) = parent {
                if let Some(parent_type) = debug_info_builder.get_type(parent_offset) {
                    Some((*parent_type).to_builder().set_const(true).finalize())
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => {
            result = parent;
            None
        }
    };

    // Wrap our resultant type in a TypeInfo so that the internal DebugInfo class can manage it
    if let Some(type_def) = type_def {
        debug_info_builder.add_type(entry.offset(), type_def);
    }
    result
}
