// Copyright 2021-2024 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::dwarfdebuginfo::{DebugInfoBuilder, DebugInfoBuilderContext, TypeUID};
use crate::types::get_type;
use crate::{helpers::*, ReaderType};

use binaryninja::{
    rc::*,
    types::{EnumerationBuilder, FunctionParameter, ReferenceType, Type, TypeBuilder},
};

use gimli::Dwarf;
use gimli::{constants, AttributeValue::Encoding, DebuggingInformationEntry, Unit};

pub(crate) fn handle_base_type<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
) -> Option<Ref<Type>> {
    // All base types have:
    //   DW_AT_encoding (our concept of type_class)
    //   DW_AT_byte_size and/or DW_AT_bit_size
    //   *DW_AT_name
    //   *DW_AT_endianity (assumed default for arch)
    //   *DW_AT_data_bit_offset (assumed 0)
    //   *Some indication of signedness?
    //   * = Optional

    let name = debug_info_builder_context.get_name(dwarf, unit, entry)?;
    let size = get_size_as_usize(entry)?;
    match entry.attr_value(constants::DW_AT_encoding) {
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
                constants::DW_ATE_decimal_float => Some(Type::named_float(size, name)),
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

pub(crate) fn handle_enum<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
) -> Option<Ref<Type>> {
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
            let name = debug_info_builder_context.get_name(dwarf, unit, child.entry())?;
            match &child.entry().attr(constants::DW_AT_const_value) {
                Ok(Some(attr)) => {
                    if let Some(value) = get_attr_as_u64(attr) {
                        enumeration_builder.insert(name, value);
                    } else {
                        // Somehow the child entry is not a const value.
                        log::error!("Unhandled enum member value type for `{}`", name);
                    }
                }
                Ok(None) => {
                    // Somehow the child entry does not have a const value.
                    log::error!("Enum member `{}` has no constant value attribute", name);
                }
                Err(e) => {
                    log::error!("Error parsing next attribute entry for `{}`: {}", name, e);
                    return None;
                }
            }
        }
    }

    let width = match get_size_as_usize(entry).unwrap_or(8) {
        0 => debug_info_builder_context.default_address_size(),
        x => x,
    };

    Some(Type::enumeration(
        &enumeration_builder.finalize(),
        // TODO: This looks bad, look at the comment in [`Type::width`].
        width.try_into().expect("Enum cannot be zero width"),
        false,
    ))
}

pub(crate) fn handle_typedef(
    debug_info_builder: &mut DebugInfoBuilder,
    entry_type: Option<TypeUID>,
    typedef_name: &str,
) -> (Option<Ref<Type>>, bool) {
    // All base types have:
    //   DW_AT_name
    //   *DW_AT_type
    //   * = Optional

    // This will fail in the case where we have a typedef to a type that doesn't exist (failed to parse, incomplete, etc)
    if let Some(entry_type_offset) = entry_type {
        if let Some(t) = debug_info_builder.get_type(entry_type_offset) {
            return (Some(t.get_type()), typedef_name != t.name);
        }
    }

    // 5.3: "typedef represents a declaration of the type that is not also a definition"
    (None, false)
}

pub(crate) fn handle_pointer<R: ReaderType>(
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
    entry_type: Option<TypeUID>,
    reference_type: ReferenceType,
) -> Option<Ref<Type>> {
    // All pointer types have:
    //   DW_AT_type
    //   *DW_AT_byte_size
    //   ?DW_AT_name
    //   ?DW_AT_address
    //   ?DW_AT_allocated
    //   ?DW_AT_associated
    //   ?DW_AT_data_location
    //   * = Optional

    if let Some(pointer_size) = get_size_as_usize(entry) {
        if let Some(entry_type_offset) = entry_type {
            let parent_type = debug_info_builder
                .get_type(entry_type_offset)
                .unwrap()
                .get_type();
            Some(Type::pointer_of_width(
                parent_type.as_ref(),
                pointer_size,
                false,
                false,
                Some(reference_type),
            ))
        } else {
            Some(Type::pointer_of_width(
                Type::void().as_ref(),
                pointer_size,
                false,
                false,
                Some(reference_type),
            ))
        }
    } else if let Some(entry_type_offset) = entry_type {
        let parent_type = debug_info_builder
            .get_type(entry_type_offset)
            .unwrap()
            .get_type();
        Some(Type::pointer_of_width(
            parent_type.as_ref(),
            debug_info_builder_context.default_address_size(),
            false,
            false,
            Some(reference_type),
        ))
    } else {
        Some(Type::pointer_of_width(
            Type::void().as_ref(),
            debug_info_builder_context.default_address_size(),
            false,
            false,
            Some(reference_type),
        ))
    }
}

pub(crate) fn handle_array<R: ReaderType>(
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder: &mut DebugInfoBuilder,
    entry_type: Option<TypeUID>,
) -> Option<Ref<Type>> {
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

    if let Some(entry_type_offset) = entry_type {
        let parent_type = debug_info_builder
            .get_type(entry_type_offset)
            .unwrap()
            .get_type();

        let mut tree = unit.entries_tree(Some(entry.offset())).unwrap();
        let mut children = tree.root().unwrap().children();

        // TODO : This is currently applying the size in reverse order
        let mut result_type: Option<Ref<Type>> = None;
        while let Ok(Some(child)) = children.next() {
            if let Some(inner_type) = result_type {
                result_type = Some(Type::array(
                    inner_type.as_ref(),
                    get_subrange_size(child.entry()),
                ));
            } else {
                result_type = Some(Type::array(
                    parent_type.as_ref(),
                    get_subrange_size(child.entry()),
                ));
            }
        }

        result_type.map_or(Some(Type::array(parent_type.as_ref(), 0)), Some)
    } else {
        None
    }
}

pub(crate) fn handle_function<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
    entry_type: Option<TypeUID>,
) -> Option<Ref<Type>> {
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

    let return_type = match entry_type {
        Some(entry_type_offset) => debug_info_builder
            .get_type(entry_type_offset)
            .expect("Subroutine return type was not processed")
            .get_type(),
        None => Type::void(),
    };

    // Alias function type in the case that it contains itself
    let name = debug_info_builder_context
        .get_name(dwarf, unit, entry)
        .unwrap_or("_unnamed_func".to_string());
    let ntr =
        Type::named_type_from_type(&name, &Type::function(return_type.as_ref(), vec![], false));
    debug_info_builder.add_type(get_uid(dwarf, unit, entry), name, ntr, false);

    let mut parameters: Vec<FunctionParameter> = vec![];
    let mut variable_arguments = false;

    // Get all the children and populate
    let mut tree = unit.entries_tree(Some(entry.offset())).unwrap();
    let mut children = tree.root().unwrap().children();
    while let Ok(Some(child)) = children.next() {
        if child.entry().tag() == constants::DW_TAG_formal_parameter {
            if let (Some(child_uid), Some(name)) = {
                (
                    get_type(
                        dwarf,
                        unit,
                        child.entry(),
                        debug_info_builder_context,
                        debug_info_builder,
                    ),
                    debug_info_builder_context.get_name(dwarf, unit, child.entry()),
                )
            } {
                let child_type = debug_info_builder.get_type(child_uid).unwrap().get_type();
                parameters.push(FunctionParameter::new(child_type, name, None));
            }
        } else if child.entry().tag() == constants::DW_TAG_unspecified_parameters {
            variable_arguments = true;
        }
    }

    // Remove the aliased type from the builder.
    debug_info_builder.remove_type(get_uid(dwarf, unit, entry));

    Some(Type::function(
        return_type.as_ref(),
        parameters,
        variable_arguments,
    ))
}

pub(crate) fn handle_const(
    debug_info_builder: &mut DebugInfoBuilder,
    entry_type: Option<TypeUID>,
) -> Option<Ref<Type>> {
    // All const types have:
    //   ?DW_AT_allocated
    //   ?DW_AT_associated
    //   ?DW_AT_data_location
    //   ?DW_AT_name
    //   ?DW_AT_sibling
    //   ?DW_AT_type

    if let Some(entry_type_offset) = entry_type {
        let parent_type = debug_info_builder
            .get_type(entry_type_offset)
            .unwrap()
            .get_type();
        Some((*parent_type).to_builder().set_const(true).finalize())
    } else {
        Some(TypeBuilder::void().set_const(true).finalize())
    }
}

pub(crate) fn handle_volatile(
    debug_info_builder: &mut DebugInfoBuilder,
    entry_type: Option<TypeUID>,
) -> Option<Ref<Type>> {
    // All const types have:
    //   ?DW_AT_allocated
    //   ?DW_AT_associated
    //   ?DW_AT_data_location
    //   ?DW_AT_name
    //   ?DW_AT_sibling
    //   ?DW_AT_type

    if let Some(entry_type_offset) = entry_type {
        let parent_type = debug_info_builder
            .get_type(entry_type_offset)
            .unwrap()
            .get_type();
        Some((*parent_type).to_builder().set_volatile(true).finalize())
    } else {
        Some(TypeBuilder::void().set_volatile(true).finalize())
    }
}
