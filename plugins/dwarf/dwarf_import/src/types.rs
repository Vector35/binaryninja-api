// Copyright 2021-2026 Vector 35 Inc.
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
use crate::helpers::*;
use crate::{die_handlers::*, ReaderType};

use binaryninja::{
    rc::*,
    types::{
        BaseStructure, MemberAccess, MemberScope, ReferenceType, StructureBuilder, StructureType,
        Type, TypeClass,
    },
};

use gimli::{constants, AttributeValue, DebuggingInformationEntry, DwAt, Dwarf, Operation, Unit};

pub(crate) fn parse_variable<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
    function_index: Option<usize>,
    lexical_block: Option<&iset::IntervalSet<u64>>,
) {
    let full_name = debug_info_builder_context.get_name(dwarf, unit, entry);
    let type_uid = get_type(
        dwarf,
        unit,
        entry,
        debug_info_builder_context,
        debug_info_builder,
    );

    let Ok(Some(attr)) = entry.attr(constants::DW_AT_location) else {
        return;
    };

    let AttributeValue::Exprloc(mut expression) = attr.value() else {
        return;
    };

    match Operation::parse(&mut expression.0, unit.encoding()) {
        Ok(Operation::FrameOffset { offset }) => {
            debug_info_builder.add_stack_variable(
                function_index,
                offset,
                full_name,
                type_uid,
                lexical_block,
            );
        }
        //Ok(Operation::RegisterOffset { register: _, offset: _, base_type: _ }) => {
        //    //TODO: look up register by index (binja register indexes don't match processor indexes?)
        //    //TODO: calculate absolute stack offset
        //    //TODO: add by absolute offset
        //},
        Ok(Operation::Address { address }) => {
            if let Some(uid) = type_uid {
                debug_info_builder.add_data_variable(address, full_name, uid)
            }
        }
        Ok(Operation::AddressIndex { index }) => {
            if let Some(uid) = type_uid {
                if let Ok(address) = dwarf.address(unit, index) {
                    debug_info_builder.add_data_variable(address, full_name, uid)
                } else {
                    tracing::warn!("Invalid index into IAT: {}", index.0);
                }
            }
        }
        Ok(Operation::ImplicitValue { data }) => {
            debug!(
                "Unhandled operation type ImplicitValue with data length {} for variable",
                data.len()
            );
        }
        Ok(Operation::EntryValue { expression }) => {
            debug!(
                "Unhandled operation type EntryValue with expression length {} for variable",
                expression.len()
            );
        }
        Ok(op) => {
            tracing::debug!("Unhandled operation type for variable: {:?}", op);
        }
        Err(e) => tracing::error!(
            "Error parsing operation type for variable {:?}: {}",
            full_name,
            e
        ),
    }
}

fn do_structure_parse<R: ReaderType>(
    dwarf: &Dwarf<R>,
    structure_type: StructureType,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
) -> Option<usize> {
    // All struct, union, and class types will have:
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

    // Structure/Class/Union _Children_ consist of:
    //  Data members:
    //   DW_AT_type
    //   *DW_AT_name
    //   *DW_AT_accessibility (default private for classes, public for everything else)
    //   *DW_AT_mutable
    //   *DW_AT_data_member_location xor *DW_AT_data_bit_offset (otherwise assume zero) <- there are some deprecations for DWARF 4
    //   *DW_AT_byte_size xor DW_AT_bit_size, iff the storage size is different than it usually would be for the given member type
    //  Function members:
    //   *DW_AT_accessibility (default private for classes, public for everything else)
    //   *DW_AT_virtuality (assume false)
    //      If true: DW_AT_vtable_elem_location
    //   *DW_AT_explicit (assume false)
    //   *DW_AT_object_pointer (assume false; for non-static member function; references the formal parameter that has "DW_AT_artificial = true" and represents "self" or "this" (language specified))
    //   *DW_AT_specification
    //   * = Optional

    if let Ok(Some(_)) = entry.attr(constants::DW_AT_declaration) {
        return None;
    }

    let full_name = if get_name(dwarf, unit, entry, debug_info_builder_context).is_some() {
        debug_info_builder_context.get_name(dwarf, unit, entry)
    } else {
        None
    };

    // Create structure with proper size
    let size = get_size_as_u64(entry).unwrap_or(0);
    let mut structure_builder = StructureBuilder::new();
    structure_builder
        .packed(true)
        .width(size)
        .structure_type(structure_type);

    // This reference type will be used by any children to grab while we're still building this type
    //  it will also be how any other types refer to this struct
    if let Some(full_name) = &full_name {
        let ntr =
            Type::named_type_from_type(full_name, &Type::structure(&structure_builder.finalize()));
        debug_info_builder.add_type(
            get_uid(dwarf, unit, entry),
            full_name.to_owned(),
            ntr,
            false,
            None,
        );
    } else {
        // We _need_ to have initial typedefs or else we can enter infinite parsing loops
        // These get overwritten in the last step with the actual type, however, so this
        // is either perfectly fine or breaking a bunch of NTRs
        let full_name = format!("anonymous_structure_{:x}", get_uid(dwarf, unit, entry));
        let ntr =
            Type::named_type_from_type(&full_name, &Type::structure(&structure_builder.finalize()));
        debug_info_builder.add_type(get_uid(dwarf, unit, entry), full_name, ntr, false, None);
    }

    // Get all the children and base classes to populate
    let mut base_structures = Vec::new();
    let mut tree = match unit.entries_tree(Some(entry.offset())) {
        Ok(x) => x,
        Err(e) => {
            tracing::error!("Failed to get structure entry tree: {}", e);
            return None;
        }
    };
    let tree_root = match tree.root() {
        Ok(x) => x,
        Err(e) => {
            tracing::error!("Failed to get structure entry tree root: {}", e);
            return None;
        }
    };
    let mut children = tree_root.children();
    while let Ok(Some(child)) = children.next() {
        let child_entry = child.entry();
        match child_entry.tag() {
            constants::DW_TAG_member => {
                let Some(child_type_id) = get_type(
                    dwarf,
                    unit,
                    child_entry,
                    debug_info_builder_context,
                    debug_info_builder,
                ) else {
                    continue;
                };

                let Some(child_dbg_ty) = debug_info_builder.get_type(child_type_id) else {
                    continue;
                };
                let child_type = child_dbg_ty.get_type();

                let Some(child_name) = debug_info_builder_context
                    .get_name(dwarf, unit, child_entry)
                    .or_else(|| match child_type.type_class() {
                        TypeClass::StructureTypeClass => Some(String::new()),
                        _ => None,
                    })
                else {
                    continue;
                };

                if let Ok(Some(raw_struct_offset)) =
                    child_entry.attr(constants::DW_AT_data_member_location)
                {
                    let Some(struct_offset_bytes) = get_attr_as_u64(&raw_struct_offset)
                        .or_else(|| get_expr_value(unit, raw_struct_offset))
                    else {
                        tracing::warn!(
                            "Failed to get DW_AT_data_member_location for offset {:#x} in unit {:?}",
                            child_entry.offset().0,
                            unit.header.offset()
                        );
                        continue;
                    };

                    structure_builder.insert(
                        &child_type,
                        &child_name,
                        struct_offset_bytes,
                        false,
                        MemberAccess::NoAccess, // TODO : Resolve actual scopes, if possible
                        MemberScope::NoScope,
                    );
                } else {
                    let select_value =
                        |e: &DebuggingInformationEntry<R>, attr: DwAt| -> Option<u64> {
                            get_attr_as_u64(&e.attr(attr).ok()??)
                        };

                    // If no byte offset, try the bitfield using DW_AT_bit_offset/DW_AT_data_bit_offset + DW_AT_bit_size
                    let bit_size = select_value(child_entry, constants::DW_AT_bit_size);
                    let bit_offset = select_value(child_entry, constants::DW_AT_bit_offset);
                    let data_bit_offset =
                        select_value(child_entry, constants::DW_AT_data_bit_offset);

                    match (bit_size, bit_offset, data_bit_offset) {
                        (Some(bit_size), Some(bit_offset), _) => {
                            // Heuristic storage unit bits from the member type width (bytes -> bits). Fallback to 8.
                            let storage_bits = {
                                let w = child_type.width();
                                if w > 0 {
                                    w * 8
                                } else {
                                    8
                                }
                            };

                            // DW_AT_bit_offset is from the MSB of the storage unit:
                            // absolute = base_byte_off*8 + storage_bits - (boffs + bit_sz)
                            // With no base_byte_off available here, treat base as 0.
                            let total_bit_off = storage_bits.saturating_sub(bit_offset + bit_size);

                            structure_builder.insert_bitwise(
                                &child_type,
                                &child_name,
                                total_bit_off,
                                Some(bit_size as u8),
                                false,
                                MemberAccess::NoAccess,
                                MemberScope::NoScope,
                            );
                        }
                        (Some(bit_size), None, Some(data_bit_offset)) => {
                            structure_builder.insert_bitwise(
                                &child_type,
                                &child_name,
                                data_bit_offset,
                                Some(bit_size as u8),
                                false,
                                MemberAccess::NoAccess,
                                MemberScope::NoScope,
                            );
                        }
                        _ => {
                            structure_builder.append(
                                &child_type,
                                &child_name,
                                MemberAccess::NoAccess,
                                MemberScope::NoScope,
                            );
                        }
                    }
                }
            }
            constants::DW_TAG_inheritance => {
                let Some(base_type_id) = get_type(
                    dwarf,
                    unit,
                    child_entry,
                    debug_info_builder_context,
                    debug_info_builder,
                ) else {
                    tracing::warn!("Failed to get base type for inheritance");
                    continue;
                };
                let Some(base_dbg_ty) = debug_info_builder.get_type(base_type_id) else {
                    continue;
                };
                let base_type = base_dbg_ty.get_type();

                let Ok(Some(raw_data_member_location)) =
                    child_entry.attr(constants::DW_AT_data_member_location)
                else {
                    tracing::warn!("Failed to get DW_AT_data_member_location for inheritance");
                    continue;
                };

                let base_offset = get_attr_as_u64(&raw_data_member_location).unwrap_or_else(|| {
                    get_expr_value(unit, raw_data_member_location).unwrap_or_default()
                });

                if let Some(ntr) = base_type.get_named_type_reference() {
                    let base_struct = BaseStructure::new(ntr, base_offset, 0);
                    base_structures.push(base_struct);
                }
            }
            _ => {}
        }
    }

    structure_builder.base_structures(&base_structures);
    let finalized_structure = Type::structure(&structure_builder.finalize());
    if let Some(full_name) = full_name {
        debug_info_builder.add_type(
            get_uid(dwarf, unit, entry) + 1, // TODO : This is super broke (uid + 1 is not guaranteed to be unique)
            full_name,
            finalized_structure,
            true,
            None,
        );
    } else {
        debug_info_builder.add_type(
            get_uid(dwarf, unit, entry),
            finalized_structure.to_string(),
            finalized_structure,
            false, // Don't commit anonymous unions (because I think it'll break things)
            None,
        );
    }
    Some(get_uid(dwarf, unit, entry))
}

// This function iterates up through the dependency references, adding all the types along the way until there are no more or stopping at the first one already tracked, then returns the UID of the type of the given DIE
pub(crate) fn get_type<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
) -> Option<TypeUID> {
    // If this node (and thus all its referenced nodes) has already been processed, just return the offset
    let entry_uid = get_uid(dwarf, unit, entry);
    if debug_info_builder.contains_type(entry_uid) {
        return Some(entry_uid);
    }

    // Don't parse types that are just declarations and not definitions
    if let Ok(Some(_)) = entry.attr(constants::DW_AT_declaration) {
        return None;
    }

    let entry_type = if let Some(die_reference) = get_attr_die(
        dwarf,
        unit,
        entry,
        debug_info_builder_context,
        constants::DW_AT_type,
    ) {
        // This needs to recurse first (before the early return below) to ensure all sub-types have been parsed
        match die_reference {
            DieReference::UnitAndOffset((dwarf, entry_unit, entry_offset)) => {
                let resolved_entry = match entry_unit.entry(entry_offset) {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::error!(
                            "Failed to resolve entry in unit {:?} at offset {:#x}: {}",
                            entry_unit.header.offset(),
                            entry_offset.0,
                            e
                        );
                        return None;
                    }
                };
                get_type(
                    dwarf,
                    entry_unit,
                    &resolved_entry,
                    debug_info_builder_context,
                    debug_info_builder,
                )
            }
            DieReference::Err => {
                tracing::warn!("Failed to fetch DIE when getting type through DW_AT_type. Debug information may be incomplete.");
                None
            }
        }
    } else if let Some(die_reference) = get_attr_die(
        dwarf,
        unit,
        entry,
        debug_info_builder_context,
        constants::DW_AT_abstract_origin,
    ) {
        // This needs to recurse first (before the early return below) to ensure all sub-types have been parsed
        match die_reference {
            DieReference::UnitAndOffset((dwarf, entry_unit, entry_offset)) => {
                let resolved_entry = match entry_unit.entry(entry_offset) {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::error!(
                            "Failed to resolve entry in unit {:?} at offset {:#x}: {}",
                            entry_unit.header.offset(),
                            entry_offset.0,
                            e
                        );
                        return None;
                    }
                };
                get_type(
                    dwarf,
                    entry_unit,
                    &resolved_entry,
                    debug_info_builder_context,
                    debug_info_builder,
                )
            }
            DieReference::Err => {
                tracing::warn!("Failed to fetch DIE when getting type through DW_AT_abstract_origin. Debug information may be incomplete.");
                None
            }
        }
    } else {
        // This needs to recurse first (before the early return below) to ensure all sub-types have been parsed
        match resolve_specification(dwarf, unit, entry, debug_info_builder_context) {
            DieReference::UnitAndOffset((dwarf, entry_unit, entry_offset))
                if entry_unit.header.offset() != unit.header.offset()
                    && entry_offset != entry.offset() =>
            {
                let resolved_entry = match entry_unit.entry(entry_offset) {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::error!(
                            "Failed to resolve entry in unit {:?} at offset {:#x}: {}",
                            entry_unit.header.offset(),
                            entry_offset.0,
                            e
                        );
                        return None;
                    }
                };
                get_type(
                    dwarf,
                    entry_unit,
                    &resolved_entry,
                    debug_info_builder_context,
                    debug_info_builder,
                )
            }
            DieReference::UnitAndOffset(_) => None,
            DieReference::Err => {
                tracing::warn!(
                    "Failed to fetch DIE when getting type. Debug information may be incomplete."
                );
                None
            }
        }
    };

    // If this node (and thus all its referenced nodes) has already been processed, just return the offset
    // This check is not redundant because this type might have been processes in the recursive calls above
    if debug_info_builder.contains_type(entry_uid) {
        return Some(entry_uid);
    }

    // Collect the required information to create a type and add it to the type map. Also, add the dependencies of this type to the type's typeinfo
    // Create the type, make a TypeInfo for it, and add it to the debug info
    let (type_def, mut commit): (Option<Ref<Type>>, bool) = match entry.tag() {
        constants::DW_TAG_base_type => (
            handle_base_type(dwarf, unit, entry, debug_info_builder_context),
            false,
        ),

        constants::DW_TAG_structure_type => {
            return do_structure_parse(
                dwarf,
                StructureType::StructStructureType,
                unit,
                entry,
                debug_info_builder_context,
                debug_info_builder,
            )
        }
        constants::DW_TAG_class_type => {
            return do_structure_parse(
                dwarf,
                StructureType::ClassStructureType,
                unit,
                entry,
                debug_info_builder_context,
                debug_info_builder,
            )
        }
        constants::DW_TAG_union_type => {
            return do_structure_parse(
                dwarf,
                StructureType::UnionStructureType,
                unit,
                entry,
                debug_info_builder_context,
                debug_info_builder,
            )
        }

        // Enum
        constants::DW_TAG_enumeration_type => (
            handle_enum(dwarf, unit, entry, debug_info_builder_context),
            true,
        ),

        // Basic types
        constants::DW_TAG_typedef => {
            if let Some(name) = debug_info_builder_context.get_name(dwarf, unit, entry) {
                handle_typedef(debug_info_builder, entry_type, &name)
            } else {
                (None, false)
            }
        }
        constants::DW_TAG_pointer_type => (
            handle_pointer(
                entry,
                debug_info_builder_context,
                debug_info_builder,
                entry_type,
                ReferenceType::PointerReferenceType,
            ),
            false,
        ),
        constants::DW_TAG_reference_type => (
            handle_pointer(
                entry,
                debug_info_builder_context,
                debug_info_builder,
                entry_type,
                ReferenceType::ReferenceReferenceType,
            ),
            false,
        ),
        constants::DW_TAG_rvalue_reference_type => (
            handle_pointer(
                entry,
                debug_info_builder_context,
                debug_info_builder,
                entry_type,
                ReferenceType::RValueReferenceType,
            ),
            false,
        ),
        constants::DW_TAG_array_type => (
            handle_array(unit, entry, debug_info_builder, entry_type),
            false,
        ),

        // Strange Types
        constants::DW_TAG_unspecified_type => (Some(Type::void()), false),
        constants::DW_TAG_subroutine_type => (
            handle_function(
                dwarf,
                unit,
                entry,
                debug_info_builder_context,
                debug_info_builder,
                entry_type,
            ),
            false,
        ),

        // Weird types
        constants::DW_TAG_const_type => (handle_const(debug_info_builder, entry_type), false),
        constants::DW_TAG_volatile_type => (handle_volatile(debug_info_builder, entry_type), true), // TODO : Maybe false here

        // Pass-through everything else!
        _ => return entry_type,
    };

    // Wrap our resultant type in a TypeInfo so that the internal DebugInfo class can manage it
    if let Some(type_def) = type_def {
        let name = if get_name(dwarf, unit, entry, debug_info_builder_context).is_some() {
            debug_info_builder_context.get_name(dwarf, unit, entry)
        } else {
            None
        }
        .unwrap_or_else(|| {
            commit = false;
            type_def.to_string()
        });

        debug_info_builder.add_type(entry_uid, name, type_def, commit, entry_type);
        Some(entry_uid)
    } else {
        None
    }
}
