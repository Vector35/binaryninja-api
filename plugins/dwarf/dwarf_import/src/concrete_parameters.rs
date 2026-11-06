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

//! Signatures of concrete function instances, reconstructed from where their parameters arrive.
//!
//! A concrete instance of a function (an out-of-line DIE with `DW_AT_abstract_origin`) can take
//! different arguments than the source declaration it refers to. GCC's IPA clones (`.isra`,
//! `.constprop`, `.part`) remove parameters, reorder them, or replace one with a piece of it that has
//! no DIE of its own. The declaration's parameter list then misdescribes the code at that address.
//!
//! This module rebuilds the signature from evidence instead of from the declaration: each parameter's
//! location at the function's entry PC is mapped through the architecture's DWARF register numbering
//! and the platform's calling convention to an argument slot. A slot that is passed but has no DIE
//! (a replacement piece) stays an unnamed gap rather than shifting later parameters into it. A
//! parameter GCC marks as removed (`DW_OP_GNU_parameter_ref`) takes no slot.
//!
//! The located slots fix where the named parameters are, but when a parameter was removed they are only
//! a lower bound on how many arguments the clone takes: a replacement piece can follow the last located
//! slot without any DWARF evidence. Such signatures are padded with unnamed placeholders up to the
//! source parameter count (see ConcreteParameter::Placeholder) rather than claimed exact.
//!
//! Anything this cannot place with confidence (stack arguments, pieces, constants, a parameter with no
//! location at entry, an aggregate return that may use a hidden pointer, an unsupported architecture)
//! gives up, and the caller keeps the existing behavior for that function.

use std::collections::HashMap;

use binaryninja::architecture::{Architecture, Register};
use binaryninja::binary_view::BinaryView;
use binaryninja::calling_convention::CallingConvention;
use gimli::{constants, AttributeValue, DebuggingInformationEntry, Dwarf, Expression, Operation, Unit};

use crate::dwarfdebuginfo::{DebugInfoBuilder, DebugInfoBuilderContext, TypeUID};
use crate::helpers::{get_attr_die, DieReference};
use crate::types::get_type;
use crate::ReaderType;

/// One argument slot of a reconstructed signature, in calling-convention order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ConcreteParameter {
    /// A DWARF parameter that arrives in this slot.
    Named { name: String, type_uid: TypeUID },
    /// A slot that is passed (a later slot is a known parameter) but that no DIE describes, such as a
    /// piece of a parameter that GCC's IPA-SRA passes instead of the whole. Its type is not known.
    Gap { size: usize },
    /// A speculative compatibility placeholder after the last located parameter. When GCC removed a
    /// parameter, it may pass a replacement piece in a slot past every parameter DWARF locates, and
    /// DWARF does not say whether it does. The located slots are therefore only a lower bound on the
    /// clone's arity, so the signature is padded with placeholders up to the source parameter count:
    /// that never drops an argument the declaration's signature had, but a placeholder may be a slot
    /// that is not actually passed. The located parameters' slots are unaffected.
    Placeholder { size: usize },
}

/// Maps DWARF register numbers to integer argument slots of the platform's default calling convention.
pub(crate) struct ArgumentRegisters {
    slots: HashMap<u16, usize>,
    register_size: usize,
}

// DWARF register numbers 0-15 for x86-64 (System V psABI, also used by MinGW).
const X86_64_DWARF_REGISTERS: [&str; 16] = [
    "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

impl ArgumentRegisters {
    /// Returns None for architectures whose DWARF register numbering is not mapped here; their
    /// concrete instances keep the existing behavior.
    pub(crate) fn for_view(bv: &BinaryView) -> Option<Self> {
        let platform = bv.default_platform()?;
        let arch = platform.arch();
        let (dwarf_names, register_size): (&[&str], usize) = match arch.name().as_str() {
            "x86_64" => (&X86_64_DWARF_REGISTERS, 8),
            _ => return None,
        };
        let calling_convention = platform.get_default_calling_convention()?;
        let arg_names: Vec<String> = calling_convention
            .int_arg_registers()
            .iter()
            .filter_map(|id| arch.register_from_id(*id))
            .map(|reg| reg.name().to_string())
            .collect();

        let mut slots = HashMap::new();
        for (dwarf_number, name) in dwarf_names.iter().enumerate() {
            if let Some(slot) = arg_names.iter().position(|arg| arg == name) {
                slots.insert(dwarf_number as u16, slot);
            }
        }
        if slots.is_empty() {
            return None;
        }
        Some(Self {
            slots,
            register_size,
        })
    }
}

/// Where a parameter is at the function's entry PC.
enum EntryLocation {
    /// In a register (DWARF number).
    Register(u16),
    /// GCC removed it from this instance (`DW_OP_GNU_parameter_ref`): nothing is passed for it.
    Removed,
    /// Anything else: no location covering the entry, stack, pieces, constants, ...
    Unsupported,
}

fn classify_expression<R: ReaderType>(expression: Expression<R>, unit: &Unit<R>) -> EntryLocation {
    let mut operations = expression.operations(unit.encoding());
    let mut ops = vec![];
    loop {
        match operations.next() {
            Ok(Some(op)) => {
                ops.push(op);
                if ops.len() > 2 {
                    return EntryLocation::Unsupported;
                }
            }
            Ok(None) => break,
            // A malformed expression must not be classified by the prefix that did decode.
            Err(_) => return EntryLocation::Unsupported,
        }
    }

    match ops.as_slice() {
        [Operation::Register { register }] => EntryLocation::Register(register.0),
        // At the entry PC, the entry value of a register is that register.
        [Operation::EntryValue { expression }, Operation::StackValue] => {
            let mut inner = Expression(expression.clone()).operations(unit.encoding());
            match (inner.next(), inner.next()) {
                (Ok(Some(Operation::Register { register })), Ok(None)) => {
                    EntryLocation::Register(register.0)
                }
                _ => EntryLocation::Unsupported,
            }
        }
        [Operation::ParameterRef { .. }, Operation::StackValue] => EntryLocation::Removed,
        _ => EntryLocation::Unsupported,
    }
}

fn entry_location<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    parameter: &DebuggingInformationEntry<R>,
    entry_pc: u64,
) -> EntryLocation {
    let value = match parameter.attr_value(constants::DW_AT_location) {
        Ok(Some(value)) => value,
        _ => return EntryLocation::Unsupported,
    };
    if let AttributeValue::Exprloc(expression) = value {
        return classify_expression(expression, unit);
    }

    let Ok(Some(offset)) = dwarf.attr_locations_offset(unit, value) else {
        return EntryLocation::Unsupported;
    };
    let Ok(mut locations) = dwarf.locations(unit, offset) else {
        return EntryLocation::Unsupported;
    };
    loop {
        match locations.next() {
            Ok(Some(location)) => {
                if (location.range.begin <= entry_pc) && (entry_pc < location.range.end) {
                    return classify_expression(location.data, unit);
                }
            }
            _ => return EntryLocation::Unsupported,
        }
    }
}

/// Whether `entry` has `attr`, or None if the attribute cannot be read.
fn has_attribute<R: ReaderType>(entry: &DebuggingInformationEntry<R>, attr: constants::DwAt) -> Option<bool> {
    match entry.attr_value(attr) {
        Ok(Some(_)) => Some(true),
        Ok(None) => Some(false),
        Err(_) => None,
    }
}

/// True if the function may return a structure, union, class, or array, which may be returned through
/// a hidden pointer argument that occupies the first argument slot. Anything that cannot be resolved
/// counts as an aggregate, so reconstruction falls back.
fn returns_aggregate<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
) -> bool {
    // Find the return type the way get_type does for a subprogram: its own DW_AT_type, else the one
    // inherited through DW_AT_abstract_origin, else through DW_AT_specification, at each step of the
    // chain. A chain with no DW_AT_type anywhere returns void.
    let mut current = (dwarf, unit, entry.offset());
    let mut reference = None;
    for _ in 0..32 {
        let (current_dwarf, current_unit, current_offset) = current;
        let Ok(current_entry) = current_unit.entry(current_offset) else {
            return true;
        };
        match has_attribute(&current_entry, constants::DW_AT_type) {
            Some(true) => {
                reference = get_attr_die(
                    current_dwarf,
                    current_unit,
                    &current_entry,
                    debug_info_builder_context,
                    constants::DW_AT_type,
                );
                break;
            }
            Some(false) => (),
            None => return true,
        }
        let inherited = match (
            has_attribute(&current_entry, constants::DW_AT_abstract_origin),
            has_attribute(&current_entry, constants::DW_AT_specification),
        ) {
            (Some(true), _) => constants::DW_AT_abstract_origin,
            (Some(false), Some(true)) => constants::DW_AT_specification,
            (Some(false), Some(false)) => return false,
            _ => return true,
        };
        match get_attr_die(
            current_dwarf,
            current_unit,
            &current_entry,
            debug_info_builder_context,
            inherited,
        ) {
            Some(DieReference::UnitAndOffset(next)) => current = next,
            _ => return true,
        }
    }

    // Look through typedefs and qualifiers. A qualifier with no DW_AT_type qualifies void.
    for _ in 0..32 {
        let Some(DieReference::UnitAndOffset((type_dwarf, type_unit, type_offset))) = reference else {
            return true;
        };
        let Ok(type_entry) = type_unit.entry(type_offset) else {
            return true;
        };
        match type_entry.tag() {
            constants::DW_TAG_structure_type
            | constants::DW_TAG_union_type
            | constants::DW_TAG_class_type
            | constants::DW_TAG_array_type => return true,
            constants::DW_TAG_typedef
            | constants::DW_TAG_const_type
            | constants::DW_TAG_volatile_type
            | constants::DW_TAG_restrict_type
            | constants::DW_TAG_atomic_type => {
                match has_attribute(&type_entry, constants::DW_AT_type) {
                    Some(true) => (),
                    Some(false) => return false,
                    None => return true,
                }
                reference = get_attr_die(
                    type_dwarf,
                    type_unit,
                    &type_entry,
                    debug_info_builder_context,
                    constants::DW_AT_type,
                );
            }
            _ => return false,
        }
    }
    // Conservatively treat an unresolved chain as an aggregate.
    true
}

/// Reconstructs the argument slots of a concrete function instance from its parameters' entry
/// locations. Returns None when the signature cannot be placed with confidence; see the module docs.
pub(crate) fn reconstruct_concrete_parameters<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    entry_pc: u64,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    debug_info_builder: &mut DebugInfoBuilder,
) -> Option<Vec<ConcreteParameter>> {
    let argument_registers = debug_info_builder_context.argument_registers()?;
    if !matches!(entry.attr_value(constants::DW_AT_abstract_origin), Ok(Some(_))) {
        return None;
    }
    if !entry.has_children() {
        return None;
    }
    // The entry PC must be the function's single low PC. A function split across ranges, or with an
    // explicit DW_AT_entry_pc, is left alone, as is one whose attributes cannot be read.
    if has_attribute(entry, constants::DW_AT_low_pc) != Some(true)
        || has_attribute(entry, constants::DW_AT_ranges) != Some(false)
        || has_attribute(entry, constants::DW_AT_entry_pc) != Some(false)
    {
        return None;
    }
    if returns_aggregate(dwarf, unit, entry, debug_info_builder_context) {
        return None;
    }

    let mut tree = unit.entries_tree(Some(entry.offset())).ok()?;
    let root = tree.root().ok()?;
    let mut children = root.children();
    let mut slots: HashMap<usize, ConcreteParameter> = HashMap::new();
    let mut parameter_count = 0;
    let mut removed_count = 0;
    loop {
        let child = match children.next() {
            Ok(Some(child)) => child,
            Ok(None) => break,
            // A child that cannot be read could be a parameter: do not reconstruct from the rest.
            Err(_) => return None,
        };
        match child.entry().tag() {
            constants::DW_TAG_unspecified_parameters => return None,
            constants::DW_TAG_formal_parameter => {
                parameter_count += 1;
                match entry_location(dwarf, unit, child.entry(), entry_pc) {
                    EntryLocation::Removed => removed_count += 1,
                    EntryLocation::Unsupported => return None,
                    EntryLocation::Register(register) => {
                        let slot = *argument_registers.slots.get(&register)?;
                        if slots.contains_key(&slot) {
                            return None;
                        }
                        let name = debug_info_builder_context
                            .get_name(dwarf, unit, child.entry())
                            .unwrap_or_default();
                        let type_uid = get_type(
                            dwarf,
                            unit,
                            child.entry(),
                            debug_info_builder_context,
                            debug_info_builder,
                        )
                        .unwrap_or(0);
                        slots.insert(slot, ConcreteParameter::Named { name, type_uid });
                    }
                }
            }
            _ => (),
        }
    }
    if parameter_count == 0 {
        return None;
    }

    let size = argument_registers.register_size;
    let located_count = slots.keys().max().map_or(0, |max| max + 1);
    let mut result: Vec<ConcreteParameter> = (0..located_count)
        .map(|slot| slots.remove(&slot).unwrap_or(ConcreteParameter::Gap { size }))
        .collect();
    // With a removed parameter, the located slots are only a lower bound (see Placeholder).
    if removed_count > 0 {
        while result.len() < parameter_count {
            result.push(ConcreteParameter::Placeholder { size });
        }
    }
    Some(result)
}
