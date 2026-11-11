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
//! and the platform's calling convention to an argument slot. A register-sized scalar on the stack
//! (`DW_OP_fbreg` from a CFA frame base, or the stack pointer at entry) takes the stack argument slot
//! after the argument registers. A slot that is passed but has no DIE
//! (a replacement piece) stays an unnamed gap rather than shifting later parameters into it. A
//! parameter GCC marks as removed (`DW_OP_GNU_parameter_ref`) takes no slot.
//!
//! The located slots fix where the named parameters are, but when a parameter was removed they are only
//! a lower bound on how many arguments the clone takes: a replacement piece can follow the last located
//! slot without any DWARF evidence. Such signatures are padded with unnamed placeholders up to the
//! source parameter count (see `ConcreteParameter::Placeholder`) rather than claimed exact.
//!
//! Anything this cannot place with confidence (aggregates or misaligned values on the stack, pieces,
//! constants, a parameter with no location at entry, an aggregate return that may use a hidden pointer,
//! an unsupported architecture) gives up, and the caller keeps the existing behavior for that function.

use std::collections::HashMap;

use binaryninja::architecture::{Architecture, Register};
use binaryninja::binary_view::BinaryView;
use binaryninja::calling_convention::CallingConvention;
use gimli::{
    constants, AttributeValue, DebuggingInformationEntry, Dwarf, Expression, Operation, Unit,
};

use crate::dwarfdebuginfo::{DebugInfoBuilder, DebugInfoBuilderContext, TypeUID};
use crate::helpers::{get_attr_die, get_size_as_u64, DieReference};
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

/// The most argument slots a reconstructed signature may have. A stack location further out is treated
/// as malformed, so a corrupt or hostile offset cannot size the signature. C only requires compilers to
/// support 127 parameters, and each takes at most a few slots.
const MAX_ARGUMENT_SLOTS: usize = 256;

/// Maps DWARF register numbers to integer argument slots of the platform's default calling convention,
/// and stack locations to the stack argument slots that follow them.
pub(crate) struct ArgumentRegisters {
    slots: HashMap<u16, usize>,
    register_size: usize,
    /// Number of integer argument registers: the first stack argument is the slot after them.
    int_arg_count: usize,
    /// DWARF number of the stack pointer.
    stack_pointer: u16,
    /// Bytes between the stack pointer at the entry PC and the CFA: the return address the call pushed.
    return_address_size: i64,
    /// Offset of the first stack argument from the CFA (past any space reserved for the argument
    /// registers, as on Windows x64).
    first_stack_argument: i64,
}

/// A DWARF register name lookup from gimli's per-architecture tables.
type DwarfRegisterLookup = fn(&str) -> Option<gimli::Register>;

/// gimli's DWARF register numbering for an architecture, and the size of the return address its calls
/// push on the stack. Only architectures whose stack argument layout this module has been checked
/// against are listed; adding one is an entry here plus a check of those stack rules.
fn dwarf_register_numbering(arch_name: &str) -> Option<(DwarfRegisterLookup, i64)> {
    match arch_name {
        "x86_64" => Some((gimli::X86_64::name_to_register, 8)),
        _ => None,
    }
}

impl ArgumentRegisters {
    /// Returns None for architectures without a DWARF register numbering here; their concrete
    /// instances keep the existing behavior.
    pub(crate) fn for_view(bv: &BinaryView) -> Option<Self> {
        let platform = bv.default_platform()?;
        let arch = platform.arch();
        let (dwarf_register, return_address_size) = dwarf_register_numbering(&arch.name())?;
        let calling_convention = platform.get_default_calling_convention()?;
        let arg_registers = calling_convention.int_arg_registers();

        // An argument register gimli does not number simply never matches a DWARF location, so a
        // function using it is not reconstructed.
        let mut slots = HashMap::new();
        for (slot, id) in arg_registers.iter().enumerate() {
            let Some(register) = arch.register_from_id(*id) else {
                continue;
            };
            if let Some(dwarf_number) = dwarf_register(&register.name()) {
                slots.insert(dwarf_number.0, slot);
            }
        }
        if slots.is_empty() {
            return None;
        }
        let stack_pointer = dwarf_register(&arch.stack_pointer_reg()?.name())?.0;
        let register_size = arch.address_size();
        if register_size == 0 {
            return None;
        }
        let int_arg_count = arg_registers.len();
        let first_stack_argument = if calling_convention.reserved_stack_space_for_arg_registers() {
            i64::try_from(int_arg_count * register_size).ok()?
        } else {
            0
        };
        Some(Self {
            slots,
            register_size,
            int_arg_count,
            stack_pointer,
            return_address_size,
            first_stack_argument,
        })
    }
}

impl ArgumentRegisters {
    /// The argument slot of a stack location at `cfa_offset` from the CFA. Stack arguments follow the
    /// register arguments, one slot each. None for a location below the first stack argument,
    /// misaligned, or past `MAX_ARGUMENT_SLOTS`.
    fn stack_slot(&self, cfa_offset: i64) -> Option<usize> {
        let offset = usize::try_from(cfa_offset.checked_sub(self.first_stack_argument)?).ok()?;
        if offset % self.register_size != 0 {
            return None;
        }
        let slot = self.int_arg_count + offset / self.register_size;
        (slot < MAX_ARGUMENT_SLOTS).then_some(slot)
    }
}

/// Where a parameter is at the function's entry PC.
enum EntryLocation {
    /// In a register (DWARF number).
    Register(u16),
    /// In memory on the stack, at this offset from the CFA.
    Stack(i64),
    /// GCC removed it from this instance (`DW_OP_GNU_parameter_ref`): nothing is passed for it.
    Removed,
    /// Anything else: no location covering the entry, pieces, constants, computed values, ...
    Unsupported,
}

/// `frame_base_is_cfa`: the function's `DW_AT_frame_base` is `DW_OP_call_frame_cfa`, so `DW_OP_fbreg`
/// offsets are relative to the CFA.
fn classify_expression<R: ReaderType>(
    expression: Expression<R>,
    unit: &Unit<R>,
    argument_registers: &ArgumentRegisters,
    frame_base_is_cfa: bool,
) -> EntryLocation {
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
        [Operation::FrameOffset { offset }] if frame_base_is_cfa => EntryLocation::Stack(*offset),
        // At the entry PC, the stack pointer is the CFA minus the return address.
        [Operation::RegisterOffset {
            register,
            offset,
            base_type,
        }] if (register.0 == argument_registers.stack_pointer) && (base_type.0 == 0) => offset
            .checked_sub(argument_registers.return_address_size)
            .map_or(EntryLocation::Unsupported, EntryLocation::Stack),
        _ => EntryLocation::Unsupported,
    }
}

fn entry_location<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    parameter: &DebuggingInformationEntry<R>,
    entry_pc: u64,
    argument_registers: &ArgumentRegisters,
    frame_base_is_cfa: bool,
) -> EntryLocation {
    let Ok(Some(value)) = parameter.attr_value(constants::DW_AT_location) else {
        return EntryLocation::Unsupported;
    };
    if let AttributeValue::Exprloc(expression) = value {
        return classify_expression(expression, unit, argument_registers, frame_base_is_cfa);
    }

    let Ok(Some(offset)) = dwarf.attr_locations_offset(unit, value) else {
        return EntryLocation::Unsupported;
    };
    let Ok(mut locations) = dwarf.locations(unit, offset) else {
        return EntryLocation::Unsupported;
    };
    // A parameter GCC removed may have no location at the entry PC, only DW_OP_GNU_parameter_ref
    // ranges later in the function. If every range is one, it is removed, not merely dead at entry.
    let mut all_removed = true;
    let mut any_location = false;
    loop {
        match locations.next() {
            Ok(Some(location)) => {
                let covers_entry =
                    (location.range.begin <= entry_pc) && (entry_pc < location.range.end);
                let classified =
                    classify_expression(location.data, unit, argument_registers, frame_base_is_cfa);
                if covers_entry {
                    return classified;
                }
                any_location = true;
                all_removed &= matches!(classified, EntryLocation::Removed);
            }
            Ok(None) if any_location && all_removed => return EntryLocation::Removed,
            _ => return EntryLocation::Unsupported,
        }
    }
}

/// True if the function's `DW_AT_frame_base` is exactly `DW_OP_call_frame_cfa`.
fn frame_base_is_cfa<R: ReaderType>(entry: &DebuggingInformationEntry<R>, unit: &Unit<R>) -> bool {
    let Ok(Some(AttributeValue::Exprloc(expression))) =
        entry.attr_value(constants::DW_AT_frame_base)
    else {
        return false;
    };
    let mut operations = expression.operations(unit.encoding());
    matches!(
        (operations.next(), operations.next()),
        (Ok(Some(Operation::CallFrameCFA)), Ok(None))
    )
}

/// Whether `entry` has `attr`, or None if the attribute cannot be read.
fn has_attribute<R: ReaderType>(
    entry: &DebuggingInformationEntry<R>,
    attr: constants::DwAt,
) -> Option<bool> {
    match entry.attr_value(attr) {
        Ok(Some(_)) => Some(true),
        Ok(None) => Some(false),
        Err(_) => None,
    }
}

/// The type of a function's return value or a parameter, after looking through typedefs and
/// qualifiers.
enum ResolvedType {
    Void,
    Type {
        tag: constants::DwTag,
        byte_size: Option<u64>,
        /// A floating-point, complex, or decimal base type, which calling conventions pass in their
        /// own registers rather than in integer argument slots.
        float: bool,
    },
}

/// True if the base type's `DW_AT_encoding` is one a calling convention may pass outside the integer
/// argument slots. None if the encoding cannot be read.
fn has_float_encoding<R: ReaderType>(type_entry: &DebuggingInformationEntry<R>) -> Option<bool> {
    match type_entry.attr_value(constants::DW_AT_encoding) {
        Ok(Some(AttributeValue::Encoding(encoding))) => Some(matches!(
            encoding,
            constants::DW_ATE_float
                | constants::DW_ATE_complex_float
                | constants::DW_ATE_imaginary_float
                | constants::DW_ATE_decimal_float
        )),
        Ok(_) => Some(false),
        Err(_) => None,
    }
}

/// Resolves the type of `entry` (a subprogram's return type, or a parameter's type) the way `get_type`
/// does: its own `DW_AT_type`, else the one inherited through `DW_AT_abstract_origin`, else through
/// `DW_AT_specification`, at each step of the chain. Returns None when anything cannot be resolved.
fn resolve_type<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
) -> Option<ResolvedType> {
    let mut current = (dwarf, unit, entry.offset());
    let mut reference = None;
    let mut found = false;
    for _ in 0..32 {
        let (current_dwarf, current_unit, current_offset) = current;
        let current_entry = current_unit.entry(current_offset).ok()?;
        if has_attribute(&current_entry, constants::DW_AT_type)? {
            reference = get_attr_die(
                current_dwarf,
                current_unit,
                &current_entry,
                debug_info_builder_context,
                constants::DW_AT_type,
            );
            found = true;
            break;
        }
        let inherited = if has_attribute(&current_entry, constants::DW_AT_abstract_origin)? {
            constants::DW_AT_abstract_origin
        } else if has_attribute(&current_entry, constants::DW_AT_specification)? {
            constants::DW_AT_specification
        } else {
            // No DW_AT_type anywhere in the chain: void.
            return Some(ResolvedType::Void);
        };
        match get_attr_die(
            current_dwarf,
            current_unit,
            &current_entry,
            debug_info_builder_context,
            inherited,
        ) {
            Some(DieReference::UnitAndOffset(next)) => current = next,
            _ => return None,
        }
    }
    if !found {
        return None;
    }

    // Look through typedefs and qualifiers. A qualifier with no DW_AT_type qualifies void.
    for _ in 0..32 {
        let Some(DieReference::UnitAndOffset((type_dwarf, type_unit, type_offset))) = reference
        else {
            return None;
        };
        let type_entry = type_unit.entry(type_offset).ok()?;
        match type_entry.tag() {
            constants::DW_TAG_typedef
            | constants::DW_TAG_const_type
            | constants::DW_TAG_volatile_type
            | constants::DW_TAG_restrict_type
            | constants::DW_TAG_atomic_type => {
                if !has_attribute(&type_entry, constants::DW_AT_type)? {
                    return Some(ResolvedType::Void);
                }
                reference = get_attr_die(
                    type_dwarf,
                    type_unit,
                    &type_entry,
                    debug_info_builder_context,
                    constants::DW_AT_type,
                );
            }
            tag => {
                let float = tag == constants::DW_TAG_base_type && has_float_encoding(&type_entry)?;
                return Some(ResolvedType::Type {
                    tag,
                    byte_size: get_size_as_u64(&type_entry),
                    float,
                });
            }
        }
    }
    None
}

const fn is_aggregate(tag: constants::DwTag) -> bool {
    matches!(
        tag,
        constants::DW_TAG_structure_type
            | constants::DW_TAG_union_type
            | constants::DW_TAG_class_type
            | constants::DW_TAG_array_type
    )
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
    match resolve_type(dwarf, unit, entry, debug_info_builder_context) {
        Some(ResolvedType::Void) => false,
        Some(ResolvedType::Type { tag, .. }) => is_aggregate(tag),
        None => true,
    }
}

/// True if a parameter passed on the stack takes exactly one stack slot the way an integer argument
/// does: a scalar of at most the register size that is not an aggregate (which the calling convention
/// may pass differently) or a floating-point value. The signature is laid out by the calling
/// convention, which would give a floating-point parameter a float register even though DWARF puts it
/// on the stack (for example when DIE-less pieces took the float registers).
fn fits_one_stack_slot<R: ReaderType>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    parameter: &DebuggingInformationEntry<R>,
    debug_info_builder_context: &DebugInfoBuilderContext<R>,
    register_size: usize,
) -> bool {
    let Some(ResolvedType::Type {
        tag,
        byte_size,
        float,
    }) = resolve_type(dwarf, unit, parameter, debug_info_builder_context)
    else {
        return false;
    };
    if float {
        return false;
    }
    let size = match tag {
        constants::DW_TAG_base_type | constants::DW_TAG_enumeration_type => byte_size,
        constants::DW_TAG_pointer_type
        | constants::DW_TAG_reference_type
        | constants::DW_TAG_rvalue_reference_type => byte_size.or(Some(register_size as u64)),
        _ => None,
    };
    matches!(size, Some(size) if size > 0 && size <= register_size as u64)
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
    if !entry.has_children() || has_attribute(entry, constants::DW_AT_abstract_origin) != Some(true)
    {
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

    let cfa_frame_base = frame_base_is_cfa(entry, unit);
    let size = argument_registers.register_size;

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
                let slot = match entry_location(
                    dwarf,
                    unit,
                    child.entry(),
                    entry_pc,
                    argument_registers,
                    cfa_frame_base,
                ) {
                    EntryLocation::Removed => {
                        removed_count += 1;
                        None
                    }
                    EntryLocation::Unsupported => return None,
                    // A register the convention does not pass integer arguments in, such as a
                    // floating-point register, cannot be placed: give up.
                    EntryLocation::Register(register) => {
                        Some(*argument_registers.slots.get(&register)?)
                    }
                    EntryLocation::Stack(cfa_offset) => {
                        let slot = argument_registers.stack_slot(cfa_offset)?;
                        if !fits_one_stack_slot(
                            dwarf,
                            unit,
                            child.entry(),
                            debug_info_builder_context,
                            size,
                        ) {
                            return None;
                        }
                        Some(slot)
                    }
                };
                if let Some(slot) = slot {
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
            _ => (),
        }
    }
    if parameter_count == 0 {
        return None;
    }

    let located_count = slots.keys().max().map_or(0, |max| max + 1);
    let mut result: Vec<ConcreteParameter> = (0..located_count)
        .map(|slot| {
            slots
                .remove(&slot)
                .unwrap_or(ConcreteParameter::Gap { size })
        })
        .collect();
    // With a removed parameter, the located slots are only a lower bound (see Placeholder).
    if removed_count > 0 {
        while result.len() < parameter_count {
            result.push(ConcreteParameter::Placeholder { size });
        }
    }
    Some(result)
}
