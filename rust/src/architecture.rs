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

//! Architectures provide disassembly, lifting, and associated metadata about a CPU to inform
//! analysis and decompilation.
//!
//! For more information see the [`Architecture`] trait and the [`CoreArchitecture`] structure for
//! querying already registered architectures.

// RegisterInfo purge
use binaryninjacore_sys::*;
use std::fmt::{Debug, Formatter};

use crate::{
    calling_convention::CoreCallingConvention,
    data_buffer::DataBuffer,
    disassembly::InstructionTextToken,
    ffi::INVALID_REGISTER,
    function::{Function, Location, NativeBlock},
    platform::Platform,
    rc::*,
    relocation::CoreRelocationHandler,
    string::{IntoCStr, *},
    types::{NameAndType, Type},
    Endianness,
};
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::{
    borrow::Borrow,
    ffi::{c_char, c_void, CString},
    hash::Hash,
    mem::MaybeUninit,
};

use std::ptr::NonNull;

use crate::function_recognizer::FunctionRecognizer;
use crate::relocation::{CustomRelocationHandlerHandle, RelocationHandler};

use crate::basic_block::BasicBlock;
use crate::confidence::Conf;
use crate::logger::Logger;
use crate::low_level_il::expression::ValueExpr;
use crate::low_level_il::lifting::{
    get_default_flag_cond_llil, get_default_flag_write_llil, LowLevelILFlagWriteOp,
};
use crate::low_level_il::{LowLevelILMutableExpression, LowLevelILMutableFunction};

pub mod basic_block;
pub mod branches;
pub mod flag;
pub mod instruction;
pub mod intrinsic;
pub mod register;

// Re-export all the submodules to keep from breaking everyone's code.
// We split these out just to clarify each part, not necessarily to enforce an extra namespace.
pub use basic_block::*;
pub use branches::*;
pub use flag::*;
pub use instruction::*;
pub use intrinsic::*;
pub use register::*;

/// The [`Architecture`] trait is the backbone of Binary Ninja's analysis capabilities. It tells the
/// core how to interpret the machine code into LLIL, a generic intermediate representation for
/// program analysis.
///
/// To add support for a new Instruction Set Architecture (ISA), you must implement this trait and
/// register it. The core analysis loop relies on your implementation for three critical stages:
///
/// 1.  **Disassembly ([`Architecture::instruction_text`])**: Machine code into human-readable text (e.g., `55` -> `push rbp`).
/// 2.  **Control Flow Analysis ([`Architecture::instruction_info`])**: Identifying where execution goes next (e.g., "This is a `call` instruction, it targets address `0x401000`").
/// 3.  **Lifting ([`Architecture::instruction_llil`])**: Translating machine code into **Low Level Intermediate Language (LLIL)**, which enables decompilation and automated analysis.
pub trait Architecture: 'static + Sized + AsRef<CoreArchitecture> {
    type Handle: Borrow<Self> + Clone;

    /// The [`RegisterInfo`] associated with this architecture.
    type RegisterInfo: RegisterInfo<RegType = Self::Register>;

    /// The [`Register`] associated with this architecture.
    type Register: Register<InfoType = Self::RegisterInfo>;

    /// The [`RegisterStackInfo`] associated with this architecture.
    ///
    /// You may only set this to [`UnusedRegisterStack`] if [`Self::RegisterStack`] is as well.
    type RegisterStackInfo: RegisterStackInfo<
        RegType = Self::Register,
        RegInfoType = Self::RegisterInfo,
        RegStackType = Self::RegisterStack,
    >;

    /// The [`RegisterStack`] associated with this architecture.
    ///
    /// If you do not override [`Architecture::register_stack_from_id`] and [`Architecture::register_stacks`],
    /// you may set this to [`UnusedRegisterStack`].
    type RegisterStack: RegisterStack<
        InfoType = Self::RegisterStackInfo,
        RegType = Self::Register,
        RegInfoType = Self::RegisterInfo,
    >;

    /// The [`Flag`] associated with this architecture.
    ///
    /// If you do not override [`Architecture::flag_from_id`] and [`Architecture::flags`], you may
    /// set this to [`UnusedFlag`].
    type Flag: Flag<FlagClass = Self::FlagClass>;

    /// The [`FlagWrite`] associated with this architecture.
    ///
    /// Can only be set to [`UnusedFlag`] if [`Self::Flag`] is as well. Otherwise, it is expected that
    /// this points to a custom [`FlagWrite`] with the following functions defined:
    ///
    /// - [`Architecture::flag_write_types`]
    /// - [`Architecture::flag_write_from_id`]
    type FlagWrite: FlagWrite<FlagType = Self::Flag, FlagClass = Self::FlagClass>;

    /// The [`FlagClass`] associated with this architecture.
    ///
    /// Can only be set to [`UnusedFlag`] if [`Self::Flag`] is as well. Otherwise, it is expected that
    /// this points to a custom [`FlagClass`] with the following functions defined:
    ///
    /// - [`Architecture::flag_classes`]
    /// - [`Architecture::flag_class_from_id`]
    type FlagClass: FlagClass;

    /// The [`FlagGroup`] associated with this architecture.
    ///
    /// Can only be set to [`UnusedFlag`] if [`Self::Flag`] is as well. Otherwise, it is expected that
    /// this points to a custom [`FlagGroup`] with the following functions defined:
    ///
    /// - [`Architecture::flag_groups`]
    /// - [`Architecture::flag_group_from_id`]
    type FlagGroup: FlagGroup<FlagType = Self::Flag, FlagClass = Self::FlagClass>;

    type Intrinsic: Intrinsic;

    fn endianness(&self) -> Endianness;
    fn address_size(&self) -> usize;
    fn default_integer_size(&self) -> usize;
    fn instruction_alignment(&self) -> usize;

    /// The maximum length of an instruction in bytes. This is used to determine the size of the buffer
    /// given to callbacks such as [`Architecture::instruction_info`], [`Architecture::instruction_text`]
    /// and [`Architecture::instruction_llil`].
    ///
    /// NOTE: The maximum **CANNOT** be greater than 256.
    fn max_instr_len(&self) -> usize;

    /// How many bytes to display in the opcode space before displaying a `...`, typically set to
    /// the [`Architecture::max_instr_len`], however, can be overridden to display a truncated opcode.
    fn opcode_display_len(&self) -> usize {
        self.max_instr_len()
    }

    /// In binaries with multiple architectures, you may wish to associate a specific architecture
    /// with a given virtual address. This can be seen in armv7 where odd addresses are associated
    /// with the thumb architecture.
    fn associated_arch_by_addr(&self, _addr: u64) -> CoreArchitecture {
        *self.as_ref()
    }

    /// Returns the [`InstructionInfo`] at the given virtual address with `data`.
    ///
    /// The [`InstructionInfo`] object should always fill the proper length and branches if not, the
    /// next instruction will likely be incorrect.
    fn instruction_info(&self, data: &[u8], addr: u64) -> Option<InstructionInfo>;

    /// Disassembles a raw byte sequence into a human-readable list of text tokens.
    ///
    /// This function is responsible for the visual representation of assembly instructions.
    /// It does *not* define semantics (use [`Architecture::instruction_llil`] for that);
    /// it simply tells the UI how to print the instruction.
    ///
    /// # Returns
    ///
    /// An `Option` containing a tuple:
    ///
    /// * `usize`: The size of the decoded instruction in bytes. Is used to advance to the next instruction.
    /// * `Vec<InstructionTextToken>`: A list of text tokens representing the instruction.
    ///
    /// Returns `None` if the bytes do not form a valid instruction.
    fn instruction_text(
        &self,
        data: &[u8],
        addr: u64,
    ) -> Option<(usize, Vec<InstructionTextToken>)>;

    /// Disassembles a raw byte sequence into a human-readable list of text tokens.
    ///
    /// This function is responsible for the visual representation of assembly instructions.
    /// It does *not* define semantics (use [`Architecture::instruction_llil`] for that);
    /// it simply tells the UI how to print the instruction. This variant includes contextual data, which
    /// can be produced by analyze_basic_blocks
    ///
    /// # Returns
    ///
    /// An `Option` containing a tuple:
    ///
    /// * `usize`: The size of the decoded instruction in bytes. Is used to advance to the next instruction.
    /// * `Vec<InstructionTextToken>`: A list of text tokens representing the instruction.
    ///
    /// Returns `None` if the bytes do not form a valid instruction.
    fn instruction_text_with_context(
        &self,
        data: &[u8],
        addr: u64,
        _context: Option<NonNull<c_void>>,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        self.instruction_text(data, addr)
    }

    // TODO: Why do we need to return a boolean here? Does `None` not represent the same thing?
    /// Appends arbitrary low-level il instructions to `il`.
    ///
    /// If `None` is returned, no instructions were appended and the data is invalid. If `Some` is returned,
    /// the instructions consumed length is returned (necessary for variable length instruction decoding).
    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &LowLevelILMutableFunction,
    ) -> Option<(usize, bool)>;

    /// Performs basic block recovery and commits the results to the function analysis.
    ///
    /// NOTE: Only implement this method if function-level analysis is required. Otherwise, do not
    /// implement to let default basic block analysis take place.
    fn analyze_basic_blocks(
        &self,
        function: &mut Function,
        context: &mut BasicBlockAnalysisContext,
    ) {
        unsafe {
            BNArchitectureDefaultAnalyzeBasicBlocks(function.handle, context.handle);
        }
    }

    fn lift_function(
        &self,
        function: LowLevelILMutableFunction,
        context: &mut FunctionLifterContext,
    ) -> bool {
        unsafe { BNArchitectureDefaultLiftFunction(function.handle, context.handle) }
    }

    /// Fallback flag value calculation path. This method is invoked when the core is unable to
    /// recover the flag using semantics and resorts to emitting instructions that explicitly set each
    /// observed flag to the value of an expression returned by this function.
    ///
    /// This function *MUST NOT* append instructions that have side effects.
    ///
    /// This function *MUST NOT* observe the values of other flags.
    ///
    /// This function *MUST* return `None` or an expression representing a boolean value.
    fn flag_write_llil<'a>(
        &self,
        flag: Self::Flag,
        flag_write_type: Self::FlagWrite,
        op: LowLevelILFlagWriteOp<Self::Register>,
        il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>> {
        let role = flag.role(flag_write_type.class());
        Some(get_default_flag_write_llil(self, role, op, il))
    }

    /// Determines what flags need to be examined to attempt automatic recovery of the flag uses semantics.
    ///
    /// If automatic recovery is not possible, the [`Architecture::flag_cond_llil`] method will be invoked
    /// to give this [`Architecture`] implementation arbitrary control over the expression to be evaluated.
    fn flags_required_for_flag_condition(
        &self,
        _condition: FlagCondition,
        _class: Option<Self::FlagClass>,
    ) -> Vec<Self::Flag> {
        Vec::new()
    }

    /// This function *MUST NOT* append instructions that have side effects.
    ///
    /// This function *MUST NOT* observe the values of flags not returned by
    /// `flags_required_for_flag_condition`.
    ///
    /// This function *MUST* return `None` or an expression representing a boolean value.
    fn flag_cond_llil<'a>(
        &self,
        cond: FlagCondition,
        class: Option<Self::FlagClass>,
        il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>> {
        Some(get_default_flag_cond_llil(self, cond, class, il))
    }

    /// Performs fallback resolution when the core was unable to recover the semantics of a
    /// `LLIL_FLAG_GROUP` expression. This occurs when multiple instructions may have set the flags
    /// at the flag group query, or when the `FlagGroup::flag_conditions()` map doesn't have an entry
    /// for the `FlagClass` associated with the `FlagWrite` type of the expression that last set
    /// the flags required by the `FlagGroup` `group`.
    ///
    /// In this fallback path, the `Architecture` must generate the boolean expression in terms of
    /// the values of that flags returned by `group`'s `flags_required` method.
    ///
    /// This function must return an expression representing a boolean (as in, size of `0`) value.
    /// It is not allowed to add any instructions that can cause side effects.
    ///
    /// This function must not observe the values of any flag not returned by `group`'s
    /// `flags_required` method.
    fn flag_group_llil<'a>(
        &self,
        _group: Self::FlagGroup,
        _il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>> {
        None
    }

    fn registers_all(&self) -> Vec<Self::Register>;

    fn register_from_id(&self, id: RegisterId) -> Option<Self::Register>;

    fn registers_full_width(&self) -> Vec<Self::Register>;

    // TODO: Document the difference between global and system registers.
    fn registers_global(&self) -> Vec<Self::Register> {
        Vec::new()
    }

    // TODO: Document the difference between global and system registers.
    fn registers_system(&self) -> Vec<Self::Register> {
        Vec::new()
    }

    fn stack_pointer_reg(&self) -> Option<Self::Register>;

    fn link_reg(&self) -> Option<Self::Register> {
        None
    }

    /// List of concrete register stacks for this architecture.
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::register_stack_from_id`]
    fn register_stacks(&self) -> Vec<Self::RegisterStack> {
        Vec::new()
    }

    /// Get the [`Self::RegisterStack`] associated with the given [`RegisterStackId`].
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::register_stacks`]
    fn register_stack_from_id(&self, _id: RegisterStackId) -> Option<Self::RegisterStack> {
        None
    }

    /// List of concrete flags for this architecture.
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::flag_from_id`]
    /// - [`Architecture::flag_write_types`]
    /// - [`Architecture::flag_write_from_id`]
    /// - [`Architecture::flag_classes`]
    /// - [`Architecture::flag_class_from_id`]
    /// - [`Architecture::flag_groups`]
    /// - [`Architecture::flag_group_from_id`]
    fn flags(&self) -> Vec<Self::Flag> {
        Vec::new()
    }

    /// Get the [`Self::Flag`] associated with the given [`FlagId`].
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::flags`]
    /// - [`Architecture::flag_write_types`]
    /// - [`Architecture::flag_write_from_id`]
    /// - [`Architecture::flag_classes`]
    /// - [`Architecture::flag_class_from_id`]
    /// - [`Architecture::flag_groups`]
    /// - [`Architecture::flag_group_from_id`]
    fn flag_from_id(&self, _id: FlagId) -> Option<Self::Flag> {
        None
    }

    /// List of concrete flag write types for this architecture.
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::flags`]
    /// - [`Architecture::flag_from_id`]
    /// - [`Architecture::flag_write_from_id`]
    /// - [`Architecture::flag_classes`]
    /// - [`Architecture::flag_class_from_id`]
    /// - [`Architecture::flag_groups`]
    /// - [`Architecture::flag_group_from_id`]
    fn flag_write_types(&self) -> Vec<Self::FlagWrite> {
        Vec::new()
    }

    /// Get the [`Self::FlagWrite`] associated with the given [`FlagWriteId`].
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::flags`]
    /// - [`Architecture::flag_from_id`]
    /// - [`Architecture::flag_write_types`]
    /// - [`Architecture::flag_classes`]
    /// - [`Architecture::flag_class_from_id`]
    /// - [`Architecture::flag_groups`]
    /// - [`Architecture::flag_group_from_id`]
    fn flag_write_from_id(&self, _id: FlagWriteId) -> Option<Self::FlagWrite> {
        None
    }

    /// List of concrete flag classes for this architecture.
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::flags`]
    /// - [`Architecture::flag_from_id`]
    /// - [`Architecture::flag_write_from_id`]
    /// - [`Architecture::flag_class_from_id`]
    /// - [`Architecture::flag_groups`]
    /// - [`Architecture::flag_group_from_id`]
    fn flag_classes(&self) -> Vec<Self::FlagClass> {
        Vec::new()
    }

    /// Get the [`Self::FlagClass`] associated with the given [`FlagClassId`].
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::flags`]
    /// - [`Architecture::flag_from_id`]
    /// - [`Architecture::flag_write_from_id`]
    /// - [`Architecture::flag_classes`]
    /// - [`Architecture::flag_groups`]
    /// - [`Architecture::flag_group_from_id`]
    fn flag_class_from_id(&self, _id: FlagClassId) -> Option<Self::FlagClass> {
        None
    }

    /// List of concrete flag groups for this architecture.
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::flags`]
    /// - [`Architecture::flag_from_id`]
    /// - [`Architecture::flag_write_from_id`]
    /// - [`Architecture::flag_classes`]
    /// - [`Architecture::flag_class_from_id`]
    /// - [`Architecture::flag_group_from_id`]
    fn flag_groups(&self) -> Vec<Self::FlagGroup> {
        Vec::new()
    }

    /// Get the [`Self::FlagGroup`] associated with the given [`FlagGroupId`].
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::flags`]
    /// - [`Architecture::flag_from_id`]
    /// - [`Architecture::flag_write_from_id`]
    /// - [`Architecture::flag_classes`]
    /// - [`Architecture::flag_class_from_id`]
    /// - [`Architecture::flag_groups`]
    fn flag_group_from_id(&self, _id: FlagGroupId) -> Option<Self::FlagGroup> {
        None
    }

    /// List of concrete intrinsics for this architecture.
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::intrinsic_from_id`]
    fn intrinsics(&self) -> Vec<Self::Intrinsic> {
        Vec::new()
    }

    fn intrinsic_class(&self, _id: IntrinsicId) -> BNIntrinsicClass {
        BNIntrinsicClass::GeneralIntrinsicClass
    }

    /// Get the [`Self::Intrinsic`] associated with the given [`IntrinsicId`].
    ///
    /// You **must** override the following functions as well:
    ///
    /// - [`Architecture::intrinsics`]
    fn intrinsic_from_id(&self, _id: IntrinsicId) -> Option<Self::Intrinsic> {
        None
    }

    /// Let the UI display this patch option.
    ///
    /// If set to true, you must override [`Architecture::assemble`].
    fn can_assemble(&self) -> bool {
        false
    }

    /// Assemble the code at the specified address and return the machine code in bytes.
    ///
    /// If overridden, you must set [`Architecture::can_assemble`] to `true`.
    fn assemble(&self, _code: &str, _addr: u64) -> Result<Vec<u8>, String> {
        Err("Assemble unsupported".into())
    }

    /// Let the UI display this patch option.
    ///
    /// If set to true, you must override [`Architecture::invert_branch`].
    fn is_never_branch_patch_available(&self, data: &[u8], addr: u64) -> bool {
        self.is_invert_branch_patch_available(data, addr)
    }

    /// Let the UI display this patch option.
    ///
    /// If set to true, you must override [`Architecture::always_branch`].
    fn is_always_branch_patch_available(&self, _data: &[u8], _addr: u64) -> bool {
        false
    }

    /// Let the UI display this patch option.
    ///
    /// If set to true, you must override [`Architecture::invert_branch`].
    fn is_invert_branch_patch_available(&self, _data: &[u8], _addr: u64) -> bool {
        false
    }

    /// Let the UI display this patch option.
    ///
    /// If set to true, you must override [`Architecture::skip_and_return_value`].
    fn is_skip_and_return_zero_patch_available(&self, data: &[u8], addr: u64) -> bool {
        self.is_skip_and_return_value_patch_available(data, addr)
    }

    /// Let the UI display this patch option.
    ///
    /// If set to true, you must override [`Architecture::skip_and_return_value`].
    fn is_skip_and_return_value_patch_available(&self, _data: &[u8], _addr: u64) -> bool {
        false
    }

    fn convert_to_nop(&self, _data: &mut [u8], _addr: u64) -> bool {
        false
    }

    /// Patch the instruction to always branch.
    ///
    /// If overridden, you must also override [`Architecture::is_always_branch_patch_available`].
    fn always_branch(&self, _data: &mut [u8], _addr: u64) -> bool {
        false
    }

    /// Patch the instruction to invert the branch condition.
    ///
    /// If overridden, you must also override [`Architecture::is_invert_branch_patch_available`].
    fn invert_branch(&self, _data: &mut [u8], _addr: u64) -> bool {
        false
    }

    /// Patch the instruction to skip and return value.
    ///
    /// If overridden, you must also override [`Architecture::is_skip_and_return_value_patch_available`].
    fn skip_and_return_value(&self, _data: &mut [u8], _addr: u64, _value: u64) -> bool {
        false
    }

    fn handle(&self) -> Self::Handle;
}

pub trait ArchitectureWithFunctionContext: Architecture {
    type FunctionArchContext: Send + Sync + 'static;

    fn instruction_text_with_typed_context(
        &self,
        data: &[u8],
        addr: u64,
        _context: Option<&Self::FunctionArchContext>,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        self.instruction_text(data, addr)
    }
}

pub struct FunctionLifterContext {
    pub(crate) handle: *mut BNFunctionLifterContext,
    pub function: Ref<LowLevelILMutableFunction>,
    pub platform: Ref<Platform>,
    pub logger: Ref<Logger>,
    pub blocks: Vec<Ref<BasicBlock<NativeBlock>>>,
    pub no_return_calls: HashSet<Location>,
    pub contextual_returns: HashMap<Location, bool>,
    pub inlined_remapping: HashMap<Location, Location>,
    pub user_indirect_branches: HashMap<Location, HashSet<Location>>,
    pub auto_indirect_branches: HashMap<Location, HashSet<Location>>,
    pub inlined_calls: HashSet<u64>,
}

unsafe fn lifter_context_slice<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        debug_assert!(!ptr.is_null());
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

impl FunctionLifterContext {
    pub unsafe fn from_raw(
        function: *mut BNLowLevelILFunction,
        handle: *mut BNFunctionLifterContext,
    ) -> Self {
        Self::from_raw_with_arch(function, handle, None)
    }

    pub(crate) unsafe fn from_raw_with_arch(
        function: *mut BNLowLevelILFunction,
        handle: *mut BNFunctionLifterContext,
        arch: Option<CoreArchitecture>,
    ) -> Self {
        debug_assert!(!function.is_null());
        debug_assert!(!handle.is_null());
        let flc_ref = &*handle;
        let platform = unsafe { Platform::ref_from_raw(BNNewPlatformReference(flc_ref.platform)) };
        let logger = unsafe { Logger::ref_from_raw(BNNewLoggerReference(flc_ref.logger)) };

        let mut blocks = Vec::new();
        for i in 0..flc_ref.basicBlockCount {
            let block = unsafe {
                Some(BasicBlock::ref_from_raw(
                    BNNewBasicBlockReference(*flc_ref.basicBlocks.add(i)),
                    NativeBlock::new(),
                ))
            };

            blocks.push(block.unwrap());
        }

        let raw_no_return_calls: &[BNArchitectureAndAddress] =
            lifter_context_slice(flc_ref.noReturnCalls, flc_ref.noReturnCallsCount);
        let no_return_calls: HashSet<Location> =
            raw_no_return_calls.iter().map(Location::from).collect();

        let raw_contextual_return_locs: &[BNArchitectureAndAddress] = unsafe {
            lifter_context_slice(
                flc_ref.contextualFunctionReturnLocations,
                flc_ref.contextualFunctionReturnCount,
            )
        };
        let raw_contextual_return_vals: &[bool] = unsafe {
            lifter_context_slice(
                flc_ref.contextualFunctionReturnValues,
                flc_ref.contextualFunctionReturnCount,
            )
        };
        let contextual_returns: HashMap<Location, bool> = raw_contextual_return_locs
            .iter()
            .map(Location::from)
            .zip(raw_contextual_return_vals.iter().copied())
            .collect();

        let inlined_remapping: HashMap<Location, Location> = {
            let raw_inline_remap_locs: &[BNArchitectureAndAddress] = lifter_context_slice(
                flc_ref.inlinedRemappingKeys,
                flc_ref.inlinedRemappingEntryCount,
            );

            let raw_inline_remap_dests: &[BNArchitectureAndAddress] = lifter_context_slice(
                flc_ref.inlinedRemappingValues,
                flc_ref.inlinedRemappingEntryCount,
            );

            raw_inline_remap_locs
                .iter()
                .map(Location::from)
                .zip(raw_inline_remap_dests.iter().map(Location::from))
                .collect()
        };

        let mut user_indirect_branches: HashMap<Location, HashSet<Location>> = HashMap::new();
        let mut auto_indirect_branches: HashMap<Location, HashSet<Location>> = HashMap::new();
        for i in 0..flc_ref.indirectBranchesCount {
            let entry = unsafe { *flc_ref.indirectBranches.add(i) };
            let src = Location::new(
                Some(CoreArchitecture::from_raw(entry.sourceArch)),
                entry.sourceAddr,
            );
            let dest = Location::new(
                Some(CoreArchitecture::from_raw(entry.destArch)),
                entry.destAddr,
            );
            if entry.autoDefined {
                auto_indirect_branches.entry(src).or_default().insert(dest);
            } else {
                user_indirect_branches.entry(src).or_default().insert(dest);
            }
        }

        let inlined_calls: HashSet<u64> =
            lifter_context_slice(flc_ref.inlinedCalls, flc_ref.inlinedCallsCount)
                .iter()
                .copied()
                .collect();

        FunctionLifterContext {
            handle,
            function: LowLevelILMutableFunction::ref_from_raw_with_arch(
                BNNewLowLevelILFunctionReference(function),
                arch,
            ),
            platform,
            logger,
            blocks,
            no_return_calls,
            contextual_returns,
            inlined_remapping,
            user_indirect_branches,
            auto_indirect_branches,
            inlined_calls,
        }
    }

    pub fn prepare_block_translation(
        &self,
        func: &LowLevelILMutableFunction,
        arch: &CoreArchitecture,
        address: u64,
    ) {
        unsafe {
            BNPrepareBlockTranslation(func.handle, arch.handle, address);
        }
    }

    pub fn get_function_arch_context<A: ArchitectureWithFunctionContext>(
        &self,
        _arch: &A,
    ) -> Option<&A::FunctionArchContext> {
        unsafe {
            let ptr = (*self.handle).functionArchContext;
            if ptr.is_null() {
                None
            } else {
                Some(&*(ptr as *const A::FunctionArchContext))
            }
        }
    }
}

// TODO: WTF?!?!?!?
pub struct CoreArchitectureList(*mut *mut BNArchitecture, usize);

impl Deref for CoreArchitectureList {
    type Target = [CoreArchitecture];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.0 as *mut CoreArchitecture, self.1) }
    }
}

impl Drop for CoreArchitectureList {
    fn drop(&mut self) {
        unsafe {
            BNFreeArchitectureList(self.0);
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreArchitecture {
    pub(crate) handle: *mut BNArchitecture,
}

impl CoreArchitecture {
    // TODO: Leave a note on architecture lifetimes. Specifically that they are never freed.
    pub unsafe fn from_raw(handle: *mut BNArchitecture) -> Self {
        debug_assert!(!handle.is_null());
        CoreArchitecture { handle }
    }

    pub fn list_all() -> CoreArchitectureList {
        let mut count: usize = 0;
        let archs = unsafe { BNGetArchitectureList(&mut count) };

        CoreArchitectureList(archs, count)
    }

    pub fn by_name(name: &str) -> Option<Self> {
        let name = name.to_cstr();
        let handle = unsafe { BNGetArchitectureByName(name.as_ptr()) };
        match handle.is_null() {
            false => Some(CoreArchitecture { handle }),
            true => None,
        }
    }

    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNGetArchitectureName(self.handle)) }
    }

    pub fn register_stack_for_register(&self, reg: CoreRegister) -> Option<CoreRegisterStack> {
        match unsafe { BNGetArchitectureRegisterStackForRegister(self.handle, reg.id().0) } {
            INVALID_REGISTER => None,
            reg_stack => CoreRegisterStack::new(*self, RegisterStackId::from(reg_stack)),
        }
    }
}

unsafe impl Send for CoreArchitecture {}
unsafe impl Sync for CoreArchitecture {}

impl AsRef<CoreArchitecture> for CoreArchitecture {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Architecture for CoreArchitecture {
    type Handle = Self;

    type RegisterInfo = CoreRegisterInfo;
    type Register = CoreRegister;
    type RegisterStackInfo = CoreRegisterStackInfo;
    type RegisterStack = CoreRegisterStack;
    type Flag = CoreFlag;
    type FlagWrite = CoreFlagWrite;
    type FlagClass = CoreFlagClass;
    type FlagGroup = CoreFlagGroup;
    type Intrinsic = CoreIntrinsic;

    fn endianness(&self) -> Endianness {
        unsafe { BNGetArchitectureEndianness(self.handle) }
    }

    fn address_size(&self) -> usize {
        unsafe { BNGetArchitectureAddressSize(self.handle) }
    }

    fn default_integer_size(&self) -> usize {
        unsafe { BNGetArchitectureDefaultIntegerSize(self.handle) }
    }

    fn instruction_alignment(&self) -> usize {
        unsafe { BNGetArchitectureInstructionAlignment(self.handle) }
    }

    fn max_instr_len(&self) -> usize {
        unsafe { BNGetArchitectureMaxInstructionLength(self.handle) }
    }

    fn opcode_display_len(&self) -> usize {
        unsafe { BNGetArchitectureOpcodeDisplayLength(self.handle) }
    }

    fn associated_arch_by_addr(&self, addr: u64) -> CoreArchitecture {
        let handle = unsafe { BNGetAssociatedArchitectureByAddress(self.handle, addr as *mut _) };
        CoreArchitecture { handle }
    }

    fn instruction_info(&self, data: &[u8], addr: u64) -> Option<InstructionInfo> {
        let mut info = BNInstructionInfo::default();
        if unsafe { BNGetInstructionInfo(self.handle, data.as_ptr(), addr, data.len(), &mut info) }
        {
            Some(info.into())
        } else {
            None
        }
    }

    fn instruction_text(
        &self,
        data: &[u8],
        addr: u64,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        let mut consumed = data.len();
        let mut count: usize = 0;
        let mut result: *mut BNInstructionTextToken = std::ptr::null_mut();

        unsafe {
            if BNGetInstructionText(
                self.handle,
                data.as_ptr(),
                addr,
                &mut consumed,
                &mut result,
                &mut count,
            ) {
                let instr_text_tokens = std::slice::from_raw_parts(result, count)
                    .iter()
                    .map(InstructionTextToken::from_raw)
                    .collect();
                BNFreeInstructionText(result, count);
                Some((consumed, instr_text_tokens))
            } else {
                None
            }
        }
    }

    fn instruction_text_with_context(
        &self,
        data: &[u8],
        addr: u64,
        context: Option<NonNull<c_void>>,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        let mut consumed = data.len();
        let mut count: usize = 0;
        let mut result: *mut BNInstructionTextToken = std::ptr::null_mut();
        let ctx_ptr: *mut c_void = context.map_or(std::ptr::null_mut(), |p| p.as_ptr());
        unsafe {
            if BNGetInstructionTextWithContext(
                self.handle,
                data.as_ptr(),
                addr,
                &mut consumed,
                ctx_ptr,
                &mut result,
                &mut count,
            ) {
                let instr_text_tokens = std::slice::from_raw_parts(result, count)
                    .iter()
                    .map(InstructionTextToken::from_raw)
                    .collect();
                BNFreeInstructionText(result, count);
                Some((consumed, instr_text_tokens))
            } else {
                None
            }
        }
    }

    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &LowLevelILMutableFunction,
    ) -> Option<(usize, bool)> {
        let mut size = data.len();
        let success = unsafe {
            BNGetInstructionLowLevelIL(
                self.handle,
                data.as_ptr(),
                addr,
                &mut size as *mut _,
                il.handle,
            )
        };

        if !success {
            None
        } else {
            Some((size, true))
        }
    }

    /// Performs basic block recovery and commits the results to the function analysis.
    ///
    /// NOTE: Only implement this method if function-level analysis is required. Otherwise, do not
    /// implement to let default basic block analysis take place.
    ///
    /// NOTE: The default implementation exists in C++ here: <https://github.com/Vector35/binaryninja-api/blob/dev/defaultabb.cpp>
    fn analyze_basic_blocks(
        &self,
        function: &mut Function,
        context: &mut BasicBlockAnalysisContext,
    ) {
        unsafe {
            BNArchitectureAnalyzeBasicBlocks(self.handle, function.handle, context.handle);
        }
    }

    fn lift_function(
        &self,
        function: LowLevelILMutableFunction,
        context: &mut FunctionLifterContext,
    ) -> bool {
        unsafe { BNArchitectureLiftFunction(self.handle, function.handle, context.handle) }
    }

    fn flag_write_llil<'a>(
        &self,
        _flag: Self::Flag,
        _flag_write: Self::FlagWrite,
        _op: LowLevelILFlagWriteOp<Self::Register>,
        _il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>> {
        None
    }

    fn flags_required_for_flag_condition(
        &self,
        condition: FlagCondition,
        class: Option<Self::FlagClass>,
    ) -> Vec<Self::Flag> {
        let class_id_raw = class.map(|c| c.id().0).unwrap_or(0);

        unsafe {
            let mut count: usize = 0;
            let flags = BNGetArchitectureFlagsRequiredForFlagCondition(
                self.handle,
                condition,
                class_id_raw,
                &mut count,
            );

            let ret = std::slice::from_raw_parts(flags, count)
                .iter()
                .map(|&id| FlagId::from(id))
                .filter_map(|flag| CoreFlag::new(*self, flag))
                .collect();

            BNFreeRegisterList(flags);

            ret
        }
    }

    fn flag_cond_llil<'a>(
        &self,
        _cond: FlagCondition,
        _class: Option<Self::FlagClass>,
        _il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>> {
        None
    }

    fn flag_group_llil<'a>(
        &self,
        _group: Self::FlagGroup,
        _il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>> {
        None
    }

    fn registers_all(&self) -> Vec<CoreRegister> {
        unsafe {
            let mut count: usize = 0;
            let registers_raw = BNGetAllArchitectureRegisters(self.handle, &mut count);

            let ret = std::slice::from_raw_parts(registers_raw, count)
                .iter()
                .map(|&id| RegisterId::from(id))
                .filter_map(|reg| CoreRegister::new(*self, reg))
                .collect();

            BNFreeRegisterList(registers_raw);

            ret
        }
    }

    fn register_from_id(&self, id: RegisterId) -> Option<CoreRegister> {
        CoreRegister::new(*self, id)
    }

    fn registers_full_width(&self) -> Vec<CoreRegister> {
        unsafe {
            let mut count: usize = 0;
            let registers_raw = BNGetFullWidthArchitectureRegisters(self.handle, &mut count);

            let ret = std::slice::from_raw_parts(registers_raw, count)
                .iter()
                .map(|&id| RegisterId::from(id))
                .filter_map(|reg| CoreRegister::new(*self, reg))
                .collect();

            BNFreeRegisterList(registers_raw);

            ret
        }
    }

    fn registers_global(&self) -> Vec<CoreRegister> {
        unsafe {
            let mut count: usize = 0;
            let registers_raw = BNGetArchitectureGlobalRegisters(self.handle, &mut count);

            let ret = std::slice::from_raw_parts(registers_raw, count)
                .iter()
                .map(|&id| RegisterId::from(id))
                .filter_map(|reg| CoreRegister::new(*self, reg))
                .collect();

            BNFreeRegisterList(registers_raw);

            ret
        }
    }

    fn registers_system(&self) -> Vec<CoreRegister> {
        unsafe {
            let mut count: usize = 0;
            let registers_raw = BNGetArchitectureSystemRegisters(self.handle, &mut count);

            let ret = std::slice::from_raw_parts(registers_raw, count)
                .iter()
                .map(|&id| RegisterId::from(id))
                .filter_map(|reg| CoreRegister::new(*self, reg))
                .collect();

            BNFreeRegisterList(registers_raw);

            ret
        }
    }

    fn stack_pointer_reg(&self) -> Option<CoreRegister> {
        match unsafe { BNGetArchitectureStackPointerRegister(self.handle) } {
            INVALID_REGISTER => None,
            reg => Some(CoreRegister::new(*self, reg.into())?),
        }
    }

    fn link_reg(&self) -> Option<CoreRegister> {
        match unsafe { BNGetArchitectureLinkRegister(self.handle) } {
            INVALID_REGISTER => None,
            reg => Some(CoreRegister::new(*self, reg.into())?),
        }
    }

    fn register_stacks(&self) -> Vec<CoreRegisterStack> {
        unsafe {
            let mut count: usize = 0;
            let reg_stacks_raw = BNGetAllArchitectureRegisterStacks(self.handle, &mut count);

            let ret = std::slice::from_raw_parts(reg_stacks_raw, count)
                .iter()
                .map(|&id| RegisterStackId::from(id))
                .filter_map(|reg_stack| CoreRegisterStack::new(*self, reg_stack))
                .collect();

            BNFreeRegisterList(reg_stacks_raw);

            ret
        }
    }

    fn register_stack_from_id(&self, id: RegisterStackId) -> Option<CoreRegisterStack> {
        CoreRegisterStack::new(*self, id)
    }

    fn flags(&self) -> Vec<CoreFlag> {
        unsafe {
            let mut count: usize = 0;
            let flags_raw = BNGetAllArchitectureFlags(self.handle, &mut count);

            let ret = std::slice::from_raw_parts(flags_raw, count)
                .iter()
                .map(|&id| FlagId::from(id))
                .filter_map(|flag| CoreFlag::new(*self, flag))
                .collect();

            BNFreeRegisterList(flags_raw);

            ret
        }
    }

    fn flag_from_id(&self, id: FlagId) -> Option<CoreFlag> {
        CoreFlag::new(*self, id)
    }

    fn flag_write_types(&self) -> Vec<CoreFlagWrite> {
        unsafe {
            let mut count: usize = 0;
            let flag_writes_raw = BNGetAllArchitectureFlagWriteTypes(self.handle, &mut count);

            let ret = std::slice::from_raw_parts(flag_writes_raw, count)
                .iter()
                .map(|&id| FlagWriteId::from(id))
                .filter_map(|flag_write| CoreFlagWrite::new(*self, flag_write))
                .collect();

            BNFreeRegisterList(flag_writes_raw);

            ret
        }
    }

    fn flag_write_from_id(&self, id: FlagWriteId) -> Option<CoreFlagWrite> {
        CoreFlagWrite::new(*self, id)
    }

    fn flag_classes(&self) -> Vec<CoreFlagClass> {
        unsafe {
            let mut count: usize = 0;
            let flag_classes_raw = BNGetAllArchitectureSemanticFlagClasses(self.handle, &mut count);

            let ret = std::slice::from_raw_parts(flag_classes_raw, count)
                .iter()
                .map(|&id| FlagClassId::from(id))
                .filter_map(|flag_class| CoreFlagClass::new(*self, flag_class))
                .collect();

            BNFreeRegisterList(flag_classes_raw);

            ret
        }
    }

    fn flag_class_from_id(&self, id: FlagClassId) -> Option<CoreFlagClass> {
        CoreFlagClass::new(*self, id)
    }

    fn flag_groups(&self) -> Vec<CoreFlagGroup> {
        unsafe {
            let mut count: usize = 0;
            let flag_groups_raw = BNGetAllArchitectureSemanticFlagGroups(self.handle, &mut count);

            let ret = std::slice::from_raw_parts(flag_groups_raw, count)
                .iter()
                .map(|&id| FlagGroupId::from(id))
                .filter_map(|flag_group| CoreFlagGroup::new(*self, flag_group))
                .collect();

            BNFreeRegisterList(flag_groups_raw);

            ret
        }
    }

    fn flag_group_from_id(&self, id: FlagGroupId) -> Option<CoreFlagGroup> {
        CoreFlagGroup::new(*self, id)
    }

    fn intrinsics(&self) -> Vec<CoreIntrinsic> {
        unsafe {
            let mut count: usize = 0;
            let intrinsics_raw = BNGetAllArchitectureIntrinsics(self.handle, &mut count);

            let intrinsics = std::slice::from_raw_parts_mut(intrinsics_raw, count)
                .iter()
                .map(|&id| IntrinsicId::from(id))
                .filter_map(|intrinsic| CoreIntrinsic::new(*self, intrinsic))
                .collect();

            BNFreeRegisterList(intrinsics_raw);

            intrinsics
        }
    }

    fn intrinsic_from_id(&self, id: IntrinsicId) -> Option<CoreIntrinsic> {
        CoreIntrinsic::new(*self, id)
    }

    fn can_assemble(&self) -> bool {
        unsafe { BNCanArchitectureAssemble(self.handle) }
    }

    fn assemble(&self, code: &str, addr: u64) -> Result<Vec<u8>, String> {
        let code = CString::new(code).map_err(|_| "Invalid encoding in code string".to_string())?;

        let result = DataBuffer::new(&[]);
        // TODO: This is actually a list of errors.
        let mut error_raw: *mut c_char = std::ptr::null_mut();
        let res = unsafe {
            BNAssemble(
                self.handle,
                code.as_ptr(),
                addr,
                result.as_raw(),
                &mut error_raw as *mut *mut c_char,
            )
        };

        let error = raw_to_string(error_raw);
        unsafe {
            BNFreeString(error_raw);
        }

        if res {
            Ok(result.get_data().to_vec())
        } else {
            Err(error.unwrap_or_else(|| "Assemble failed".into()))
        }
    }

    fn is_never_branch_patch_available(&self, data: &[u8], addr: u64) -> bool {
        unsafe {
            BNIsArchitectureNeverBranchPatchAvailable(self.handle, data.as_ptr(), addr, data.len())
        }
    }

    fn is_always_branch_patch_available(&self, data: &[u8], addr: u64) -> bool {
        unsafe {
            BNIsArchitectureAlwaysBranchPatchAvailable(self.handle, data.as_ptr(), addr, data.len())
        }
    }

    fn is_invert_branch_patch_available(&self, data: &[u8], addr: u64) -> bool {
        unsafe {
            BNIsArchitectureInvertBranchPatchAvailable(self.handle, data.as_ptr(), addr, data.len())
        }
    }

    fn is_skip_and_return_zero_patch_available(&self, data: &[u8], addr: u64) -> bool {
        unsafe {
            BNIsArchitectureSkipAndReturnZeroPatchAvailable(
                self.handle,
                data.as_ptr(),
                addr,
                data.len(),
            )
        }
    }

    fn is_skip_and_return_value_patch_available(&self, data: &[u8], addr: u64) -> bool {
        unsafe {
            BNIsArchitectureSkipAndReturnValuePatchAvailable(
                self.handle,
                data.as_ptr(),
                addr,
                data.len(),
            )
        }
    }

    fn convert_to_nop(&self, data: &mut [u8], addr: u64) -> bool {
        unsafe { BNArchitectureConvertToNop(self.handle, data.as_mut_ptr(), addr, data.len()) }
    }

    fn always_branch(&self, data: &mut [u8], addr: u64) -> bool {
        unsafe { BNArchitectureAlwaysBranch(self.handle, data.as_mut_ptr(), addr, data.len()) }
    }

    fn invert_branch(&self, data: &mut [u8], addr: u64) -> bool {
        unsafe { BNArchitectureInvertBranch(self.handle, data.as_mut_ptr(), addr, data.len()) }
    }

    fn skip_and_return_value(&self, data: &mut [u8], addr: u64, value: u64) -> bool {
        unsafe {
            BNArchitectureSkipAndReturnValue(
                self.handle,
                data.as_mut_ptr(),
                addr,
                data.len(),
                value,
            )
        }
    }

    fn handle(&self) -> CoreArchitecture {
        *self
    }
}

impl Debug for CoreArchitecture {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreArchitecture")
            .field("name", &self.name())
            .field("endianness", &self.endianness())
            .field("address_size", &self.address_size())
            .field("instruction_alignment", &self.instruction_alignment())
            .finish()
    }
}

macro_rules! cc_func {
    ($get_name:ident, $get_api:ident, $set_name:ident, $set_api:ident) => {
        fn $get_name(&self) -> Option<Ref<CoreCallingConvention>> {
            let arch = self.as_ref();

            unsafe {
                let cc = $get_api(arch.handle);

                if cc.is_null() {
                    None
                } else {
                    Some(CoreCallingConvention::ref_from_raw(
                        cc,
                        self.as_ref().handle(),
                    ))
                }
            }
        }

        fn $set_name(&self, cc: &CoreCallingConvention) {
            let arch = self.as_ref();

            assert!(
                cc.arch_handle.borrow().as_ref().handle == arch.handle,
                "use of calling convention with non-matching architecture!"
            );

            unsafe {
                $set_api(arch.handle, cc.handle);
            }
        }
    };
}

/// Contains helper methods for all types implementing 'Architecture'
pub trait ArchitectureExt: Architecture {
    fn register_by_name(&self, name: &str) -> Option<Self::Register> {
        let name = name.to_cstr();

        match unsafe { BNGetArchitectureRegisterByName(self.as_ref().handle, name.as_ptr()) } {
            INVALID_REGISTER => None,
            reg => self.register_from_id(reg.into()),
        }
    }

    fn calling_convention_by_name(&self, name: &str) -> Option<Ref<CoreCallingConvention>> {
        let name = name.to_cstr();
        unsafe {
            let result = NonNull::new(BNGetArchitectureCallingConventionByName(
                self.as_ref().handle,
                name.as_ptr(),
            ))?;
            Some(CoreCallingConvention::ref_from_raw(
                result.as_ptr(),
                self.as_ref().handle(),
            ))
        }
    }

    fn calling_conventions(&self) -> Array<CoreCallingConvention> {
        unsafe {
            let mut count = 0;
            let calling_convs =
                BNGetArchitectureCallingConventions(self.as_ref().handle, &mut count);
            Array::new(calling_convs, count, self.as_ref().handle())
        }
    }

    cc_func!(
        get_default_calling_convention,
        BNGetArchitectureDefaultCallingConvention,
        set_default_calling_convention,
        BNSetArchitectureDefaultCallingConvention
    );

    cc_func!(
        get_cdecl_calling_convention,
        BNGetArchitectureCdeclCallingConvention,
        set_cdecl_calling_convention,
        BNSetArchitectureCdeclCallingConvention
    );

    cc_func!(
        get_stdcall_calling_convention,
        BNGetArchitectureStdcallCallingConvention,
        set_stdcall_calling_convention,
        BNSetArchitectureStdcallCallingConvention
    );

    cc_func!(
        get_fastcall_calling_convention,
        BNGetArchitectureFastcallCallingConvention,
        set_fastcall_calling_convention,
        BNSetArchitectureFastcallCallingConvention
    );

    fn standalone_platform(&self) -> Option<Ref<Platform>> {
        unsafe {
            let handle = BNGetArchitectureStandalonePlatform(self.as_ref().handle);

            if handle.is_null() {
                return None;
            }

            Some(Platform::ref_from_raw(handle))
        }
    }

    fn relocation_handler(&self, view_name: &str) -> Option<Ref<CoreRelocationHandler>> {
        let view_name = match CString::new(view_name) {
            Ok(view_name) => view_name,
            Err(_) => return None,
        };

        unsafe {
            let handle =
                BNArchitectureGetRelocationHandler(self.as_ref().handle, view_name.as_ptr());

            if handle.is_null() {
                return None;
            }

            Some(CoreRelocationHandler::ref_from_raw(handle))
        }
    }

    fn register_relocation_handler<R, F>(&self, name: &str, func: F)
    where
        R: 'static
            + RelocationHandler<Handle = CustomRelocationHandlerHandle<R>>
            + Send
            + Sync
            + Sized,
        F: FnOnce(CustomRelocationHandlerHandle<R>, CoreRelocationHandler) -> R,
    {
        crate::relocation::register_relocation_handler(self.as_ref(), name, func);
    }

    fn register_function_recognizer<R>(&self, recognizer: R)
    where
        R: 'static + FunctionRecognizer + Send + Sync + Sized,
    {
        crate::function_recognizer::register_arch_function_recognizer(self.as_ref(), recognizer);
    }
}

impl<T: Architecture> ArchitectureExt for T {}

/// Registers a new architecture with the given name.
///
/// NOTE: This function should only be called within `CorePluginInit`.
pub fn register_architecture<A, F>(name: &str, func: F) -> &'static A
where
    A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync + Sized,
    F: FnOnce(CustomArchitectureHandle<A>, CoreArchitecture) -> A,
{
    register_architecture_impl(name, func, |_| {})
}

fn register_architecture_impl<A, F, C>(name: &str, func: F, customize: C) -> &'static A
where
    A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync + Sized,
    F: FnOnce(CustomArchitectureHandle<A>, CoreArchitecture) -> A,
    C: FnOnce(&mut BNCustomArchitecture),
{
    #[repr(C)]
    struct ArchitectureBuilder<A, F>
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
        F: FnOnce(CustomArchitectureHandle<A>, CoreArchitecture) -> A,
    {
        arch: MaybeUninit<A>,
        func: Option<F>,
    }

    extern "C" fn cb_init<A, F>(ctxt: *mut c_void, obj: *mut BNArchitecture)
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
        F: FnOnce(CustomArchitectureHandle<A>, CoreArchitecture) -> A,
    {
        unsafe {
            let custom_arch = &mut *(ctxt as *mut ArchitectureBuilder<A, F>);
            let custom_arch_handle = CustomArchitectureHandle {
                handle: ctxt as *mut A,
            };

            let create = custom_arch.func.take().unwrap();
            custom_arch
                .arch
                .write(create(custom_arch_handle, CoreArchitecture::from_raw(obj)));
        }
    }

    extern "C" fn cb_endianness<A>(ctxt: *mut c_void) -> BNEndianness
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        custom_arch.endianness()
    }

    extern "C" fn cb_address_size<A>(ctxt: *mut c_void) -> usize
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        custom_arch.address_size()
    }

    extern "C" fn cb_default_integer_size<A>(ctxt: *mut c_void) -> usize
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        custom_arch.default_integer_size()
    }

    extern "C" fn cb_instruction_alignment<A>(ctxt: *mut c_void) -> usize
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        custom_arch.instruction_alignment()
    }

    extern "C" fn cb_max_instr_len<A>(ctxt: *mut c_void) -> usize
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        custom_arch.max_instr_len()
    }

    extern "C" fn cb_opcode_display_len<A>(ctxt: *mut c_void) -> usize
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        custom_arch.opcode_display_len()
    }

    extern "C" fn cb_associated_arch_by_addr<A>(
        ctxt: *mut c_void,
        addr: *mut u64,
    ) -> *mut BNArchitecture
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let addr = unsafe { *(addr) };

        custom_arch.associated_arch_by_addr(addr).handle
    }

    extern "C" fn cb_instruction_info<A>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: usize,
        result: *mut BNInstructionInfo,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts(data, len) };

        match custom_arch.instruction_info(data, addr) {
            Some(info) => {
                // SAFETY: Passed in to be written to
                unsafe { *result = info.into() };
                true
            }
            None => false,
        }
    }

    extern "C" fn cb_get_instruction_text<A>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: *mut usize,
        result: *mut *mut BNInstructionTextToken,
        count: *mut usize,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts(data, *len) };
        let result = unsafe { &mut *result };

        let Some((res_size, res_tokens)) = custom_arch.instruction_text(data, addr) else {
            return false;
        };

        let res_tokens: Box<[BNInstructionTextToken]> = res_tokens
            .into_iter()
            .map(InstructionTextToken::into_raw)
            .collect();
        unsafe {
            // NOTE: Freed with `cb_free_instruction_text`
            let res_tokens = Box::leak(res_tokens);
            *result = res_tokens.as_mut_ptr();
            *count = res_tokens.len();
            *len = res_size;
        }
        true
    }

    pub unsafe extern "C" fn cb_get_instruction_text_with_context<A>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: *mut usize,
        context: *mut c_void,
        result: *mut *mut BNInstructionTextToken,
        count: *mut usize,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts(data, *len) };
        let result = unsafe { &mut *result };
        let context = NonNull::new(context);

        let Some((res_size, res_tokens)) =
            custom_arch.instruction_text_with_context(data, addr, context)
        else {
            return false;
        };

        let res_tokens: Box<[BNInstructionTextToken]> = res_tokens
            .into_iter()
            .map(InstructionTextToken::into_raw)
            .collect();
        unsafe {
            // NOTE: Freed with `cb_free_instruction_text`
            let res_tokens = Box::leak(res_tokens);
            *result = res_tokens.as_mut_ptr();
            *count = res_tokens.len();
            *len = res_size;
        }
        true
    }

    extern "C" fn cb_free_instruction_text(tokens: *mut BNInstructionTextToken, count: usize) {
        unsafe {
            let raw_tokens = std::slice::from_raw_parts_mut(tokens, count);
            let boxed_tokens = Box::from_raw(raw_tokens);
            for token in boxed_tokens {
                InstructionTextToken::free_raw(token);
            }
        }
    }

    extern "C" fn cb_instruction_llil<A>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: *mut usize,
        il: *mut BNLowLevelILFunction,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts(data, *len) };
        let lifter = unsafe {
            LowLevelILMutableFunction::from_raw_with_arch(il, Some(*custom_arch.as_ref()))
        };

        match custom_arch.instruction_llil(data, addr, &lifter) {
            Some((res_len, res_value)) => {
                unsafe { *len = res_len };
                res_value
            }
            None => false,
        }
    }

    extern "C" fn cb_analyze_basic_blocks<A>(
        ctxt: *mut c_void,
        function: *mut BNFunction,
        context: *mut BNBasicBlockAnalysisContext,
    ) where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut function = unsafe { Function::from_raw(function) };
        let mut context: BasicBlockAnalysisContext =
            unsafe { BasicBlockAnalysisContext::from_raw(context) };
        custom_arch.analyze_basic_blocks(&mut function, &mut context);
    }

    extern "C" fn cb_lift_function<A>(
        ctxt: *mut c_void,
        function: *mut BNLowLevelILFunction,
        context: *mut BNFunctionLifterContext,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let llil = unsafe {
            LowLevelILMutableFunction::from_raw_with_arch(function, Some(*custom_arch.as_ref()))
        };

        let mut ctx = unsafe {
            FunctionLifterContext::from_raw_with_arch(
                function,
                context,
                Some(*custom_arch.as_ref()),
            )
        };
        custom_arch.lift_function(llil, &mut ctx)
    }

    extern "C" fn cb_reg_name<A>(ctxt: *mut c_void, reg: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        match custom_arch.register_from_id(reg.into()) {
            Some(reg) => BnString::into_raw(BnString::new(reg.name().as_ref())),
            None => BnString::into_raw(BnString::new("invalid_reg")),
        }
    }

    extern "C" fn cb_flag_name<A>(ctxt: *mut c_void, flag: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        match custom_arch.flag_from_id(flag.into()) {
            Some(flag) => BnString::into_raw(BnString::new(flag.name().as_ref())),
            None => BnString::into_raw(BnString::new("invalid_flag")),
        }
    }

    extern "C" fn cb_flag_write_name<A>(ctxt: *mut c_void, flag_write: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        match custom_arch.flag_write_from_id(flag_write.into()) {
            Some(flag_write) => BnString::into_raw(BnString::new(flag_write.name().as_ref())),
            None => BnString::into_raw(BnString::new("invalid_flag_write")),
        }
    }

    extern "C" fn cb_semantic_flag_class_name<A>(ctxt: *mut c_void, class: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        match custom_arch.flag_class_from_id(class.into()) {
            Some(class) => BnString::into_raw(BnString::new(class.name().as_ref())),
            None => BnString::into_raw(BnString::new("invalid_flag_class")),
        }
    }

    extern "C" fn cb_semantic_flag_group_name<A>(ctxt: *mut c_void, group: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        match custom_arch.flag_group_from_id(group.into()) {
            Some(group) => BnString::into_raw(BnString::new(group.name().as_ref())),
            None => BnString::into_raw(BnString::new("invalid_flag_group")),
        }
    }

    extern "C" fn cb_registers_full_width<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut regs: Box<[_]> = custom_arch
            .registers_full_width()
            .iter()
            .map(|r| r.id().0)
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = regs.len() };
        let regs_ptr = regs.as_mut_ptr();
        std::mem::forget(regs);
        regs_ptr
    }

    extern "C" fn cb_registers_all<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut regs: Box<[_]> = custom_arch
            .registers_all()
            .iter()
            .map(|r| r.id().0)
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = regs.len() };
        let regs_ptr = regs.as_mut_ptr();
        std::mem::forget(regs);
        regs_ptr
    }

    extern "C" fn cb_registers_global<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut regs: Box<[_]> = custom_arch
            .registers_global()
            .iter()
            .map(|r| r.id().0)
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = regs.len() };
        let regs_ptr = regs.as_mut_ptr();
        std::mem::forget(regs);
        regs_ptr
    }

    extern "C" fn cb_registers_system<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut regs: Box<[_]> = custom_arch
            .registers_system()
            .iter()
            .map(|r| r.id().0)
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = regs.len() };
        let regs_ptr = regs.as_mut_ptr();
        std::mem::forget(regs);
        regs_ptr
    }

    extern "C" fn cb_flags<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut flags: Box<[_]> = custom_arch.flags().iter().map(|f| f.id().0).collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = flags.len() };
        let flags_ptr = flags.as_mut_ptr();
        std::mem::forget(flags);
        flags_ptr
    }

    extern "C" fn cb_flag_write_types<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut flag_writes: Box<[_]> = custom_arch
            .flag_write_types()
            .iter()
            .map(|f| f.id().0)
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = flag_writes.len() };
        let flags_ptr = flag_writes.as_mut_ptr();
        std::mem::forget(flag_writes);
        flags_ptr
    }

    extern "C" fn cb_semantic_flag_classes<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut flag_classes: Box<[_]> = custom_arch
            .flag_classes()
            .iter()
            .map(|f| f.id().0)
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = flag_classes.len() };
        let flags_ptr = flag_classes.as_mut_ptr();
        std::mem::forget(flag_classes);
        flags_ptr
    }

    extern "C" fn cb_semantic_flag_groups<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut flag_groups: Box<[_]> =
            custom_arch.flag_groups().iter().map(|f| f.id().0).collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = flag_groups.len() };
        let flags_ptr = flag_groups.as_mut_ptr();
        std::mem::forget(flag_groups);
        flags_ptr
    }

    extern "C" fn cb_flag_role<A>(ctxt: *mut c_void, flag: u32, class: u32) -> BNFlagRole
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        if let (Some(flag), class) = (
            custom_arch.flag_from_id(FlagId(flag)),
            custom_arch.flag_class_from_id(FlagClassId(class)),
        ) {
            flag.role(class)
        } else {
            FlagRole::SpecialFlagRole
        }
    }

    extern "C" fn cb_flags_required_for_flag_cond<A>(
        ctxt: *mut c_void,
        cond: BNLowLevelILFlagCondition,
        class: u32,
        count: *mut usize,
    ) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let class = custom_arch.flag_class_from_id(FlagClassId(class));
        let mut flags: Box<[_]> = custom_arch
            .flags_required_for_flag_condition(cond, class)
            .iter()
            .map(|f| f.id().0)
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = flags.len() };
        let flags_ptr = flags.as_mut_ptr();
        std::mem::forget(flags);
        flags_ptr
    }

    extern "C" fn cb_flags_required_for_semantic_flag_group<A>(
        ctxt: *mut c_void,
        group: u32,
        count: *mut usize,
    ) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        if let Some(group) = custom_arch.flag_group_from_id(FlagGroupId(group)) {
            let mut flags: Box<[_]> = group.flags_required().iter().map(|f| f.id().0).collect();

            // SAFETY: `count` is an out parameter
            unsafe { *count = flags.len() };
            let flags_ptr = flags.as_mut_ptr();
            std::mem::forget(flags);
            flags_ptr
        } else {
            unsafe {
                *count = 0;
            }
            std::ptr::null_mut()
        }
    }

    extern "C" fn cb_flag_conditions_for_semantic_flag_group<A>(
        ctxt: *mut c_void,
        group: u32,
        count: *mut usize,
    ) -> *mut BNFlagConditionForSemanticClass
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        if let Some(group) = custom_arch.flag_group_from_id(FlagGroupId(group)) {
            let flag_conditions = group.flag_conditions();
            let mut flags: Box<[_]> = flag_conditions
                .iter()
                .map(|(&class, &condition)| BNFlagConditionForSemanticClass {
                    semanticClass: class.id().0,
                    condition,
                })
                .collect();

            // SAFETY: `count` is an out parameter
            unsafe { *count = flags.len() };
            let flags_ptr = flags.as_mut_ptr();
            std::mem::forget(flags);
            flags_ptr
        } else {
            unsafe {
                *count = 0;
            }
            std::ptr::null_mut()
        }
    }

    extern "C" fn cb_free_flag_conditions_for_semantic_flag_group<A>(
        _ctxt: *mut c_void,
        conds: *mut BNFlagConditionForSemanticClass,
        count: usize,
    ) where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        if conds.is_null() {
            return;
        }

        unsafe {
            let flags_ptr = std::ptr::slice_from_raw_parts_mut(conds, count);
            let _flags = Box::from_raw(flags_ptr);
        }
    }

    extern "C" fn cb_flags_written_by_write_type<A>(
        ctxt: *mut c_void,
        write_type: u32,
        count: *mut usize,
    ) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        if let Some(write_type) = custom_arch.flag_write_from_id(FlagWriteId(write_type)) {
            let mut flags_written: Box<[_]> = write_type
                .flags_written()
                .iter()
                .map(|f| f.id().0)
                .collect();

            // SAFETY: `count` is an out parameter
            unsafe { *count = flags_written.len() };
            let flags_ptr = flags_written.as_mut_ptr();
            std::mem::forget(flags_written);
            flags_ptr
        } else {
            unsafe {
                *count = 0;
            }
            std::ptr::null_mut()
        }
    }

    extern "C" fn cb_semantic_class_for_flag_write_type<A>(
        ctxt: *mut c_void,
        write_type: u32,
    ) -> u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        custom_arch
            .flag_write_from_id(FlagWriteId(write_type))
            .map(|w| w.class())
            .and_then(|c| c.map(|c| c.id().0))
            .unwrap_or(0)
    }

    extern "C" fn cb_flag_write_llil<A>(
        ctxt: *mut c_void,
        op: BNLowLevelILOperation,
        size: usize,
        flag_write: u32,
        flag: u32,
        operands_raw: *mut BNRegisterOrConstant,
        operand_count: usize,
        il: *mut BNLowLevelILFunction,
    ) -> usize
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let flag_write = custom_arch.flag_write_from_id(FlagWriteId(flag_write));
        let flag = custom_arch.flag_from_id(FlagId(flag));
        let operands = unsafe { std::slice::from_raw_parts(operands_raw, operand_count) };
        let lifter = unsafe {
            LowLevelILMutableFunction::from_raw_with_arch(il, Some(*custom_arch.as_ref()))
        };

        if let (Some(flag_write), Some(flag)) = (flag_write, flag) {
            if let Some(op) = LowLevelILFlagWriteOp::from_op(custom_arch, size, op, operands) {
                if let Some(expr) = custom_arch.flag_write_llil(flag, flag_write, op, &lifter) {
                    // TODO verify that returned expr is a bool value
                    return expr.index.0;
                }
            } else {
                tracing::warn!(
                    "unable to unpack flag write op: {:?} with {} operands",
                    op,
                    operands.len()
                );
            }

            let role = flag.role(flag_write.class());

            unsafe {
                BNGetDefaultArchitectureFlagWriteLowLevelIL(
                    custom_arch.as_ref().handle,
                    op,
                    size,
                    role,
                    operands_raw,
                    operand_count,
                    il,
                )
            }
        } else {
            // TODO this should be impossible; requires bad flag/flag_write ids passed in;
            // explode more violently
            lifter.unimplemented().index.0
        }
    }

    extern "C" fn cb_flag_cond_llil<A>(
        ctxt: *mut c_void,
        cond: FlagCondition,
        class: u32,
        il: *mut BNLowLevelILFunction,
    ) -> usize
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let class = custom_arch.flag_class_from_id(FlagClassId(class));

        let lifter = unsafe {
            LowLevelILMutableFunction::from_raw_with_arch(il, Some(*custom_arch.as_ref()))
        };
        if let Some(expr) = custom_arch.flag_cond_llil(cond, class, &lifter) {
            // TODO verify that returned expr is a bool value
            return expr.index.0;
        }

        lifter.unimplemented().index.0
    }

    extern "C" fn cb_flag_group_llil<A>(
        ctxt: *mut c_void,
        group: u32,
        il: *mut BNLowLevelILFunction,
    ) -> usize
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let lifter = unsafe {
            LowLevelILMutableFunction::from_raw_with_arch(il, Some(*custom_arch.as_ref()))
        };

        if let Some(group) = custom_arch.flag_group_from_id(FlagGroupId(group)) {
            if let Some(expr) = custom_arch.flag_group_llil(group, &lifter) {
                // TODO verify that returned expr is a bool value
                return expr.index.0;
            }
        }

        lifter.unimplemented().index.0
    }

    extern "C" fn cb_free_register_list(_ctxt: *mut c_void, regs: *mut u32, count: usize) {
        if regs.is_null() {
            return;
        }

        unsafe {
            let regs_ptr = std::ptr::slice_from_raw_parts_mut(regs, count);
            let _regs = Box::from_raw(regs_ptr);
        }
    }

    extern "C" fn cb_register_info<A>(ctxt: *mut c_void, reg: u32, result: *mut BNRegisterInfo)
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let result = unsafe { &mut *result };

        if let Some(reg) = custom_arch.register_from_id(RegisterId(reg)) {
            let info = reg.info();

            result.fullWidthRegister = match info.parent() {
                Some(p) => p.id().0,
                None => reg.id().0,
            };

            result.offset = info.offset();
            result.size = info.size();
            result.extend = info.implicit_extend().into();
        }
    }

    extern "C" fn cb_stack_pointer<A>(ctxt: *mut c_void) -> u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        if let Some(reg) = custom_arch.stack_pointer_reg() {
            reg.id().0
        } else {
            INVALID_REGISTER
        }
    }

    extern "C" fn cb_link_reg<A>(ctxt: *mut c_void) -> u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        if let Some(reg) = custom_arch.link_reg() {
            reg.id().0
        } else {
            INVALID_REGISTER
        }
    }

    extern "C" fn cb_reg_stack_name<A>(ctxt: *mut c_void, stack: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        match custom_arch.register_stack_from_id(RegisterStackId(stack)) {
            Some(stack) => BnString::into_raw(BnString::new(stack.name().as_ref())),
            None => BnString::into_raw(BnString::new("invalid_reg_stack")),
        }
    }

    extern "C" fn cb_reg_stacks<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut regs: Box<[_]> = custom_arch
            .register_stacks()
            .iter()
            .map(|r| r.id().0)
            .collect();

        // SAFETY: Passed in to be written
        unsafe { *count = regs.len() };
        let regs_ptr = regs.as_mut_ptr();
        std::mem::forget(regs);
        regs_ptr
    }

    extern "C" fn cb_reg_stack_info<A>(
        ctxt: *mut c_void,
        stack: u32,
        result: *mut BNRegisterStackInfo,
    ) where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let result = unsafe { &mut *result };

        if let Some(stack) = custom_arch.register_stack_from_id(RegisterStackId(stack)) {
            let info = stack.info();

            let (reg, count) = info.storage_regs();
            result.firstStorageReg = reg.id().0;
            result.storageCount = count as u32;

            if let Some((reg, count)) = info.top_relative_regs() {
                result.firstTopRelativeReg = reg.id().0;
                result.topRelativeCount = count as u32;
            } else {
                result.firstTopRelativeReg = INVALID_REGISTER;
                result.topRelativeCount = 0;
            }

            result.stackTopReg = info.stack_top_reg().id().0;
        }
    }

    extern "C" fn cb_intrinsic_class<A>(ctxt: *mut c_void, intrinsic: u32) -> BNIntrinsicClass
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        match custom_arch.intrinsic_from_id(IntrinsicId(intrinsic)) {
            Some(intrinsic) => intrinsic.class(),
            // TODO: Make this unreachable?
            None => BNIntrinsicClass::GeneralIntrinsicClass,
        }
    }

    extern "C" fn cb_intrinsic_name<A>(ctxt: *mut c_void, intrinsic: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        match custom_arch.intrinsic_from_id(IntrinsicId(intrinsic)) {
            Some(intrinsic) => BnString::into_raw(BnString::new(intrinsic.name())),
            None => BnString::into_raw(BnString::new("invalid_intrinsic")),
        }
    }

    extern "C" fn cb_intrinsics<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut intrinsics: Box<[_]> = custom_arch.intrinsics().iter().map(|i| i.id().0).collect();

        // SAFETY: Passed in to be written
        unsafe { *count = intrinsics.len() };
        let intrinsics_ptr = intrinsics.as_mut_ptr();
        std::mem::forget(intrinsics);
        intrinsics_ptr
    }

    extern "C" fn cb_intrinsic_inputs<A>(
        ctxt: *mut c_void,
        intrinsic: u32,
        count: *mut usize,
    ) -> *mut BNNameAndType
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        let Some(intrinsic) = custom_arch.intrinsic_from_id(IntrinsicId(intrinsic)) else {
            // SAFETY: Passed in to be written
            unsafe {
                *count = 0;
            }
            return std::ptr::null_mut();
        };

        let inputs = intrinsic.inputs();
        // NOTE: The into_raw will leak and be freed later by `cb_free_name_and_types`.
        let raw_inputs: Box<[_]> = inputs.into_iter().map(NameAndType::into_raw).collect();

        // SAFETY: Passed in to be written
        unsafe {
            *count = raw_inputs.len();
        }

        if raw_inputs.is_empty() {
            std::ptr::null_mut()
        } else {
            // Core is responsible for calling back to `cb_free_name_and_types`.
            Box::leak(raw_inputs).as_mut_ptr()
        }
    }

    extern "C" fn cb_free_name_and_types<A>(
        _ctxt: *mut c_void,
        nt: *mut BNNameAndType,
        count: usize,
    ) where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        if nt.is_null() {
            return;
        }

        // Reconstruct the box and drop.
        let nt_ptr = std::ptr::slice_from_raw_parts_mut(nt, count);
        // SAFETY: nt_ptr is a pointer to a Box.
        let boxed_name_and_types = unsafe { Box::from_raw(nt_ptr) };
        for nt in boxed_name_and_types {
            NameAndType::free_raw(nt);
        }
    }

    extern "C" fn cb_intrinsic_outputs<A>(
        ctxt: *mut c_void,
        intrinsic: u32,
        count: *mut usize,
    ) -> *mut BNTypeWithConfidence
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        let Some(intrinsic) = custom_arch.intrinsic_from_id(IntrinsicId(intrinsic)) else {
            // SAFETY: Passed in to be written
            unsafe {
                *count = 0;
            }
            return std::ptr::null_mut();
        };

        let outputs = intrinsic.outputs();
        let raw_outputs: Box<[BNTypeWithConfidence]> = outputs
            .into_iter()
            // Leaked to be freed later by `cb_free_type_list`.
            .map(Conf::<Ref<Type>>::into_raw)
            .collect();

        // SAFETY: Passed in to be written
        unsafe {
            *count = raw_outputs.len();
        }

        if raw_outputs.is_empty() {
            std::ptr::null_mut()
        } else {
            // Core is responsible for calling back to `cb_free_type_list`.
            Box::leak(raw_outputs).as_mut_ptr()
        }
    }

    extern "C" fn cb_free_type_list<A>(
        ctxt: *mut c_void,
        tl: *mut BNTypeWithConfidence,
        count: usize,
    ) where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let _custom_arch = unsafe { &*(ctxt as *mut A) };
        if !tl.is_null() {
            let boxed_types =
                unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(tl, count)) };
            for ty in boxed_types {
                Conf::<Ref<Type>>::free_raw(ty);
            }
        }
    }

    extern "C" fn cb_can_assemble<A>(ctxt: *mut c_void) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        custom_arch.can_assemble()
    }

    extern "C" fn cb_assemble<A>(
        ctxt: *mut c_void,
        code: *const c_char,
        addr: u64,
        buffer: *mut BNDataBuffer,
        errors: *mut *mut c_char,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let code = raw_to_string(code).unwrap_or("".into());
        let mut buffer = DataBuffer::from_raw(buffer);

        let result = match custom_arch.assemble(&code, addr) {
            Ok(result) => {
                buffer.set_data(&result);
                unsafe {
                    *errors = BnString::into_raw(BnString::new(""));
                }
                true
            }
            Err(result) => {
                unsafe {
                    *errors = BnString::into_raw(BnString::new(result));
                }
                false
            }
        };

        // Caller owns the data buffer, don't free it
        std::mem::forget(buffer);

        result
    }

    extern "C" fn cb_is_never_branch_patch_available<A>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: usize,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts(data, len) };
        custom_arch.is_never_branch_patch_available(data, addr)
    }

    extern "C" fn cb_is_always_branch_patch_available<A>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: usize,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts(data, len) };
        custom_arch.is_always_branch_patch_available(data, addr)
    }

    extern "C" fn cb_is_invert_branch_patch_available<A>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: usize,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts(data, len) };
        custom_arch.is_invert_branch_patch_available(data, addr)
    }

    extern "C" fn cb_is_skip_and_return_zero_patch_available<A>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: usize,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts(data, len) };
        custom_arch.is_skip_and_return_zero_patch_available(data, addr)
    }

    extern "C" fn cb_is_skip_and_return_value_patch_available<A>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: usize,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts(data, len) };
        custom_arch.is_skip_and_return_value_patch_available(data, addr)
    }

    extern "C" fn cb_convert_to_nop<A>(
        ctxt: *mut c_void,
        data: *mut u8,
        addr: u64,
        len: usize,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts_mut(data, len) };
        custom_arch.convert_to_nop(data, addr)
    }

    extern "C" fn cb_always_branch<A>(
        ctxt: *mut c_void,
        data: *mut u8,
        addr: u64,
        len: usize,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts_mut(data, len) };
        custom_arch.always_branch(data, addr)
    }

    extern "C" fn cb_invert_branch<A>(
        ctxt: *mut c_void,
        data: *mut u8,
        addr: u64,
        len: usize,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts_mut(data, len) };
        custom_arch.invert_branch(data, addr)
    }

    extern "C" fn cb_skip_and_return_value<A>(
        ctxt: *mut c_void,
        data: *mut u8,
        addr: u64,
        len: usize,
        val: u64,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts_mut(data, len) };
        custom_arch.skip_and_return_value(data, addr, val)
    }

    let name = name.to_cstr();

    let uninit_arch = ArchitectureBuilder {
        arch: MaybeUninit::zeroed(),
        func: Some(func),
    };

    let raw = Box::into_raw(Box::new(uninit_arch));
    let mut custom_arch = BNCustomArchitecture {
        context: raw as *mut _,
        init: Some(cb_init::<A, F>),
        getEndianness: Some(cb_endianness::<A>),
        getAddressSize: Some(cb_address_size::<A>),
        getDefaultIntegerSize: Some(cb_default_integer_size::<A>),
        getInstructionAlignment: Some(cb_instruction_alignment::<A>),
        // TODO: Make getOpcodeDisplayLength optional.
        getMaxInstructionLength: Some(cb_max_instr_len::<A>),
        // TODO: Make getOpcodeDisplayLength optional.
        getOpcodeDisplayLength: Some(cb_opcode_display_len::<A>),
        getAssociatedArchitectureByAddress: Some(cb_associated_arch_by_addr::<A>),
        getInstructionInfo: Some(cb_instruction_info::<A>),
        getInstructionText: Some(cb_get_instruction_text::<A>),
        getInstructionTextWithContext: Some(cb_get_instruction_text_with_context::<A>),
        freeInstructionText: Some(cb_free_instruction_text),
        getInstructionLowLevelIL: Some(cb_instruction_llil::<A>),
        analyzeBasicBlocks: Some(cb_analyze_basic_blocks::<A>),
        liftFunction: Some(cb_lift_function::<A>),
        freeFunctionArchContext: None,

        getRegisterName: Some(cb_reg_name::<A>),
        getFlagName: Some(cb_flag_name::<A>),
        getFlagWriteTypeName: Some(cb_flag_write_name::<A>),
        getSemanticFlagClassName: Some(cb_semantic_flag_class_name::<A>),
        getSemanticFlagGroupName: Some(cb_semantic_flag_group_name::<A>),

        getFullWidthRegisters: Some(cb_registers_full_width::<A>),
        getAllRegisters: Some(cb_registers_all::<A>),
        getAllFlags: Some(cb_flags::<A>),
        getAllFlagWriteTypes: Some(cb_flag_write_types::<A>),
        getAllSemanticFlagClasses: Some(cb_semantic_flag_classes::<A>),
        getAllSemanticFlagGroups: Some(cb_semantic_flag_groups::<A>),

        getFlagRole: Some(cb_flag_role::<A>),
        getFlagsRequiredForFlagCondition: Some(cb_flags_required_for_flag_cond::<A>),

        getFlagsRequiredForSemanticFlagGroup: Some(cb_flags_required_for_semantic_flag_group::<A>),
        getFlagConditionsForSemanticFlagGroup: Some(
            cb_flag_conditions_for_semantic_flag_group::<A>,
        ),
        freeFlagConditionsForSemanticFlagGroup: Some(
            cb_free_flag_conditions_for_semantic_flag_group::<A>,
        ),

        getFlagsWrittenByFlagWriteType: Some(cb_flags_written_by_write_type::<A>),
        getSemanticClassForFlagWriteType: Some(cb_semantic_class_for_flag_write_type::<A>),

        getFlagWriteLowLevelIL: Some(cb_flag_write_llil::<A>),
        getFlagConditionLowLevelIL: Some(cb_flag_cond_llil::<A>),
        getSemanticFlagGroupLowLevelIL: Some(cb_flag_group_llil::<A>),

        freeRegisterList: Some(cb_free_register_list),
        getRegisterInfo: Some(cb_register_info::<A>),
        getStackPointerRegister: Some(cb_stack_pointer::<A>),
        getLinkRegister: Some(cb_link_reg::<A>),
        getGlobalRegisters: Some(cb_registers_global::<A>),
        getSystemRegisters: Some(cb_registers_system::<A>),

        getRegisterStackName: Some(cb_reg_stack_name::<A>),
        getAllRegisterStacks: Some(cb_reg_stacks::<A>),
        getRegisterStackInfo: Some(cb_reg_stack_info::<A>),

        getIntrinsicClass: Some(cb_intrinsic_class::<A>),
        getIntrinsicName: Some(cb_intrinsic_name::<A>),
        getAllIntrinsics: Some(cb_intrinsics::<A>),
        getIntrinsicInputs: Some(cb_intrinsic_inputs::<A>),
        freeNameAndTypeList: Some(cb_free_name_and_types::<A>),
        getIntrinsicOutputs: Some(cb_intrinsic_outputs::<A>),
        freeTypeList: Some(cb_free_type_list::<A>),

        canAssemble: Some(cb_can_assemble::<A>),
        assemble: Some(cb_assemble::<A>),

        isNeverBranchPatchAvailable: Some(cb_is_never_branch_patch_available::<A>),
        isAlwaysBranchPatchAvailable: Some(cb_is_always_branch_patch_available::<A>),
        isInvertBranchPatchAvailable: Some(cb_is_invert_branch_patch_available::<A>),
        isSkipAndReturnZeroPatchAvailable: Some(cb_is_skip_and_return_zero_patch_available::<A>),
        isSkipAndReturnValuePatchAvailable: Some(cb_is_skip_and_return_value_patch_available::<A>),

        convertToNop: Some(cb_convert_to_nop::<A>),
        alwaysBranch: Some(cb_always_branch::<A>),
        invertBranch: Some(cb_invert_branch::<A>),
        skipAndReturnValue: Some(cb_skip_and_return_value::<A>),
    };

    customize(&mut custom_arch);

    unsafe {
        let res = BNRegisterArchitecture(name.as_ptr(), &mut custom_arch as *mut _);
        assert!(!res.is_null());

        (*raw).arch.assume_init_mut()
    }
}

pub fn register_architecture_with_function_context<A, F>(name: &str, func: F) -> &'static A
where
    A: 'static
        + ArchitectureWithFunctionContext<Handle = CustomArchitectureHandle<A>>
        + Send
        + Sync
        + Sized,
    F: FnOnce(CustomArchitectureHandle<A>, CoreArchitecture) -> A,
{
    unsafe extern "C" fn cb_free_function_arch_context_typed<A>(
        _ctxt: *mut c_void,
        context: *mut c_void,
    ) where
        A: 'static
            + ArchitectureWithFunctionContext<Handle = CustomArchitectureHandle<A>>
            + Send
            + Sync,
    {
        if context.is_null() {
            return;
        }
        // The context was allocated via Box::into_raw in set_function_arch_context,
        // so we reconstruct the Box here and let it drop.
        let _ = unsafe { Box::from_raw(context as *mut A::FunctionArchContext) };
    }

    unsafe extern "C" fn cb_get_instruction_text_with_context_typed<A>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: *mut usize,
        context: *mut c_void,
        result: *mut *mut BNInstructionTextToken,
        count: *mut usize,
    ) -> bool
    where
        A: 'static
            + ArchitectureWithFunctionContext<Handle = CustomArchitectureHandle<A>>
            + Send
            + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { std::slice::from_raw_parts(data, *len) };
        let result = unsafe { &mut *result };
        let typed_context: Option<&A::FunctionArchContext> = if context.is_null() {
            None
        } else {
            Some(unsafe { &*(context as *const A::FunctionArchContext) })
        };

        let Some((res_size, res_tokens)) =
            custom_arch.instruction_text_with_typed_context(data, addr, typed_context)
        else {
            return false;
        };

        let res_tokens: Box<[BNInstructionTextToken]> = res_tokens
            .into_iter()
            .map(InstructionTextToken::into_raw)
            .collect();
        unsafe {
            let res_tokens = Box::leak(res_tokens);
            *result = res_tokens.as_mut_ptr();
            *count = res_tokens.len();
            *len = res_size;
        }
        true
    }

    register_architecture_impl(name, func, |custom_arch| {
        custom_arch.freeFunctionArchContext = Some(cb_free_function_arch_context_typed::<A>);
        custom_arch.getInstructionTextWithContext =
            Some(cb_get_instruction_text_with_context_typed::<A>);
    })
}

#[derive(Debug)]
pub struct CustomArchitectureHandle<A>
where
    A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
{
    handle: *mut A,
}

unsafe impl<A> Send for CustomArchitectureHandle<A> where
    A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync
{
}

unsafe impl<A> Sync for CustomArchitectureHandle<A> where
    A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync
{
}

impl<A> Clone for CustomArchitectureHandle<A>
where
    A: 'static + Architecture<Handle = Self> + Send + Sync,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<A> Copy for CustomArchitectureHandle<A> where
    A: 'static + Architecture<Handle = Self> + Send + Sync
{
}

impl<A> Borrow<A> for CustomArchitectureHandle<A>
where
    A: 'static + Architecture<Handle = Self> + Send + Sync,
{
    fn borrow(&self) -> &A {
        unsafe { &*self.handle }
    }
}
