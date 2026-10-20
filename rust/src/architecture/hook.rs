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

//! Hooks that override selected operations of an existing architecture.

use super::*;

// Keep the hook defaults and the Architecture adapter in sync using one signature list.
macro_rules! architecture_hook {
    ($(fn $name:ident $(<$lt:lifetime>)? ($($arg:ident: $ty:ty),* $(,)?) -> $ret:ty;)*) => {
        /// Overrides selected operations of an already registered architecture.
        ///
        /// Every method defaults to forwarding to `base`, the previous implementation in the
        /// hook chain. Override only the methods you need. Use the supplied `base` to delegate:
        /// looking up the hooked architecture by name inside a callback would call the hook again.
        ///
        /// Flag-write operations without a typed representation are delivered as
        /// [`LowLevelILFlagWriteOp::Raw`], including their complete operand list.
        ///
        /// The methods have the same semantics as their counterparts in [`Architecture`].
        /// Contextual disassembly forwards to the previous contextual implementation; override
        /// [`ArchitectureHook::instruction_text_with_context`] to change contextual text.
        ///
        /// Register implementations with [`register_architecture_hook`].
        pub trait ArchitectureHook: Send + Sync + 'static {
            $(
                #[doc = concat!("See [`Architecture::", stringify!($name), "`].")]
                fn $name $(<$lt>)? (&self, base: &CoreArchitecture, $($arg: $ty),*) -> $ret {
                    base.$name($($arg),*)
                }
            )*
        }

        impl<H: ArchitectureHook> Architecture for HookArchitecture<H> {
            type Handle = CustomArchitectureHandle<Self>;
            type RegisterInfo = CoreRegisterInfo;
            type Register = CoreRegister;
            type RegisterStackInfo = CoreRegisterStackInfo;
            type RegisterStack = CoreRegisterStack;
            type Flag = CoreFlag;
            type FlagWrite = CoreFlagWrite;
            type FlagClass = CoreFlagClass;
            type FlagGroup = CoreFlagGroup;
            type Intrinsic = CoreIntrinsic;

            $(
                fn $name $(<$lt>)? (&self, $($arg: $ty),*) -> $ret {
                    self.hook.$name(&self.base, $($arg),*)
                }
            )*

            fn handle(&self) -> Self::Handle {
                self.handle
            }
        }
    };
}

architecture_hook! {
    fn endianness() -> Endianness;
    fn address_size() -> usize;
    fn default_integer_size() -> usize;
    fn instruction_alignment() -> usize;
    fn linear_sweep_initial_alignment() -> usize;
    fn linear_sweep_analysis_capabilities() -> u32;
    fn max_instr_len() -> usize;
    fn opcode_display_len() -> usize;
    fn associated_arch_by_addr(addr: &mut u64) -> CoreArchitecture;
    fn instruction_info(data: &[u8], addr: u64) -> Option<InstructionInfo>;
    fn instruction_text(data: &[u8], addr: u64) -> Option<(usize, Vec<InstructionTextToken>)>;
    fn instruction_text_with_context(
        data: &[u8],
        addr: u64,
        context: Option<NonNull<c_void>>,
    ) -> Option<(usize, Vec<InstructionTextToken>)>;
    fn instruction_llil(
        data: &[u8],
        addr: u64,
        il: &LowLevelILMutableFunction,
    ) -> Option<(usize, bool)>;
    fn analyze_basic_blocks(function: &mut Function, context: &mut BasicBlockAnalysisContext) -> ();
    fn lift_function(
        function: LowLevelILMutableFunction,
        context: &mut FunctionLifterContext,
    ) -> bool;
    fn flag_write_llil<'a>(
        flag: CoreFlag,
        flag_write_type: CoreFlagWrite,
        op: LowLevelILFlagWriteOp<CoreRegister>,
        il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>>;
    fn flags_required_for_flag_condition(
        condition: FlagCondition,
        class: Option<CoreFlagClass>,
    ) -> Vec<CoreFlag>;
    fn flag_cond_llil<'a>(
        cond: FlagCondition,
        class: Option<CoreFlagClass>,
        il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>>;
    fn flag_group_llil<'a>(
        group: CoreFlagGroup,
        il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>>;
    fn registers_all() -> Vec<CoreRegister>;
    fn register_from_id(id: RegisterId) -> Option<CoreRegister>;
    fn registers_full_width() -> Vec<CoreRegister>;
    fn registers_global() -> Vec<CoreRegister>;
    fn registers_system() -> Vec<CoreRegister>;
    fn stack_pointer_reg() -> Option<CoreRegister>;
    fn link_reg() -> Option<CoreRegister>;
    fn register_stacks() -> Vec<CoreRegisterStack>;
    fn register_stack_from_id(id: RegisterStackId) -> Option<CoreRegisterStack>;
    fn flags() -> Vec<CoreFlag>;
    fn flag_from_id(id: FlagId) -> Option<CoreFlag>;
    fn flag_write_types() -> Vec<CoreFlagWrite>;
    fn flag_write_from_id(id: FlagWriteId) -> Option<CoreFlagWrite>;
    fn flag_classes() -> Vec<CoreFlagClass>;
    fn flag_class_from_id(id: FlagClassId) -> Option<CoreFlagClass>;
    fn flag_groups() -> Vec<CoreFlagGroup>;
    fn flag_group_from_id(id: FlagGroupId) -> Option<CoreFlagGroup>;
    fn intrinsics() -> Vec<CoreIntrinsic>;
    fn intrinsic_class(id: IntrinsicId) -> BNIntrinsicClass;
    fn intrinsic_from_id(id: IntrinsicId) -> Option<CoreIntrinsic>;
    fn can_assemble() -> bool;
    fn assemble(code: &str, addr: u64) -> Result<Vec<u8>, String>;
    fn is_never_branch_patch_available(data: &[u8], addr: u64) -> bool;
    fn is_always_branch_patch_available(data: &[u8], addr: u64) -> bool;
    fn is_invert_branch_patch_available(data: &[u8], addr: u64) -> bool;
    fn is_skip_and_return_zero_patch_available(data: &[u8], addr: u64) -> bool;
    fn is_skip_and_return_value_patch_available(data: &[u8], addr: u64) -> bool;
    fn convert_to_nop(data: &mut [u8], addr: u64) -> bool;
    fn always_branch(data: &mut [u8], addr: u64) -> bool;
    fn invert_branch(data: &mut [u8], addr: u64) -> bool;
    fn skip_and_return_value(data: &mut [u8], addr: u64, value: u64) -> bool;
}

struct HookArchitecture<H: ArchitectureHook> {
    hook: H,
    base: CoreArchitecture,
    handle: CustomArchitectureHandle<Self>,
}

impl<H: ArchitectureHook> AsRef<CoreArchitecture> for HookArchitecture<H> {
    fn as_ref(&self) -> &CoreArchitecture {
        &self.base
    }
}

/// Installs a hook on `base`, affecting all existing users of that architecture.
///
/// Hooks run in reverse registration order. Each callback receives the previous implementation,
/// which can be called to delegate without recursion. The hook is retained for the lifetime of
/// the core and cannot be unregistered. The returned reference can be used to access its state.
///
/// Like [`register_architecture`], call this during `CorePluginInit`, after the base architecture
/// is registered and before analysis starts.
///
/// ```no_run
/// use binaryninja::architecture::{
///     register_architecture_hook, Architecture, ArchitectureHook, CoreArchitecture,
/// };
/// use binaryninja::disassembly::{InstructionTextToken, InstructionTextTokenKind};
///
/// struct Annotate;
/// impl ArchitectureHook for Annotate {
///     fn instruction_text(
///         &self, base: &CoreArchitecture, data: &[u8], addr: u64,
///     ) -> Option<(usize, Vec<InstructionTextToken>)> {
///         let (length, mut tokens) = base.instruction_text(data, addr)?;
///         tokens.push(InstructionTextToken::new(" ; hooked", InstructionTextTokenKind::Annotation));
///         Some((length, tokens))
///     }
/// }
/// register_architecture_hook(CoreArchitecture::by_name("x86_64").unwrap(), Annotate);
/// ```
pub fn register_architecture_hook<H: ArchitectureHook>(
    base: CoreArchitecture,
    hook: H,
) -> &'static H {
    let registered = super::register_architecture_impl(
        ArchitectureRegistration::Hook(base),
        |handle, base| HookArchitecture { hook, base, handle },
        |_| {},
    );
    &registered.hook
}
