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

//! Architectures provide disassembly, lifting, and associated metadata about a CPU to inform analysis and decompilation.

// container abstraction to avoid Vec<> (want CoreArchFlagList, CoreArchRegList)
// RegisterInfo purge
use binaryninjacore_sys::*;
use std::fmt::{Debug, Formatter};

use crate::{
    calling_convention::CoreCallingConvention,
    data_buffer::DataBuffer,
    disassembly::InstructionTextToken,
    low_level_il::{MutableLiftedILExpr, MutableLiftedILFunction},
    platform::Platform,
    rc::*,
    relocation::CoreRelocationHandler,
    string::BnStrCompatible,
    string::*,
    types::{NameAndType, Type},
    Endianness,
};
use std::ops::Deref;
use std::{
    borrow::{Borrow, Cow},
    collections::HashMap,
    ffi::{c_char, c_int, c_void, CStr, CString},
    fmt::Display,
    hash::Hash,
    mem::MaybeUninit,
};

use crate::function_recognizer::FunctionRecognizer;
use crate::relocation::{CustomRelocationHandlerHandle, RelocationHandler};

use crate::confidence::Conf;
use crate::low_level_il::expression::ValueExpr;
use crate::low_level_il::lifting::{
    get_default_flag_cond_llil, get_default_flag_write_llil, LowLevelILFlagWriteOp,
};
pub use binaryninjacore_sys::BNFlagRole as FlagRole;
pub use binaryninjacore_sys::BNImplicitRegisterExtend as ImplicitRegisterExtend;
pub use binaryninjacore_sys::BNLowLevelILFlagCondition as FlagCondition;

macro_rules! newtype {
    ($name:ident, $inner_type:ty) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub $inner_type);

        impl From<$inner_type> for $name {
            fn from(value: $inner_type) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner_type {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

newtype!(RegisterId, u32);
newtype!(RegisterStackId, u32);
newtype!(FlagId, u32);
// TODO: Make this NonZero<u32>?
newtype!(FlagWriteId, u32);
newtype!(FlagClassId, u32);
newtype!(FlagGroupId, u32);
newtype!(IntrinsicId, u32);

#[derive(Default, Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum BranchKind {
    #[default]
    Unresolved,
    Unconditional(u64),
    False(u64),
    True(u64),
    Call(u64),
    FunctionReturn,
    SystemCall,
    Indirect,
    Exception,
    UserDefined,
}

#[derive(Default, Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct BranchInfo {
    /// If `None` the target architecture is the same as the branch instruction.
    pub arch: Option<CoreArchitecture>,
    pub kind: BranchKind,
}

impl BranchInfo {
    /// Branches to an instruction with the current architecture.
    pub fn new(kind: BranchKind) -> Self {
        Self { arch: None, kind }
    }

    /// Branches to an instruction with an explicit architecture.
    ///
    /// Use this if your architecture can transition to another architecture with a branch.
    pub fn new_with_arch(kind: BranchKind, arch: CoreArchitecture) -> Self {
        Self {
            arch: Some(arch),
            kind,
        }
    }

    pub fn target(&self) -> Option<u64> {
        match self.kind {
            BranchKind::Unconditional(target) => Some(target),
            BranchKind::False(target) => Some(target),
            BranchKind::True(target) => Some(target),
            BranchKind::Call(target) => Some(target),
            _ => None,
        }
    }
}

impl From<BranchInfo> for BNBranchType {
    fn from(value: BranchInfo) -> Self {
        match value.kind {
            BranchKind::Unresolved => BNBranchType::UnresolvedBranch,
            BranchKind::Unconditional(_) => BNBranchType::UnconditionalBranch,
            BranchKind::False(_) => BNBranchType::FalseBranch,
            BranchKind::True(_) => BNBranchType::TrueBranch,
            BranchKind::Call(_) => BNBranchType::CallDestination,
            BranchKind::FunctionReturn => BNBranchType::FunctionReturn,
            BranchKind::SystemCall => BNBranchType::SystemCall,
            BranchKind::Indirect => BNBranchType::IndirectBranch,
            BranchKind::Exception => BNBranchType::ExceptionBranch,
            BranchKind::UserDefined => BNBranchType::UserDefinedBranch,
        }
    }
}

impl From<BranchKind> for BranchInfo {
    fn from(value: BranchKind) -> Self {
        Self {
            arch: None,
            kind: value,
        }
    }
}

/// This is the number of branches that can be specified in an [`InstructionInfo`].
pub const NUM_BRANCH_INFO: usize = 3;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct InstructionInfo {
    pub length: usize,
    // TODO: This field name is really long...
    pub arch_transition_by_target_addr: bool,
    pub delay_slots: u8,
    pub branches: [Option<BranchInfo>; NUM_BRANCH_INFO],
}

impl InstructionInfo {
    // TODO: `new_with_delay_slot`?
    pub fn new(length: usize, delay_slots: u8) -> Self {
        Self {
            length,
            arch_transition_by_target_addr: false,
            delay_slots,
            branches: Default::default(),
        }
    }

    pub fn add_branch(&mut self, branch_info: impl Into<BranchInfo>) {
        // Will go through each slot and attempt to add the branch info.
        // TODO: Return a result with BranchInfoSlotsFilled error.
        for branch in &mut self.branches {
            if branch.is_none() {
                *branch = Some(branch_info.into());
                return;
            }
        }
    }
}

impl From<BNInstructionInfo> for InstructionInfo {
    fn from(value: BNInstructionInfo) -> Self {
        // TODO: This is quite ugly, but we destructure the branch info so this will have to do.
        let mut branch_info = [None; NUM_BRANCH_INFO];
        #[allow(clippy::needless_range_loop)]
        for i in 0..value.branchCount.min(NUM_BRANCH_INFO) {
            let branch_target = value.branchTarget[i];
            branch_info[i] = Some(BranchInfo {
                kind: match value.branchType[i] {
                    BNBranchType::UnconditionalBranch => BranchKind::Unconditional(branch_target),
                    BNBranchType::FalseBranch => BranchKind::False(branch_target),
                    BNBranchType::TrueBranch => BranchKind::True(branch_target),
                    BNBranchType::CallDestination => BranchKind::Call(branch_target),
                    BNBranchType::FunctionReturn => BranchKind::FunctionReturn,
                    BNBranchType::SystemCall => BranchKind::SystemCall,
                    BNBranchType::IndirectBranch => BranchKind::Indirect,
                    BNBranchType::ExceptionBranch => BranchKind::Exception,
                    BNBranchType::UnresolvedBranch => BranchKind::Unresolved,
                    BNBranchType::UserDefinedBranch => BranchKind::UserDefined,
                },
                arch: if value.branchArch[i].is_null() {
                    None
                } else {
                    Some(unsafe { CoreArchitecture::from_raw(value.branchArch[i]) })
                },
            });
        }
        Self {
            length: value.length,
            arch_transition_by_target_addr: value.archTransitionByTargetAddr,
            delay_slots: value.delaySlots,
            branches: branch_info,
        }
    }
}

impl From<InstructionInfo> for BNInstructionInfo {
    fn from(value: InstructionInfo) -> Self {
        let branch_count = value.branches.into_iter().filter(Option::is_some).count();
        // TODO: This is quite ugly, but we destructure the branch info so this will have to do.
        let branch_info_0 = value.branches[0].unwrap_or_default();
        let branch_info_1 = value.branches[1].unwrap_or_default();
        let branch_info_2 = value.branches[2].unwrap_or_default();
        Self {
            length: value.length,
            branchCount: branch_count,
            archTransitionByTargetAddr: value.arch_transition_by_target_addr,
            delaySlots: value.delay_slots,
            branchType: [
                branch_info_0.into(),
                branch_info_1.into(),
                branch_info_2.into(),
            ],
            branchTarget: [
                branch_info_0.target().unwrap_or_default(),
                branch_info_1.target().unwrap_or_default(),
                branch_info_2.target().unwrap_or_default(),
            ],
            branchArch: [
                branch_info_0
                    .arch
                    .map(|a| a.handle)
                    .unwrap_or(std::ptr::null_mut()),
                branch_info_1
                    .arch
                    .map(|a| a.handle)
                    .unwrap_or(std::ptr::null_mut()),
                branch_info_2
                    .arch
                    .map(|a| a.handle)
                    .unwrap_or(std::ptr::null_mut()),
            ],
        }
    }
}

pub trait RegisterInfo: Sized {
    type RegType: Register<InfoType = Self>;

    fn parent(&self) -> Option<Self::RegType>;
    fn size(&self) -> usize;
    fn offset(&self) -> usize;
    fn implicit_extend(&self) -> ImplicitRegisterExtend;
}

pub trait Register: Debug + Sized + Clone + Copy + Hash + Eq {
    type InfoType: RegisterInfo<RegType = Self>;

    fn name(&self) -> Cow<str>;
    fn info(&self) -> Self::InfoType;

    /// Unique identifier for this `Register`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> RegisterId;
}

pub trait RegisterStackInfo: Sized {
    type RegStackType: RegisterStack<InfoType = Self>;
    type RegType: Register<InfoType = Self::RegInfoType>;
    type RegInfoType: RegisterInfo<RegType = Self::RegType>;

    fn storage_regs(&self) -> (Self::RegType, usize);
    fn top_relative_regs(&self) -> Option<(Self::RegType, usize)>;
    fn stack_top_reg(&self) -> Self::RegType;
}

pub trait RegisterStack: Debug + Sized + Clone + Copy {
    type InfoType: RegisterStackInfo<
        RegType = Self::RegType,
        RegInfoType = Self::RegInfoType,
        RegStackType = Self,
    >;
    type RegType: Register<InfoType = Self::RegInfoType>;
    type RegInfoType: RegisterInfo<RegType = Self::RegType>;

    fn name(&self) -> Cow<str>;
    fn info(&self) -> Self::InfoType;

    /// Unique identifier for this `RegisterStack`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> RegisterStackId;
}

pub trait Flag: Debug + Sized + Clone + Copy + Hash + Eq {
    type FlagClass: FlagClass;

    fn name(&self) -> Cow<str>;
    fn role(&self, class: Option<Self::FlagClass>) -> FlagRole;

    /// Unique identifier for this `Flag`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> FlagId;
}

pub trait FlagWrite: Sized + Clone + Copy {
    type FlagType: Flag;
    type FlagClass: FlagClass;

    fn name(&self) -> Cow<str>;
    fn class(&self) -> Option<Self::FlagClass>;

    /// Unique identifier for this `FlagWrite`.
    ///
    /// *MUST NOT* be 0.
    /// *MUST* be in the range [1, 0x7fff_ffff]
    fn id(&self) -> FlagWriteId;

    fn flags_written(&self) -> Vec<Self::FlagType>;
}

pub trait FlagClass: Sized + Clone + Copy + Hash + Eq {
    fn name(&self) -> Cow<str>;

    /// Unique identifier for this `FlagClass`.
    ///
    /// *MUST NOT* be 0.
    /// *MUST* be in the range [1, 0x7fff_ffff]
    fn id(&self) -> FlagClassId;
}

pub trait FlagGroup: Debug + Sized + Clone + Copy {
    type FlagType: Flag;
    type FlagClass: FlagClass;

    fn name(&self) -> Cow<str>;

    /// Unique identifier for this `FlagGroup`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> FlagGroupId;

    /// Returns the list of flags that need to be resolved in order
    /// to take the clean flag resolution path -- at time of writing,
    /// all required flags must have been set by the same instruction,
    /// and the 'querying' instruction must be reachable from *one*
    /// instruction that sets all of these flags.
    fn flags_required(&self) -> Vec<Self::FlagType>;

    /// Returns the mapping of Semantic Flag Classes to Flag Conditions,
    /// in the context of this Flag Group.
    ///
    /// Example:
    ///
    /// If we have a group representing `cr1_lt` (as in PowerPC), we would
    /// have multiple Semantic Flag Classes used by the different Flag Write
    /// Types to represent the different comparisons, so for `cr1_lt` we
    /// would return a mapping along the lines of:
    ///
    /// ```text
    /// cr1_signed -> LLFC_SLT,
    /// cr1_unsigned -> LLFC_ULT,
    /// ```
    ///
    /// This allows the core to recover the semantics of the comparison and
    /// inline it into conditional branches when appropriate.
    fn flag_conditions(&self) -> HashMap<Self::FlagClass, FlagCondition>;
}

pub trait Intrinsic: Debug + Sized + Clone + Copy {
    fn name(&self) -> Cow<str>;

    /// Unique identifier for this `Intrinsic`.
    fn id(&self) -> IntrinsicId;

    /// The intrinsic class for this `Intrinsic`.
    fn class(&self) -> BNIntrinsicClass {
        BNIntrinsicClass::GeneralIntrinsicClass
    }

    // TODO: Maybe just return `(String, Conf<Ref<Type>>)`?
    /// List of the input names and types for this intrinsic.
    fn inputs(&self) -> Vec<NameAndType>;

    /// List of the output types for this intrinsic.
    fn outputs(&self) -> Vec<Conf<Ref<Type>>>;
}

pub trait Architecture: 'static + Sized + AsRef<CoreArchitecture> {
    type Handle: Borrow<Self> + Clone;

    type RegisterInfo: RegisterInfo<RegType = Self::Register>;
    type Register: Register<InfoType = Self::RegisterInfo>;
    type RegisterStackInfo: RegisterStackInfo<
        RegType = Self::Register,
        RegInfoType = Self::RegisterInfo,
        RegStackType = Self::RegisterStack,
    >;
    type RegisterStack: RegisterStack<
        InfoType = Self::RegisterStackInfo,
        RegType = Self::Register,
        RegInfoType = Self::RegisterInfo,
    >;

    type Flag: Flag<FlagClass = Self::FlagClass>;
    type FlagWrite: FlagWrite<FlagType = Self::Flag, FlagClass = Self::FlagClass>;
    type FlagClass: FlagClass;
    type FlagGroup: FlagGroup<FlagType = Self::Flag, FlagClass = Self::FlagClass>;

    type Intrinsic: Intrinsic;

    fn endianness(&self) -> Endianness;
    fn address_size(&self) -> usize;
    fn default_integer_size(&self) -> usize;
    fn instruction_alignment(&self) -> usize;
    fn max_instr_len(&self) -> usize;
    fn opcode_display_len(&self) -> usize;

    fn associated_arch_by_addr(&self, addr: u64) -> CoreArchitecture;

    fn instruction_info(&self, data: &[u8], addr: u64) -> Option<InstructionInfo>;
    fn instruction_text(
        &self,
        data: &[u8],
        addr: u64,
    ) -> Option<(usize, Vec<InstructionTextToken>)>;
    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &mut MutableLiftedILFunction<Self>,
    ) -> Option<(usize, bool)>;

    /// Fallback flag value calculation path. This method is invoked when the core is unable to
    /// recover flag use semantics, and resorts to emitting instructions that explicitly set each
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
        il: &'a mut MutableLiftedILFunction<Self>,
    ) -> Option<MutableLiftedILExpr<'a, Self, ValueExpr>> {
        let role = flag.role(flag_write_type.class());
        Some(get_default_flag_write_llil(self, role, op, il))
    }

    /// Determines what flags need to be examined in order to attempt automatic recovery of the
    /// semantics of this flag use.
    ///
    /// If automatic recovery is not possible, the `flag_cond_llil` method will be invoked to give
    /// this `Architecture` implementation arbitrary control over the expression to be evaluated.
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
        il: &'a mut MutableLiftedILFunction<Self>,
    ) -> Option<MutableLiftedILExpr<'a, Self, ValueExpr>> {
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
        _il: &'a mut MutableLiftedILFunction<Self>,
    ) -> Option<MutableLiftedILExpr<'a, Self, ValueExpr>> {
        None
    }

    fn registers_all(&self) -> Vec<Self::Register>;
    fn registers_full_width(&self) -> Vec<Self::Register>;
    fn registers_global(&self) -> Vec<Self::Register> {
        Vec::new()
    }
    fn registers_system(&self) -> Vec<Self::Register> {
        Vec::new()
    }

    fn register_stacks(&self) -> Vec<Self::RegisterStack> {
        Vec::new()
    }

    fn flags(&self) -> Vec<Self::Flag> {
        Vec::new()
    }
    fn flag_write_types(&self) -> Vec<Self::FlagWrite> {
        Vec::new()
    }
    fn flag_classes(&self) -> Vec<Self::FlagClass> {
        Vec::new()
    }
    fn flag_groups(&self) -> Vec<Self::FlagGroup> {
        Vec::new()
    }

    fn stack_pointer_reg(&self) -> Option<Self::Register>;
    fn link_reg(&self) -> Option<Self::Register> {
        None
    }

    fn register_from_id(&self, id: RegisterId) -> Option<Self::Register>;

    fn register_stack_from_id(&self, _id: RegisterStackId) -> Option<Self::RegisterStack> {
        None
    }

    fn flag_from_id(&self, _id: FlagId) -> Option<Self::Flag> {
        None
    }
    fn flag_write_from_id(&self, _id: FlagWriteId) -> Option<Self::FlagWrite> {
        None
    }
    fn flag_class_from_id(&self, _id: FlagClassId) -> Option<Self::FlagClass> {
        None
    }
    fn flag_group_from_id(&self, _id: FlagGroupId) -> Option<Self::FlagGroup> {
        None
    }

    fn intrinsics(&self) -> Vec<Self::Intrinsic> {
        Vec::new()
    }
    fn intrinsic_class(&self, _id: IntrinsicId) -> BNIntrinsicClass {
        BNIntrinsicClass::GeneralIntrinsicClass
    }
    fn intrinsic_from_id(&self, _id: IntrinsicId) -> Option<Self::Intrinsic> {
        None
    }

    fn can_assemble(&self) -> bool {
        false
    }
    fn assemble(&self, _code: &str, _addr: u64) -> Result<Vec<u8>, String> {
        Err("Assemble unsupported".into())
    }

    fn is_never_branch_patch_available(&self, _data: &[u8], _addr: u64) -> bool {
        false
    }
    fn is_always_branch_patch_available(&self, _data: &[u8], _addr: u64) -> bool {
        false
    }
    fn is_invert_branch_patch_available(&self, _data: &[u8], _addr: u64) -> bool {
        false
    }
    fn is_skip_and_return_zero_patch_available(&self, _data: &[u8], _addr: u64) -> bool {
        false
    }
    fn is_skip_and_return_value_patch_available(&self, _data: &[u8], _addr: u64) -> bool {
        false
    }

    fn convert_to_nop(&self, _data: &mut [u8], _addr: u64) -> bool {
        false
    }

    fn always_branch(&self, _data: &mut [u8], _addr: u64) -> bool {
        false
    }

    fn invert_branch(&self, _data: &mut [u8], _addr: u64) -> bool {
        false
    }

    fn skip_and_return_value(&self, _data: &mut [u8], _addr: u64, _value: u64) -> bool {
        false
    }

    fn handle(&self) -> Self::Handle;
}

/// Type for architrectures that do not use register stacks. Will panic if accessed as a register stack.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnusedRegisterStackInfo<R: Register> {
    _reg: std::marker::PhantomData<R>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnusedRegisterStack<R: Register> {
    _reg: std::marker::PhantomData<R>,
}

impl<R: Register> RegisterStackInfo for UnusedRegisterStackInfo<R> {
    type RegStackType = UnusedRegisterStack<R>;
    type RegType = R;
    type RegInfoType = R::InfoType;

    fn storage_regs(&self) -> (Self::RegType, usize) {
        unreachable!()
    }
    fn top_relative_regs(&self) -> Option<(Self::RegType, usize)> {
        unreachable!()
    }
    fn stack_top_reg(&self) -> Self::RegType {
        unreachable!()
    }
}

impl<R: Register> RegisterStack for UnusedRegisterStack<R> {
    type InfoType = UnusedRegisterStackInfo<R>;
    type RegType = R;
    type RegInfoType = R::InfoType;

    fn name(&self) -> Cow<str> {
        unreachable!()
    }
    fn id(&self) -> RegisterStackId {
        unreachable!()
    }
    fn info(&self) -> Self::InfoType {
        unreachable!()
    }
}

/// Type for architrectures that do not use flags. Will panic if accessed as a flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnusedFlag;

impl Flag for UnusedFlag {
    type FlagClass = Self;
    fn name(&self) -> Cow<str> {
        unreachable!()
    }
    fn role(&self, _class: Option<Self::FlagClass>) -> FlagRole {
        unreachable!()
    }
    fn id(&self) -> FlagId {
        unreachable!()
    }
}

impl FlagWrite for UnusedFlag {
    type FlagType = Self;
    type FlagClass = Self;
    fn name(&self) -> Cow<str> {
        unreachable!()
    }
    fn class(&self) -> Option<Self> {
        unreachable!()
    }
    fn id(&self) -> FlagWriteId {
        unreachable!()
    }
    fn flags_written(&self) -> Vec<Self::FlagType> {
        unreachable!()
    }
}

impl FlagClass for UnusedFlag {
    fn name(&self) -> Cow<str> {
        unreachable!()
    }
    fn id(&self) -> FlagClassId {
        unreachable!()
    }
}

impl FlagGroup for UnusedFlag {
    type FlagType = Self;
    type FlagClass = Self;
    fn name(&self) -> Cow<str> {
        unreachable!()
    }
    fn id(&self) -> FlagGroupId {
        unreachable!()
    }
    fn flags_required(&self) -> Vec<Self::FlagType> {
        unreachable!()
    }
    fn flag_conditions(&self) -> HashMap<Self, FlagCondition> {
        unreachable!()
    }
}

/// Type for architrectures that do not use intrinsics. Will panic if accessed as an intrinsic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnusedIntrinsic;

impl Intrinsic for UnusedIntrinsic {
    fn name(&self) -> Cow<str> {
        unreachable!()
    }
    fn id(&self) -> IntrinsicId {
        unreachable!()
    }
    fn inputs(&self) -> Vec<NameAndType> {
        unreachable!()
    }
    fn outputs(&self) -> Vec<Conf<Ref<Type>>> {
        unreachable!()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CoreRegisterInfo {
    arch: CoreArchitecture,
    id: RegisterId,
    info: BNRegisterInfo,
}

impl CoreRegisterInfo {
    pub fn new(arch: CoreArchitecture, id: RegisterId, info: BNRegisterInfo) -> Self {
        Self { arch, id, info }
    }
}

impl RegisterInfo for CoreRegisterInfo {
    type RegType = CoreRegister;

    fn parent(&self) -> Option<CoreRegister> {
        if self.id != RegisterId::from(self.info.fullWidthRegister) {
            Some(CoreRegister::new(
                self.arch,
                RegisterId::from(self.info.fullWidthRegister),
            )?)
        } else {
            None
        }
    }

    fn size(&self) -> usize {
        self.info.size
    }

    fn offset(&self) -> usize {
        self.info.offset
    }

    fn implicit_extend(&self) -> ImplicitRegisterExtend {
        self.info.extend
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreRegister {
    arch: CoreArchitecture,
    id: RegisterId,
}

impl CoreRegister {
    pub fn new(arch: CoreArchitecture, id: RegisterId) -> Option<Self> {
        let register = Self { arch, id };
        register.is_valid().then_some(register)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the register is actually valid.
        let name = unsafe { BNGetArchitectureRegisterName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl Register for CoreRegister {
    type InfoType = CoreRegisterInfo;

    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureRegisterName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn info(&self) -> CoreRegisterInfo {
        CoreRegisterInfo::new(self.arch, self.id, unsafe {
            BNGetArchitectureRegisterInfo(self.arch.handle, self.id.into())
        })
    }

    fn id(&self) -> RegisterId {
        self.id
    }
}

impl Debug for CoreRegister {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreRegister")
            .field("id", &self.id)
            .finish()
    }
}

impl CoreArrayProvider for CoreRegister {
    type Raw = u32;
    type Context = CoreArchitecture;
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CoreRegister {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeRegisterList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::new(*context, RegisterId::from(*raw)).expect("Register list contains valid registers")
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CoreRegisterStackInfo {
    arch: CoreArchitecture,
    // TODO: Wrap BNRegisterStackInfo
    info: BNRegisterStackInfo,
}

impl CoreRegisterStackInfo {
    pub fn new(arch: CoreArchitecture, info: BNRegisterStackInfo) -> Self {
        Self { arch, info }
    }
}

impl RegisterStackInfo for CoreRegisterStackInfo {
    type RegStackType = CoreRegisterStack;
    type RegType = CoreRegister;
    type RegInfoType = CoreRegisterInfo;

    fn storage_regs(&self) -> (Self::RegType, usize) {
        (
            CoreRegister::new(self.arch, RegisterId::from(self.info.firstStorageReg))
                .expect("Storage register is valid"),
            self.info.storageCount as usize,
        )
    }

    fn top_relative_regs(&self) -> Option<(Self::RegType, usize)> {
        if self.info.topRelativeCount == 0 {
            None
        } else {
            Some((
                CoreRegister::new(self.arch, RegisterId::from(self.info.firstTopRelativeReg))
                    .expect("Top relative register is valid"),
                self.info.topRelativeCount as usize,
            ))
        }
    }

    fn stack_top_reg(&self) -> Self::RegType {
        CoreRegister::new(self.arch, RegisterId::from(self.info.stackTopReg))
            .expect("Stack top register is valid")
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreRegisterStack {
    arch: CoreArchitecture,
    id: RegisterStackId,
}

impl CoreRegisterStack {
    pub fn new(arch: CoreArchitecture, id: RegisterStackId) -> Option<Self> {
        let register_stack = Self { arch, id };
        register_stack.is_valid().then_some(register_stack)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the stack register is actually valid.
        let name = unsafe { BNGetArchitectureRegisterStackName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl RegisterStack for CoreRegisterStack {
    type InfoType = CoreRegisterStackInfo;
    type RegType = CoreRegister;
    type RegInfoType = CoreRegisterInfo;

    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureRegisterStackName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn info(&self) -> CoreRegisterStackInfo {
        CoreRegisterStackInfo::new(self.arch, unsafe {
            BNGetArchitectureRegisterStackInfo(self.arch.handle, self.id.into())
        })
    }

    fn id(&self) -> RegisterStackId {
        self.id
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreFlag {
    arch: CoreArchitecture,
    id: FlagId,
}

impl CoreFlag {
    pub fn new(arch: CoreArchitecture, id: FlagId) -> Option<Self> {
        let flag = Self { arch, id };
        flag.is_valid().then_some(flag)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the flag is actually valid.
        let name = unsafe { BNGetArchitectureFlagName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl Flag for CoreFlag {
    type FlagClass = CoreFlagClass;

    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureFlagName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn role(&self, class: Option<CoreFlagClass>) -> FlagRole {
        unsafe {
            BNGetArchitectureFlagRole(
                self.arch.handle,
                self.id.into(),
                class.map(|c| c.id.0).unwrap_or(0),
            )
        }
    }

    fn id(&self) -> FlagId {
        self.id
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreFlagWrite {
    arch: CoreArchitecture,
    id: FlagWriteId,
}

impl CoreFlagWrite {
    pub fn new(arch: CoreArchitecture, id: FlagWriteId) -> Option<Self> {
        let flag_write = Self { arch, id };
        flag_write.is_valid().then_some(flag_write)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the flag write is actually valid.
        let name = unsafe { BNGetArchitectureFlagWriteTypeName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl FlagWrite for CoreFlagWrite {
    type FlagType = CoreFlag;
    type FlagClass = CoreFlagClass;

    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureFlagWriteTypeName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn class(&self) -> Option<CoreFlagClass> {
        let class = unsafe {
            BNGetArchitectureSemanticClassForFlagWriteType(self.arch.handle, self.id.into())
        };

        match class {
            0 => None,
            class_id => Some(CoreFlagClass::new(self.arch, class_id.into())?),
        }
    }

    fn id(&self) -> FlagWriteId {
        self.id
    }

    fn flags_written(&self) -> Vec<CoreFlag> {
        let mut count: usize = 0;
        let regs: *mut u32 = unsafe {
            BNGetArchitectureFlagsWrittenByFlagWriteType(
                self.arch.handle,
                self.id.into(),
                &mut count,
            )
        };

        let ret = unsafe {
            std::slice::from_raw_parts(regs, count)
                .iter()
                .map(|id| FlagId::from(*id))
                .filter_map(|reg| CoreFlag::new(self.arch, reg))
                .collect()
        };

        unsafe {
            BNFreeRegisterList(regs);
        }

        ret
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreFlagClass {
    arch: CoreArchitecture,
    id: FlagClassId,
}

impl CoreFlagClass {
    pub fn new(arch: CoreArchitecture, id: FlagClassId) -> Option<Self> {
        let flag = Self { arch, id };
        flag.is_valid().then_some(flag)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the flag is actually valid.
        let name =
            unsafe { BNGetArchitectureSemanticFlagClassName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl FlagClass for CoreFlagClass {
    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureSemanticFlagClassName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn id(&self) -> FlagClassId {
        self.id
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CoreFlagGroup {
    arch: CoreArchitecture,
    id: FlagGroupId,
}

impl CoreFlagGroup {
    pub fn new(arch: CoreArchitecture, id: FlagGroupId) -> Option<Self> {
        let flag_group = Self { arch, id };
        flag_group.is_valid().then_some(flag_group)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the flag group is actually valid.
        let name =
            unsafe { BNGetArchitectureSemanticFlagGroupName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl FlagGroup for CoreFlagGroup {
    type FlagType = CoreFlag;
    type FlagClass = CoreFlagClass;

    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureSemanticFlagGroupName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn id(&self) -> FlagGroupId {
        self.id
    }

    fn flags_required(&self) -> Vec<CoreFlag> {
        let mut count: usize = 0;
        let regs: *mut u32 = unsafe {
            BNGetArchitectureFlagsRequiredForSemanticFlagGroup(
                self.arch.handle,
                self.id.into(),
                &mut count,
            )
        };

        let ret = unsafe {
            std::slice::from_raw_parts(regs, count)
                .iter()
                .map(|id| FlagId::from(*id))
                .filter_map(|reg| CoreFlag::new(self.arch, reg))
                .collect()
        };

        unsafe {
            BNFreeRegisterList(regs);
        }

        ret
    }

    fn flag_conditions(&self) -> HashMap<CoreFlagClass, FlagCondition> {
        let mut count: usize = 0;

        unsafe {
            let flag_conds = BNGetArchitectureFlagConditionsForSemanticFlagGroup(
                self.arch.handle,
                self.id.into(),
                &mut count,
            );

            let ret = std::slice::from_raw_parts_mut(flag_conds, count)
                .iter()
                .filter_map(|class_cond| {
                    Some((
                        CoreFlagClass::new(self.arch, class_cond.semanticClass.into())?,
                        class_cond.condition,
                    ))
                })
                .collect();

            BNFreeFlagConditionsForSemanticFlagGroup(flag_conds);

            ret
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CoreIntrinsic {
    pub arch: CoreArchitecture,
    pub id: IntrinsicId,
}

impl CoreIntrinsic {
    pub fn new(arch: CoreArchitecture, id: IntrinsicId) -> Option<Self> {
        let intrinsic = Self { arch, id };
        intrinsic.is_valid().then_some(intrinsic)
    }

    fn is_valid(&self) -> bool {
        // We check the name to see if the intrinsic is actually valid.
        let name = unsafe { BNGetArchitectureIntrinsicName(self.arch.handle, self.id.into()) };
        match name.is_null() {
            true => false,
            false => {
                unsafe { BNFreeString(name) };
                true
            }
        }
    }
}

impl Intrinsic for CoreIntrinsic {
    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureIntrinsicName(self.arch.handle, self.id.into());

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            // TODO: ^ the above assertion nullifies any benefit to passing back Cow tho?
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn id(&self) -> IntrinsicId {
        self.id
    }

    fn class(&self) -> BNIntrinsicClass {
        unsafe { BNGetArchitectureIntrinsicClass(self.arch.handle, self.id.into()) }
    }

    fn inputs(&self) -> Vec<NameAndType> {
        let mut count: usize = 0;
        unsafe {
            let inputs =
                BNGetArchitectureIntrinsicInputs(self.arch.handle, self.id.into(), &mut count);

            let ret = std::slice::from_raw_parts_mut(inputs, count)
                .iter()
                .map(NameAndType::from_raw)
                .collect();

            BNFreeNameAndTypeList(inputs, count);

            ret
        }
    }

    fn outputs(&self) -> Vec<Conf<Ref<Type>>> {
        let mut count: usize = 0;
        unsafe {
            let inputs =
                BNGetArchitectureIntrinsicOutputs(self.arch.handle, self.id.into(), &mut count);

            let ret = std::slice::from_raw_parts_mut(inputs, count)
                .iter()
                .map(Conf::<Ref<Type>>::from_raw)
                .collect();

            BNFreeOutputTypeList(inputs, count);

            ret
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
    pub(crate) unsafe fn from_raw(handle: *mut BNArchitecture) -> Self {
        debug_assert!(!handle.is_null());
        CoreArchitecture { handle }
    }

    pub fn list_all() -> CoreArchitectureList {
        let mut count: usize = 0;
        let archs = unsafe { BNGetArchitectureList(&mut count) };

        CoreArchitectureList(archs, count)
    }

    pub fn by_name(name: &str) -> Option<Self> {
        let handle =
            unsafe { BNGetArchitectureByName(name.into_bytes_with_nul().as_ptr() as *mut _) };
        match handle.is_null() {
            false => Some(CoreArchitecture { handle }),
            true => None,
        }
    }

    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetArchitectureName(self.handle)) }
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

    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &mut MutableLiftedILFunction<Self>,
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

    fn flag_write_llil<'a>(
        &self,
        _flag: Self::Flag,
        _flag_write: Self::FlagWrite,
        _op: LowLevelILFlagWriteOp<Self::Register>,
        _il: &'a mut MutableLiftedILFunction<Self>,
    ) -> Option<MutableLiftedILExpr<'a, Self, ValueExpr>> {
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
        _il: &'a mut MutableLiftedILFunction<Self>,
    ) -> Option<MutableLiftedILExpr<'a, Self, ValueExpr>> {
        None
    }

    fn flag_group_llil<'a>(
        &self,
        _group: Self::FlagGroup,
        _il: &'a mut MutableLiftedILFunction<Self>,
    ) -> Option<MutableLiftedILExpr<'a, Self, ValueExpr>> {
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

    fn stack_pointer_reg(&self) -> Option<CoreRegister> {
        match unsafe { BNGetArchitectureStackPointerRegister(self.handle) } {
            0xffff_ffff => None,
            reg => Some(CoreRegister::new(*self, reg.into())?),
        }
    }

    fn link_reg(&self) -> Option<CoreRegister> {
        match unsafe { BNGetArchitectureLinkRegister(self.handle) } {
            0xffff_ffff => None,
            reg => Some(CoreRegister::new(*self, reg.into())?),
        }
    }

    fn register_from_id(&self, id: RegisterId) -> Option<CoreRegister> {
        CoreRegister::new(*self, id)
    }

    fn register_stack_from_id(&self, id: RegisterStackId) -> Option<CoreRegisterStack> {
        CoreRegisterStack::new(*self, id)
    }

    fn flag_from_id(&self, id: FlagId) -> Option<CoreFlag> {
        CoreFlag::new(*self, id)
    }

    fn flag_write_from_id(&self, id: FlagWriteId) -> Option<CoreFlagWrite> {
        CoreFlagWrite::new(*self, id)
    }

    fn flag_class_from_id(&self, id: FlagClassId) -> Option<CoreFlagClass> {
        CoreFlagClass::new(*self, id)
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

        let result = match DataBuffer::new(&[]) {
            Ok(result) => result,
            Err(_) => return Err("Result buffer allocation failed".to_string()),
        };
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
            .field("default_integer_size", &self.default_integer_size())
            .field("instruction_alignment", &self.instruction_alignment())
            .field("max_instr_len", &self.max_instr_len())
            .field("opcode_display_len", &self.opcode_display_len())
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
    fn register_by_name<S: BnStrCompatible>(&self, name: S) -> Option<Self::Register> {
        let name = name.into_bytes_with_nul();

        match unsafe {
            BNGetArchitectureRegisterByName(self.as_ref().handle, name.as_ref().as_ptr() as *mut _)
        } {
            0xffff_ffff => None,
            reg => self.register_from_id(reg.into()),
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

    fn register_relocation_handler<S, R, F>(&self, name: S, func: F)
    where
        S: BnStrCompatible,
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

pub fn register_architecture<S, A, F>(name: S, func: F) -> &'static A
where
    S: BnStrCompatible,
    A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync + Sized,
    F: FnOnce(CustomArchitectureHandle<A>, CoreArchitecture) -> A,
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
        let custom_arch_handle = CustomArchitectureHandle {
            handle: ctxt as *mut A,
        };

        let data = unsafe { std::slice::from_raw_parts(data, *len) };
        let mut lifter = unsafe { MutableLiftedILFunction::from_raw(custom_arch_handle, il) };

        match custom_arch.instruction_llil(data, addr, &mut lifter) {
            Some((res_len, res_value)) => {
                unsafe { *len = res_len };
                res_value
            }
            None => false,
        }
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
        let custom_arch_handle = CustomArchitectureHandle {
            handle: ctxt as *mut A,
        };

        let flag_write = custom_arch.flag_write_from_id(FlagWriteId(flag_write));
        let flag = custom_arch.flag_from_id(FlagId(flag));
        let operands = unsafe { std::slice::from_raw_parts(operands_raw, operand_count) };
        let mut lifter = unsafe { MutableLiftedILFunction::from_raw(custom_arch_handle, il) };

        if let (Some(flag_write), Some(flag)) = (flag_write, flag) {
            if let Some(op) = LowLevelILFlagWriteOp::from_op(custom_arch, size, op, operands) {
                if let Some(expr) = custom_arch.flag_write_llil(flag, flag_write, op, &mut lifter) {
                    // TODO verify that returned expr is a bool value
                    return expr.index.0;
                }
            } else {
                log::warn!(
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
        let custom_arch_handle = CustomArchitectureHandle {
            handle: ctxt as *mut A,
        };

        let class = custom_arch.flag_class_from_id(FlagClassId(class));

        let mut lifter = unsafe { MutableLiftedILFunction::from_raw(custom_arch_handle, il) };
        if let Some(expr) = custom_arch.flag_cond_llil(cond, class, &mut lifter) {
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
        let custom_arch_handle = CustomArchitectureHandle {
            handle: ctxt as *mut A,
        };

        let mut lifter = unsafe { MutableLiftedILFunction::from_raw(custom_arch_handle, il) };

        if let Some(group) = custom_arch.flag_group_from_id(FlagGroupId(group)) {
            if let Some(expr) = custom_arch.flag_group_llil(group, &mut lifter) {
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
            result.extend = info.implicit_extend();
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
            0xffff_ffff
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
            0xffff_ffff
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
                result.firstTopRelativeReg = 0xffff_ffff;
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
        let boxed_types = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(tl, count)) };
        for ty in boxed_types {
            Conf::<Ref<Type>>::free_raw(ty);
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

    let name = name.into_bytes_with_nul();

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
        freeInstructionText: Some(cb_free_instruction_text),
        getInstructionLowLevelIL: Some(cb_instruction_llil::<A>),

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

    unsafe {
        let res =
            BNRegisterArchitecture(name.as_ref().as_ptr() as *mut _, &mut custom_arch as *mut _);

        assert!(!res.is_null());

        (*raw).arch.assume_init_mut()
    }
}

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

#[repr(i32)]
pub enum LlvmServicesDialect {
    Unspecified = 0,
    Att = 1,
    Intel = 2,
}

#[repr(i32)]
pub enum LlvmServicesCodeModel {
    Default = 0,
    Small = 1,
    Kernel = 2,
    Medium = 3,
    Large = 4,
}

#[repr(i32)]
pub enum LlvmServicesRelocMode {
    Static = 0,
    PIC = 1,
    DynamicNoPIC = 2,
}

pub fn llvm_assemble(
    code: &str,
    dialect: LlvmServicesDialect,
    arch_triple: &str,
    code_model: LlvmServicesCodeModel,
    reloc_mode: LlvmServicesRelocMode,
) -> Result<Vec<u8>, String> {
    let code = CString::new(code).map_err(|_| "Invalid encoding in code string".to_string())?;
    let arch_triple = CString::new(arch_triple)
        .map_err(|_| "Invalid encoding in architecture triple string".to_string())?;
    let mut out_bytes: *mut c_char = std::ptr::null_mut();
    let mut out_bytes_len: c_int = 0;
    let mut err_bytes: *mut c_char = std::ptr::null_mut();
    let mut err_len: c_int = 0;

    unsafe {
        BNLlvmServicesInit();
    }

    let result = unsafe {
        BNLlvmServicesAssemble(
            code.as_ptr(),
            dialect as i32,
            arch_triple.as_ptr(),
            code_model as i32,
            reloc_mode as i32,
            &mut out_bytes as *mut *mut c_char,
            &mut out_bytes_len as *mut c_int,
            &mut err_bytes as *mut *mut c_char,
            &mut err_len as *mut c_int,
        )
    };

    let out = if out_bytes_len == 0 {
        Vec::new()
    } else {
        unsafe {
            std::slice::from_raw_parts(
                out_bytes as *const c_char as *const u8,
                out_bytes_len as usize,
            )
        }
        .to_vec()
    };

    let errors = if err_len == 0 {
        "".into()
    } else {
        String::from_utf8_lossy(unsafe {
            std::slice::from_raw_parts(err_bytes as *const c_char as *const u8, err_len as usize)
        })
        .into_owned()
    };

    unsafe {
        BNLlvmServicesAssembleFree(out_bytes, err_bytes);
    }

    if result == 0 {
        Ok(out)
    } else {
        Err(errors)
    }
}
