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

use std::{
    borrow::{Borrow, Cow},
    collections::HashMap,
    ffi::{c_char, c_int, CStr, CString},
    hash::Hash,
    mem::{zeroed, MaybeUninit},
    ops, ptr, slice,
};

use crate::{
    callingconvention::CallingConvention,
    databuffer::DataBuffer,
    disassembly::InstructionTextToken,
    llil::{
        get_default_flag_cond_llil, get_default_flag_write_llil, FlagWriteOp, LiftedExpr, Lifter,
    },
    platform::Platform,
    rc::*,
    relocation::CoreRelocationHandler,
    string::BnStrCompatible,
    string::*,
    types::{Conf, NameAndType, Type},
    {BranchType, Endianness},
};

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum BranchInfo {
    Unconditional(u64),
    False(u64),
    True(u64),
    Call(u64),
    FunctionReturn,
    SystemCall,
    Indirect,
    Exception,
    Unresolved,
    UserDefined,
}

pub struct BranchIter<'a>(&'a InstructionInfo, ops::Range<usize>);
impl<'a> Iterator for BranchIter<'a> {
    type Item = (BranchInfo, Option<CoreArchitecture>);

    fn next(&mut self) -> Option<Self::Item> {
        use crate::BranchType::*;

        match self.1.next() {
            Some(i) => {
                let target = (self.0).0.branchTarget[i];
                let arch = (self.0).0.branchArch[i];
                let arch = if arch.is_null() {
                    None
                } else {
                    Some(CoreArchitecture(arch))
                };

                let res = match (self.0).0.branchType[i] {
                    UnconditionalBranch => BranchInfo::Unconditional(target),
                    FalseBranch => BranchInfo::False(target),
                    TrueBranch => BranchInfo::True(target),
                    CallDestination => BranchInfo::Call(target),
                    FunctionReturn => BranchInfo::FunctionReturn,
                    SystemCall => BranchInfo::SystemCall,
                    IndirectBranch => BranchInfo::Indirect,
                    ExceptionBranch => BranchInfo::Exception,
                    UnresolvedBranch => BranchInfo::Unresolved,
                    UserDefinedBranch => BranchInfo::UserDefined,
                };

                Some((res, arch))
            }
            _ => None,
        }
    }
}

#[repr(C)]
pub struct InstructionInfo(BNInstructionInfo);
impl InstructionInfo {
    pub fn new(len: usize, delay_slots: u8) -> Self {
        InstructionInfo(BNInstructionInfo {
            length: len,
            archTransitionByTargetAddr: false,
            delaySlots: delay_slots,
            branchCount: 0usize,
            branchType: [BranchType::UnresolvedBranch; 3],
            branchTarget: [0u64; 3],
            branchArch: [ptr::null_mut(); 3],
        })
    }

    pub fn len(&self) -> usize {
        self.0.length
    }

    pub fn is_empty(&self) -> bool {
        self.0.length == 0
    }

    pub fn branch_count(&self) -> usize {
        self.0.branchCount
    }

    pub fn delay_slots(&self) -> u8 {
        self.0.delaySlots
    }

    pub fn branches(&self) -> BranchIter {
        BranchIter(self, 0..self.branch_count())
    }

    pub fn allow_arch_transition_by_target_addr(&mut self, transition: bool) {
        self.0.archTransitionByTargetAddr = transition;
    }

    pub fn add_branch(&mut self, branch: BranchInfo, arch: Option<CoreArchitecture>) {
        if self.0.branchCount < self.0.branchType.len() {
            let idx = self.0.branchCount;

            let ty = match branch {
                BranchInfo::Unconditional(t) => {
                    self.0.branchTarget[idx] = t;
                    BranchType::UnconditionalBranch
                }
                BranchInfo::False(t) => {
                    self.0.branchTarget[idx] = t;
                    BranchType::FalseBranch
                }
                BranchInfo::True(t) => {
                    self.0.branchTarget[idx] = t;
                    BranchType::TrueBranch
                }
                BranchInfo::Call(t) => {
                    self.0.branchTarget[idx] = t;
                    BranchType::CallDestination
                }
                BranchInfo::FunctionReturn => BranchType::FunctionReturn,
                BranchInfo::SystemCall => BranchType::SystemCall,
                BranchInfo::Indirect => BranchType::IndirectBranch,
                BranchInfo::Exception => BranchType::ExceptionBranch,
                BranchInfo::Unresolved => BranchType::UnresolvedBranch,
                BranchInfo::UserDefined => BranchType::UserDefinedBranch,
            };

            self.0.branchType[idx] = ty;
            self.0.branchArch[idx] = match arch {
                Some(a) => a.0,
                _ => ptr::null_mut(),
            };

            self.0.branchCount += 1;
        } else {
            error!("Attempt to branch to instruction with no additional branch space!");
        }
    }
}

use crate::functionrecognizer::FunctionRecognizer;
use crate::relocation::{CustomRelocationHandlerHandle, RelocationHandler};
pub use binaryninjacore_sys::BNFlagRole as FlagRole;
pub use binaryninjacore_sys::BNImplicitRegisterExtend as ImplicitRegisterExtend;
pub use binaryninjacore_sys::BNLowLevelILFlagCondition as FlagCondition;

pub trait RegisterInfo: Sized {
    type RegType: Register<InfoType = Self>;

    fn parent(&self) -> Option<Self::RegType>;
    fn size(&self) -> usize;
    fn offset(&self) -> usize;
    fn implicit_extend(&self) -> ImplicitRegisterExtend;
}

pub trait Register: Sized + Clone + Copy + Hash + Eq {
    type InfoType: RegisterInfo<RegType = Self>;

    fn name(&self) -> Cow<str>;
    fn info(&self) -> Self::InfoType;

    /// Unique identifier for this `Register`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> u32;
}

pub trait RegisterStackInfo: Sized {
    type RegStackType: RegisterStack<InfoType = Self>;
    type RegType: Register<InfoType = Self::RegInfoType>;
    type RegInfoType: RegisterInfo<RegType = Self::RegType>;

    fn storage_regs(&self) -> (Self::RegType, u32);
    fn top_relative_regs(&self) -> Option<(Self::RegType, u32)>;
    fn stack_top_reg(&self) -> Self::RegType;
}

pub trait RegisterStack: Sized + Clone + Copy {
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
    fn id(&self) -> u32;
}

pub trait Flag: Sized + Clone + Copy + Hash + Eq {
    type FlagClass: FlagClass;

    fn name(&self) -> Cow<str>;
    fn role(&self, class: Option<Self::FlagClass>) -> FlagRole;

    /// Unique identifier for this `Flag`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> u32;
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
    fn id(&self) -> u32;

    fn flags_written(&self) -> Vec<Self::FlagType>;
}

pub trait FlagClass: Sized + Clone + Copy + Hash + Eq {
    fn name(&self) -> Cow<str>;

    /// Unique identifier for this `FlagClass`.
    ///
    /// *MUST NOT* be 0.
    /// *MUST* be in the range [1, 0x7fff_ffff]
    fn id(&self) -> u32;
}

pub trait FlagGroup: Sized + Clone + Copy {
    type FlagType: Flag;
    type FlagClass: FlagClass;

    fn name(&self) -> Cow<str>;

    /// Unique identifier for this `FlagGroup`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> u32;

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

pub trait Intrinsic: Sized + Clone + Copy {
    fn name(&self) -> Cow<str>;

    /// Unique identifier for this `Intrinsic`.
    fn id(&self) -> u32;

    /// Reeturns the list of the input names and types for this intrinsic.
    fn inputs(&self) -> Vec<Ref<NameAndType>>;

    /// Returns the list of the output types for this intrinsic.
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

    fn associated_arch_by_addr(&self, addr: &mut u64) -> CoreArchitecture;

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
        il: &mut Lifter<Self>,
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
        op: FlagWriteOp<Self::Register>,
        il: &'a mut Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>> {
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
        il: &'a mut Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>> {
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
        _il: &'a mut Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>> {
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

    fn register_from_id(&self, id: u32) -> Option<Self::Register>;

    fn register_stack_from_id(&self, _id: u32) -> Option<Self::RegisterStack> {
        None
    }

    fn flag_from_id(&self, _id: u32) -> Option<Self::Flag> {
        None
    }
    fn flag_write_from_id(&self, _id: u32) -> Option<Self::FlagWrite> {
        None
    }
    fn flag_class_from_id(&self, _id: u32) -> Option<Self::FlagClass> {
        None
    }
    fn flag_group_from_id(&self, _id: u32) -> Option<Self::FlagGroup> {
        None
    }

    fn intrinsics(&self) -> Vec<Self::Intrinsic> {
        Vec::new()
    }
    fn intrinsic_class(&self, _id: u32) -> binaryninjacore_sys::BNIntrinsicClass {
        binaryninjacore_sys::BNIntrinsicClass::GeneralIntrinsicClass
    }
    fn intrinsic_from_id(&self, _id: u32) -> Option<Self::Intrinsic> {
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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnusedRegisterStack<R: Register> {
    _reg: std::marker::PhantomData<R>,
}

impl<R: Register> RegisterStackInfo for UnusedRegisterStackInfo<R> {
    type RegStackType = UnusedRegisterStack<R>;
    type RegType = R;
    type RegInfoType = R::InfoType;

    fn storage_regs(&self) -> (Self::RegType, u32) {
        unreachable!()
    }
    fn top_relative_regs(&self) -> Option<(Self::RegType, u32)> {
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
    fn id(&self) -> u32 {
        unreachable!()
    }
    fn info(&self) -> Self::InfoType {
        unreachable!()
    }
}

/// Type for architrectures that do not use flags. Will panic if accessed as a flag.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnusedFlag;

impl Flag for UnusedFlag {
    type FlagClass = Self;
    fn name(&self) -> Cow<str> {
        unreachable!()
    }
    fn role(&self, _class: Option<Self::FlagClass>) -> FlagRole {
        unreachable!()
    }
    fn id(&self) -> u32 {
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
    fn id(&self) -> u32 {
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
    fn id(&self) -> u32 {
        unreachable!()
    }
}

impl FlagGroup for UnusedFlag {
    type FlagType = Self;
    type FlagClass = Self;
    fn name(&self) -> Cow<str> {
        unreachable!()
    }
    fn id(&self) -> u32 {
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
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnusedIntrinsic;

impl Intrinsic for UnusedIntrinsic {
    fn name(&self) -> Cow<str> {
        unreachable!()
    }
    fn id(&self) -> u32 {
        unreachable!()
    }
    fn inputs(&self) -> Vec<Ref<NameAndType>> {
        unreachable!()
    }
    fn outputs(&self) -> Vec<Conf<Ref<Type>>> {
        unreachable!()
    }
}

pub struct CoreRegisterInfo(*mut BNArchitecture, u32, BNRegisterInfo);
impl RegisterInfo for CoreRegisterInfo {
    type RegType = CoreRegister;

    fn parent(&self) -> Option<CoreRegister> {
        if self.1 != self.2.fullWidthRegister {
            Some(CoreRegister(self.0, self.2.fullWidthRegister))
        } else {
            None
        }
    }

    fn size(&self) -> usize {
        self.2.size
    }

    fn offset(&self) -> usize {
        self.2.offset
    }

    fn implicit_extend(&self) -> ImplicitRegisterExtend {
        self.2.extend
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreRegister(*mut BNArchitecture, u32);
impl Register for CoreRegister {
    type InfoType = CoreRegisterInfo;

    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureRegisterName(self.0, self.1);

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
        CoreRegisterInfo(self.0, self.1, unsafe {
            BNGetArchitectureRegisterInfo(self.0, self.1)
        })
    }

    fn id(&self) -> u32 {
        self.1
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
        Self(context.0, *raw)
    }
}

pub struct CoreRegisterStackInfo(*mut BNArchitecture, BNRegisterStackInfo);

impl RegisterStackInfo for CoreRegisterStackInfo {
    type RegStackType = CoreRegisterStack;
    type RegType = CoreRegister;
    type RegInfoType = CoreRegisterInfo;

    fn storage_regs(&self) -> (Self::RegType, u32) {
        (
            CoreRegister(self.0, self.1.firstStorageReg),
            self.1.storageCount,
        )
    }

    fn top_relative_regs(&self) -> Option<(Self::RegType, u32)> {
        if self.1.topRelativeCount == 0 {
            None
        } else {
            Some((
                CoreRegister(self.0, self.1.firstTopRelativeReg),
                self.1.topRelativeCount,
            ))
        }
    }

    fn stack_top_reg(&self) -> Self::RegType {
        CoreRegister(self.0, self.1.stackTopReg)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreRegisterStack(*mut BNArchitecture, u32);

impl RegisterStack for CoreRegisterStack {
    type InfoType = CoreRegisterStackInfo;
    type RegType = CoreRegister;
    type RegInfoType = CoreRegisterInfo;

    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureRegisterStackName(self.0, self.1);

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
        CoreRegisterStackInfo(self.0, unsafe {
            BNGetArchitectureRegisterStackInfo(self.0, self.1)
        })
    }

    fn id(&self) -> u32 {
        self.1
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreFlag(*mut BNArchitecture, u32);
impl Flag for CoreFlag {
    type FlagClass = CoreFlagClass;

    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureFlagName(self.0, self.1);

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
        let class_id = match class {
            Some(class) => class.1,
            _ => 0,
        };

        unsafe { BNGetArchitectureFlagRole(self.0, self.1, class_id) }
    }

    fn id(&self) -> u32 {
        self.1
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreFlagWrite(*mut BNArchitecture, u32);
impl FlagWrite for CoreFlagWrite {
    type FlagType = CoreFlag;
    type FlagClass = CoreFlagClass;

    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureFlagWriteTypeName(self.0, self.1);

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn id(&self) -> u32 {
        self.1
    }

    fn flags_written(&self) -> Vec<CoreFlag> {
        let mut count: usize = 0;
        let regs: *mut u32 = unsafe {
            BNGetArchitectureFlagsWrittenByFlagWriteType(self.0, self.1, &mut count as *mut _)
        };

        let ret = unsafe {
            slice::from_raw_parts_mut(regs, count)
                .iter()
                .map(|reg| CoreFlag(self.0, *reg))
                .collect()
        };

        unsafe {
            BNFreeRegisterList(regs);
        }

        ret
    }

    fn class(&self) -> Option<CoreFlagClass> {
        let class = unsafe { BNGetArchitectureSemanticClassForFlagWriteType(self.0, self.1) };

        match class {
            0 => None,
            id => Some(CoreFlagClass(self.0, id)),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CoreFlagClass(*mut BNArchitecture, u32);
impl FlagClass for CoreFlagClass {
    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureSemanticFlagClassName(self.0, self.1);

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn id(&self) -> u32 {
        self.1
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct CoreFlagGroup(*mut BNArchitecture, u32);
impl FlagGroup for CoreFlagGroup {
    type FlagType = CoreFlag;
    type FlagClass = CoreFlagClass;

    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureSemanticFlagGroupName(self.0, self.1);

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn id(&self) -> u32 {
        self.1
    }

    fn flags_required(&self) -> Vec<CoreFlag> {
        let mut count: usize = 0;
        let regs: *mut u32 = unsafe {
            BNGetArchitectureFlagsRequiredForSemanticFlagGroup(self.0, self.1, &mut count as *mut _)
        };

        let ret = unsafe {
            slice::from_raw_parts_mut(regs, count)
                .iter()
                .map(|reg| CoreFlag(self.0, *reg))
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
                self.0,
                self.1,
                &mut count as *mut _,
            );

            let ret = slice::from_raw_parts_mut(flag_conds, count)
                .iter()
                .map(|class_cond| {
                    (
                        CoreFlagClass(self.0, class_cond.semanticClass),
                        class_cond.condition,
                    )
                })
                .collect();

            BNFreeFlagConditionsForSemanticFlagGroup(flag_conds);

            ret
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CoreIntrinsic(pub(crate) *mut BNArchitecture, pub(crate) u32);

impl Intrinsic for crate::architecture::CoreIntrinsic {
    fn name(&self) -> Cow<str> {
        unsafe {
            let name = BNGetArchitectureIntrinsicName(self.0, self.1);

            // We need to guarantee ownership, as if we're still
            // a Borrowed variant we're about to free the underlying
            // memory.
            let res = CStr::from_ptr(name);
            let res = res.to_string_lossy().into_owned().into();

            BNFreeString(name);

            res
        }
    }

    fn id(&self) -> u32 {
        self.1
    }

    fn inputs(&self) -> Vec<Ref<NameAndType>> {
        let mut count: usize = 0;

        unsafe {
            let inputs = BNGetArchitectureIntrinsicInputs(self.0, self.1, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(inputs, count)
                .iter()
                .map(|x| NameAndType::from_raw(x).to_owned())
                .collect();

            BNFreeNameAndTypeList(inputs, count);

            ret
        }
    }

    fn outputs(&self) -> Vec<Conf<Ref<Type>>> {
        let mut count: usize = 0;

        unsafe {
            let inputs = BNGetArchitectureIntrinsicOutputs(self.0, self.1, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(inputs, count)
                .iter()
                .map(|input| (*input).into())
                .collect();

            BNFreeOutputTypeList(inputs, count);

            ret
        }
    }
}

pub struct CoreArchitectureList(*mut *mut BNArchitecture, usize);
impl ops::Deref for CoreArchitectureList {
    type Target = [CoreArchitecture];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts_mut(self.0 as *mut CoreArchitecture, self.1) }
    }
}

impl Drop for CoreArchitectureList {
    fn drop(&mut self) {
        unsafe {
            BNFreeArchitectureList(self.0);
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct CoreArchitecture(pub(crate) *mut BNArchitecture);

unsafe impl Send for CoreArchitecture {}
unsafe impl Sync for CoreArchitecture {}

impl CoreArchitecture {
    pub(crate) unsafe fn from_raw(raw: *mut BNArchitecture) -> Self {
        CoreArchitecture(raw)
    }

    pub fn list_all() -> CoreArchitectureList {
        let mut count: usize = 0;
        let archs = unsafe { BNGetArchitectureList(&mut count as *mut _) };

        CoreArchitectureList(archs, count)
    }

    pub fn by_name(name: &str) -> Option<Self> {
        let res = unsafe { BNGetArchitectureByName(name.into_bytes_with_nul().as_ptr() as *mut _) };

        match res.is_null() {
            false => Some(CoreArchitecture(res)),
            true => None,
        }
    }

    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetArchitectureName(self.0)) }
    }
}

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
        unsafe { BNGetArchitectureEndianness(self.0) }
    }

    fn address_size(&self) -> usize {
        unsafe { BNGetArchitectureAddressSize(self.0) }
    }

    fn default_integer_size(&self) -> usize {
        unsafe { BNGetArchitectureDefaultIntegerSize(self.0) }
    }

    fn instruction_alignment(&self) -> usize {
        unsafe { BNGetArchitectureInstructionAlignment(self.0) }
    }

    fn max_instr_len(&self) -> usize {
        unsafe { BNGetArchitectureMaxInstructionLength(self.0) }
    }

    fn opcode_display_len(&self) -> usize {
        unsafe { BNGetArchitectureOpcodeDisplayLength(self.0) }
    }

    fn associated_arch_by_addr(&self, addr: &mut u64) -> CoreArchitecture {
        let arch = unsafe { BNGetAssociatedArchitectureByAddress(self.0, addr as *mut _) };

        CoreArchitecture(arch)
    }

    fn instruction_info(&self, data: &[u8], addr: u64) -> Option<InstructionInfo> {
        let mut info = unsafe { zeroed::<InstructionInfo>() };
        let success = unsafe {
            BNGetInstructionInfo(
                self.0,
                data.as_ptr(),
                addr,
                data.len(),
                &mut (info.0) as *mut _,
            )
        };

        if success {
            Some(info)
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
        let mut result: *mut BNInstructionTextToken = ptr::null_mut();

        unsafe {
            if BNGetInstructionText(
                self.0,
                data.as_ptr(),
                addr,
                &mut consumed as *mut _,
                &mut result as *mut _,
                &mut count as *mut _,
            ) {
                let vec = slice::from_raw_parts(result, count)
                    .iter()
                    .map(|x| InstructionTextToken::from_raw(x).to_owned())
                    .collect();
                BNFreeInstructionText(result, count);
                Some((consumed, vec))
            } else {
                None
            }
        }
    }

    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &mut Lifter<Self>,
    ) -> Option<(usize, bool)> {
        let mut size = data.len();
        let success = unsafe {
            BNGetInstructionLowLevelIL(self.0, data.as_ptr(), addr, &mut size as *mut _, il.handle)
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
        _op: FlagWriteOp<Self::Register>,
        _il: &'a mut Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>> {
        None
    }

    fn flag_cond_llil<'a>(
        &self,
        _cond: FlagCondition,
        _class: Option<Self::FlagClass>,
        _il: &'a mut Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>> {
        None
    }

    fn flag_group_llil<'a>(
        &self,
        _group: Self::FlagGroup,
        _il: &'a mut Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>> {
        None
    }

    fn registers_all(&self) -> Vec<CoreRegister> {
        unsafe {
            let mut count: usize = 0;
            let regs = BNGetAllArchitectureRegisters(self.0, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(regs, count)
                .iter()
                .map(|reg| CoreRegister(self.0, *reg))
                .collect();

            BNFreeRegisterList(regs);

            ret
        }
    }

    fn registers_full_width(&self) -> Vec<CoreRegister> {
        unsafe {
            let mut count: usize = 0;
            let regs = BNGetFullWidthArchitectureRegisters(self.0, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(regs, count)
                .iter()
                .map(|reg| CoreRegister(self.0, *reg))
                .collect();

            BNFreeRegisterList(regs);

            ret
        }
    }

    fn registers_global(&self) -> Vec<CoreRegister> {
        unsafe {
            let mut count: usize = 0;
            let regs = BNGetArchitectureGlobalRegisters(self.0, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(regs, count)
                .iter()
                .map(|reg| CoreRegister(self.0, *reg))
                .collect();

            BNFreeRegisterList(regs);

            ret
        }
    }

    fn registers_system(&self) -> Vec<CoreRegister> {
        unsafe {
            let mut count: usize = 0;
            let regs = BNGetArchitectureSystemRegisters(self.0, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(regs, count)
                .iter()
                .map(|reg| CoreRegister(self.0, *reg))
                .collect();

            BNFreeRegisterList(regs);

            ret
        }
    }

    fn register_stacks(&self) -> Vec<CoreRegisterStack> {
        unsafe {
            let mut count: usize = 0;
            let regs = BNGetAllArchitectureRegisterStacks(self.0, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(regs, count)
                .iter()
                .map(|reg| CoreRegisterStack(self.0, *reg))
                .collect();

            BNFreeRegisterList(regs);

            ret
        }
    }

    fn flags(&self) -> Vec<CoreFlag> {
        unsafe {
            let mut count: usize = 0;
            let regs = BNGetAllArchitectureFlags(self.0, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(regs, count)
                .iter()
                .map(|reg| CoreFlag(self.0, *reg))
                .collect();

            BNFreeRegisterList(regs);

            ret
        }
    }

    fn flag_write_types(&self) -> Vec<CoreFlagWrite> {
        unsafe {
            let mut count: usize = 0;
            let regs = BNGetAllArchitectureFlagWriteTypes(self.0, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(regs, count)
                .iter()
                .map(|reg| CoreFlagWrite(self.0, *reg))
                .collect();

            BNFreeRegisterList(regs);

            ret
        }
    }

    fn flag_classes(&self) -> Vec<CoreFlagClass> {
        unsafe {
            let mut count: usize = 0;
            let regs = BNGetAllArchitectureSemanticFlagClasses(self.0, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(regs, count)
                .iter()
                .map(|reg| CoreFlagClass(self.0, *reg))
                .collect();

            BNFreeRegisterList(regs);

            ret
        }
    }

    fn flag_groups(&self) -> Vec<CoreFlagGroup> {
        unsafe {
            let mut count: usize = 0;
            let regs = BNGetAllArchitectureSemanticFlagGroups(self.0, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(regs, count)
                .iter()
                .map(|reg| CoreFlagGroup(self.0, *reg))
                .collect();

            BNFreeRegisterList(regs);

            ret
        }
    }

    fn flags_required_for_flag_condition(
        &self,
        condition: FlagCondition,
        class: Option<Self::FlagClass>,
    ) -> Vec<Self::Flag> {
        let class_id = class.map(|c| c.id()).unwrap_or(0);

        unsafe {
            let mut count: usize = 0;
            let flags = BNGetArchitectureFlagsRequiredForFlagCondition(
                self.0,
                condition,
                class_id,
                &mut count as *mut _,
            );

            let ret = slice::from_raw_parts_mut(flags, count)
                .iter()
                .map(|flag| CoreFlag(self.0, *flag))
                .collect();

            BNFreeRegisterList(flags);

            ret
        }
    }

    fn stack_pointer_reg(&self) -> Option<CoreRegister> {
        match unsafe { BNGetArchitectureStackPointerRegister(self.0) } {
            0xffff_ffff => None,
            reg => Some(CoreRegister(self.0, reg)),
        }
    }

    fn link_reg(&self) -> Option<CoreRegister> {
        match unsafe { BNGetArchitectureLinkRegister(self.0) } {
            0xffff_ffff => None,
            reg => Some(CoreRegister(self.0, reg)),
        }
    }

    fn register_from_id(&self, id: u32) -> Option<CoreRegister> {
        // TODO validate in debug builds
        Some(CoreRegister(self.0, id))
    }

    fn register_stack_from_id(&self, id: u32) -> Option<CoreRegisterStack> {
        // TODO validate in debug builds
        Some(CoreRegisterStack(self.0, id))
    }

    fn flag_from_id(&self, id: u32) -> Option<CoreFlag> {
        // TODO validate in debug builds
        Some(CoreFlag(self.0, id))
    }

    fn flag_write_from_id(&self, id: u32) -> Option<CoreFlagWrite> {
        // TODO validate in debug builds
        Some(CoreFlagWrite(self.0, id))
    }

    fn flag_class_from_id(&self, id: u32) -> Option<CoreFlagClass> {
        // TODO validate in debug builds
        Some(CoreFlagClass(self.0, id))
    }

    fn flag_group_from_id(&self, id: u32) -> Option<CoreFlagGroup> {
        // TODO validate in debug builds
        Some(CoreFlagGroup(self.0, id))
    }

    fn intrinsics(&self) -> Vec<CoreIntrinsic> {
        unsafe {
            let mut count: usize = 0;
            let intrinsics = BNGetAllArchitectureIntrinsics(self.0, &mut count as *mut _);

            let ret = slice::from_raw_parts_mut(intrinsics, count)
                .iter()
                .map(|reg| CoreIntrinsic(self.0, *reg))
                .collect();

            BNFreeRegisterList(intrinsics);

            ret
        }
    }

    fn intrinsic_class(&self, id: u32) -> binaryninjacore_sys::BNIntrinsicClass {
        unsafe { BNGetArchitectureIntrinsicClass(self.0, id) }
    }

    fn intrinsic_from_id(&self, id: u32) -> Option<CoreIntrinsic> {
        // TODO validate in debug builds
        Some(CoreIntrinsic(self.0, id))
    }

    fn can_assemble(&self) -> bool {
        unsafe { BNCanArchitectureAssemble(self.0) }
    }

    fn assemble(&self, code: &str, addr: u64) -> Result<Vec<u8>, String> {
        let code = CString::new(code).map_err(|_| "Invalid encoding in code string".to_string())?;

        let result = match DataBuffer::new(&[]) {
            Ok(result) => result,
            Err(_) => return Err("Result buffer allocation failed".to_string()),
        };
        let mut error_raw: *mut c_char = ptr::null_mut();
        let res = unsafe {
            BNAssemble(
                self.0,
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
            BNIsArchitectureNeverBranchPatchAvailable(self.0, data.as_ptr(), addr, data.len())
        }
    }

    fn is_always_branch_patch_available(&self, data: &[u8], addr: u64) -> bool {
        unsafe {
            BNIsArchitectureAlwaysBranchPatchAvailable(self.0, data.as_ptr(), addr, data.len())
        }
    }

    fn is_invert_branch_patch_available(&self, data: &[u8], addr: u64) -> bool {
        unsafe {
            BNIsArchitectureInvertBranchPatchAvailable(self.0, data.as_ptr(), addr, data.len())
        }
    }

    fn is_skip_and_return_zero_patch_available(&self, data: &[u8], addr: u64) -> bool {
        unsafe {
            BNIsArchitectureSkipAndReturnZeroPatchAvailable(self.0, data.as_ptr(), addr, data.len())
        }
    }

    fn is_skip_and_return_value_patch_available(&self, data: &[u8], addr: u64) -> bool {
        unsafe {
            BNIsArchitectureSkipAndReturnValuePatchAvailable(
                self.0,
                data.as_ptr(),
                addr,
                data.len(),
            )
        }
    }

    fn convert_to_nop(&self, data: &mut [u8], addr: u64) -> bool {
        unsafe { BNArchitectureConvertToNop(self.0, data.as_mut_ptr(), addr, data.len()) }
    }

    fn always_branch(&self, data: &mut [u8], addr: u64) -> bool {
        unsafe { BNArchitectureAlwaysBranch(self.0, data.as_mut_ptr(), addr, data.len()) }
    }

    fn invert_branch(&self, data: &mut [u8], addr: u64) -> bool {
        unsafe { BNArchitectureInvertBranch(self.0, data.as_mut_ptr(), addr, data.len()) }
    }

    fn skip_and_return_value(&self, data: &mut [u8], addr: u64, value: u64) -> bool {
        unsafe {
            BNArchitectureSkipAndReturnValue(self.0, data.as_mut_ptr(), addr, data.len(), value)
        }
    }

    fn handle(&self) -> CoreArchitecture {
        *self
    }
}

macro_rules! cc_func {
    ($get_name:ident, $get_api:ident, $set_name:ident, $set_api:ident) => {
        fn $get_name(&self) -> Option<Ref<CallingConvention<Self>>> {
            let handle = self.as_ref();

            unsafe {
                let cc = $get_api(handle.0);

                if cc.is_null() {
                    None
                } else {
                    Some(CallingConvention::ref_from_raw(cc, self.handle()))
                }
            }
        }

        fn $set_name(&self, cc: &CallingConvention<Self>) {
            let handle = self.as_ref();

            assert!(
                cc.arch_handle.borrow().as_ref().0 == handle.0,
                "use of calling convention with non-matching architecture!"
            );

            unsafe {
                $set_api(handle.0, cc.handle);
            }
        }
    };
}

/// Contains helper methods for all types implementing 'Architecture'
pub trait ArchitectureExt: Architecture {
    fn register_by_name<S: BnStrCompatible>(&self, name: S) -> Option<Self::Register> {
        let name = name.into_bytes_with_nul();

        match unsafe {
            BNGetArchitectureRegisterByName(self.as_ref().0, name.as_ref().as_ptr() as *mut _)
        } {
            0xffff_ffff => None,
            reg => self.register_from_id(reg),
        }
    }

    fn calling_conventions(&self) -> Array<CallingConvention<Self>> {
        unsafe {
            let mut count = 0;
            let calling_convs = BNGetArchitectureCallingConventions(self.as_ref().0, &mut count);
            Array::new(calling_convs, count, self.handle())
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
            let handle = BNGetArchitectureStandalonePlatform(self.as_ref().0);

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
            let handle = BNArchitectureGetRelocationHandler(self.as_ref().0, view_name.as_ptr());

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
        crate::functionrecognizer::register_arch_function_recognizer(self.as_ref(), recognizer);
    }
}

impl<T: Architecture> ArchitectureExt for T {}

pub fn register_architecture<S, A, F>(name: S, func: F) -> &'static A
where
    S: BnStrCompatible,
    A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync + Sized,
    F: FnOnce(CustomArchitectureHandle<A>, CoreArchitecture) -> A,
{
    use std::mem;
    use std::os::raw::{c_char, c_void};

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
                .write(create(custom_arch_handle, CoreArchitecture(obj)));
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
        let addr = unsafe { &mut *(addr) };

        custom_arch.associated_arch_by_addr(addr).0
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
        let data = unsafe { slice::from_raw_parts(data, len) };
        let result = unsafe { &mut *(result as *mut InstructionInfo) };

        match custom_arch.instruction_info(data, addr) {
            Some(info) => {
                result.0 = info.0;
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
        let data = unsafe { slice::from_raw_parts(data, *len) };
        let result = unsafe { &mut *result };

        let Some((res_size, res_tokens)) = custom_arch.instruction_text(data, addr) else {
            return false;
        };

        let res_tokens: Box<[_]> = res_tokens.into_boxed_slice();
        unsafe {
            let res_tokens = Box::leak(res_tokens);
            let r_ptr = res_tokens.as_mut_ptr();
            let r_count = res_tokens.len();

            *result = &mut (*r_ptr).0;
            *count = r_count;
            *len = res_size;
        }
        true
    }

    extern "C" fn cb_free_instruction_text(tokens: *mut BNInstructionTextToken, count: usize) {
        let _tokens = unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(tokens, count)) };
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

        let data = unsafe { slice::from_raw_parts(data, *len) };
        let mut lifter = unsafe { Lifter::from_raw(custom_arch_handle, il) };

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

        match custom_arch.register_from_id(reg) {
            Some(reg) => BnString::new(reg.name().as_ref()).into_raw(),
            None => BnString::new("invalid_reg").into_raw(),
        }
    }

    extern "C" fn cb_flag_name<A>(ctxt: *mut c_void, flag: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        match custom_arch.flag_from_id(flag) {
            Some(flag) => BnString::new(flag.name().as_ref()).into_raw(),
            None => BnString::new("invalid_flag").into_raw(),
        }
    }

    extern "C" fn cb_flag_write_name<A>(ctxt: *mut c_void, flag_write: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        match custom_arch.flag_write_from_id(flag_write) {
            Some(flag_write) => BnString::new(flag_write.name().as_ref()).into_raw(),
            None => BnString::new("invalid_flag_write").into_raw(),
        }
    }

    extern "C" fn cb_semantic_flag_class_name<A>(ctxt: *mut c_void, class: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        match custom_arch.flag_class_from_id(class) {
            Some(class) => BnString::new(class.name().as_ref()).into_raw(),
            None => BnString::new("invalid_flag_class").into_raw(),
        }
    }

    extern "C" fn cb_semantic_flag_group_name<A>(ctxt: *mut c_void, group: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        match custom_arch.flag_group_from_id(group) {
            Some(group) => BnString::new(group.name().as_ref()).into_raw(),
            None => BnString::new("invalid_flag_group").into_raw(),
        }
    }

    extern "C" fn cb_registers_full_width<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut regs: Vec<_> = custom_arch
            .registers_full_width()
            .iter()
            .map(|r| r.id())
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = regs.len() };
        let regs_ptr = regs.as_mut_ptr();
        mem::forget(regs);
        regs_ptr
    }

    extern "C" fn cb_registers_all<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut regs: Vec<_> = custom_arch.registers_all().iter().map(|r| r.id()).collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = regs.len() };
        let regs_ptr = regs.as_mut_ptr();
        mem::forget(regs);
        regs_ptr
    }

    extern "C" fn cb_registers_global<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut regs: Vec<_> = custom_arch
            .registers_global()
            .iter()
            .map(|r| r.id())
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = regs.len() };
        let regs_ptr = regs.as_mut_ptr();
        mem::forget(regs);
        regs_ptr
    }

    extern "C" fn cb_registers_system<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut regs: Vec<_> = custom_arch
            .registers_system()
            .iter()
            .map(|r| r.id())
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = regs.len() };
        let regs_ptr = regs.as_mut_ptr();
        mem::forget(regs);
        regs_ptr
    }

    extern "C" fn cb_flags<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut flags: Vec<_> = custom_arch.flags().iter().map(|f| f.id()).collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = flags.len() };
        let flags_ptr = flags.as_mut_ptr();
        mem::forget(flags);
        flags_ptr
    }

    extern "C" fn cb_flag_write_types<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut flag_writes: Vec<_> = custom_arch
            .flag_write_types()
            .iter()
            .map(|f| f.id())
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = flag_writes.len() };
        let flags_ptr = flag_writes.as_mut_ptr();
        mem::forget(flag_writes);
        flags_ptr
    }

    extern "C" fn cb_semantic_flag_classes<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut flag_classes: Vec<_> = custom_arch.flag_classes().iter().map(|f| f.id()).collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = flag_classes.len() };
        let flags_ptr = flag_classes.as_mut_ptr();
        mem::forget(flag_classes);
        flags_ptr
    }

    extern "C" fn cb_semantic_flag_groups<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut flag_groups: Vec<_> = custom_arch.flag_groups().iter().map(|f| f.id()).collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = flag_groups.len() };
        let flags_ptr = flag_groups.as_mut_ptr();
        mem::forget(flag_groups);
        flags_ptr
    }

    extern "C" fn cb_flag_role<A>(ctxt: *mut c_void, flag: u32, class: u32) -> BNFlagRole
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        if let (Some(flag), class) = (
            custom_arch.flag_from_id(flag),
            custom_arch.flag_class_from_id(class),
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
        let class = custom_arch.flag_class_from_id(class);
        let mut flags: Vec<_> = custom_arch
            .flags_required_for_flag_condition(cond, class)
            .iter()
            .map(|f| f.id())
            .collect();

        // SAFETY: `count` is an out parameter
        unsafe { *count = flags.len() };
        let flags_ptr = flags.as_mut_ptr();
        mem::forget(flags);
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

        if let Some(group) = custom_arch.flag_group_from_id(group) {
            let mut flags: Vec<_> = group.flags_required().iter().map(|f| f.id()).collect();

            // SAFETY: `count` is an out parameter
            unsafe { *count = flags.len() };
            let flags_ptr = flags.as_mut_ptr();
            mem::forget(flags);
            flags_ptr
        } else {
            unsafe {
                *count = 0;
            }
            ptr::null_mut()
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

        if let Some(group) = custom_arch.flag_group_from_id(group) {
            let flag_conditions = group.flag_conditions();
            let mut flags = flag_conditions
                .iter()
                .map(|(&class, &condition)| BNFlagConditionForSemanticClass {
                    semanticClass: class.id(),
                    condition,
                })
                .collect::<Vec<_>>();

            // SAFETY: `count` is an out parameter
            unsafe { *count = flags.len() };
            let flags_ptr = flags.as_mut_ptr();
            mem::forget(flags);
            flags_ptr
        } else {
            unsafe {
                *count = 0;
            }
            ptr::null_mut()
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
            let flags_ptr = ptr::slice_from_raw_parts_mut(conds, count);
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

        if let Some(write_type) = custom_arch.flag_write_from_id(write_type) {
            let mut flags_written: Vec<_> =
                write_type.flags_written().iter().map(|f| f.id()).collect();

            // SAFETY: `count` is an out parameter
            unsafe { *count = flags_written.len() };
            let flags_ptr = flags_written.as_mut_ptr();
            mem::forget(flags_written);
            flags_ptr
        } else {
            unsafe {
                *count = 0;
            }
            ptr::null_mut()
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
            .flag_write_from_id(write_type)
            .map(|w| w.class())
            .and_then(|c| c.map(|c| c.id()))
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

        let flag_write = custom_arch.flag_write_from_id(flag_write);
        let flag = custom_arch.flag_from_id(flag);
        let operands = unsafe { slice::from_raw_parts(operands_raw, operand_count) };
        let mut lifter = unsafe { Lifter::from_raw(custom_arch_handle, il) };

        if let (Some(flag_write), Some(flag)) = (flag_write, flag) {
            if let Some(op) = FlagWriteOp::from_op(custom_arch, size, op, operands) {
                if let Some(expr) = custom_arch.flag_write_llil(flag, flag_write, op, &mut lifter) {
                    // TODO verify that returned expr is a bool value
                    return expr.expr_idx;
                }
            } else {
                warn!(
                    "unable to unpack flag write op: {:?} with {} operands",
                    op,
                    operands.len()
                );
            }

            let role = flag.role(flag_write.class());

            unsafe {
                BNGetDefaultArchitectureFlagWriteLowLevelIL(
                    custom_arch.as_ref().0,
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
            lifter.unimplemented().expr_idx
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

        let class = custom_arch.flag_class_from_id(class);

        let mut lifter = unsafe { Lifter::from_raw(custom_arch_handle, il) };
        if let Some(expr) = custom_arch.flag_cond_llil(cond, class, &mut lifter) {
            // TODO verify that returned expr is a bool value
            return expr.expr_idx;
        }

        lifter.unimplemented().expr_idx
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

        let mut lifter = unsafe { Lifter::from_raw(custom_arch_handle, il) };

        if let Some(group) = custom_arch.flag_group_from_id(group) {
            if let Some(expr) = custom_arch.flag_group_llil(group, &mut lifter) {
                // TODO verify that returned expr is a bool value
                return expr.expr_idx;
            }
        }

        lifter.unimplemented().expr_idx
    }

    extern "C" fn cb_free_register_list(_ctxt: *mut c_void, regs: *mut u32, count: usize) {
        if regs.is_null() {
            return;
        }

        unsafe {
            let regs_ptr = ptr::slice_from_raw_parts_mut(regs, count);
            let _regs = Box::from_raw(regs_ptr);
        }
    }

    extern "C" fn cb_register_info<A>(ctxt: *mut c_void, reg: u32, result: *mut BNRegisterInfo)
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let result = unsafe { &mut *result };

        if let Some(reg) = custom_arch.register_from_id(reg) {
            let info = reg.info();

            result.fullWidthRegister = match info.parent() {
                Some(p) => p.id(),
                None => reg.id(),
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
            reg.id()
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
            reg.id()
        } else {
            0xffff_ffff
        }
    }

    extern "C" fn cb_reg_stack_name<A>(ctxt: *mut c_void, stack: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };

        match custom_arch.register_stack_from_id(stack) {
            Some(stack) => BnString::new(stack.name().as_ref()).into_raw(),
            None => BnString::new("invalid_reg_stack").into_raw(),
        }
    }

    extern "C" fn cb_reg_stacks<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut regs: Vec<_> = custom_arch
            .register_stacks()
            .iter()
            .map(|r| r.id())
            .collect();

        // SAFETY: Passed in to be written
        unsafe { *count = regs.len() };
        let regs_ptr = regs.as_mut_ptr();
        mem::forget(regs);
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

        if let Some(stack) = custom_arch.register_stack_from_id(stack) {
            let info = stack.info();

            let (reg, count) = info.storage_regs();
            result.firstStorageReg = reg.id();
            result.storageCount = count;

            if let Some((reg, count)) = info.top_relative_regs() {
                result.firstTopRelativeReg = reg.id();
                result.topRelativeCount = count;
            } else {
                result.firstTopRelativeReg = 0xffff_ffff;
                result.topRelativeCount = 0;
            }

            result.stackTopReg = info.stack_top_reg().id();
        }
    }

    extern "C" fn cb_intrinsic_class<A>(ctxt: *mut c_void, intrinsic: u32) -> BNIntrinsicClass
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        custom_arch.intrinsic_class(intrinsic)
    }

    extern "C" fn cb_intrinsic_name<A>(ctxt: *mut c_void, intrinsic: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        match custom_arch.intrinsic_from_id(intrinsic) {
            Some(intrinsic) => BnString::new(intrinsic.name().as_ref()).into_raw(),
            None => BnString::new("invalid_intrinsic").into_raw(),
        }
    }

    extern "C" fn cb_intrinsics<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let mut intrinsics: Vec<_> = custom_arch.intrinsics().iter().map(|i| i.id()).collect();

        // SAFETY: Passed in to be written
        unsafe { *count = intrinsics.len() };
        let intrinsics_ptr = intrinsics.as_mut_ptr();
        mem::forget(intrinsics);
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

        let Some(intrinsic) = custom_arch.intrinsic_from_id(intrinsic) else {
            unsafe {
                *count = 0;
            }
            return ptr::null_mut();
        };

        let inputs = intrinsic.inputs();
        let mut res: Box<[_]> = inputs
            .into_iter()
            .map(|input| unsafe { Ref::into_raw(input) }.0)
            .collect();

        unsafe {
            *count = res.len();
            if res.is_empty() {
                ptr::null_mut()
            } else {
                let raw = res.as_mut_ptr();
                mem::forget(res);
                raw
            }
        }
    }

    extern "C" fn cb_free_name_and_types<A>(ctxt: *mut c_void, nt: *mut BNNameAndType, count: usize)
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let _custom_arch = unsafe { &*(ctxt as *mut A) };

        if !nt.is_null() {
            unsafe {
                let name_and_types = Box::from_raw(ptr::slice_from_raw_parts_mut(nt, count));
                for nt in name_and_types.iter() {
                    Ref::new(NameAndType::from_raw(nt));
                }
            }
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

        if let Some(intrinsic) = custom_arch.intrinsic_from_id(intrinsic) {
            let inputs = intrinsic.outputs();
            let mut res: Box<[_]> = inputs.iter().map(|input| input.as_ref().into()).collect();

            unsafe {
                *count = res.len();
                if res.is_empty() {
                    ptr::null_mut()
                } else {
                    let raw = res.as_mut_ptr();
                    mem::forget(res);
                    raw
                }
            }
        } else {
            unsafe {
                *count = 0;
            }
            ptr::null_mut()
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
            let _type_list = unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(tl, count)) };
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
                    *errors = BnString::new("").into_raw();
                }
                true
            }
            Err(result) => {
                unsafe {
                    *errors = BnString::new(result).into_raw();
                }
                false
            }
        };

        // Caller owns the data buffer, don't free it
        mem::forget(buffer);

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
        let data = unsafe { slice::from_raw_parts(data, len) };
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
        let data = unsafe { slice::from_raw_parts(data, len) };
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
        let data = unsafe { slice::from_raw_parts(data, len) };
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
        let data = unsafe { slice::from_raw_parts(data, len) };
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
        let data = unsafe { slice::from_raw_parts(data, len) };
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
        let data = unsafe { slice::from_raw_parts_mut(data, len) };
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
        let data = unsafe { slice::from_raw_parts_mut(data, len) };
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
        let data = unsafe { slice::from_raw_parts_mut(data, len) };
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
        let data = unsafe { slice::from_raw_parts_mut(data, len) };
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
        getMaxInstructionLength: Some(cb_max_instr_len::<A>),
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
    let mut out_bytes: *mut c_char = ptr::null_mut();
    let mut out_bytes_len: c_int = 0;
    let mut err_bytes: *mut c_char = ptr::null_mut();
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
            slice::from_raw_parts(
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
            slice::from_raw_parts(err_bytes as *const c_char as *const u8, err_len as usize)
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
