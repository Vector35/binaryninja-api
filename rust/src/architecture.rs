// Copyright 2021 Vector 35 Inc.
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

// container abstraction to avoid Vec<> (want CoreArchFlagList, CoreArchRegList)
// RegisterInfo purge
use binaryninjacore_sys::*;

use std::any::Any;
use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::hash::Hash;
use std::mem::zeroed;
use std::ops;
use std::ops::Drop;
use std::ptr;
use std::slice;
use std::sync::Arc;

use crate::basicblock::{BasicBlock, BlockContext};
use crate::binaryview::BinaryView;
use crate::callingconvention::CallingConvention;
use crate::function::Function;
use crate::platform::Platform;
use crate::{BranchType, Endianness};

use crate::llil::{
    get_default_block_llil, get_default_flag_cond_llil, get_default_flag_write_llil,
    get_default_function_llil,
};
use crate::llil::{FlagWriteOp, LiftedExpr, Lifter};

use crate::rc::*;
use crate::string::*;

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
pub struct InstructionContext(pub(crate) BNInstructionContext);
impl InstructionContext {
    pub fn new<C: BlockContext>(
        binary_view: Option<Ref<BinaryView>>,
        function: Option<Ref<Function>>,
        block: Option<Ref<BasicBlock<C>>>,
        user_data: Option<Arc<Box<dyn Any>>>,
    ) -> Self {
        use std::os::raw::c_void;

        InstructionContext(BNInstructionContext {
            binaryView: binary_view.map_or(ptr::null_mut(), |binary_view| binary_view.handle),
            function: function.map_or(ptr::null_mut(), |function| function.handle),
            block: block.map_or(ptr::null_mut(), |block| block.handle),
            userData: user_data.map_or(ptr::null_mut(), |user_data| {
                Arc::into_raw(user_data) as *mut c_void
            }),
        })
    }

    pub fn binary_view(&self) -> Ref<BinaryView> {
        unsafe { BinaryView::from_raw(self.0.binaryView) }
    }

    pub fn function(&self) -> Ref<Function> {
        unsafe { Function::from_raw(self.0.function) }
    }

    pub fn block<C: BlockContext>(&self, context: C) -> Ref<BasicBlock<C>> {
        unsafe { BasicBlock::<C>::from_raw(self.0.block, context) }.to_owned()
    }

    pub fn user_data(&self) -> Option<Arc<Box<dyn Any>>> {
        if self.0.userData.is_null() {
            None
        } else {
            Some(unsafe { Arc::from_raw(self.0.userData as *const _) })
        }
    }
}

#[repr(C)]
pub struct InstructionInfo(BNInstructionInfo);
impl InstructionInfo {
    pub fn new(len: usize, branch_delay: bool) -> Self {
        InstructionInfo(BNInstructionInfo {
            length: len,
            archTransitionByTargetAddr: false,
            branchDelay: branch_delay,
            branchCount: 0usize,
            branchType: [BranchType::UnresolvedBranch; 3],
            branchTarget: [0u64; 3],
            branchArch: [ptr::null_mut(); 3],
        })
    }

    pub fn len(&self) -> usize {
        self.0.length
    }
    pub fn branch_count(&self) -> usize {
        self.0.branchCount
    }
    pub fn branch_delay(&self) -> bool {
        self.0.branchDelay
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

pub enum InstructionTextTokenContents {
    Text,
    Instruction,
    OperandSeparator,
    Register,
    Integer(u64),         // TODO size?
    PossibleAddress(u64), // TODO size?
    BeginMemoryOperand,
    EndMemoryOperand,
    FloatingPoint,
    CodeRelativeAddress(u64),
}

pub use binaryninjacore_sys::BNInstructionTextTokenContext as InstructionTextTokenContext;

#[repr(C)]
pub struct InstructionTextToken(BNInstructionTextToken);
impl InstructionTextToken {
    pub fn new<T: Into<Vec<u8>>>(contents: InstructionTextTokenContents, text: T) -> Self {
        use self::BNInstructionTextTokenType::*;
        use self::InstructionTextTokenContents::*;

        let mut res: BNInstructionTextToken = unsafe { zeroed() };

        res.context = InstructionTextTokenContext::NoTokenContext;
        res.address = 0;
        res.size = 0; // TODO supply? x86 seems to, others don't...
        res.operand = 0xffff_ffff;
        res.confidence = 0xff;

        match contents {
            Integer(v) => res.value = v,
            PossibleAddress(v) | CodeRelativeAddress(v) => {
                res.value = v;
                res.address = v;
            }
            _ => {}
        }

        res.type_ = match contents {
            Text => TextToken,
            Instruction => InstructionToken,
            OperandSeparator => OperandSeparatorToken,
            Register => RegisterToken,
            Integer(_) => IntegerToken,
            PossibleAddress(_) => PossibleAddressToken,
            BeginMemoryOperand => BeginMemoryOperandToken,
            EndMemoryOperand => EndMemoryOperandToken,
            FloatingPoint => FloatingPointToken,
            CodeRelativeAddress(_) => CodeRelativeAddressToken,
        };

        res.text = CString::new(text).unwrap().into_raw();

        InstructionTextToken(res)
    }

    pub fn text(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0.text) }
    }

    pub fn contents(&self) -> InstructionTextTokenContents {
        use self::BNInstructionTextTokenType::*;
        use self::InstructionTextTokenContents::*;

        match self.0.type_ {
            TextToken => Text,
            InstructionToken => Instruction,
            OperandSeparatorToken => OperandSeparator,
            RegisterToken => Register,
            IntegerToken => Integer(self.0.value),
            PossibleAddressToken => PossibleAddress(self.0.value),
            BeginMemoryOperandToken => BeginMemoryOperand,
            EndMemoryOperandToken => EndMemoryOperand,
            FloatingPointToken => FloatingPoint,
            CodeRelativeAddressToken => CodeRelativeAddress(self.0.value),
            _ => unimplemented!("woops"),
        }
    }

    pub fn context(&self) -> InstructionTextTokenContext {
        self.0.context
    }

    pub fn size(&self) -> usize {
        self.0.size
    }

    pub fn operand(&self) -> usize {
        self.0.operand
    }

    pub fn address(&self) -> u64 {
        self.0.address
    }
}

impl Clone for InstructionTextToken {
    fn clone(&self) -> Self {
        InstructionTextToken(BNInstructionTextToken {
            type_: self.0.type_,
            context: self.0.context,
            address: self.0.address,
            size: self.0.size,
            operand: self.0.operand,
            value: self.0.value,
            width: 0,
            text: self.text().to_owned().into_raw(),
            confidence: 0xff,
            typeNames: ptr::null_mut(),
            namesCount: 0,
        })
    }
}

impl Drop for InstructionTextToken {
    fn drop(&mut self) {
        let _owned = unsafe { CString::from_raw(self.0.text) };
    }
}

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

pub trait Register: Sized + Clone + Copy {
    type InfoType: RegisterInfo<RegType = Self>;

    fn name(&self) -> Cow<str>;
    fn info(&self) -> Self::InfoType;

    /// Unique identifier for this `Register`.
    ///
    /// *MUST* be in the range [0, 0x7fff_ffff]
    fn id(&self) -> u32;
}

pub trait Flag: Sized + Clone + Copy {
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
    /// ```
    /// cr1_signed -> LLFC_SLT,
    /// cr1_unsigned -> LLFC_ULT,
    /// ```
    ///
    /// This allows the core to recover the semantics of the comparison and
    /// inline it into conditional branches when appropriate.
    fn flag_conditions(&self) -> HashMap<Self::FlagClass, FlagCondition>;
}

pub trait Architecture: 'static + Sized + AsRef<CoreArchitecture> {
    type Handle: Borrow<Self> + Clone;

    type RegisterInfo: RegisterInfo<RegType = Self::Register>;
    type Register: Register<InfoType = Self::RegisterInfo>;

    type Flag: Flag<FlagClass = Self::FlagClass>;
    type FlagWrite: FlagWrite<FlagType = Self::Flag, FlagClass = Self::FlagClass>;
    type FlagClass: FlagClass;
    type FlagGroup: FlagGroup<FlagType = Self::Flag, FlagClass = Self::FlagClass>;

    type InstructionTextContainer: Into<Vec<InstructionTextToken>>;

    fn endianness(&self) -> Endianness;
    fn address_size(&self) -> usize;
    fn default_integer_size(&self) -> usize;
    fn instruction_alignment(&self) -> usize;
    fn max_instr_len(&self) -> usize;
    fn opcode_display_len(&self) -> usize;

    fn associated_arch_by_addr(&self, addr: &mut u64) -> CoreArchitecture;

    fn instruction_info(
        &self,
        data: &[u8],
        addr: u64,
        ctxt: Option<&mut InstructionContext>,
    ) -> Option<InstructionInfo>;
    fn instruction_text(
        &self,
        data: &[u8],
        addr: u64,
        ctxt: Option<&mut InstructionContext>,
    ) -> Option<(usize, Self::InstructionTextContainer)>;
    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        ctxt: Option<&mut InstructionContext>,
        il: &mut Lifter<Self>,
    ) -> Option<(usize, bool)>;
    fn block_llil<C: BlockContext>(
        &self,
        block: BasicBlock<C>,
        ctxt: Option<&mut InstructionContext>,
        il: &mut Lifter<Self>,
    ) -> Option<bool> {
        Some(get_default_block_llil(self, block, ctxt, il))
    }
    fn function_llil<C: BlockContext>(
        &self,
        func: Ref<Function>,
        block: Vec<BasicBlock<C>>,
        ctxt: Option<&mut InstructionContext>,
        il: &mut Lifter<Self>,
    ) -> Option<bool> {
        Some(get_default_function_llil(self, func, block, ctxt, il))
    }

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
        condition: FlagCondition,
        class: Option<Self::FlagClass>,
    ) -> Vec<Self::Flag>;

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
        group: Self::FlagGroup,
        il: &'a mut Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>>;

    fn registers_all(&self) -> Vec<Self::Register>;
    fn registers_full_width(&self) -> Vec<Self::Register>;
    fn registers_global(&self) -> Vec<Self::Register>;
    fn registers_system(&self) -> Vec<Self::Register>;

    fn flags(&self) -> Vec<Self::Flag>;
    fn flag_write_types(&self) -> Vec<Self::FlagWrite>;
    fn flag_classes(&self) -> Vec<Self::FlagClass>;
    fn flag_groups(&self) -> Vec<Self::FlagGroup>;

    fn stack_pointer_reg(&self) -> Option<Self::Register>;
    fn link_reg(&self) -> Option<Self::Register>;

    fn register_from_id(&self, id: u32) -> Option<Self::Register>;
    fn flag_from_id(&self, id: u32) -> Option<Self::Flag>;
    fn flag_write_from_id(&self, id: u32) -> Option<Self::FlagWrite>;
    fn flag_class_from_id(&self, id: u32) -> Option<Self::FlagClass>;
    fn flag_group_from_id(&self, id: u32) -> Option<Self::FlagGroup>;

    fn handle(&self) -> Self::Handle;
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

pub struct InstructionTextTokenList(*mut BNInstructionTextToken, usize);

impl ops::Deref for InstructionTextTokenList {
    type Target = [InstructionTextToken];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(&*(self.0 as *const InstructionTextToken), self.1) }
    }
}

impl Drop for InstructionTextTokenList {
    fn drop(&mut self) {
        unsafe { BNFreeInstructionText(self.0, self.1) }
    }
}

impl Into<Vec<InstructionTextToken>> for InstructionTextTokenList {
    fn into(self) -> Vec<InstructionTextToken> {
        self.to_vec()
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

    pub fn by_name<N: Into<Vec<u8>>>(name: N) -> Option<Self> {
        let name = match CString::new(name) {
            Ok(s) => s,
            _ => return None,
        };

        let res = unsafe { BNGetArchitectureByName(name.as_ptr()) };

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
    type Flag = CoreFlag;
    type FlagWrite = CoreFlagWrite;
    type FlagClass = CoreFlagClass;
    type FlagGroup = CoreFlagGroup;

    type InstructionTextContainer = InstructionTextTokenList;

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

    fn instruction_info(
        &self,
        data: &[u8],
        addr: u64,
        ctxt: Option<&mut InstructionContext>,
    ) -> Option<InstructionInfo> {
        let mut info = unsafe { zeroed::<InstructionInfo>() };
        let success = unsafe {
            BNGetInstructionInfo(
                self.0,
                data.as_ptr(),
                addr,
                data.len(),
                ctxt.map_or(ptr::null_mut(), |ctxt| &mut ctxt.0 as *mut _),
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
        ctxt: Option<&mut InstructionContext>,
    ) -> Option<(usize, InstructionTextTokenList)> {
        let mut consumed = data.len();
        let mut count: usize = 0;
        let mut result: *mut BNInstructionTextToken = ptr::null_mut();

        unsafe {
            if BNGetInstructionText(
                self.0,
                data.as_ptr(),
                addr,
                &mut consumed as *mut _,
                ctxt.map_or(ptr::null_mut(), |ctxt| &mut ctxt.0 as *mut _),
                &mut result as *mut _,
                &mut count as *mut _,
            ) {
                Some((consumed, InstructionTextTokenList(result, count)))
            } else {
                None
            }
        }
    }

    fn instruction_llil(
        &self,
        _data: &[u8],
        _addr: u64,
        _ctxt: Option<&mut InstructionContext>,
        _il: &mut Lifter<Self>,
    ) -> Option<(usize, bool)> {
        None
    }

    fn block_llil<C: BlockContext>(
        &self,
        block: BasicBlock<C>,
        ctxt: Option<&mut InstructionContext>,
        il: &mut Lifter<Self>,
    ) -> Option<bool> {
        Some(unsafe {
            BNGetArchitectureBlockLowLevelIL(
                self.0,
                block.handle,
                ctxt.map_or(ptr::null_mut(), |ctxt| &mut ctxt.0 as *mut _),
                il.handle,
            )
        })
    }

    fn function_llil<C: BlockContext>(
        &self,
        func: Ref<Function>,
        blocks: Vec<BasicBlock<C>>,
        ctxt: Option<&mut InstructionContext>,
        il: &mut Lifter<Self>,
    ) -> Option<bool> {
        let mut blocks = blocks
            .into_iter()
            .map(|block| block.handle)
            .collect::<Vec<_>>();
        Some(unsafe {
            BNGetArchitectureFunctionLowLevelIL(
                self.0,
                func.handle,
                blocks.as_mut_ptr(),
                blocks.len(),
                ctxt.map_or(ptr::null_mut(), |ctxt| &mut ctxt.0 as *mut _),
                il.handle,
            )
        })
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
        let name = name.as_bytes_with_nul();

        match unsafe {
            BNGetArchitectureRegisterByName(self.as_ref().0, name.as_ref().as_ptr() as *mut _)
        } {
            0xffff_ffff => None,
            reg => self.register_from_id(reg),
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
        arch: A,
        func: F,
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

            let create = ptr::read(&custom_arch.func);
            ptr::write(
                &mut custom_arch.arch,
                create(custom_arch_handle, CoreArchitecture(obj)),
            );
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
        insn_ctxt: *mut BNInstructionContext,
        result: *mut BNInstructionInfo,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { slice::from_raw_parts(data, len) };
        let mut insn_ctxt = if insn_ctxt.is_null() {
            None
        } else {
            unsafe { Some(InstructionContext(*insn_ctxt)) }
        };
        let result = unsafe { &mut *(result as *mut InstructionInfo) };

        match custom_arch.instruction_info(data, addr, insn_ctxt.as_mut()) {
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
        insn_ctxt: *mut BNInstructionContext,
        result: *mut *mut BNInstructionTextToken,
        count: *mut usize,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let data = unsafe { slice::from_raw_parts(data, *len) };
        let mut insn_ctxt = if insn_ctxt.is_null() {
            None
        } else {
            unsafe { Some(InstructionContext(*insn_ctxt)) }
        };
        let result = unsafe { &mut *result };

        match custom_arch.instruction_text(data, addr, insn_ctxt.as_mut()) {
            Some((res_size, res_tokens)) => {
                unsafe {
                    let mut res_tokens = res_tokens.into();
                    res_tokens.shrink_to_fit();
                    assert!(res_tokens.capacity() == res_tokens.len());

                    *len = res_size;
                    *count = res_tokens.len();

                    *result = res_tokens.as_mut_ptr() as *mut _;
                    mem::forget(res_tokens);
                }
                true
            }
            None => false,
        }
    }

    extern "C" fn cb_free_instruction_text(tokens: *mut BNInstructionTextToken, count: usize) {
        let _tokens =
            unsafe { Vec::from_raw_parts(tokens as *mut InstructionTextToken, count, count) };
    }

    extern "C" fn cb_instruction_llil<A>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: *mut usize,
        insn_ctxt: *mut BNInstructionContext,
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
        let mut insn_ctxt = if insn_ctxt.is_null() {
            None
        } else {
            unsafe { Some(InstructionContext(*insn_ctxt)) }
        };
        let mut lifter = unsafe { Lifter::from_raw(custom_arch_handle, il) };

        match custom_arch.instruction_llil(data, addr, insn_ctxt.as_mut(), &mut lifter) {
            Some((res_len, res_value)) => {
                unsafe { *len = res_len };
                res_value
            }
            None => false,
        }
    }

    extern "C" fn cb_block_llil<A>(
        ctxt: *mut c_void,
        block: *mut BNBasicBlock,
        insn_ctxt: *mut BNInstructionContext,
        il: *mut BNLowLevelILFunction,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        use crate::function::NativeBlock;

        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let custom_arch_handle = CustomArchitectureHandle {
            handle: ctxt as *mut A,
        };

        let block = unsafe { BasicBlock::from_raw(block, NativeBlock::new()) };
        let mut insn_ctxt = if insn_ctxt.is_null() {
            None
        } else {
            unsafe { Some(InstructionContext(*insn_ctxt)) }
        };
        let mut lifter = unsafe { Lifter::from_raw(custom_arch_handle, il) };

        match custom_arch.block_llil(block, insn_ctxt.as_mut(), &mut lifter) {
            Some(res_value) => res_value,
            None => false,
        }
    }

    extern "C" fn cb_function_llil<A>(
        ctxt: *mut c_void,
        func: *mut BNFunction,
        blocks: *mut *mut BNBasicBlock,
        block_count: usize,
        insn_ctxt: *mut BNInstructionContext,
        il: *mut BNLowLevelILFunction,
    ) -> bool
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        use crate::function::NativeBlock;

        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let custom_arch_handle = CustomArchitectureHandle {
            handle: ctxt as *mut A,
        };

        let func = unsafe { Function::from_raw(func) };

        let blocks = unsafe { slice::from_raw_parts_mut(blocks, block_count) };
        let blocks = blocks
            .into_iter()
            .map(|block: &mut *mut BNBasicBlock| unsafe {
                BasicBlock::from_raw(*block, NativeBlock::new())
            })
            .collect::<Vec<BasicBlock<_>>>();

        let mut insn_ctxt = if insn_ctxt.is_null() {
            None
        } else {
            unsafe { Some(InstructionContext(*insn_ctxt)) }
        };
        let mut lifter = unsafe { Lifter::from_raw(custom_arch_handle, il) };

        match custom_arch.function_llil(func, blocks, insn_ctxt.as_mut(), &mut lifter) {
            Some(res_value) => res_value,
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

    fn alloc_register_list<I: Iterator<Item = u32> + ExactSizeIterator>(
        items: I,
        count: &mut usize,
    ) -> *mut u32 {
        let len = items.len();
        *count = len;

        if len == 0 {
            ptr::null_mut()
        } else {
            let mut res = Vec::with_capacity(len + 1);

            res.push(len as u32);

            for i in items {
                res.push(i.clone().into());
            }

            assert!(res.len() == len + 1);

            let raw = res.as_mut_ptr();
            mem::forget(res);

            unsafe { raw.offset(1) }
        }
    }

    extern "C" fn cb_registers_full_width<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let regs = custom_arch.registers_full_width();

        alloc_register_list(regs.iter().map(|r| r.id()), unsafe { &mut *count })
    }

    extern "C" fn cb_registers_all<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let regs = custom_arch.registers_all();

        alloc_register_list(regs.iter().map(|r| r.id()), unsafe { &mut *count })
    }

    extern "C" fn cb_registers_global<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let regs = custom_arch.registers_global();

        alloc_register_list(regs.iter().map(|r| r.id()), unsafe { &mut *count })
    }

    extern "C" fn cb_registers_system<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let regs = custom_arch.registers_system();

        alloc_register_list(regs.iter().map(|r| r.id()), unsafe { &mut *count })
    }

    extern "C" fn cb_flags<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let flags = custom_arch.flags();

        alloc_register_list(flags.iter().map(|r| r.id()), unsafe { &mut *count })
    }

    extern "C" fn cb_flag_write_types<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let flag_writes = custom_arch.flag_write_types();

        alloc_register_list(flag_writes.iter().map(|r| r.id()), unsafe { &mut *count })
    }

    extern "C" fn cb_semantic_flag_classes<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let flag_classes = custom_arch.flag_classes();

        alloc_register_list(flag_classes.iter().map(|r| r.id()), unsafe { &mut *count })
    }

    extern "C" fn cb_semantic_flag_groups<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let custom_arch = unsafe { &*(ctxt as *mut A) };
        let flag_groups = custom_arch.flag_groups();

        alloc_register_list(flag_groups.iter().map(|r| r.id()), unsafe { &mut *count })
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
        let flags = custom_arch.flags_required_for_flag_condition(cond, class);

        alloc_register_list(flags.iter().map(|r| r.id()), unsafe { &mut *count })
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
            let flags = group.flags_required();
            alloc_register_list(flags.iter().map(|r| r.id()), unsafe { &mut *count })
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

            unsafe {
                let allocation_size =
                    mem::size_of::<BNFlagConditionForSemanticClass>() * flag_conditions.len();
                let result = libc::malloc(allocation_size) as *mut BNFlagConditionForSemanticClass;
                let out_slice = slice::from_raw_parts_mut(result, flag_conditions.len());

                for (i, (class, cond)) in flag_conditions.iter().enumerate() {
                    let out = out_slice.get_unchecked_mut(i);

                    out.semanticClass = class.id();
                    out.condition = *cond;
                }

                *count = flag_conditions.len();
                result
            }
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
    ) where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        unsafe {
            libc::free(conds as *mut _);
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
            let written = write_type.flags_written();
            alloc_register_list(written.iter().map(|f| f.id()), unsafe { &mut *count })
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
            .map(|w| w.id())
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

    extern "C" fn cb_free_register_list(_ctxt: *mut c_void, regs: *mut u32) {
        if regs.is_null() {
            return;
        }

        unsafe {
            let actual_start = regs.offset(-1);
            let len = *actual_start + 1;
            let _regs = Vec::from_raw_parts(actual_start, len as usize, len as usize);
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

    extern "C" fn cb_reg_stack_name<A>(ctxt: *mut c_void, _stack: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let _custom_arch = unsafe { &*(ctxt as *mut A) };
        BnString::new("reg_stack").into_raw()
    }

    extern "C" fn cb_reg_stacks<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let _custom_arch = unsafe { &*(ctxt as *mut A) };

        unsafe {
            *count = 0;
        }
        ptr::null_mut()
    }

    extern "C" fn cb_reg_stack_info<A>(
        ctxt: *mut c_void,
        _stack: u32,
        _info: *mut BNRegisterStackInfo,
    ) where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let _custom_arch = unsafe { &*(ctxt as *mut A) };
    }

    extern "C" fn cb_intrinsic_name<A>(ctxt: *mut c_void, _intrinsic: u32) -> *mut c_char
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let _custom_arch = unsafe { &*(ctxt as *mut A) };
        BnString::new("intrinsic").into_raw()
    }

    extern "C" fn cb_intrinsics<A>(ctxt: *mut c_void, count: *mut usize) -> *mut u32
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let _custom_arch = unsafe { &*(ctxt as *mut A) };

        unsafe {
            *count = 0;
        }
        ptr::null_mut()
    }

    extern "C" fn cb_intrinsic_inputs<A>(
        ctxt: *mut c_void,
        _intrinsic: u32,
        count: *mut usize,
    ) -> *mut BNNameAndType
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let _custom_arch = unsafe { &*(ctxt as *mut A) };

        unsafe {
            *count = 0;
        }
        ptr::null_mut()
    }

    extern "C" fn cb_free_name_and_types<A>(
        ctxt: *mut c_void,
        _nt: *mut BNNameAndType,
        _count: usize,
    ) where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let _custom_arch = unsafe { &*(ctxt as *mut A) };
    }

    extern "C" fn cb_intrinsic_outputs<A>(
        ctxt: *mut c_void,
        _intrinsic: u32,
        count: *mut usize,
    ) -> *mut BNTypeWithConfidence
    where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let _custom_arch = unsafe { &*(ctxt as *mut A) };

        unsafe {
            *count = 0;
        }
        ptr::null_mut()
    }

    extern "C" fn cb_free_type_list<A>(
        ctxt: *mut c_void,
        _tl: *mut BNTypeWithConfidence,
        _count: usize,
    ) where
        A: 'static + Architecture<Handle = CustomArchitectureHandle<A>> + Send + Sync,
    {
        let _custom_arch = unsafe { &*(ctxt as *mut A) };
    }

    // TODO : I have no idea what I'm doing and this is likely wrong!
    extern "C" fn cb_can_assemble(_ctxt: *mut c_void) -> bool {
        false
    }

    extern "C" fn cb_assemble(
        _ctxt: *mut c_void,
        _code: *const c_char,
        _addr: u64,
        _result: *mut BNDataBuffer,
        errors: *mut *mut c_char,
    ) -> bool {
        unsafe {
            *errors = ptr::null_mut();
        }
        false
    }

    extern "C" fn cb_patch_unavailable(
        _ctxt: *mut c_void,
        _data: *const u8,
        _addr: u64,
        _len: usize,
    ) -> bool {
        false
    }

    extern "C" fn cb_do_patch_unavailable(
        _ctxt: *mut c_void,
        _data: *mut u8,
        _addr: u64,
        _len: usize,
    ) -> bool {
        false
    }

    extern "C" fn cb_skip_patch_unavailable(
        _ctxt: *mut c_void,
        _data: *mut u8,
        _addr: u64,
        _len: usize,
        _val: u64,
    ) -> bool {
        false
    }

    let name = name.as_bytes_with_nul();

    let uninit_arch = ArchitectureBuilder {
        arch: unsafe { zeroed() },
        func: func,
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
        getBlockLowLevelIL: Some(cb_block_llil::<A>),
        getFunctionLowLevelIL: Some(cb_function_llil::<A>),

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

        getIntrinsicName: Some(cb_intrinsic_name::<A>),
        getAllIntrinsics: Some(cb_intrinsics::<A>),
        getIntrinsicInputs: Some(cb_intrinsic_inputs::<A>),
        freeNameAndTypeList: Some(cb_free_name_and_types::<A>),
        getIntrinsicOutputs: Some(cb_intrinsic_outputs::<A>),
        freeTypeList: Some(cb_free_type_list::<A>),

        canAssemble: Some(cb_can_assemble),
        assemble: Some(cb_assemble),

        isNeverBranchPatchAvailable: Some(cb_patch_unavailable),
        isAlwaysBranchPatchAvailable: Some(cb_patch_unavailable),
        isInvertBranchPatchAvailable: Some(cb_patch_unavailable),
        isSkipAndReturnZeroPatchAvailable: Some(cb_patch_unavailable),
        isSkipAndReturnValuePatchAvailable: Some(cb_patch_unavailable),

        convertToNop: Some(cb_do_patch_unavailable),
        alwaysBranch: Some(cb_do_patch_unavailable),
        invertBranch: Some(cb_do_patch_unavailable),
        skipAndReturnValue: Some(cb_skip_patch_unavailable),
    };

    unsafe {
        let res =
            BNRegisterArchitecture(name.as_ref().as_ptr() as *mut _, &mut custom_arch as *mut _);

        assert!(!res.is_null());

        &(*raw).arch
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
        Self {
            handle: self.handle,
        }
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
