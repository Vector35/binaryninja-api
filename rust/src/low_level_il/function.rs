// Copyright 2021-2025 Vector 35 Inc.
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

use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use binaryninjacore_sys::*;

use crate::architecture::CoreArchitecture;
use crate::basic_block::BasicBlock;
use crate::function::Function;
use crate::low_level_il::block::LowLevelILBlock;
use crate::rc::*;

use super::*;

#[derive(Copy, Clone, Debug)]
pub struct Mutable;
#[derive(Copy, Clone, Debug)]
pub struct Finalized;

pub trait FunctionMutability: 'static + Debug + Copy {}
impl FunctionMutability for Mutable {}
impl FunctionMutability for Finalized {}

#[derive(Copy, Clone, Debug)]
pub struct SSA;
#[derive(Copy, Clone, Debug)]
pub struct NonSSA;

pub trait FunctionForm: 'static + Debug + Copy {}
impl FunctionForm for SSA {}
impl FunctionForm for NonSSA {}

pub struct LowLevelILFunction<M: FunctionMutability, F: FunctionForm> {
    pub(crate) handle: *mut BNLowLevelILFunction,
    arch: Option<CoreArchitecture>,
    _mutability: PhantomData<M>,
    _form: PhantomData<F>,
}

impl<M, F> LowLevelILFunction<M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) unsafe fn from_raw_with_arch(
        handle: *mut BNLowLevelILFunction,
        arch: Option<CoreArchitecture>,
    ) -> Self {
        debug_assert!(!handle.is_null());

        Self {
            handle,
            arch,
            _mutability: PhantomData,
            _form: PhantomData,
        }
    }

    pub(crate) unsafe fn from_raw(handle: *mut BNLowLevelILFunction) -> Self {
        Self::from_raw_with_arch(handle, None)
    }

    pub(crate) unsafe fn ref_from_raw_with_arch(
        handle: *mut BNLowLevelILFunction,
        arch: Option<CoreArchitecture>,
    ) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self::from_raw_with_arch(handle, arch))
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNLowLevelILFunction) -> Ref<Self> {
        Self::ref_from_raw_with_arch(handle, None)
    }

    pub(crate) fn arch(&self) -> CoreArchitecture {
        match self.arch {
            None => self.function().arch(),
            Some(arch) => arch,
        }
    }

    pub fn instruction_at<L: Into<Location>>(&self, loc: L) -> Option<LowLevelILInstruction<M, F>> {
        Some(LowLevelILInstruction::new(
            self,
            self.instruction_index_at(loc)?,
        ))
    }

    pub fn instruction_index_at<L: Into<Location>>(
        &self,
        loc: L,
    ) -> Option<LowLevelInstructionIndex> {
        use binaryninjacore_sys::BNLowLevelILGetInstructionStart;
        let loc: Location = loc.into();
        // If the location does not specify an architecture, use the function's architecture.
        let arch = loc.arch.unwrap_or_else(|| self.arch());
        let instr_idx =
            unsafe { BNLowLevelILGetInstructionStart(self.handle, arch.handle, loc.addr) };
        // `instr_idx` will equal self.instruction_count() if the instruction is not valid.
        if instr_idx >= self.instruction_count() {
            None
        } else {
            Some(LowLevelInstructionIndex(instr_idx))
        }
    }

    pub fn instruction_from_index(
        &self,
        index: LowLevelInstructionIndex,
    ) -> Option<LowLevelILInstruction<M, F>> {
        if index.0 >= self.instruction_count() {
            None
        } else {
            Some(LowLevelILInstruction::new(self, index))
        }
    }

    pub fn instruction_count(&self) -> usize {
        unsafe {
            use binaryninjacore_sys::BNGetLowLevelILInstructionCount;
            BNGetLowLevelILInstructionCount(self.handle)
        }
    }

    pub fn expression_count(&self) -> usize {
        unsafe {
            use binaryninjacore_sys::BNGetLowLevelILExprCount;
            BNGetLowLevelILExprCount(self.handle)
        }
    }

    pub fn function(&self) -> Ref<Function> {
        unsafe {
            let func = BNGetLowLevelILOwnerFunction(self.handle);
            Function::ref_from_raw(func)
        }
    }

    pub fn basic_blocks(&self) -> Array<BasicBlock<LowLevelILBlock<M, F>>> {
        use binaryninjacore_sys::BNGetLowLevelILBasicBlockList;

        unsafe {
            let mut count = 0;
            let blocks = BNGetLowLevelILBasicBlockList(self.handle, &mut count);
            let context = LowLevelILBlock { function: self };
            Array::new(blocks, count, context)
        }
    }

    /// Returns the [`BasicBlock`] at the given instruction `index`.
    ///
    /// You can also retrieve this using [`LowLevelILInstruction::basic_block`].
    pub fn basic_block_containing_index(
        &self,
        index: LowLevelInstructionIndex,
    ) -> Option<Ref<BasicBlock<LowLevelILBlock<M, F>>>> {
        let block = unsafe { BNGetLowLevelILBasicBlockForInstruction(self.handle, index.0) };
        if block.is_null() {
            None
        } else {
            Some(unsafe { BasicBlock::ref_from_raw(block, LowLevelILBlock { function: self }) })
        }
    }
}

impl<M: FunctionMutability> LowLevelILFunction<M, NonSSA> {
    /// Retrieve the SSA form of the function.
    pub fn ssa_form(&self) -> Option<Ref<LowLevelILFunction<M, SSA>>> {
        let handle = unsafe { BNGetLowLevelILSSAForm(self.handle) };
        if handle.is_null() {
            return None;
        }
        Some(unsafe { LowLevelILFunction::ref_from_raw(handle) })
    }
}

// Allow instantiating Lifted IL functions for querying Lifted IL from Architectures
impl LowLevelILFunction<Mutable, NonSSA> {
    // TODO: Document what happens when you pass None for `source_func`.
    // TODO: Doing so would construct a LowLevelILFunction with no basic blocks
    // TODO: Document why you would want to do that.
    pub fn new(arch: CoreArchitecture, source_func: Option<Function>) -> Ref<Self> {
        use binaryninjacore_sys::BNCreateLowLevelILFunction;

        let handle = unsafe {
            match source_func {
                Some(func) => BNCreateLowLevelILFunction(arch.handle, func.handle),
                None => BNCreateLowLevelILFunction(arch.handle, std::ptr::null_mut()),
            }
        };

        // BNCreateLowLevelILFunction should always return a valid object.
        assert!(!handle.is_null());

        unsafe { Self::ref_from_raw_with_arch(handle, Some(arch)) }
    }

    pub fn generate_ssa_form(&self) {
        use binaryninjacore_sys::BNGenerateLowLevelILSSAForm;
        unsafe { BNGenerateLowLevelILSSAForm(self.handle) };
    }
}

impl Ref<LowLevelILFunction<Mutable, NonSSA>> {
    pub fn finalized(self) -> Ref<LowLevelILFunction<Finalized, NonSSA>> {
        unsafe {
            BNFinalizeLowLevelILFunction(self.handle);
            // Now that we have finalized return the function as is so the caller can reference the "finalized function".
            LowLevelILFunction::from_raw(self.handle).to_owned()
        }
    }
}

impl<M: FunctionMutability> Ref<LowLevelILFunction<M, SSA>> {
    /// Return a vector of all instructions that use the given SSA register.
    #[must_use]
    pub fn get_ssa_register_uses<R: ArchReg>(
        &self,
        reg: LowLevelILSSARegisterKind<R>,
    ) -> Vec<LowLevelILInstruction<M, SSA>> {
        use binaryninjacore_sys::BNGetLowLevelILSSARegisterUses;
        let register_id = match reg {
            LowLevelILSSARegisterKind::Full { kind, .. } => kind.id(),
            LowLevelILSSARegisterKind::Partial { partial_reg, .. } => partial_reg.id(),
        };
        let mut count = 0;
        let instrs = unsafe {
            BNGetLowLevelILSSARegisterUses(
                self.handle,
                register_id.into(),
                reg.version() as usize,
                &mut count,
            )
        };
        let result = unsafe { std::slice::from_raw_parts(instrs, count) }
            .iter()
            .map(|idx| LowLevelILInstruction::new(self, LowLevelInstructionIndex(*idx)))
            .collect();
        unsafe { BNFreeILInstructionList(instrs) };
        result
    }

    /// Returns the instruction that defines the given SSA register.
    #[must_use]
    pub fn get_ssa_register_definition<R: ArchReg>(
        &self,
        reg: &LowLevelILSSARegisterKind<R>,
    ) -> Option<LowLevelILInstruction<M, SSA>> {
        use binaryninjacore_sys::BNGetLowLevelILSSARegisterDefinition;
        let register_id = match reg {
            LowLevelILSSARegisterKind::Full { kind, .. } => kind.id(),
            LowLevelILSSARegisterKind::Partial { partial_reg, .. } => partial_reg.id(),
        };
        let instr_idx = unsafe {
            BNGetLowLevelILSSARegisterDefinition(
                self.handle,
                register_id.into(),
                reg.version() as usize,
            )
        };
        self.instruction_from_index(LowLevelInstructionIndex(instr_idx))
    }
}

impl<M, F> ToOwned for LowLevelILFunction<M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl<M, F> RefCountable for LowLevelILFunction<M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewLowLevelILFunctionReference(handle.handle),
            arch: handle.arch,
            _mutability: PhantomData,
            _form: PhantomData,
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeLowLevelILFunction(handle.handle);
    }
}

impl<M, F> Debug for LowLevelILFunction<M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LowLevelILFunction")
            .field("arch", &self.arch())
            .field("instruction_count", &self.instruction_count())
            .field("expression_count", &self.expression_count())
            .finish()
    }
}

unsafe impl<M: FunctionMutability, F: FunctionForm> Send for LowLevelILFunction<M, F> {}
unsafe impl<M: FunctionMutability, F: FunctionForm> Sync for LowLevelILFunction<M, F> {}

impl<M: FunctionMutability, F: FunctionForm> Eq for LowLevelILFunction<M, F> {}

impl<M: FunctionMutability, F: FunctionForm> PartialEq for LowLevelILFunction<M, F> {
    fn eq(&self, rhs: &Self) -> bool {
        self.function().eq(&rhs.function())
    }
}

impl<M: FunctionMutability, F: FunctionForm> Hash for LowLevelILFunction<M, F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.function().hash(state)
    }
}
