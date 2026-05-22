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

use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use binaryninjacore_sys::*;

use crate::architecture::{CoreArchitecture, CoreFlag};
use crate::basic_block::BasicBlock;
use crate::function::Function;
use crate::low_level_il::block::LowLevelILBlock;
use crate::rc::*;
use crate::variable::RegisterValue;

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

    pub unsafe fn from_raw(handle: *mut BNLowLevelILFunction) -> Self {
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
        // TODO: self.function() can return None under rare circumstances
        match self.arch {
            None => self.function().unwrap().arch(),
            Some(arch) => arch,
        }
    }

    pub fn instruction_at<L: Into<Location>>(
        &self,
        loc: L,
    ) -> Option<LowLevelILInstruction<'_, M, F>> {
        Some(LowLevelILInstruction::new(
            self,
            self.instruction_index_at(loc)?,
        ))
    }

    /// Get all the instructions for a given location.
    pub fn instructions_at<L: Into<Location>>(
        &self,
        loc: L,
    ) -> Vec<LowLevelILInstruction<'_, M, F>> {
        let loc = loc.into();
        self.instruction_indexes_at(loc)
            .iter()
            .map(|idx| LowLevelILInstruction::new(self, idx))
            .collect()
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

    pub fn instruction_indexes_at<L: Into<Location>>(
        &self,
        loc: L,
    ) -> Array<LowLevelInstructionIndex> {
        let loc: Location = loc.into();
        // If the location does not specify an architecture, use the function's architecture.
        let arch = loc.arch.unwrap_or_else(|| self.arch());
        let mut count = 0;
        let indexes = unsafe {
            BNLowLevelILGetInstructionsAt(self.handle, arch.handle, loc.addr, &mut count)
        };
        unsafe { Array::new(indexes, count, ()) }
    }

    pub fn instruction_from_index(
        &self,
        index: LowLevelInstructionIndex,
    ) -> Option<LowLevelILInstruction<'_, M, F>> {
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

    pub fn function(&self) -> Option<Ref<Function>> {
        unsafe {
            let func = BNGetLowLevelILOwnerFunction(self.handle);
            if func.is_null() {
                return None;
            }
            Some(Function::ref_from_raw(func))
        }
    }

    pub fn basic_blocks(&self) -> Array<BasicBlock<LowLevelILBlock<'_, M, F>>> {
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
    ) -> Option<Ref<BasicBlock<LowLevelILBlock<'_, M, F>>>> {
        let block = unsafe { BNGetLowLevelILBasicBlockForInstruction(self.handle, index.0) };
        if block.is_null() {
            None
        } else {
            Some(unsafe { BasicBlock::ref_from_raw(block, LowLevelILBlock { function: self }) })
        }
    }

    pub fn set_indirect_branches(&self, branches: &[Location]) {
        let mut bn_branches: Box<[BNArchitectureAndAddress]> = branches
            .iter()
            .map(|loc| BNArchitectureAndAddress {
                address: loc.addr,
                arch: loc.arch.unwrap_or_else(|| self.arch()).handle,
            })
            .collect();

        unsafe {
            BNLowLevelILSetIndirectBranches(self.handle, bn_branches.as_mut_ptr(), branches.len());
        }
    }
}

impl<M: FunctionMutability> LowLevelILFunction<M, NonSSA> {
    /// Retrieve the SSA form of the function.
    ///
    /// If the function has not had the SSA form generated you may call `generate_ssa_form`.
    pub fn ssa_form(&self) -> Option<Ref<LowLevelILFunction<M, SSA>>> {
        let handle = unsafe { BNGetLowLevelILSSAForm(self.handle) };
        if handle.is_null() {
            return None;
        }
        Some(unsafe { LowLevelILFunction::ref_from_raw(handle) })
    }

    /// Generates the SSA form of the function. Typically called **after** `finalize`.
    ///
    /// If you created a freestanding [`LowLevelILFunction`] with no [`LowLevelILFunction::function`]
    /// than this function will **not** generate the SSA form, as it is currently impossible.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use binaryninja::low_level_il::LowLevelILMutableFunction;
    /// use binaryninja::rc::Ref;
    /// # let mutable_llil: Ref<LowLevelILMutableFunction> = unimplemented!();
    /// // ... modify the IL
    /// let finalized_llil = mutable_llil.finalized();
    /// finalized_llil.generate_ssa_form();
    /// ```
    pub fn generate_ssa_form(&self) {
        use binaryninjacore_sys::BNGenerateLowLevelILSSAForm;
        // SSA form may only be generated if there is an owning function, otherwise it will crash.
        if self.function().is_some() {
            unsafe { BNGenerateLowLevelILSSAForm(self.handle) };
        }
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
}

impl Ref<LowLevelILFunction<Mutable, NonSSA>> {
    /// Finalize the mutated [`LowLevelILFunction`], returning a [`LowLevelILRegularFunction`].
    ///
    /// This function **will not** correct the SSA related dataflow, to do that you must call
    /// the function [`LowLevelILMutableFunction::generate_ssa_form`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use binaryninja::low_level_il::LowLevelILMutableFunction;
    /// use binaryninja::rc::Ref;
    /// # let mutable_llil: Ref<LowLevelILMutableFunction> = unimplemented!();
    /// // ... modify the IL
    /// let finalized_llil = mutable_llil.finalized();
    /// finalized_llil.generate_ssa_form();
    /// ```
    pub fn finalized(self) -> Ref<LowLevelILFunction<Finalized, NonSSA>> {
        unsafe {
            BNFinalizeLowLevelILFunction(self.handle);
            // Now that we have finalized return the function as is so the caller can reference the "finalized function".
            LowLevelILFunction::from_raw_with_arch(self.handle, self.arch).to_owned()
        }
    }
}

impl<M: FunctionMutability> LowLevelILFunction<M, SSA> {
    /// Return a vector of all instructions that use the given SSA register.
    #[must_use]
    pub fn get_ssa_register_uses<R: ArchReg>(
        &self,
        reg: impl AsRef<LowLevelILSSARegister<R>>,
    ) -> Vec<LowLevelILInstruction<'_, M, SSA>> {
        use binaryninjacore_sys::BNGetLowLevelILSSARegisterUses;
        let reg = reg.as_ref();
        let mut count = 0;
        let instrs = unsafe {
            BNGetLowLevelILSSARegisterUses(
                self.handle,
                reg.id().into(),
                reg.version as usize,
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
        reg: impl AsRef<LowLevelILSSARegister<R>>,
    ) -> Option<LowLevelILInstruction<'_, M, SSA>> {
        use binaryninjacore_sys::BNGetLowLevelILSSARegisterDefinition;
        let reg = reg.as_ref();
        let instr_idx = unsafe {
            BNGetLowLevelILSSARegisterDefinition(self.handle, reg.id().into(), reg.version as usize)
        };
        self.instruction_from_index(LowLevelInstructionIndex(instr_idx))
    }

    /// Returns the value of the given SSA register.
    #[must_use]
    pub fn get_ssa_register_value<R: ArchReg>(
        &self,
        reg: impl AsRef<LowLevelILSSARegister<R>>,
    ) -> Option<RegisterValue> {
        let reg = reg.as_ref();
        let value = unsafe {
            BNGetLowLevelILSSARegisterValue(self.handle, reg.id().into(), reg.version as usize)
        };
        if value.state == BNRegisterValueType::UndeterminedValue {
            return None;
        }
        Some(value.into())
    }

    /// Returns the value of the given SSA flag.
    #[must_use]
    pub fn get_ssa_flag_value(&self, flag: &LowLevelILSSAFlag<CoreFlag>) -> Option<RegisterValue> {
        let value = unsafe {
            BNGetLowLevelILSSAFlagValue(self.handle, flag.flag.id().0, flag.version as usize)
        };
        if value.state == BNRegisterValueType::UndeterminedValue {
            return None;
        }
        Some(value.into())
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
