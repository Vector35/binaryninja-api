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

use binaryninjacore_sys::BNFreeLowLevelILFunction;
use binaryninjacore_sys::BNGetLowLevelILOwnerFunction;
use binaryninjacore_sys::BNLowLevelILFunction;
use binaryninjacore_sys::BNNewLowLevelILFunctionReference;

use std::borrow::Borrow;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

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

pub trait FunctionMutability: 'static {}
impl FunctionMutability for Mutable {}
impl FunctionMutability for Finalized {}

#[derive(Copy, Clone, Debug)]
pub struct LiftedNonSSA;
#[derive(Copy, Clone, Debug)]
pub struct RegularNonSSA;

pub trait NonSSAVariant: 'static {}
impl NonSSAVariant for LiftedNonSSA {}
impl NonSSAVariant for RegularNonSSA {}

#[derive(Copy, Clone, Debug)]
pub struct SSA;
#[derive(Copy, Clone, Debug)]
pub struct NonSSA<V: NonSSAVariant>(V);

pub trait FunctionForm: 'static {}
impl FunctionForm for SSA {}
impl<V: NonSSAVariant> FunctionForm for NonSSA<V> {}

pub struct LowLevelILFunction<A: Architecture, M: FunctionMutability, F: FunctionForm> {
    pub(crate) arch_handle: A::Handle,
    pub(crate) handle: *mut BNLowLevelILFunction,
    _arch: PhantomData<*mut A>,
    _mutability: PhantomData<M>,
    _form: PhantomData<F>,
}

impl<A, M, F> LowLevelILFunction<A, M, F>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) unsafe fn from_raw(
        arch_handle: A::Handle,
        handle: *mut BNLowLevelILFunction,
    ) -> Self {
        debug_assert!(!handle.is_null());

        Self {
            arch_handle,
            handle,
            _arch: PhantomData,
            _mutability: PhantomData,
            _form: PhantomData,
        }
    }

    pub(crate) unsafe fn ref_from_raw(
        arch_handle: A::Handle,
        handle: *mut BNLowLevelILFunction,
    ) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self::from_raw(arch_handle, handle))
    }

    pub(crate) fn arch(&self) -> &A {
        self.arch_handle.borrow()
    }

    pub fn instruction_at<L: Into<Location>>(
        &self,
        loc: L,
    ) -> Option<LowLevelILInstruction<A, M, F>> {
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
        let arch = loc.arch.unwrap_or_else(|| *self.arch().as_ref());
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
    ) -> Option<LowLevelILInstruction<A, M, F>> {
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
}

// LLIL basic blocks are not available until the function object
// is finalized, so ensure we can't try requesting basic blocks
// during lifting
impl<A, F> LowLevelILFunction<A, Finalized, F>
where
    A: Architecture,
    F: FunctionForm,
{
    pub fn basic_blocks(&self) -> Array<BasicBlock<LowLevelILBlock<A, Finalized, F>>> {
        use binaryninjacore_sys::BNGetLowLevelILBasicBlockList;

        unsafe {
            let mut count = 0;
            let blocks = BNGetLowLevelILBasicBlockList(self.handle, &mut count);
            let context = LowLevelILBlock { function: self };
            Array::new(blocks, count, context)
        }
    }
}

// Allow instantiating Lifted IL functions for querying Lifted IL from Architectures
impl LowLevelILFunction<CoreArchitecture, Mutable, NonSSA<LiftedNonSSA>> {
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

        unsafe { Self::ref_from_raw(arch, handle) }
    }
}

impl<A, M, F> ToOwned for LowLevelILFunction<A, M, F>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl<A, M, F> RefCountable for LowLevelILFunction<A, M, F>
where
    A: Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            arch_handle: handle.arch_handle.clone(),
            handle: BNNewLowLevelILFunctionReference(handle.handle),
            _arch: PhantomData,
            _mutability: PhantomData,
            _form: PhantomData,
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeLowLevelILFunction(handle.handle);
    }
}

impl<A, M, F> Debug for LowLevelILFunction<A, M, F>
where
    A: Architecture + Debug,
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

unsafe impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Send
    for LowLevelILFunction<A, M, F>
{
}
unsafe impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Sync
    for LowLevelILFunction<A, M, F>
{
}

impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Eq for LowLevelILFunction<A, M, F> {}

impl<A: Architecture, M: FunctionMutability, F: FunctionForm> PartialEq
    for LowLevelILFunction<A, M, F>
{
    fn eq(&self, rhs: &Self) -> bool {
        self.function().eq(&rhs.function())
    }
}

impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Hash for LowLevelILFunction<A, M, F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.function().hash(state)
    }
}
