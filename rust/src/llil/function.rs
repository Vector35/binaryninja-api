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
use std::marker::PhantomData;

use crate::architecture::CoreArchitecture;
use crate::basicblock::BasicBlock;
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

pub struct Function<A: Architecture, M: FunctionMutability, F: FunctionForm> {
    pub(crate) borrower: A::Handle,
    pub(crate) handle: *mut BNLowLevelILFunction,
    _arch: PhantomData<*mut A>,
    _mutability: PhantomData<M>,
    _form: PhantomData<F>,
}

unsafe impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Send for Function<A, M, F> {}
unsafe impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Sync for Function<A, M, F> {}

impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Eq for Function<A, M, F> {}
impl<A: Architecture, M: FunctionMutability, F: FunctionForm> PartialEq for Function<A, M, F> {
    fn eq(&self, rhs: &Self) -> bool {
        self.get_function().eq(&rhs.get_function())
    }
}

use std::hash::{Hash, Hasher};
impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Hash for Function<A, M, F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_function().hash(state)
    }
}

impl<'func, A, M, F> Function<A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) unsafe fn from_raw(borrower: A::Handle, handle: *mut BNLowLevelILFunction) -> Self {
        debug_assert!(!handle.is_null());

        Self {
            borrower,
            handle,
            _arch: PhantomData,
            _mutability: PhantomData,
            _form: PhantomData,
        }
    }
    
    pub(crate) unsafe fn ref_from_raw(
        borrower: A::Handle,
        handle: *mut BNLowLevelILFunction,
    ) -> Ref<Self> {
        Ref::new(Self::from_raw(borrower, handle))
    }

    pub(crate) fn arch(&self) -> &A {
        self.borrower.borrow()
    }

    pub fn instruction_at<L: Into<Location>>(&self, loc: L) -> Option<Instruction<A, M, F>> {
        use binaryninjacore_sys::BNGetLowLevelILInstructionCount;
        use binaryninjacore_sys::BNLowLevelILGetInstructionStart;

        let loc: Location = loc.into();
        let arch_handle = loc.arch.unwrap_or_else(|| *self.arch().as_ref());

        unsafe {
            let instr_idx = BNLowLevelILGetInstructionStart(self.handle, arch_handle.0, loc.addr);

            if instr_idx >= BNGetLowLevelILInstructionCount(self.handle) {
                None
            } else {
                Some(Instruction {
                    function: self,
                    instr_idx,
                })
            }
        }
    }

    pub fn instruction_from_idx(&self, instr_idx: usize) -> Instruction<A, M, F> {
        unsafe {
            use binaryninjacore_sys::BNGetLowLevelILInstructionCount;
            if instr_idx >= BNGetLowLevelILInstructionCount(self.handle) {
                panic!("instruction index {} out of bounds", instr_idx);
            }

            Instruction {
                function: self,
                instr_idx,
            }
        }
    }

    pub fn instruction_count(&self) -> usize {
        unsafe {
            use binaryninjacore_sys::BNGetLowLevelILInstructionCount;
            BNGetLowLevelILInstructionCount(self.handle)
        }
    }

    pub fn get_function(&self) -> Ref<crate::function::Function> {
        unsafe {
            let func = BNGetLowLevelILOwnerFunction(self.handle);
            crate::function::Function::from_raw(func)
        }
    }
}

// LLIL basic blocks are not available until the function object
// is finalized, so ensure we can't try requesting basic blocks
// during lifting
impl<'func, A, F> Function<A, Finalized, F>
where
    A: 'func + Architecture,
    F: FunctionForm,
{
    pub fn basic_blocks(&self) -> Array<BasicBlock<LowLevelBlock<A, Finalized, F>>> {
        use binaryninjacore_sys::BNGetLowLevelILBasicBlockList;

        unsafe {
            let mut count = 0;
            let blocks = BNGetLowLevelILBasicBlockList(self.handle, &mut count);
            let context = LowLevelBlock { function: self };

            Array::new(blocks, count, context)
        }
    }
}

// Allow instantiating Lifted IL functions for querying Lifted IL from Architectures
impl Function<CoreArchitecture, Mutable, NonSSA<LiftedNonSSA>> {
    pub fn new(
        arch: CoreArchitecture,
        source_func: Option<crate::function::Function>,
    ) -> Result<Ref<Self>, ()> {
        use binaryninjacore_sys::BNCreateLowLevelILFunction;
        use std::ptr::null_mut;

        let handle = unsafe {
            match source_func {
                Some(func) => BNCreateLowLevelILFunction(arch.0, func.handle),
                None => BNCreateLowLevelILFunction(arch.0, null_mut()),
            }
        };
        if handle.is_null() {
            return Err(());
        }

        Ok(unsafe {
            Ref::new(Self {
                borrower: arch,
                handle,
                _arch: PhantomData,
                _mutability: PhantomData,
                _form: PhantomData,
            })
        })
    }
}

impl<'func, A, M, F> ToOwned for Function<A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl<'func, A, M, F> RefCountable for Function<A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            borrower: handle.borrower.clone(),
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

impl<'func, A, M, F> fmt::Debug for Function<A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<llil func handle {:p}>", self.handle)
    }
}
