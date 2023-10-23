use binaryninjacore_sys::BNFreeMediumLevelILFunction;
use binaryninjacore_sys::BNMediumLevelILFunction;
use binaryninjacore_sys::BNNewMediumLevelILFunctionReference;

use core::borrow::Borrow;
use core::marker::PhantomData;

use crate::basicblock::BasicBlock;
use crate::rc::Array;
use crate::rc::{Ref, RefCountable};

use super::*;

#[derive(Copy, Clone, Debug)]
pub struct Finalized;

pub trait FunctionMutability: 'static {}
impl FunctionMutability for Finalized {}

#[derive(Copy, Clone, Debug)]
pub struct RegularNonSSA;

pub trait NonSSAVariant: 'static {}
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
    pub(crate) handle: *mut BNMediumLevelILFunction,
    _arch: PhantomData<*mut A>,
    _mutability: PhantomData<M>,
    _form: PhantomData<F>,
}

unsafe impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Send for Function<A, M, F> {}
unsafe impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Sync for Function<A, M, F> {}

impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Eq for Function<A, M, F> {}
impl<A: Architecture, M: FunctionMutability, F: FunctionForm> PartialEq for Function<A, M, F> {
    fn eq(&self, rhs: &Self) -> bool {
        self.handle == rhs.handle
    }
}

use std::hash::{Hash, Hasher};

use super::instruction::Instruction;
impl<A: Architecture, M: FunctionMutability, F: FunctionForm> Hash for Function<A, M, F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

impl<'func, A, M, F> Function<A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub(crate) unsafe fn from_raw(
        borrower: A::Handle,
        handle: *mut BNMediumLevelILFunction,
    ) -> Self {
        debug_assert!(!handle.is_null());

        Self {
            borrower,
            handle,
            _arch: PhantomData,
            _mutability: PhantomData,
            _form: PhantomData,
        }
    }

    pub(crate) fn arch(&self) -> &A {
        self.borrower.borrow()
    }

    pub fn instruction_at<L: Into<Location>>(&self, loc: L) -> Option<Instruction<A, M, F>> {
        use binaryninjacore_sys::BNMediumLevelILGetInstructionStart;

        let loc: Location = loc.into();
        let arch_handle = loc.arch.unwrap_or(*self.arch().as_ref());

        let instr_idx =
            unsafe { BNMediumLevelILGetInstructionStart(self.handle, arch_handle.0, loc.addr) };

        if instr_idx >= self.instruction_count() {
            None
        } else {
            Some(Instruction {
                function: self,
                instr_idx,
            })
        }
    }

    pub fn instruction_from_idx(&self, instr_idx: usize) -> Instruction<A, M, F> {
        if instr_idx >= self.instruction_count() {
            panic!("instruction index {} out of bounds", instr_idx);
        }

        Instruction {
            function: self,
            instr_idx,
        }
    }

    pub fn instruction_count(&self) -> usize {
        unsafe {
            use binaryninjacore_sys::BNGetMediumLevelILInstructionCount;
            BNGetMediumLevelILInstructionCount(self.handle)
        }
    }
}

// MLIL basic blocks are not available until the function object
// is finalized, so ensure we can't try requesting basic blocks
// during lifting
impl<'func, A, F> Function<A, Finalized, F>
where
    A: 'func + Architecture,
    F: FunctionForm,
{
    pub fn basic_blocks(&self) -> Array<BasicBlock<MediumLevelBlock<A, Finalized, F>>> {
        use binaryninjacore_sys::BNGetMediumLevelILBasicBlockList;

        unsafe {
            let mut count = 0;
            let blocks = BNGetMediumLevelILBasicBlockList(self.handle, &mut count);
            let context = MediumLevelBlock { function: self };

            Array::new(blocks, count, context)
        }
    }

    pub fn ssa_form(&self) -> Function<A, Finalized, SSA> {
        use binaryninjacore_sys::BNGetMediumLevelILSSAForm;

        let ssa = unsafe { BNGetMediumLevelILSSAForm(self.handle) };
        assert!(!ssa.is_null());
        Function {
            borrower: self.borrower.clone(),
            handle: ssa,
            _arch: PhantomData,
            _mutability: PhantomData,
            _form: PhantomData,
        }
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
            handle: BNNewMediumLevelILFunctionReference(handle.handle),
            _arch: PhantomData,
            _mutability: PhantomData,
            _form: PhantomData,
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeMediumLevelILFunction(handle.handle);
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
