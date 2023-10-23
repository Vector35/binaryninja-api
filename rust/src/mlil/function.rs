use binaryninjacore_sys::BNFreeMediumLevelILFunction;
use binaryninjacore_sys::BNMediumLevelILFunction;
use binaryninjacore_sys::BNNewMediumLevelILFunctionReference;

use core::marker::PhantomData;

use crate::basicblock::BasicBlock;
use crate::rc::Array;
use crate::rc::{Ref, RefCountable};

use super::*;

#[derive(Copy, Clone, Debug)]
pub struct SSA;
#[derive(Copy, Clone, Debug)]
pub struct NonSSA;

pub trait FunctionForm: 'static {}
impl FunctionForm for SSA {}
impl FunctionForm for NonSSA {}

pub struct Function<F: FunctionForm> {
    pub(crate) handle: *mut BNMediumLevelILFunction,
    _form: PhantomData<F>,
}

unsafe impl<F: FunctionForm> Send for Function<F> {}
unsafe impl<F: FunctionForm> Sync for Function<F> {}

impl<F: FunctionForm> Eq for Function<F> {}
impl<F: FunctionForm> PartialEq for Function<F> {
    fn eq(&self, rhs: &Self) -> bool {
        self.handle == rhs.handle
    }
}

use std::hash::{Hash, Hasher};

use super::instruction::Instruction;
impl<F: FunctionForm> Hash for Function<F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

impl<F: FunctionForm> Function<F> {
    pub(crate) unsafe fn from_raw(handle: *mut BNMediumLevelILFunction) -> Self {
        debug_assert!(!handle.is_null());

        Self {
            handle,
            _form: PhantomData,
        }
    }

    pub fn instruction_at<L: Into<Location>>(&self, loc: L) -> Option<Instruction<F>> {
        use binaryninjacore_sys::BNMediumLevelILGetInstructionStart;

        let loc: Location = loc.into();
        let arch_handle = loc.arch.unwrap();

        let instr_idx =
            unsafe { BNMediumLevelILGetInstructionStart(self.handle, arch_handle.0, loc.addr) };

        if instr_idx >= self.instruction_count() {
            None
        } else {
            Some(Instruction {
                function: self.to_owned(),
                instr_idx,
            })
        }
    }

    pub fn instruction_from_idx(&self, instr_idx: usize) -> Instruction<F> {
        if instr_idx >= self.instruction_count() {
            panic!("instruction index {} out of bounds", instr_idx);
        }

        Instruction {
            function: self.to_owned(),
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
impl<F: FunctionForm> Function<F> {
    pub fn basic_blocks(&self) -> Array<BasicBlock<MediumLevelBlock<F>>> {
        use binaryninjacore_sys::BNGetMediumLevelILBasicBlockList;

        unsafe {
            let mut count = 0;
            let blocks = BNGetMediumLevelILBasicBlockList(self.handle, &mut count);
            let context = MediumLevelBlock {
                function: self.to_owned(),
            };

            Array::new(blocks, count, context)
        }
    }

    pub fn ssa_form(&self) -> Function<SSA> {
        use binaryninjacore_sys::BNGetMediumLevelILSSAForm;

        let ssa = unsafe { BNGetMediumLevelILSSAForm(self.handle) };
        assert!(!ssa.is_null());
        Function {
            handle: ssa,
            _form: PhantomData,
        }
    }
}

impl<F: FunctionForm> ToOwned for Function<F> {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl<F: FunctionForm> RefCountable for Function<F> {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewMediumLevelILFunctionReference(handle.handle),
            _form: PhantomData,
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeMediumLevelILFunction(handle.handle);
    }
}

impl<F: FunctionForm> fmt::Debug for Function<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<llil func handle {:p}>", self.handle)
    }
}
