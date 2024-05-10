use core::hash::{Hash, Hasher};

use binaryninjacore_sys::BNFreeMediumLevelILFunction;
use binaryninjacore_sys::BNGetMediumLevelILBasicBlockList;
use binaryninjacore_sys::BNGetMediumLevelILIndexForInstruction;
use binaryninjacore_sys::BNGetMediumLevelILInstructionCount;
use binaryninjacore_sys::BNGetMediumLevelILOwnerFunction;
use binaryninjacore_sys::BNGetMediumLevelILSSAForm;
use binaryninjacore_sys::BNMediumLevelILFunction;
use binaryninjacore_sys::BNMediumLevelILGetInstructionStart;
use binaryninjacore_sys::BNNewMediumLevelILFunctionReference;

use crate::basicblock::BasicBlock;
use crate::function::Function;
use crate::function::Location;
use crate::rc::{Array, Ref, RefCountable};

use super::{
    Form, MediumLevelILBlock, MediumLevelILInstruction, MediumLevelILLiftedInstruction, NonSSA, SSA,
};

pub struct MediumLevelILFunction<I> {
    pub(crate) handle: *mut BNMediumLevelILFunction,
    _form: std::marker::PhantomData<I>,
}

unsafe impl<I> Send for MediumLevelILFunction<I> {}
unsafe impl<I> Sync for MediumLevelILFunction<I> {}

impl<I> Eq for MediumLevelILFunction<I> {}
impl<I> PartialEq for MediumLevelILFunction<I> {
    fn eq(&self, rhs: &Self) -> bool {
        self.get_function().eq(&rhs.get_function())
    }
}

impl<I> Hash for MediumLevelILFunction<I> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_function().hash(state)
    }
}

impl<I> MediumLevelILFunction<I> {
    pub(crate) unsafe fn ref_from_raw(handle: *mut BNMediumLevelILFunction) -> Ref<Self> {
        debug_assert!(!handle.is_null());

        Self {
            handle,
            _form: std::marker::PhantomData,
        }
        .to_owned()
    }

    pub fn instruction_count(&self) -> usize {
        unsafe { BNGetMediumLevelILInstructionCount(self.handle) }
    }

    pub fn get_function(&self) -> Ref<Function> {
        unsafe {
            let func = BNGetMediumLevelILOwnerFunction(self.handle);
            Function::from_raw(func)
        }
    }
}

impl<I: Form> MediumLevelILFunction<I> {
    pub fn instruction_at<L: Into<Location>>(&self, loc: L) -> Option<MediumLevelILInstruction<I>> {
        let loc: Location = loc.into();
        let arch_handle = loc.arch.unwrap();

        let expr_idx =
            unsafe { BNMediumLevelILGetInstructionStart(self.handle, arch_handle.0, loc.addr) };

        if expr_idx >= self.instruction_count() {
            None
        } else {
            Some(MediumLevelILInstruction::new(self.to_owned(), expr_idx))
        }
    }

    pub fn instruction_from_idx(&self, expr_idx: usize) -> MediumLevelILInstruction<I> {
        MediumLevelILInstruction::new(self.to_owned(), expr_idx)
    }

    pub fn lifted_instruction_from_idx(
        &self,
        expr_idx: usize,
    ) -> MediumLevelILLiftedInstruction<I> {
        self.instruction_from_idx(expr_idx).lift()
    }

    pub fn instruction_from_instruction_idx(
        &self,
        instr_idx: usize,
    ) -> MediumLevelILInstruction<I> {
        MediumLevelILInstruction::new(self.to_owned(), unsafe {
            BNGetMediumLevelILIndexForInstruction(self.handle, instr_idx)
        })
    }

    pub fn lifted_instruction_from_instruction_idx(
        &self,
        instr_idx: usize,
    ) -> MediumLevelILLiftedInstruction<I> {
        self.instruction_from_instruction_idx(instr_idx).lift()
    }

    pub fn basic_blocks(&self) -> Array<BasicBlock<MediumLevelILBlock<I>>> {
        let mut count = 0;
        let blocks = unsafe { BNGetMediumLevelILBasicBlockList(self.handle, &mut count) };
        let context = MediumLevelILBlock {
            function: self.to_owned(),
        };

        unsafe { Array::new(blocks, count, context) }
    }
}

impl MediumLevelILFunction<NonSSA> {
    pub fn ssa_form(&self) -> MediumLevelILFunction<SSA> {
        let ssa = unsafe { BNGetMediumLevelILSSAForm(self.handle) };
        assert!(!ssa.is_null());
        MediumLevelILFunction {
            handle: ssa,
            _form: std::marker::PhantomData,
        }
    }
}

impl<I> ToOwned for MediumLevelILFunction<I> {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl<I> RefCountable for MediumLevelILFunction<I> {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewMediumLevelILFunctionReference(handle.handle),
            _form: std::marker::PhantomData,
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeMediumLevelILFunction(handle.handle);
    }
}

impl<I> core::fmt::Debug for MediumLevelILFunction<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "<mlil func handle {:p}>", self.handle)
    }
}
