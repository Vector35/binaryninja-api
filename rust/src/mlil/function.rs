use core::hash::{Hash, Hasher};

use binaryninjacore_sys::BNFreeMediumLevelILFunction;
use binaryninjacore_sys::BNGetMediumLevelILBasicBlockList;
use binaryninjacore_sys::BNGetMediumLevelILInstructionCount;
use binaryninjacore_sys::BNGetMediumLevelILOwnerFunction;
use binaryninjacore_sys::BNGetMediumLevelILSSAForm;
use binaryninjacore_sys::BNMediumLevelILFunction;
use binaryninjacore_sys::BNMediumLevelILGetInstructionStart;
use binaryninjacore_sys::BNNewMediumLevelILFunctionReference;

use crate::basicblock::BasicBlock;
use crate::function::Function;
use crate::function::Location;
use crate::rc::Array;

use super::{MediumLevelILBlock, MediumLevelILInstruction, MediumLevelILLiftedInstruction};

pub struct MediumLevelILFunction {
    pub(crate) handle: *mut BNMediumLevelILFunction,
}

unsafe impl Send for MediumLevelILFunction {}
unsafe impl Sync for MediumLevelILFunction {}

impl Eq for MediumLevelILFunction {}
impl PartialEq for MediumLevelILFunction {
    fn eq(&self, rhs: &Self) -> bool {
        self.get_function().eq(&rhs.get_function())
    }
}

impl Hash for MediumLevelILFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_function().hash(state)
    }
}

impl MediumLevelILFunction {
    pub(crate) unsafe fn from_raw(handle: *mut BNMediumLevelILFunction) -> Self {
        debug_assert!(!handle.is_null());

        // TODO is handle owned or just borrowed?
        Self {
            handle: BNNewMediumLevelILFunctionReference(handle),
        }
    }

    pub fn instruction_at<L: Into<Location>>(&self, loc: L) -> Option<MediumLevelILInstruction> {
        let loc: Location = loc.into();
        let arch_handle = loc.arch.unwrap();

        let expr_idx =
            unsafe { BNMediumLevelILGetInstructionStart(self.handle, arch_handle.0, loc.addr) };

        if expr_idx >= self.instruction_count() {
            None
        } else {
            Some(MediumLevelILInstruction::new(self.clone(), expr_idx))
        }
    }

    pub fn instruction_from_idx(&self, expr_idx: usize) -> MediumLevelILInstruction {
        MediumLevelILInstruction::new(self.clone(), expr_idx)
    }

    pub fn lifted_instruction_from_idx(&self, expr_idx: usize) -> MediumLevelILLiftedInstruction {
        self.instruction_from_idx(expr_idx).lift()
    }

    pub fn instruction_count(&self) -> usize {
        unsafe { BNGetMediumLevelILInstructionCount(self.handle) }
    }

    pub fn ssa_form(&self) -> MediumLevelILFunction {
        let ssa = unsafe { BNGetMediumLevelILSSAForm(self.handle) };
        assert!(!ssa.is_null());
        MediumLevelILFunction { handle: ssa }
    }

    pub fn get_function(&self) -> Function {
        unsafe {
            let func = BNGetMediumLevelILOwnerFunction(self.handle);
            Function::from_raw(func)
        }
    }

    pub fn basic_blocks(&self) -> Array<BasicBlock<MediumLevelILBlock>> {
        let mut count = 0;
        let blocks = unsafe { BNGetMediumLevelILBasicBlockList(self.handle, &mut count) };
        let context = MediumLevelILBlock {
            function: self.clone(),
        };

        unsafe { Array::new(blocks, count, context) }
    }
}

impl Clone for MediumLevelILFunction {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(BNNewMediumLevelILFunctionReference(self.handle)) }
    }
}

impl Drop for MediumLevelILFunction {
    fn drop(&mut self) {
        unsafe { BNFreeMediumLevelILFunction(self.handle) }
    }
}

impl core::fmt::Debug for MediumLevelILFunction {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "<mlil func handle {:p}>", self.handle)
    }
}
