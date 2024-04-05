use std::hash::{Hash, Hasher};

use binaryninjacore_sys::BNFreeHighLevelILFunction;
use binaryninjacore_sys::BNGetHighLevelILBasicBlockList;
use binaryninjacore_sys::BNGetHighLevelILInstructionCount;
use binaryninjacore_sys::BNGetHighLevelILOwnerFunction;
use binaryninjacore_sys::BNGetHighLevelILSSAForm;
use binaryninjacore_sys::BNHighLevelILFunction;
use binaryninjacore_sys::BNNewHighLevelILFunctionReference;

use crate::basicblock::BasicBlock;
use crate::function::Function;
use crate::rc::Array;

use super::{HighLevelILBlock, HighLevelILInstruction, HighLevelILLiftedInstruction};

pub struct HighLevelILFunction {
    pub(crate) full_ast: bool,
    pub(crate) handle: *mut BNHighLevelILFunction,
}

unsafe impl Send for HighLevelILFunction {}
unsafe impl Sync for HighLevelILFunction {}

impl Eq for HighLevelILFunction {}
impl PartialEq for HighLevelILFunction {
    fn eq(&self, rhs: &Self) -> bool {
        self.get_function().eq(&rhs.get_function())
    }
}

impl Hash for HighLevelILFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_function().hash(state)
    }
}

impl HighLevelILFunction {
    pub(crate) unsafe fn from_raw(handle: *mut BNHighLevelILFunction, full_ast: bool) -> Self {
        debug_assert!(!handle.is_null());
        // TODO is handle owned or just borrowed?
        Self {
            handle: BNNewHighLevelILFunctionReference(handle),
            full_ast,
        }
    }

    pub fn instruction_from_idx(&self, expr_idx: usize) -> HighLevelILInstruction {
        HighLevelILInstruction::new(self.clone(), expr_idx)
    }

    pub fn lifted_instruction_from_idx(&self, expr_idx: usize) -> HighLevelILLiftedInstruction {
        self.instruction_from_idx(expr_idx).lift()
    }

    pub fn instruction_count(&self) -> usize {
        unsafe { BNGetHighLevelILInstructionCount(self.handle) }
    }

    pub fn ssa_form(&self) -> HighLevelILFunction {
        let ssa = unsafe { BNGetHighLevelILSSAForm(self.handle) };
        assert!(!ssa.is_null());
        HighLevelILFunction {
            handle: ssa,
            full_ast: self.full_ast,
        }
    }

    pub fn get_function(&self) -> Function {
        unsafe {
            let func = BNGetHighLevelILOwnerFunction(self.handle);
            Function::from_raw(func)
        }
    }

    pub fn basic_blocks(&self) -> Array<BasicBlock<HighLevelILBlock>> {
        let mut count = 0;
        let blocks = unsafe { BNGetHighLevelILBasicBlockList(self.handle, &mut count) };
        let context = HighLevelILBlock {
            function: self.clone(),
        };

        unsafe { Array::new(blocks, count, context) }
    }
}

impl Clone for HighLevelILFunction {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(
                BNNewHighLevelILFunctionReference(self.handle),
                self.full_ast,
            )
        }
    }
}

impl Drop for HighLevelILFunction {
    fn drop(&mut self) {
        unsafe {
            BNFreeHighLevelILFunction(self.handle);
        }
    }
}

impl core::fmt::Debug for HighLevelILFunction {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "<hlil func handle {:p}>", self.handle)
    }
}
