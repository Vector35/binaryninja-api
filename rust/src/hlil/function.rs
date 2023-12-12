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
use crate::rc::{Array, Ref, RefCountable};

use super::{HighLevelILBlock, HighLevelILInstruction};

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
    pub(crate) unsafe fn ref_from_raw(
        handle: *mut BNHighLevelILFunction,
        full_ast: bool,
    ) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Self { handle, full_ast }.to_owned()
    }

    pub fn instruction_from_idx(&self, expr_idx: usize) -> HighLevelILInstruction {
        HighLevelILInstruction::new(self, expr_idx)
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

    pub fn get_function(&self) -> Ref<Function> {
        unsafe {
            let func = BNGetHighLevelILOwnerFunction(self.handle);
            Function::from_raw(func)
        }
    }

    pub fn basic_blocks(&self) -> Array<BasicBlock<HighLevelILBlock>> {
        let mut count = 0;
        let blocks = unsafe { BNGetHighLevelILBasicBlockList(self.handle, &mut count) };
        let context = HighLevelILBlock {
            function: self.to_owned(),
        };

        unsafe { Array::new(blocks, count, context) }
    }
}

impl ToOwned for HighLevelILFunction {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for HighLevelILFunction {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewHighLevelILFunctionReference(handle.handle),
            full_ast: handle.full_ast,
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeHighLevelILFunction(handle.handle);
    }
}

impl core::fmt::Debug for HighLevelILFunction {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "<hlil func handle {:p}>", self.handle)
    }
}
