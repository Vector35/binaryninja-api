mod expression;
mod info;
mod lift;
mod operation;

pub use self::expression::*;
pub use self::info::*;
pub use self::lift::*;
pub use self::operation::*;

use binaryninjacore_sys::BNFreeMediumLevelILFunction;
use binaryninjacore_sys::BNMediumLevelILFunction;
use binaryninjacore_sys::BNNewMediumLevelILFunctionReference;

use crate::{
    basicblock::{BasicBlock, BlockContext},
    function::Location,
    rc::{Array, Ref, RefCountable},
    types::Variable,
};

use core::hash::{Hash, Hasher};
use std::fmt;
use std::ops::Range;

pub struct MediumLevelILBlockIter {
    function: Ref<MediumLevelILFunction>,
    range: Range<u64>,
}

impl Iterator for MediumLevelILBlockIter {
    type Item = Expression;

    fn next(&mut self) -> Option<Self::Item> {
        self.range.next().map(|i| Expression {
            function: self.function.to_owned(),
            expr_idx: i as usize,
        })
    }
}

pub struct MediumLevelILBlock {
    pub(crate) function: Ref<MediumLevelILFunction>,
}

impl fmt::Debug for MediumLevelILBlockIter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "mlil_bb {:?}", self.function)
    }
}

impl BlockContext for MediumLevelILBlock {
    type Iter = MediumLevelILBlockIter;
    type Instruction = Expression;

    fn start(&self, block: &BasicBlock<Self>) -> Expression {
        Expression {
            function: self.function.to_owned(),
            expr_idx: block.raw_start() as usize,
        }
    }

    fn iter(&self, block: &BasicBlock<Self>) -> MediumLevelILBlockIter {
        MediumLevelILBlockIter {
            function: self.function.to_owned(),
            range: block.raw_start()..block.raw_end(),
        }
    }
}

impl Clone for MediumLevelILBlock {
    fn clone(&self) -> Self {
        MediumLevelILBlock {
            function: self.function.to_owned(),
        }
    }
}

pub struct MediumLevelILFunction {
    pub(crate) handle: *mut BNMediumLevelILFunction,
}

unsafe impl Send for MediumLevelILFunction {}
unsafe impl Sync for MediumLevelILFunction {}

impl Eq for MediumLevelILFunction {}
impl PartialEq for MediumLevelILFunction {
    fn eq(&self, rhs: &Self) -> bool {
        self.handle == rhs.handle
    }
}

impl Hash for MediumLevelILFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

impl MediumLevelILFunction {
    pub(crate) unsafe fn from_raw(handle: *mut BNMediumLevelILFunction) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    pub fn instruction_at<L: Into<Location>>(&self, loc: L) -> Option<Expression> {
        use binaryninjacore_sys::BNMediumLevelILGetInstructionStart;

        let loc: Location = loc.into();
        let arch_handle = loc.arch.unwrap();

        let expr_idx =
            unsafe { BNMediumLevelILGetInstructionStart(self.handle, arch_handle.0, loc.addr) };

        if expr_idx >= self.instruction_count() {
            None
        } else {
            Some(Expression {
                function: self.to_owned(),
                expr_idx,
            })
        }
    }

    pub fn instruction_from_idx(&self, expr_idx: usize) -> Expression {
        if expr_idx >= self.instruction_count() {
            panic!("instruction index {} out of bounds", expr_idx);
        }

        Expression {
            function: self.to_owned(),
            expr_idx,
        }
    }

    pub fn instruction_count(&self) -> usize {
        unsafe {
            use binaryninjacore_sys::BNGetMediumLevelILInstructionCount;
            BNGetMediumLevelILInstructionCount(self.handle)
        }
    }
}

impl MediumLevelILFunction {
    pub fn basic_blocks(&self) -> Array<BasicBlock<MediumLevelILBlock>> {
        use binaryninjacore_sys::BNGetMediumLevelILBasicBlockList;

        unsafe {
            let mut count = 0;
            let blocks = BNGetMediumLevelILBasicBlockList(self.handle, &mut count);
            let context = MediumLevelILBlock {
                function: self.to_owned(),
            };

            Array::new(blocks, count, context)
        }
    }

    pub fn ssa_form(&self) -> Self {
        use binaryninjacore_sys::BNGetMediumLevelILSSAForm;

        let ssa = unsafe { BNGetMediumLevelILSSAForm(self.handle) };
        assert!(!ssa.is_null());
        Self { handle: ssa }
    }
}

impl ToOwned for MediumLevelILFunction {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for MediumLevelILFunction {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewMediumLevelILFunctionReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeMediumLevelILFunction(handle.handle);
    }
}

impl fmt::Debug for MediumLevelILFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<mlil func handle {:p}>", self.handle)
    }
}
