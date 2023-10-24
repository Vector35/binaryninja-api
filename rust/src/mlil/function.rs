use binaryninjacore_sys::BNFreeMediumLevelILFunction;
use binaryninjacore_sys::BNMediumLevelILFunction;
use binaryninjacore_sys::BNNewMediumLevelILFunctionReference;

use core::hash::{Hash, Hasher};

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

pub struct Function {
    pub(crate) handle: *mut BNMediumLevelILFunction,
}

unsafe impl Send for Function {}
unsafe impl Sync for Function {}

impl Eq for Function {}
impl PartialEq for Function {
    fn eq(&self, rhs: &Self) -> bool {
        self.handle == rhs.handle
    }
}

impl Hash for Function {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

impl Function {
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

impl Function {
    pub fn basic_blocks(&self) -> Array<BasicBlock<MediumLevelBlock>> {
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

    pub fn ssa_form(&self) -> Function {
        use binaryninjacore_sys::BNGetMediumLevelILSSAForm;

        let ssa = unsafe { BNGetMediumLevelILSSAForm(self.handle) };
        assert!(!ssa.is_null());
        Function {
            handle: ssa,
        }
    }
}

impl ToOwned for Function {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Function {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewMediumLevelILFunctionReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeMediumLevelILFunction(handle.handle);
    }
}

impl fmt::Debug for Function {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<llil func handle {:p}>", self.handle)
    }
}
