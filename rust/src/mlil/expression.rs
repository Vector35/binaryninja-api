use binaryninjacore_sys::BNGetMediumLevelILByIndex;

use core::fmt;

use crate::rc::Ref;

use super::*;

pub struct Expression {
    pub(crate) function: Ref<MediumLevelILFunction>,
    pub(crate) expr_idx: usize,
}

impl Expression {
    pub(crate) fn new(function: &MediumLevelILFunction, expr_idx: usize) -> Self {
        Self {
            function: function.to_owned(),
            expr_idx,
        }
    }

    pub fn index(&self) -> usize {
        self.expr_idx
    }
}

impl Expression {
    pub fn lift(&self) -> ExprLifted {
        unsafe { ExprLifted::new(self.info()) }
    }

    pub fn info(&self) -> ExprInfo {
        unsafe {
            let op = BNGetMediumLevelILByIndex(self.function.handle, self.expr_idx);
            ExprInfo::new(&self.function, op)
        }
    }
}

impl fmt::Debug for Expression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let op_info = self.info();
        write!(f, "<expr {}: {:?}>", self.expr_idx, op_info)
    }
}
