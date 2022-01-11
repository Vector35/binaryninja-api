use std::ffi::CString;

use binaryninjacore_sys::*;

use crate::architecture::CoreArchitecture;
use crate::basicblock::{BasicBlock, BlockContext};
use crate::llil;
use crate::function::Function;
use crate::rc::*;

pub struct AnalysisContext {
    handle: *mut BNAnalysisContext,
}

impl AnalysisContext {
    pub(crate) unsafe fn from_raw(handle: *mut BNAnalysisContext) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    pub fn function(&self) -> Option<Ref<Function>> {
        unsafe {
            let p = BNAnalysisContextGetFunction(self.handle);

            if p.is_null() {
                return None;
            }

            Some(Function::from_raw(p))
        }
    }

    pub fn low_level_il_function(&self) -> Option<Ref<llil::RegularFunction<CoreArchitecture>>> {
        match self.function() {
            Some(f) => match f.low_level_il() {
                Ok(f) => Some(f),
                Err(_) => None,
            }
            None => None,
        }
    }

    pub fn set_low_level_il_function(&self, f: Ref<llil::RegularFunction<CoreArchitecture>>) {
        unsafe { BNSetLowLevelILFunction(self.handle, f.handle) }
    }

    pub fn set_lifted_il_function(&self, f: Ref<llil::LiftedFunction<CoreArchitecture>>) {
        unsafe { BNSetLiftedILFunction(self.handle, f.handle) }
    }

    pub fn mlil_function(&self) {
        unimplemented!()
    }

    pub fn set_mlil_function(&self) {
        unimplemented!()
    }

    pub fn hlil_function(&self) {
        unimplemented!()
    }

    pub fn set_hlil_function(&self) {
        unimplemented!()
    }

    pub fn set_basic_block_list<C: BlockContext>(&self, basic_block_list: &[BasicBlock<C>]) {
        let mut blocks: Vec<*mut BNBasicBlock> = Vec::with_capacity(basic_block_list.len());

        for block in basic_block_list {
            blocks.push(block.handle);
        }

        unsafe { BNSetBasicBlockList(self.handle, blocks.as_ptr() as _, blocks.len()) }
    }

    pub fn inform(&self, request: &str) -> bool {
        let req_with_nul = CString::new(request).unwrap();

        unsafe { BNAnalysisContextInform(self.handle, req_with_nul.as_ptr()) }
    }
}