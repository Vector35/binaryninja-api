use std::hash::{Hash, Hasher};

use binaryninjacore_sys::*;

use crate::architecture::CoreArchitecture;
use crate::basicblock::BasicBlock;
use crate::function::Function;
use crate::rc::{Array, Ref, RefCountable};
use crate::types::SSAVariable;

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
    pub(crate) unsafe fn ref_from_raw(
        handle: *mut BNHighLevelILFunction,
        full_ast: bool,
    ) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Self { handle, full_ast }.to_owned()
    }

    pub fn instruction_from_idx(&self, expr_idx: usize) -> HighLevelILInstruction {
        HighLevelILInstruction::new(self.to_owned(), expr_idx)
    }

    pub fn lifted_instruction_from_idx(&self, expr_idx: usize) -> HighLevelILLiftedInstruction {
        self.instruction_from_idx(expr_idx).lift()
    }

    pub fn instruction_from_instruction_idx(&self, instr_idx: usize) -> HighLevelILInstruction {
        HighLevelILInstruction::new(self.as_non_ast(), unsafe {
            BNGetHighLevelILIndexForInstruction(self.handle, instr_idx)
        })
    }

    pub fn lifted_instruction_from_instruction_idx(
        &self,
        instr_idx: usize,
    ) -> HighLevelILLiftedInstruction {
        self.instruction_from_instruction_idx(instr_idx).lift()
    }

    pub fn root(&self) -> HighLevelILInstruction {
        HighLevelILInstruction::new(self.as_ast(), unsafe {
            BNGetHighLevelILRootExpr(self.handle)
        })
    }

    pub fn set_root(&self, new_root: &HighLevelILInstruction) {
        unsafe { BNSetHighLevelILRootExpr(self.handle, new_root.index) }
    }

    pub fn lifted_root(&self) -> HighLevelILLiftedInstruction {
        self.root().lift()
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

    pub fn as_ast(&self) -> Ref<HighLevelILFunction> {
        Self {
            handle: self.handle,
            full_ast: true,
        }
        .to_owned()
    }

    pub fn as_non_ast(&self) -> Ref<HighLevelILFunction> {
        Self {
            handle: self.handle,
            full_ast: false,
        }
        .to_owned()
    }

    pub fn current_address(&self) -> u64 {
        unsafe { BNHighLevelILGetCurrentAddress(self.handle) }
    }

    pub fn set_current_address(&self, address: u64, arch: Option<CoreArchitecture>) {
        let arch = arch.unwrap_or_else(|| self.get_function().arch()).0;
        unsafe { BNHighLevelILSetCurrentAddress(self.handle, arch, address) }
    }

    /// Gets the instruction that contains the given SSA variable's definition.
    ///
    /// Since SSA variables can only be defined once, this will return the single instruction where that occurs.
    /// For SSA variable version 0s, which don't have definitions, this will return None instead.
    pub fn ssa_variable_definition(&self, variable: SSAVariable) -> Option<HighLevelILInstruction> {
        let index = unsafe {
            BNGetHighLevelILSSAVarDefinition(
                self.handle,
                &variable.variable.raw(),
                variable.version,
            )
        };
        if index >= self.instruction_count() {
            None
        } else {
            Some(HighLevelILInstruction::new(self.to_owned(), index))
        }
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
