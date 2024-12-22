use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};

use binaryninjacore_sys::*;

use super::{HighLevelILBlock, HighLevelILInstruction, HighLevelInstructionIndex};
use crate::basic_block::BasicBlock;
use crate::function::{Function, Location};
use crate::rc::{Array, Ref, RefCountable};
use crate::variable::{SSAVariable, Variable};

pub struct HighLevelILFunction {
    pub(crate) full_ast: bool,
    pub(crate) handle: *mut BNHighLevelILFunction,
}

impl HighLevelILFunction {
    pub(crate) unsafe fn ref_from_raw(
        handle: *mut BNHighLevelILFunction,
        full_ast: bool,
    ) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Self { handle, full_ast }.to_owned()
    }

    pub fn instruction_from_index(
        &self,
        index: HighLevelInstructionIndex,
    ) -> Option<HighLevelILInstruction> {
        if index.0 >= self.instruction_count() {
            None
        } else {
            Some(HighLevelILInstruction::new(self.to_owned(), index))
        }
    }

    pub fn instruction_from_expr_index(
        &self,
        expr_index: HighLevelInstructionIndex,
    ) -> Option<HighLevelILInstruction> {
        if expr_index.0 >= self.expression_count() {
            None
        } else {
            Some(HighLevelILInstruction::new_expr(
                self.to_owned(),
                expr_index,
            ))
        }
    }

    // TODO: This returns an expression index!
    pub fn root_instruction_index(&self) -> HighLevelInstructionIndex {
        HighLevelInstructionIndex(unsafe { BNGetHighLevelILRootExpr(self.handle) })
    }

    pub fn root(&self) -> HighLevelILInstruction {
        HighLevelILInstruction::new_expr(self.as_ast(), self.root_instruction_index())
    }

    pub fn set_root(&self, new_root: &HighLevelILInstruction) {
        unsafe { BNSetHighLevelILRootExpr(self.handle, new_root.expr_index.0) }
    }

    pub fn instruction_count(&self) -> usize {
        unsafe { BNGetHighLevelILInstructionCount(self.handle) }
    }

    pub fn expression_count(&self) -> usize {
        unsafe { BNGetHighLevelILExprCount(self.handle) }
    }

    pub fn ssa_form(&self) -> HighLevelILFunction {
        let ssa = unsafe { BNGetHighLevelILSSAForm(self.handle) };
        assert!(!ssa.is_null());
        HighLevelILFunction {
            handle: ssa,
            full_ast: self.full_ast,
        }
    }

    pub fn function(&self) -> Ref<Function> {
        unsafe {
            let func = BNGetHighLevelILOwnerFunction(self.handle);
            Function::ref_from_raw(func)
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

    // TODO: Rename to `current_location`?
    pub fn current_address(&self) -> Location {
        let addr = unsafe { BNHighLevelILGetCurrentAddress(self.handle) };
        Location::from(addr)
    }

    // TODO: Rename to `set_current_location`?
    pub fn set_current_address(&self, location: impl Into<Location>) {
        let location = location.into();
        let arch = location
            .arch
            .map(|a| a.handle)
            .unwrap_or_else(std::ptr::null_mut);
        unsafe { BNHighLevelILSetCurrentAddress(self.handle, arch, location.addr) }
    }

    /// Gets the instruction that contains the given SSA variable's definition.
    ///
    /// Since SSA variables can only be defined once, this will return the single instruction where that occurs.
    /// For SSA variable version 0s, which don't have definitions, this will return None instead.
    pub fn ssa_variable_definition(&self, variable: SSAVariable) -> Option<HighLevelILInstruction> {
        let index = unsafe {
            BNGetHighLevelILSSAVarDefinition(
                self.handle,
                &variable.variable.into(),
                variable.version,
            )
        };
        self.instruction_from_index(HighLevelInstructionIndex(index))
    }

    pub fn ssa_memory_definition(&self, version: usize) -> Option<HighLevelILInstruction> {
        let index = unsafe { BNGetHighLevelILSSAMemoryDefinition(self.handle, version) };
        self.instruction_from_index(HighLevelInstructionIndex(index))
    }

    /// Gets all the instructions that use the given SSA variable.
    pub fn ssa_variable_uses(&self, variable: SSAVariable) -> Array<HighLevelILInstruction> {
        let mut count = 0;
        let instrs = unsafe {
            BNGetHighLevelILSSAVarUses(
                self.handle,
                &variable.variable.into(),
                variable.version,
                &mut count,
            )
        };
        assert!(!instrs.is_null());
        unsafe { Array::new(instrs, count, self.to_owned()) }
    }

    pub fn ssa_memory_uses(&self, version: usize) -> Array<HighLevelILInstruction> {
        let mut count = 0;
        let instrs = unsafe { BNGetHighLevelILSSAMemoryUses(self.handle, version, &mut count) };
        assert!(!instrs.is_null());
        unsafe { Array::new(instrs, count, self.to_owned()) }
    }

    /// Determines if `variable` is live at any point in the function
    pub fn is_ssa_variable_live(&self, variable: SSAVariable) -> bool {
        unsafe {
            BNIsHighLevelILSSAVarLive(self.handle, &variable.variable.into(), variable.version)
        }
    }

    /// Determines if `variable` is live at a given point in the function
    pub fn is_ssa_variable_live_at(
        &self,
        variable: SSAVariable,
        instr: &HighLevelILInstruction,
    ) -> bool {
        unsafe {
            BNIsHighLevelILSSAVarLiveAt(
                self.handle,
                &variable.variable.into(),
                variable.version,
                instr.expr_index.0,
            )
        }
    }

    pub fn variable_definitions(&self, variable: Variable) -> Array<HighLevelILInstruction> {
        let mut count = 0;
        let defs = unsafe {
            BNGetHighLevelILVariableDefinitions(self.handle, &variable.into(), &mut count)
        };
        assert!(!defs.is_null());
        unsafe { Array::new(defs, count, self.to_owned()) }
    }

    pub fn variable_uses(&self, variable: Variable) -> Array<HighLevelILInstruction> {
        let mut count = 0;
        let instrs =
            unsafe { BNGetHighLevelILVariableUses(self.handle, &variable.into(), &mut count) };
        assert!(!instrs.is_null());
        unsafe { Array::new(instrs, count, self.to_owned()) }
    }

    /// Determines if `variable` is live at a given point in the function
    pub fn is_variable_live_at(&self, variable: Variable, instr: &HighLevelILInstruction) -> bool {
        unsafe { BNIsHighLevelILVarLiveAt(self.handle, &variable.into(), instr.expr_index.0) }
    }

    /// This gets just the HLIL variables - you may be interested in the union
    /// of [`Function::parameter_variables`] and [`HighLevelILFunction::aliased_variables`] as well for all the
    /// variables used in the function
    pub fn variables(&self) -> Array<Variable> {
        let mut count = 0;
        let variables = unsafe { BNGetHighLevelILVariables(self.handle, &mut count) };
        assert!(!variables.is_null());
        unsafe { Array::new(variables, count, ()) }
    }

    /// This returns a list of Variables that are taken reference to and used
    /// elsewhere. You may also wish to consider [`HighLevelILFunction::variables`]
    /// and [`Function::parameter_variables`]
    pub fn aliased_variables(&self) -> Array<Variable> {
        let mut count = 0;
        let variables = unsafe { BNGetHighLevelILAliasedVariables(self.handle, &mut count) };
        assert!(!variables.is_null());
        unsafe { Array::new(variables, count, ()) }
    }

    /// This gets the HLIL SSA variables for a given [`Variable`].
    pub fn ssa_variables(&self, variable: &Variable) -> Array<SSAVariable> {
        let mut count = 0;
        let raw_variable = BNVariable::from(variable);
        let variables =
            unsafe { BNGetHighLevelILVariableSSAVersions(self.handle, &raw_variable, &mut count) };
        unsafe { Array::new(variables, count, *variable) }
    }
}

impl Debug for HighLevelILFunction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HighLevelILFunction")
            .field("arch", &self.function().arch())
            .field("instruction_count", &self.instruction_count())
            .field("expression_count", &self.expression_count())
            .field("root", &self.root())
            .field("root", &self.root())
            .finish()
    }
}

unsafe impl Send for HighLevelILFunction {}
unsafe impl Sync for HighLevelILFunction {}

impl Eq for HighLevelILFunction {}
impl PartialEq for HighLevelILFunction {
    fn eq(&self, rhs: &Self) -> bool {
        self.function().eq(&rhs.function())
    }
}

impl Hash for HighLevelILFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.function().hash(state)
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
