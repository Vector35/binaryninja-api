use binaryninjacore_sys::*;
use std::ffi::c_char;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};

use super::{MediumLevelILBlock, MediumLevelILInstruction, MediumLevelInstructionIndex};
use crate::architecture::CoreArchitecture;
use crate::basic_block::BasicBlock;
use crate::confidence::Conf;
use crate::disassembly::DisassemblySettings;
use crate::flowgraph::FlowGraph;
use crate::function::{Function, Location};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref, RefCountable};
use crate::string::BnStrCompatible;
use crate::types::Type;
use crate::variable::{PossibleValueSet, RegisterValue, SSAVariable, UserVariableValue, Variable};

// TODO: Does this belong here?
pub use binaryninjacore_sys::BNFunctionGraphType as FunctionGraphType;

pub struct MediumLevelILFunction {
    pub(crate) handle: *mut BNMediumLevelILFunction,
}

impl MediumLevelILFunction {
    pub(crate) unsafe fn from_raw(handle: *mut BNMediumLevelILFunction) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNMediumLevelILFunction) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self::from_raw(handle))
    }

    pub fn instruction_at<L: Into<Location>>(&self, loc: L) -> Option<MediumLevelILInstruction> {
        Some(MediumLevelILInstruction::new(
            self.to_owned(),
            self.instruction_index_at(loc)?,
        ))
    }

    pub fn instruction_index_at<L: Into<Location>>(
        &self,
        loc: L,
    ) -> Option<MediumLevelInstructionIndex> {
        let loc: Location = loc.into();
        let arch = loc
            .arch
            .map(|a| a.handle)
            .unwrap_or_else(std::ptr::null_mut);
        let instr_idx = unsafe { BNMediumLevelILGetInstructionStart(self.handle, arch, loc.addr) };
        // `instr_idx` will equal self.instruction_count() if the instruction is not valid.
        if instr_idx >= self.instruction_count() {
            None
        } else {
            Some(MediumLevelInstructionIndex(instr_idx))
        }
    }

    pub fn instruction_from_index(
        &self,
        index: MediumLevelInstructionIndex,
    ) -> Option<MediumLevelILInstruction> {
        if index.0 >= self.instruction_count() {
            None
        } else {
            Some(MediumLevelILInstruction::new(self.to_owned(), index))
        }
    }

    pub fn instruction_from_expr_index(
        &self,
        expr_index: MediumLevelInstructionIndex,
    ) -> Option<MediumLevelILInstruction> {
        if expr_index.0 >= self.expression_count() {
            None
        } else {
            Some(MediumLevelILInstruction::new_expr(
                self.to_owned(),
                expr_index,
            ))
        }
    }

    pub fn instruction_count(&self) -> usize {
        unsafe { BNGetMediumLevelILInstructionCount(self.handle) }
    }

    pub fn expression_count(&self) -> usize {
        unsafe { BNGetMediumLevelILExprCount(self.handle) }
    }

    pub fn ssa_form(&self) -> MediumLevelILFunction {
        let ssa = unsafe { BNGetMediumLevelILSSAForm(self.handle) };
        assert!(!ssa.is_null());
        MediumLevelILFunction { handle: ssa }
    }

    pub fn function(&self) -> Ref<Function> {
        unsafe {
            let func = BNGetMediumLevelILOwnerFunction(self.handle);
            Function::ref_from_raw(func)
        }
    }

    pub fn basic_blocks(&self) -> Array<BasicBlock<MediumLevelILBlock>> {
        let mut count = 0;
        let blocks = unsafe { BNGetMediumLevelILBasicBlockList(self.handle, &mut count) };
        let context = MediumLevelILBlock {
            function: self.to_owned(),
        };
        unsafe { Array::new(blocks, count, context) }
    }

    pub fn var_definitions(&self, var: &Variable) -> Array<MediumLevelILInstruction> {
        let mut count = 0;
        let raw_var = BNVariable::from(var);
        let raw_instr_idxs =
            unsafe { BNGetMediumLevelILVariableDefinitions(self.handle, &raw_var, &mut count) };
        assert!(!raw_instr_idxs.is_null());
        unsafe { Array::new(raw_instr_idxs, count, self.to_owned()) }
    }

    pub fn create_user_stack_var<'a, S: BnStrCompatible, C: Into<Conf<&'a Type>>>(
        self,
        offset: i64,
        var_type: C,
        name: S,
    ) {
        let mut owned_raw_var_ty = Conf::<&Type>::into_raw(var_type.into());
        let name = name.into_bytes_with_nul();
        unsafe {
            BNCreateUserStackVariable(
                self.function().handle,
                offset,
                &mut owned_raw_var_ty,
                name.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    pub fn delete_user_stack_var(self, offset: i64) {
        unsafe { BNDeleteUserStackVariable(self.function().handle, offset) }
    }

    pub fn create_user_var<'a, S: BnStrCompatible, C: Into<Conf<&'a Type>>>(
        &self,
        var: &Variable,
        var_type: C,
        name: S,
        ignore_disjoint_uses: bool,
    ) {
        let raw_var = BNVariable::from(var);
        let mut owned_raw_var_ty = Conf::<&Type>::into_raw(var_type.into());
        let name = name.into_bytes_with_nul();
        unsafe {
            BNCreateUserVariable(
                self.function().handle,
                &raw_var,
                &mut owned_raw_var_ty,
                name.as_ref().as_ptr() as *const _,
                ignore_disjoint_uses,
            )
        }
    }

    pub fn delete_user_var(&self, var: &Variable) {
        let raw_var = BNVariable::from(var);
        unsafe { BNDeleteUserVariable(self.function().handle, &raw_var) }
    }

    pub fn is_var_user_defined(&self, var: &Variable) -> bool {
        let raw_var = BNVariable::from(var);
        unsafe { BNIsVariableUserDefined(self.function().handle, &raw_var) }
    }

    /// Allows the user to specify a PossibleValueSet value for an MLIL
    /// variable at its definition site.
    ///
    /// .. warning:: Setting the variable value, triggers a reanalysis of the
    /// function and allows the dataflow to compute and propagate values which
    /// depend on the current variable. This implies that branch conditions
    /// whose values can be determined statically will be computed, leading to
    /// potential branch elimination at the HLIL layer.
    ///
    /// * `var` - Variable for which the value is to be set
    /// * `addr` - Address of the definition site of the variable
    /// * `value` - Informed value of the variable
    ///
    /// # Example
    /// ```no_run
    /// # use binaryninja::medium_level_il::MediumLevelILFunction;
    /// # use binaryninja::variable::PossibleValueSet;
    /// # let mlil_fun: MediumLevelILFunction = todo!();
    /// let user_var_val = mlil_fun.user_var_values().iter().next().unwrap();
    /// let def_address = user_var_val.def_site.addr;
    /// let var_value = PossibleValueSet::ConstantValue { value: 5 };
    /// mlil_fun
    ///     .set_user_var_value(&user_var_val.variable, def_address, var_value)
    ///     .unwrap();
    /// ```
    pub fn set_user_var_value(
        &self,
        var: &Variable,
        addr: u64,
        value: PossibleValueSet,
    ) -> Result<(), ()> {
        let Some(_def_site) = self
            .var_definitions(var)
            .iter()
            .find(|def| def.address == addr)
        else {
            // Error "No definition for Variable found at given address"
            return Err(());
        };
        let function = self.function();
        let def_site = BNArchitectureAndAddress {
            arch: function.arch().handle,
            address: addr,
        };
        let raw_var = BNVariable::from(var);
        let raw_value = PossibleValueSet::into_raw(value);
        unsafe { BNSetUserVariableValue(function.handle, &raw_var, &def_site, &raw_value) }
        PossibleValueSet::free_owned_raw(raw_value);
        Ok(())
    }

    /// Clears a previously defined user variable value.
    ///
    /// * `var` - Variable for which the value was informed
    /// * `def_addr` - Address of the definition site of the variable
    pub fn clear_user_var_value(&self, var: &Variable, addr: u64) -> Result<(), ()> {
        let Some(_var_def) = self
            .var_definitions(var)
            .iter()
            .find(|site| site.address == addr)
        else {
            //error "Could not get definition for Variable"
            return Err(());
        };

        let function = self.function();
        let raw_var = BNVariable::from(var);
        let def_site = BNArchitectureAndAddress {
            arch: function.arch().handle,
            address: addr,
        };

        unsafe { BNClearUserVariableValue(function.handle, &raw_var, &def_site) };
        Ok(())
    }

    /// Returns a map of current defined user variable values.
    /// Returns a Map of user current defined user variable values and their definition sites.
    pub fn user_var_values(&self) -> Array<UserVariableValue> {
        let mut count = 0;
        let function = self.function();
        let var_values = unsafe { BNGetAllUserVariableValues(function.handle, &mut count) };
        assert!(!var_values.is_null());
        unsafe { Array::new(var_values, count, ()) }
    }

    /// Clear all user defined variable values.
    pub fn clear_user_var_values(&self) -> Result<(), ()> {
        for user_var_val in &self.user_var_values() {
            self.clear_user_var_value(&user_var_val.variable, user_var_val.def_site.addr)?;
        }
        Ok(())
    }

    pub fn create_auto_stack_var<'a, T: Into<Conf<&'a Type>>, S: BnStrCompatible>(
        &self,
        offset: i64,
        var_type: T,
        name: S,
    ) {
        let mut owned_raw_var_ty = Conf::<&Type>::into_raw(var_type.into());
        let name = name.into_bytes_with_nul();
        let name_c_str = name.as_ref();
        unsafe {
            BNCreateAutoStackVariable(
                self.function().handle,
                offset,
                &mut owned_raw_var_ty,
                name_c_str.as_ptr() as *const c_char,
            )
        }
    }

    pub fn delete_auto_stack_var(&self, offset: i64) {
        unsafe { BNDeleteAutoStackVariable(self.function().handle, offset) }
    }

    pub fn create_auto_var<'a, S: BnStrCompatible, C: Into<Conf<&'a Type>>>(
        &self,
        var: &Variable,
        var_type: C,
        name: S,
        ignore_disjoint_uses: bool,
    ) {
        let raw_var = BNVariable::from(var);
        let mut owned_raw_var_ty = Conf::<&Type>::into_raw(var_type.into());
        let name = name.into_bytes_with_nul();
        let name_c_str = name.as_ref();
        unsafe {
            BNCreateAutoVariable(
                self.function().handle,
                &raw_var,
                &mut owned_raw_var_ty,
                name_c_str.as_ptr() as *const c_char,
                ignore_disjoint_uses,
            )
        }
    }

    /// Returns a list of ILReferenceSource objects (IL xrefs or cross-references)
    /// that reference the given variable. The variable is a local variable that can be either on the stack,
    /// in a register, or in a flag.
    /// This function is related to get_hlil_var_refs(), which returns variable references collected
    /// from HLIL. The two can be different in several cases, e.g., multiple variables in MLIL can be merged
    /// into a single variable in HLIL.
    ///
    /// * `var` - Variable for which to query the xref
    ///
    /// # Example
    /// ```no_run
    /// # use binaryninja::medium_level_il::MediumLevelILFunction;
    /// # use binaryninja::variable::Variable;
    /// # let mlil_fun: MediumLevelILFunction = todo!();
    /// # let mlil_var: Variable = todo!();
    /// let instr_idx = mlil_fun.var_refs(&mlil_var).get(0).expr_idx;
    /// ```
    pub fn var_refs(&self, var: &Variable) -> Array<ILReferenceSource> {
        let mut count = 0;
        let mut raw_var = BNVariable::from(var);
        let refs = unsafe {
            BNGetMediumLevelILVariableReferences(self.function().handle, &mut raw_var, &mut count)
        };
        assert!(!refs.is_null());
        unsafe { Array::new(refs, count, ()) }
    }

    /// Retrieves variable references from a specified location or range within a medium-level IL function.
    ///
    /// Passing in a `length` will query a range for variable references, instead of just the address
    /// specified in `location`.
    pub fn var_refs_from(
        &self,
        location: impl Into<Location>,
        length: Option<u64>,
    ) -> Array<VariableReferenceSource> {
        let location = location.into();
        let raw_arch = location
            .arch
            .map(|a| a.handle)
            .unwrap_or(std::ptr::null_mut());
        let function = self.function();
        let mut count = 0;

        let refs = if let Some(length) = length {
            unsafe {
                BNGetMediumLevelILVariableReferencesInRange(
                    function.handle,
                    raw_arch,
                    location.addr,
                    length,
                    &mut count,
                )
            }
        } else {
            unsafe {
                BNGetMediumLevelILVariableReferencesFrom(
                    function.handle,
                    raw_arch,
                    location.addr,
                    &mut count,
                )
            }
        };
        assert!(!refs.is_null());
        unsafe { Array::new(refs, count, ()) }
    }

    // TODO: Rename to `current_location`?
    /// Current IL Address
    pub fn current_address(&self) -> Location {
        let addr = unsafe { BNMediumLevelILGetCurrentAddress(self.handle) };
        Location::from(addr)
    }

    // TODO: Rename to `set_current_location`?
    /// Set the current IL Address
    pub fn set_current_address(&self, location: impl Into<Location>) {
        let location = location.into();
        let arch = location
            .arch
            .map(|a| a.handle)
            .unwrap_or(std::ptr::null_mut());
        unsafe { BNMediumLevelILSetCurrentAddress(self.handle, arch, location.addr) }
    }

    /// Returns the [`BasicBlock`] at the given instruction `index`.
    ///
    /// You can also retrieve this using [`MediumLevelILInstruction::basic_block`].
    pub fn basic_block_containing_index(
        &self,
        index: MediumLevelInstructionIndex,
    ) -> Option<Ref<BasicBlock<MediumLevelILBlock>>> {
        let context = MediumLevelILBlock {
            function: self.to_owned(),
        };
        // TODO: If we can guarantee self.index is valid we can omit the wrapped Option.
        let basic_block_ptr =
            unsafe { BNGetMediumLevelILBasicBlockForInstruction(self.handle, index.0) };
        match basic_block_ptr.is_null() {
            false => Some(unsafe { BasicBlock::ref_from_raw(basic_block_ptr, context) }),
            true => None,
        }
    }

    /// Ends the function and computes the list of basic blocks.
    ///
    /// NOTE: This should be called after updating MLIL.
    pub fn finalize(&self) {
        unsafe { BNFinalizeMediumLevelILFunction(self.handle) }
    }

    /// Generate SSA form given the current MLIL.
    ///
    /// NOTE: This should be called after updating MLIL.
    ///
    /// * `analyze_conditionals` - whether to analyze conditionals
    /// * `handle_aliases` - whether to handle aliases
    /// * `non_aliased_vars` - optional list of variables known to be not aliased
    /// * `aliased_vars` - optional list of variables known to be aliased
    pub fn generate_ssa_form(
        &self,
        analyze_conditionals: bool,
        handle_aliases: bool,
        non_aliased_vars: impl IntoIterator<Item = Variable>,
        aliased_vars: impl IntoIterator<Item = Variable>,
    ) {
        let raw_non_aliased_vars: Vec<BNVariable> =
            non_aliased_vars.into_iter().map(Into::into).collect();
        let raw_aliased_vars: Vec<BNVariable> = aliased_vars.into_iter().map(Into::into).collect();
        unsafe {
            BNGenerateMediumLevelILSSAForm(
                self.handle,
                analyze_conditionals,
                handle_aliases,
                raw_non_aliased_vars.as_ptr() as *mut _,
                raw_non_aliased_vars.len(),
                raw_aliased_vars.as_ptr() as *mut _,
                raw_aliased_vars.len(),
            )
        }
    }

    /// Gets the instruction that contains the given SSA variable's definition.
    ///
    /// Since SSA variables can only be defined once, this will return the single instruction where that occurs.
    /// For SSA variable version 0s, which don't have definitions, this will return `None` instead.
    pub fn ssa_variable_definition(
        &self,
        ssa_variable: &SSAVariable,
    ) -> Option<MediumLevelILInstruction> {
        let raw_var = BNVariable::from(ssa_variable.variable);
        let result = unsafe {
            BNGetMediumLevelILSSAVarDefinition(self.handle, &raw_var, ssa_variable.version)
        };
        // TODO: Does this return the expression or instruction index? Also we dont diff and this prob doesnt work.
        self.instruction_from_index(MediumLevelInstructionIndex(result))
    }

    pub fn ssa_memory_definition(&self, version: usize) -> Option<MediumLevelILInstruction> {
        let result = unsafe { BNGetMediumLevelILSSAMemoryDefinition(self.handle, version) };
        // TODO: Does this return the expression or instruction index? Also we dont diff and this prob doesnt work.
        self.instruction_from_index(MediumLevelInstructionIndex(result))
    }

    /// Gets all the instructions that use the given SSA variable.
    pub fn ssa_variable_uses(&self, ssa_variable: &SSAVariable) -> Array<MediumLevelILInstruction> {
        let mut count = 0;
        let raw_var = BNVariable::from(ssa_variable.variable);
        let uses = unsafe {
            BNGetMediumLevelILSSAVarUses(self.handle, &raw_var, ssa_variable.version, &mut count)
        };
        assert!(!uses.is_null());
        unsafe { Array::new(uses, count, self.to_owned()) }
    }

    pub fn ssa_memory_uses(&self, version: usize) -> Array<MediumLevelILInstruction> {
        let mut count = 0;
        let uses = unsafe { BNGetMediumLevelILSSAMemoryUses(self.handle, version, &mut count) };
        assert!(!uses.is_null());
        unsafe { Array::new(uses, count, self.to_owned()) }
    }

    /// Determines if `variable` is live at any point in the function
    pub fn is_ssa_variable_live(&self, ssa_variable: &SSAVariable) -> bool {
        let raw_var = BNVariable::from(ssa_variable.variable);
        unsafe { BNIsMediumLevelILSSAVarLive(self.handle, &raw_var, ssa_variable.version) }
    }

    pub fn variable_definitions(&self, variable: &Variable) -> Array<MediumLevelILInstruction> {
        let mut count = 0;
        let raw_var = BNVariable::from(variable);
        let defs =
            unsafe { BNGetMediumLevelILVariableDefinitions(self.handle, &raw_var, &mut count) };
        unsafe { Array::new(defs, count, self.to_owned()) }
    }

    pub fn variable_uses(&self, variable: &Variable) -> Array<MediumLevelILInstruction> {
        let mut count = 0;
        let raw_var = BNVariable::from(variable);
        let uses = unsafe { BNGetMediumLevelILVariableUses(self.handle, &raw_var, &mut count) };
        unsafe { Array::new(uses, count, self.to_owned()) }
    }

    /// Computes the list of instructions for which `var` is live.
    /// If `include_last_use` is false, the last use of the variable will not be included in the
    /// list (this allows for easier computation of overlaps in liveness between two variables).
    /// If the variable is never used, this function will return an empty list.
    ///
    /// `var` - the variable to query
    /// `include_last_use` - whether to include the last use of the variable in the list of instructions
    pub fn live_instruction_for_variable(
        &self,
        variable: &Variable,
        include_last_user: bool,
    ) -> Array<MediumLevelILInstruction> {
        let mut count = 0;
        let raw_var = BNVariable::from(variable);
        let uses = unsafe {
            BNGetMediumLevelILLiveInstructionsForVariable(
                self.handle,
                &raw_var,
                include_last_user,
                &mut count,
            )
        };
        unsafe { Array::new(uses, count, self.to_owned()) }
    }

    pub fn ssa_variable_value(&self, ssa_variable: &SSAVariable) -> RegisterValue {
        let raw_var = BNVariable::from(ssa_variable.variable);
        unsafe { BNGetMediumLevelILSSAVarValue(self.handle, &raw_var, ssa_variable.version) }.into()
    }

    pub fn create_graph(&self, settings: Option<DisassemblySettings>) -> Ref<FlowGraph> {
        let settings = settings.map(|x| x.handle).unwrap_or(std::ptr::null_mut());
        let graph = unsafe { BNCreateMediumLevelILFunctionGraph(self.handle, settings) };
        unsafe { FlowGraph::ref_from_raw(graph) }
    }

    /// This gets just the MLIL variables - you may be interested in the union
    /// of [`MediumLevelILFunction::aliased_variables`] and [`Function::parameter_variables`] for
    /// all the variables used in the function
    pub fn variables(&self) -> Array<Variable> {
        let mut count = 0;
        let uses = unsafe { BNGetMediumLevelILVariables(self.handle, &mut count) };
        unsafe { Array::new(uses, count, ()) }
    }

    /// This returns a list of Variables that are taken reference to and used
    /// elsewhere. You may also wish to consider [`MediumLevelILFunction::variables`]
    /// and [`Function::parameter_variables`]
    pub fn aliased_variables(&self) -> Array<Variable> {
        let mut count = 0;
        let uses = unsafe { BNGetMediumLevelILAliasedVariables(self.handle, &mut count) };
        unsafe { Array::new(uses, count, ()) }
    }

    /// This gets the MLIL SSA variables for a given [`Variable`].
    pub fn ssa_variables(&self, variable: &Variable) -> Array<SSAVariable> {
        let mut count = 0;
        let raw_variable = BNVariable::from(variable);
        let versions = unsafe {
            BNGetMediumLevelILVariableSSAVersions(self.handle, &raw_variable, &mut count)
        };
        unsafe { Array::new(versions, count, *variable) }
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

impl Debug for MediumLevelILFunction {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("MediumLevelILFunction")
            .field("arch", &self.function().arch())
            .field("instruction_count", &self.instruction_count())
            .finish()
    }
}

unsafe impl Send for MediumLevelILFunction {}
unsafe impl Sync for MediumLevelILFunction {}

impl Eq for MediumLevelILFunction {}
impl PartialEq for MediumLevelILFunction {
    fn eq(&self, rhs: &Self) -> bool {
        self.function().eq(&rhs.function())
    }
}

impl Hash for MediumLevelILFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.function().hash(state)
    }
}

pub struct ILReferenceSource {
    pub function: Ref<Function>,
    pub arch: CoreArchitecture,
    pub addr: u64,
    pub graph_type: FunctionGraphType,
    pub expr_idx: usize,
}

impl From<BNILReferenceSource> for ILReferenceSource {
    fn from(value: BNILReferenceSource) -> Self {
        Self {
            function: unsafe { Function::ref_from_raw(value.func) },
            arch: unsafe { CoreArchitecture::from_raw(value.arch) },
            addr: value.addr,
            graph_type: value.type_,
            expr_idx: value.exprId,
        }
    }
}

impl From<&BNILReferenceSource> for ILReferenceSource {
    fn from(value: &BNILReferenceSource) -> Self {
        Self {
            function: unsafe { Function::from_raw(value.func).to_owned() },
            arch: unsafe { CoreArchitecture::from_raw(value.arch) },
            addr: value.addr,
            graph_type: value.type_,
            expr_idx: value.exprId,
        }
    }
}

impl CoreArrayProvider for ILReferenceSource {
    type Raw = BNILReferenceSource;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for ILReferenceSource {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeILReferences(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        raw.into()
    }
}

pub struct VariableReferenceSource {
    pub variable: Variable,
    pub source: ILReferenceSource,
}

impl From<BNVariableReferenceSource> for VariableReferenceSource {
    fn from(value: BNVariableReferenceSource) -> Self {
        Self {
            variable: Variable::from(value.var),
            source: value.source.into(),
        }
    }
}

impl From<&BNVariableReferenceSource> for VariableReferenceSource {
    fn from(value: &BNVariableReferenceSource) -> Self {
        Self {
            variable: Variable::from(value.var),
            // TODO: We really need to document this better, or have some other facility for this.
            // NOTE: We take this as a ref to increment the function ref.
            source: ILReferenceSource::from(&value.source),
        }
    }
}

impl CoreArrayProvider for VariableReferenceSource {
    type Raw = BNVariableReferenceSource;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for VariableReferenceSource {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeVariableReferenceSourceList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        raw.into()
    }
}
