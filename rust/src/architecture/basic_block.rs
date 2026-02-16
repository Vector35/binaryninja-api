use crate::architecture::{ArchitectureWithFunctionContext, CoreArchitecture, IndirectBranchInfo};
use crate::basic_block::BasicBlock;
use crate::function::{Function, Location, NativeBlock};
use crate::rc::Ref;
use binaryninjacore_sys::*;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

pub struct BasicBlockAnalysisContext {
    pub(crate) handle: *mut BNBasicBlockAnalysisContext,
    contextual_returns_dirty: bool,

    // In
    pub indirect_branches: Vec<IndirectBranchInfo>,
    pub indirect_no_return_calls: HashSet<Location>,
    pub analysis_skip_override: BNFunctionAnalysisSkipOverride,
    pub guided_analysis_mode: bool,
    pub trigger_guided_on_invalid_instruction: bool,
    pub translate_tail_calls: bool,
    pub disallow_branch_to_string: bool,
    pub max_function_size: u64,

    // In/Out
    pub max_size_reached: bool,
    contextual_returns: HashMap<Location, bool>,

    // Out
    direct_code_references: HashMap<u64, Location>,
    direct_no_return_calls: HashSet<Location>,
    halted_disassembly_addresses: HashSet<Location>,
    inlined_unresolved_indirect_branches: HashSet<Location>,
}

impl BasicBlockAnalysisContext {
    pub unsafe fn from_raw(handle: *mut BNBasicBlockAnalysisContext) -> Self {
        debug_assert!(!handle.is_null());

        let ctx_ref = &*handle;

        let raw_indirect_branches: &[BNIndirectBranchInfo] =
            std::slice::from_raw_parts(ctx_ref.indirectBranches, ctx_ref.indirectBranchesCount);
        let indirect_branches: Vec<IndirectBranchInfo> = raw_indirect_branches
            .iter()
            .map(IndirectBranchInfo::from)
            .collect();

        let raw_indirect_no_return_calls: &[BNArchitectureAndAddress] = std::slice::from_raw_parts(
            ctx_ref.indirectNoReturnCalls,
            ctx_ref.indirectNoReturnCallsCount,
        );
        let indirect_no_return_calls: HashSet<Location> = raw_indirect_no_return_calls
            .iter()
            .map(Location::from)
            .collect();

        let raw_contextual_return_locs: &[BNArchitectureAndAddress] = unsafe {
            std::slice::from_raw_parts(
                ctx_ref.contextualFunctionReturnLocations,
                ctx_ref.contextualFunctionReturnCount,
            )
        };
        let raw_contextual_return_vals: &[bool] = unsafe {
            std::slice::from_raw_parts(
                ctx_ref.contextualFunctionReturnValues,
                ctx_ref.contextualFunctionReturnCount,
            )
        };
        let contextual_returns: HashMap<Location, bool> = raw_contextual_return_locs
            .iter()
            .map(Location::from)
            .zip(raw_contextual_return_vals.iter().copied())
            .collect();

        // The lists below this are out params and are possibly not initialized.
        let raw_direct_ref_sources: &[BNArchitectureAndAddress] = match ctx_ref
            .directRefSources
            .is_null()
        {
            true => &[],
            false => std::slice::from_raw_parts(ctx_ref.directRefSources, ctx_ref.directRefCount),
        };
        let raw_direct_ref_targets: &[u64] = match ctx_ref.directRefTargets.is_null() {
            true => &[],
            false => std::slice::from_raw_parts(ctx_ref.directRefTargets, ctx_ref.directRefCount),
        };
        let direct_code_references: HashMap<u64, Location> = raw_direct_ref_targets
            .iter()
            .copied()
            .zip(raw_direct_ref_sources.iter().map(Location::from))
            .collect();

        let raw_direct_no_return_calls: &[BNArchitectureAndAddress] =
            match ctx_ref.directNoReturnCalls.is_null() {
                true => &[],
                false => std::slice::from_raw_parts(
                    ctx_ref.directNoReturnCalls,
                    ctx_ref.directNoReturnCallsCount,
                ),
            };
        let direct_no_return_calls: HashSet<Location> = raw_direct_no_return_calls
            .iter()
            .map(Location::from)
            .collect();

        let raw_halted_disassembly_address: &[BNArchitectureAndAddress] =
            match ctx_ref.haltedDisassemblyAddresses.is_null() {
                true => &[],
                false => std::slice::from_raw_parts(
                    ctx_ref.haltedDisassemblyAddresses,
                    ctx_ref.haltedDisassemblyAddressesCount,
                ),
            };
        let halted_disassembly_addresses: HashSet<Location> = raw_halted_disassembly_address
            .iter()
            .map(Location::from)
            .collect();

        let raw_inlined_unresolved_indirect_branches: &[BNArchitectureAndAddress] =
            match ctx_ref.inlinedUnresolvedIndirectBranches.is_null() {
                true => &[],
                false => std::slice::from_raw_parts(
                    ctx_ref.inlinedUnresolvedIndirectBranches,
                    ctx_ref.inlinedUnresolvedIndirectBranchCount,
                ),
            };
        let inlined_unresolved_indirect_branches: HashSet<Location> =
            raw_inlined_unresolved_indirect_branches
                .iter()
                .map(Location::from)
                .collect();

        BasicBlockAnalysisContext {
            handle,
            contextual_returns_dirty: false,
            indirect_branches,
            indirect_no_return_calls,
            analysis_skip_override: ctx_ref.analysisSkipOverride,
            guided_analysis_mode: ctx_ref.guidedAnalysisMode,
            trigger_guided_on_invalid_instruction: ctx_ref.triggerGuidedOnInvalidInstruction,
            translate_tail_calls: ctx_ref.translateTailCalls,
            disallow_branch_to_string: ctx_ref.disallowBranchToString,
            max_function_size: ctx_ref.maxFunctionSize,
            max_size_reached: ctx_ref.maxSizeReached,
            contextual_returns,
            direct_code_references,
            direct_no_return_calls,
            halted_disassembly_addresses,
            inlined_unresolved_indirect_branches,
        }
    }

    /// Adds a contextual function return location and its value to the current function.
    pub fn add_contextual_return(&mut self, loc: impl Into<Location>, value: bool) {
        let loc = loc.into();
        if !self.contextual_returns.contains_key(&loc) {
            self.contextual_returns_dirty = true;
        }

        self.contextual_returns.insert(loc, value);
    }

    /// Adds a direct code reference to the current function.
    pub fn add_direct_code_reference(&mut self, target: u64, src: impl Into<Location>) {
        self.direct_code_references
            .entry(target)
            .or_insert(src.into());
    }

    /// Adds a direct no-return call location to the current function.
    pub fn add_direct_no_return_call(&mut self, loc: impl Into<Location>) {
        self.direct_no_return_calls.insert(loc.into());
    }

    /// Adds an address to the set of halted disassembly addresses.
    pub fn add_halted_disassembly_address(&mut self, loc: impl Into<Location>) {
        self.halted_disassembly_addresses.insert(loc.into());
    }

    pub fn add_inlined_unresolved_indirect_branch(&mut self, loc: impl Into<Location>) {
        self.inlined_unresolved_indirect_branches.insert(loc.into());
    }

    pub fn set_function_arch_context<A: ArchitectureWithFunctionContext>(
        &mut self,
        _arch: &A,
        context: Box<A::FunctionArchContext>,
    ) -> bool {
        unsafe {
            if !(*self.handle).functionArchContext.is_null() {
                return false;
            }
            (*self.handle).functionArchContext = Box::into_raw(context) as *mut std::ffi::c_void;
        }
        true
    }

    pub fn get_function_arch_context<A: ArchitectureWithFunctionContext>(
        &self,
        _arch: &A,
    ) -> Option<&A::FunctionArchContext> {
        unsafe {
            let ptr = (*self.handle).functionArchContext;
            if ptr.is_null() {
                None
            } else {
                Some(&*(ptr as *const A::FunctionArchContext))
            }
        }
    }

    /// Creates a new [`BasicBlock`] at the specified address for the given [`CoreArchitecture`].
    ///
    /// After creating, you can add using [`BasicBlockAnalysisContext::add_basic_block`].
    pub fn create_basic_block(
        &self,
        arch: CoreArchitecture,
        start: u64,
    ) -> Option<Ref<BasicBlock<NativeBlock>>> {
        let raw_block =
            unsafe { BNAnalyzeBasicBlocksContextCreateBasicBlock(self.handle, arch.handle, start) };

        if raw_block.is_null() {
            return None;
        }

        unsafe { Some(BasicBlock::ref_from_raw(raw_block, NativeBlock::new())) }
    }

    /// Adds a [`BasicBlock`] to the current function.
    ///
    /// You can create a [`BasicBlock`] via [`BasicBlockAnalysisContext::create_basic_block`].
    pub fn add_basic_block(&self, block: Ref<BasicBlock<NativeBlock>>) {
        unsafe {
            BNAnalyzeBasicBlocksContextAddBasicBlockToFunction(self.handle, block.handle);
        }
    }

    /// Adds a temporary outgoing reference to the specified function.
    pub fn add_temp_outgoing_reference(&self, target: &Function) {
        unsafe {
            BNAnalyzeBasicBlocksContextAddTempReference(self.handle, target.handle);
        }
    }

    /// To be called before finalizing the basic block analysis.
    fn update_direct_code_references(&mut self) {
        let total = self.direct_code_references.len();
        let mut sources: Vec<BNArchitectureAndAddress> = Vec::with_capacity(total);
        let mut targets: Vec<u64> = Vec::with_capacity(total);
        for (target, src) in &self.direct_code_references {
            sources.push(src.into());
            targets.push(*target);
        }
        unsafe {
            BNAnalyzeBasicBlocksContextSetDirectCodeReferences(
                self.handle,
                sources.as_mut_ptr(),
                targets.as_mut_ptr(),
                total,
            );
        }
    }

    /// To be called before finalizing the basic block analysis.
    fn update_direct_no_return_calls(&mut self) {
        let total = self.direct_no_return_calls.len();
        let mut raw_locations: Vec<_> = self
            .direct_no_return_calls
            .iter()
            .map(BNArchitectureAndAddress::from)
            .collect();
        unsafe {
            BNAnalyzeBasicBlocksContextSetDirectNoReturnCalls(
                self.handle,
                raw_locations.as_mut_ptr(),
                total,
            );
        }
    }

    /// To be called before finalizing the basic block analysis.
    fn update_inlined_unresolved_indirect_branches(&mut self) {
        let total = self.inlined_unresolved_indirect_branches.len();
        let mut raw_locations: Vec<_> = self
            .inlined_unresolved_indirect_branches
            .iter()
            .map(BNArchitectureAndAddress::from)
            .collect();
        unsafe {
            BNAnalyzeBasicBlocksContextSetInlinedUnresolvedIndirectBranches(
                self.handle,
                raw_locations.as_mut_ptr(),
                total,
            );
        }
    }

    /// To be called before finalizing the basic block analysis.
    fn update_halted_disassembly_addresses(&mut self) {
        let total = self.halted_disassembly_addresses.len();
        let mut raw_locations: Vec<_> = self
            .halted_disassembly_addresses
            .iter()
            .map(BNArchitectureAndAddress::from)
            .collect();
        unsafe {
            BNAnalyzeBasicBlocksContextSetHaltedDisassemblyAddresses(
                self.handle,
                raw_locations.as_mut_ptr(),
                total,
            );
        }
    }

    /// To be called before finalizing the basic block analysis.
    fn update_contextual_returns(&mut self) {
        let total = self.contextual_returns.len();
        let mut locations: Vec<BNArchitectureAndAddress> = Vec::with_capacity(total);
        let mut values: Vec<bool> = Vec::with_capacity(total);
        for (loc, value) in &self.contextual_returns {
            locations.push(loc.into());
            values.push(*value);
        }
        unsafe {
            BNAnalyzeBasicBlocksContextSetContextualFunctionReturns(
                self.handle,
                locations.as_mut_ptr(),
                values.as_mut_ptr(),
                total,
            );
        }
    }

    /// Finalizes the function's basic block analysis.
    pub fn finalize(&mut self) {
        if !self.direct_code_references.is_empty() {
            self.update_direct_code_references();
        }

        if !self.direct_no_return_calls.is_empty() {
            self.update_direct_no_return_calls();
        }

        if !self.halted_disassembly_addresses.is_empty() {
            self.update_halted_disassembly_addresses();
        }

        if !self.inlined_unresolved_indirect_branches.is_empty() {
            self.update_inlined_unresolved_indirect_branches();
        }

        unsafe {
            (*self.handle).maxSizeReached = self.max_size_reached;
        }

        if self.contextual_returns_dirty {
            self.update_contextual_returns();
        }
    }
}

impl Debug for BasicBlockAnalysisContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicBlockAnalysisContext")
            .field("indirect_branches", &self.indirect_branches)
            .field("indirect_no_return_calls", &self.indirect_no_return_calls)
            .field("analysis_skip_override", &self.analysis_skip_override)
            .field("translate_tail_calls", &self.translate_tail_calls)
            .field("disallow_branch_to_string", &self.disallow_branch_to_string)
            .field("max_function_size", &self.max_function_size)
            .field("guided_analysis_mode", &self.guided_analysis_mode)
            .field(
                "trigger_guided_on_invalid_instruction",
                &self.trigger_guided_on_invalid_instruction,
            )
            .field("max_size_reached", &self.max_size_reached)
            .field("contextual_returns", &self.contextual_returns)
            .field("direct_code_references", &self.direct_code_references)
            .field("direct_no_return_calls", &self.direct_no_return_calls)
            .field(
                "halted_disassembly_addresses",
                &self.halted_disassembly_addresses,
            )
            .finish()
    }
}
