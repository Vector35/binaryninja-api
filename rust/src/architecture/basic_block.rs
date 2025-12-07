use crate::architecture::{CoreArchitecture, IndirectBranchInfo};
use crate::basic_block::BasicBlock;
use crate::function::{Function, Location, NativeBlock};
use crate::rc::Ref;
use binaryninjacore_sys::*;
use std::collections::{HashMap, HashSet};

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

        let indirect_branches = (0..ctx_ref.indirectBranchesCount)
            .map(|i| {
                let raw: BNIndirectBranchInfo =
                    unsafe { std::ptr::read(ctx_ref.indirectBranches.add(i)) };
                IndirectBranchInfo::from(raw)
            })
            .collect::<Vec<_>>();

        let indirect_no_return_calls = (0..ctx_ref.indirectNoReturnCallsCount)
            .map(|i| {
                let raw = unsafe { std::ptr::read(ctx_ref.indirectNoReturnCalls.add(i)) };
                Location::from(raw)
            })
            .collect::<HashSet<_>>();

        let contextual_returns = (0..ctx_ref.contextualFunctionReturnCount)
            .map(|i| {
                let loc = unsafe {
                    let raw = std::ptr::read(ctx_ref.contextualFunctionReturnLocations.add(i));
                    Location::from(raw)
                };
                let val = unsafe { *ctx_ref.contextualFunctionReturnValues.add(i) };
                (loc, val)
            })
            .collect::<HashMap<_, _>>();

        let direct_code_references = (0..ctx_ref.directRefCount)
            .map(|i| {
                let src = unsafe {
                    let raw = std::ptr::read(ctx_ref.directRefSources.add(i));
                    Location::from(raw)
                };
                let tgt = unsafe { *ctx_ref.directRefTargets.add(i) };
                (tgt, src)
            })
            .collect::<HashMap<_, _>>();

        let direct_no_return_calls = (0..ctx_ref.directNoReturnCallsCount)
            .map(|i| {
                let raw = unsafe { std::ptr::read(ctx_ref.directNoReturnCalls.add(i)) };
                Location::from(raw)
            })
            .collect::<HashSet<_>>();

        let halted_disassembly_addresses = (0..ctx_ref.haltedDisassemblyAddressesCount)
            .map(|i| {
                let raw = unsafe { std::ptr::read(ctx_ref.haltedDisassemblyAddresses.add(i)) };
                Location::from(raw)
            })
            .collect::<HashSet<_>>();

        let inlined_unresolved_indirect_branches = (0..ctx_ref
            .inlinedUnresolvedIndirectBranchCount)
            .map(|i| {
                let raw =
                    unsafe { std::ptr::read(ctx_ref.inlinedUnresolvedIndirectBranches.add(i)) };
                Location::from(raw)
            })
            .collect::<HashSet<_>>();

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

    pub fn add_contextual_return(&mut self, loc: impl Into<Location>, value: bool) {
        let loc = loc.into();
        if !self.contextual_returns.contains_key(&loc) {
            self.contextual_returns_dirty = true;
        }

        self.contextual_returns.insert(loc, value);
    }

    pub fn add_direct_code_reference(&mut self, target: u64, src: impl Into<Location>) {
        self.direct_code_references
            .entry(target)
            .or_insert(src.into());
    }

    pub fn add_direct_no_return_call(&mut self, loc: impl Into<Location>) {
        self.direct_no_return_calls.insert(loc.into());
    }

    pub fn add_halted_disassembly_address(&mut self, loc: impl Into<Location>) {
        self.halted_disassembly_addresses.insert(loc.into());
    }

    pub fn add_inlined_unresolved_indirect_branch(&mut self, loc: impl Into<Location>) {
        self.inlined_unresolved_indirect_branches.insert(loc.into());
    }

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

    pub fn add_basic_block(&self, block: Ref<BasicBlock<NativeBlock>>) {
        unsafe {
            BNAnalyzeBasicBlocksContextAddBasicBlockToFunction(self.handle, block.handle);
        }
    }

    pub fn add_temp_outgoing_reference(&self, target: &Function) {
        unsafe {
            BNAnalyzeBasicBlocksContextAddTempReference(self.handle, target.handle);
        }
    }

    pub fn finalize(&mut self) {
        if !self.direct_code_references.is_empty() {
            let total = self.direct_code_references.len();
            let mut sources: Vec<BNArchitectureAndAddress> = Vec::with_capacity(total);
            let mut targets: Vec<u64> = Vec::with_capacity(total);
            for (target, src) in &self.direct_code_references {
                sources.push(BNArchitectureAndAddress::from(src));
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

        if !self.direct_no_return_calls.is_empty() {
            let total = self.direct_no_return_calls.len();
            let mut locations: Vec<BNArchitectureAndAddress> = Vec::with_capacity(total);
            for loc in &self.direct_no_return_calls {
                locations.push(BNArchitectureAndAddress::from(loc));
            }
            unsafe {
                BNAnalyzeBasicBlocksContextSetDirectNoReturnCalls(
                    self.handle,
                    locations.as_mut_ptr(),
                    total,
                );
            }
        }

        if !self.halted_disassembly_addresses.is_empty() {
            let total = self.halted_disassembly_addresses.len();
            let mut locations: Vec<BNArchitectureAndAddress> = Vec::with_capacity(total);
            for loc in &self.halted_disassembly_addresses {
                locations.push(BNArchitectureAndAddress::from(loc));
            }
            unsafe {
                BNAnalyzeBasicBlocksContextSetHaltedDisassemblyAddresses(
                    self.handle,
                    locations.as_mut_ptr(),
                    total,
                );
            }
        }

        if !self.inlined_unresolved_indirect_branches.is_empty() {
            let total = self.inlined_unresolved_indirect_branches.len();
            let mut locations: Vec<BNArchitectureAndAddress> = Vec::with_capacity(total);
            for loc in &self.inlined_unresolved_indirect_branches {
                locations.push(BNArchitectureAndAddress::from(loc));
            }
            unsafe {
                BNAnalyzeBasicBlocksContextSetInlinedUnresolvedIndirectBranches(
                    self.handle,
                    locations.as_mut_ptr(),
                    total,
                );
            }
        }

        unsafe {
            (*self.handle).maxSizeReached = self.max_size_reached;
        }

        if self.contextual_returns_dirty {
            let total = self.contextual_returns.len();
            let mut locations: Vec<BNArchitectureAndAddress> = Vec::with_capacity(total);
            let mut values: Vec<bool> = Vec::with_capacity(total);
            for (loc, value) in &self.contextual_returns {
                locations.push(BNArchitectureAndAddress::from(loc));
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

        unsafe { BNAnalyzeBasicBlocksContextFinalize(self.handle) };
    }
}
