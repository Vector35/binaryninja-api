use crate::architecture::{BranchInfo, BranchKind, CoreArchitecture};
use binaryninjacore_sys::*;

/// This is the number of branches that can be specified in an [`InstructionInfo`].
pub const NUM_BRANCH_INFO: usize = 3;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct InstructionInfo {
    pub length: usize,
    // TODO: This field name is really long...
    pub arch_transition_by_target_addr: bool,
    pub delay_slots: u8,
    pub branches: [Option<BranchInfo>; NUM_BRANCH_INFO],
}

impl InstructionInfo {
    // TODO: `new_with_delay_slot`?
    pub fn new(length: usize, delay_slots: u8) -> Self {
        Self {
            length,
            arch_transition_by_target_addr: false,
            delay_slots,
            branches: Default::default(),
        }
    }

    /// Add a branch to this [`InstructionInfo`], maximum of 3 branches may be added (as per [`NUM_BRANCH_INFO`]).
    pub fn add_branch(&mut self, branch_info: impl Into<BranchInfo>) {
        // Will go through each slot and attempt to add the branch info.
        // TODO: Return a result with BranchInfoSlotsFilled error.
        for branch in &mut self.branches {
            if branch.is_none() {
                *branch = Some(branch_info.into());
                return;
            }
        }
    }
}

impl From<BNInstructionInfo> for InstructionInfo {
    fn from(value: BNInstructionInfo) -> Self {
        // TODO: This is quite ugly, but we destructure the branch info so this will have to do.
        let mut branch_info = [None; NUM_BRANCH_INFO];
        #[allow(clippy::needless_range_loop)]
        for i in 0..value.branchCount.min(NUM_BRANCH_INFO) {
            let branch_target = value.branchTarget[i];
            branch_info[i] = Some(BranchInfo {
                kind: match value.branchType[i] {
                    BNBranchType::UnconditionalBranch => BranchKind::Unconditional(branch_target),
                    BNBranchType::FalseBranch => BranchKind::False(branch_target),
                    BNBranchType::TrueBranch => BranchKind::True(branch_target),
                    BNBranchType::CallDestination => BranchKind::Call(branch_target),
                    BNBranchType::FunctionReturn => BranchKind::FunctionReturn,
                    BNBranchType::SystemCall => BranchKind::SystemCall,
                    BNBranchType::IndirectBranch => BranchKind::Indirect,
                    BNBranchType::ExceptionBranch => BranchKind::Exception,
                    BNBranchType::UnresolvedBranch => BranchKind::Unresolved,
                    BNBranchType::UserDefinedBranch => BranchKind::UserDefined,
                },
                arch: if value.branchArch[i].is_null() {
                    None
                } else {
                    Some(unsafe { CoreArchitecture::from_raw(value.branchArch[i]) })
                },
            });
        }
        Self {
            length: value.length,
            arch_transition_by_target_addr: value.archTransitionByTargetAddr,
            delay_slots: value.delaySlots,
            branches: branch_info,
        }
    }
}

impl From<InstructionInfo> for BNInstructionInfo {
    fn from(value: InstructionInfo) -> Self {
        let branch_count = value.branches.into_iter().filter(Option::is_some).count();
        // TODO: This is quite ugly, but we destructure the branch info so this will have to do.
        let branch_info_0 = value.branches[0].unwrap_or_default();
        let branch_info_1 = value.branches[1].unwrap_or_default();
        let branch_info_2 = value.branches[2].unwrap_or_default();
        Self {
            length: value.length,
            branchCount: branch_count,
            archTransitionByTargetAddr: value.arch_transition_by_target_addr,
            delaySlots: value.delay_slots,
            branchType: [
                branch_info_0.into(),
                branch_info_1.into(),
                branch_info_2.into(),
            ],
            branchTarget: [
                branch_info_0.target().unwrap_or_default(),
                branch_info_1.target().unwrap_or_default(),
                branch_info_2.target().unwrap_or_default(),
            ],
            branchArch: [
                branch_info_0
                    .arch
                    .map(|a| a.handle)
                    .unwrap_or(std::ptr::null_mut()),
                branch_info_1
                    .arch
                    .map(|a| a.handle)
                    .unwrap_or(std::ptr::null_mut()),
                branch_info_2
                    .arch
                    .map(|a| a.handle)
                    .unwrap_or(std::ptr::null_mut()),
            ],
        }
    }
}
