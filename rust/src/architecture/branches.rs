use crate::architecture::CoreArchitecture;
use crate::function::Location;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner};
use binaryninjacore_sys::*;

pub use binaryninjacore_sys::BNBranchType as BranchType;

#[derive(Default, Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum BranchKind {
    #[default]
    Unresolved,
    Unconditional(u64),
    False(u64),
    True(u64),
    Call(u64),
    FunctionReturn,
    SystemCall,
    Indirect,
    Exception,
    UserDefined,
}

#[derive(Default, Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct BranchInfo {
    /// If `None`, the target architecture is the same as the branching instruction.
    pub arch: Option<CoreArchitecture>,
    pub kind: BranchKind,
}

impl BranchInfo {
    /// Branches to an instruction with the current architecture.
    pub fn new(kind: BranchKind) -> Self {
        Self { arch: None, kind }
    }

    /// Branches to an instruction with an explicit architecture.
    ///
    /// Use this if your architecture can transition to another architecture with a branch.
    pub fn new_with_arch(kind: BranchKind, arch: CoreArchitecture) -> Self {
        Self {
            arch: Some(arch),
            kind,
        }
    }

    pub fn target(&self) -> Option<u64> {
        match self.kind {
            BranchKind::Unconditional(target) => Some(target),
            BranchKind::False(target) => Some(target),
            BranchKind::True(target) => Some(target),
            BranchKind::Call(target) => Some(target),
            _ => None,
        }
    }
}

impl From<BranchInfo> for BNBranchType {
    fn from(value: BranchInfo) -> Self {
        match value.kind {
            BranchKind::Unresolved => BNBranchType::UnresolvedBranch,
            BranchKind::Unconditional(_) => BNBranchType::UnconditionalBranch,
            BranchKind::False(_) => BNBranchType::FalseBranch,
            BranchKind::True(_) => BNBranchType::TrueBranch,
            BranchKind::Call(_) => BNBranchType::CallDestination,
            BranchKind::FunctionReturn => BNBranchType::FunctionReturn,
            BranchKind::SystemCall => BNBranchType::SystemCall,
            BranchKind::Indirect => BNBranchType::IndirectBranch,
            BranchKind::Exception => BNBranchType::ExceptionBranch,
            BranchKind::UserDefined => BNBranchType::UserDefinedBranch,
        }
    }
}

impl From<BranchKind> for BranchInfo {
    fn from(value: BranchKind) -> Self {
        Self {
            arch: None,
            kind: value,
        }
    }
}

impl From<BranchKind> for BranchType {
    fn from(value: BranchKind) -> Self {
        match value {
            BranchKind::Unresolved => BranchType::UnresolvedBranch,
            BranchKind::Unconditional(_) => BranchType::UnconditionalBranch,
            BranchKind::True(_) => BranchType::TrueBranch,
            BranchKind::False(_) => BranchType::FalseBranch,
            BranchKind::Call(_) => BranchType::CallDestination,
            BranchKind::FunctionReturn => BranchType::FunctionReturn,
            BranchKind::SystemCall => BranchType::SystemCall,
            BranchKind::Indirect => BranchType::IndirectBranch,
            BranchKind::Exception => BranchType::ExceptionBranch,
            BranchKind::UserDefined => BranchType::UserDefinedBranch,
        }
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct IndirectBranchInfo {
    pub source: Location,
    pub dest: Location,
    pub auto_defined: bool,
}

impl From<BNIndirectBranchInfo> for IndirectBranchInfo {
    fn from(value: BNIndirectBranchInfo) -> Self {
        Self {
            source: Location::from_raw(value.sourceAddr, value.sourceArch),
            dest: Location::from_raw(value.destAddr, value.destArch),
            auto_defined: value.autoDefined,
        }
    }
}

impl From<IndirectBranchInfo> for BNIndirectBranchInfo {
    fn from(value: IndirectBranchInfo) -> Self {
        let source_arch = value
            .source
            .arch
            .map(|a| a.handle)
            .unwrap_or(std::ptr::null_mut());
        let dest_arch = value
            .source
            .arch
            .map(|a| a.handle)
            .unwrap_or(std::ptr::null_mut());
        Self {
            sourceArch: source_arch,
            sourceAddr: value.source.addr,
            destArch: dest_arch,
            destAddr: value.dest.addr,
            autoDefined: value.auto_defined,
        }
    }
}

impl From<&BNIndirectBranchInfo> for IndirectBranchInfo {
    fn from(value: &BNIndirectBranchInfo) -> Self {
        Self::from(*value)
    }
}

impl CoreArrayProvider for IndirectBranchInfo {
    type Raw = BNIndirectBranchInfo;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for IndirectBranchInfo {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeIndirectBranchList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from(*raw)
    }
}
