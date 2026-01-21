use binaryninja::architecture;
use binaryninja::architecture::{CoreArchitecture, FlagId, FlagRole, FlagWriteId, UnusedFlagClass};

use std::borrow::Cow;

// NOTE: GIE, CPUOFF, OSCOFF, SG0, and SG1 not implemented as it's not clear how they would be used
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flag {
    C,
    Z,
    N,
    V,
}

impl architecture::Flag for Flag {
    type FlagClass = UnusedFlagClass;

    fn flags(_arch: &CoreArchitecture) -> Vec<Self> {
        vec![Flag::C, Flag::Z, Flag::N, Flag::V]
    }

    fn name(&self) -> Cow<'_, str> {
        match self {
            Self::C => "c".into(),
            Self::Z => "z".into(),
            Self::N => "n".into(),
            Self::V => "v".into(),
        }
    }

    fn role(&self, _class: Option<Self::FlagClass>) -> FlagRole {
        match self {
            Self::C => FlagRole::CarryFlagRole,
            Self::Z => FlagRole::ZeroFlagRole,
            Self::N => FlagRole::NegativeSignFlagRole,
            Self::V => FlagRole::OverflowFlagRole,
        }
    }

    fn id(&self) -> FlagId {
        match self {
            Self::C => 0,
            Self::Z => 1,
            Self::N => 2,
            Self::V => 8,
        }
        .into()
    }

    fn from_id(_arch: &CoreArchitecture, id: FlagId) -> Option<Self> {
        match id.0 {
            0 => Some(Self::C),
            1 => Some(Self::Z),
            2 => Some(Self::N),
            8 => Some(Self::V),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagWrite {
    All,
    Nz,
    Nvz,
    Cnz,
}

impl architecture::FlagWrite for FlagWrite {
    type FlagType = Flag;
    type FlagClass = UnusedFlagClass;

    fn flag_write_types(_arch: &CoreArchitecture) -> Vec<Self> {
        vec![
            FlagWrite::All,
            FlagWrite::Nz,
            FlagWrite::Nvz,
            FlagWrite::Cnz,
        ]
    }

    fn name(&self) -> Cow<'_, str> {
        match self {
            Self::All => "*".into(),
            Self::Nz => "nz".into(),
            Self::Nvz => "nvz".into(),
            Self::Cnz => "cnz".into(),
        }
    }

    fn class(&self) -> Option<Self::FlagClass> {
        None
    }

    fn id(&self) -> FlagWriteId {
        match self {
            Self::All => 1,
            Self::Nz => 2,
            Self::Nvz => 3,
            Self::Cnz => 4,
        }
        .into()
    }

    fn from_id(_arch: &CoreArchitecture, id: FlagWriteId) -> Option<Self> {
        match id.0 {
            1 => Some(Self::All),
            2 => Some(Self::Nz),
            3 => Some(Self::Nvz),
            4 => Some(Self::Cnz),
            _ => None,
        }
    }

    fn flags_written(&self) -> Vec<Self::FlagType> {
        match self {
            Self::All => vec![Flag::C, Flag::N, Flag::V, Flag::Z],
            Self::Nz => vec![Flag::N, Flag::Z],
            Self::Nvz => vec![Flag::N, Flag::V, Flag::Z],
            Self::Cnz => vec![Flag::C, Flag::N, Flag::Z],
        }
    }
}
