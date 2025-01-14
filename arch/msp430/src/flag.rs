use binaryninja::architecture;
use binaryninja::architecture::{FlagClassId, FlagGroupId, FlagId, FlagRole, FlagWriteId};

use std::borrow::Cow;
use std::collections::HashMap;

// NOTE: GIE, CPUOFF, OSCOFF, SG0, and SG1 not implemented as it's not clear how they would be used
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flag {
    C,
    Z,
    N,
    V,
}

impl architecture::Flag for Flag {
    type FlagClass = FlagClass;

    fn name(&self) -> Cow<str> {
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
}

impl TryFrom<FlagId> for Flag {
    type Error = ();
    fn try_from(flag: FlagId) -> Result<Self, Self::Error> {
        match flag.0 {
            0 => Ok(Self::C),
            1 => Ok(Self::Z),
            2 => Ok(Self::N),
            8 => Ok(Self::V),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlagClass {}

impl architecture::FlagClass for FlagClass {
    fn name(&self) -> Cow<str> {
        unimplemented!()
    }

    fn id(&self) -> FlagClassId {
        unimplemented!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagGroup {}

impl architecture::FlagGroup for FlagGroup {
    type FlagType = Flag;
    type FlagClass = FlagClass;

    fn name(&self) -> Cow<str> {
        unimplemented!()
    }

    fn id(&self) -> FlagGroupId {
        unimplemented!()
    }

    fn flags_required(&self) -> Vec<Self::FlagType> {
        unimplemented!()
    }

    fn flag_conditions(&self) -> HashMap<Self::FlagClass, architecture::FlagCondition> {
        unimplemented!()
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
    type FlagClass = FlagClass;

    fn name(&self) -> Cow<str> {
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

    fn flags_written(&self) -> Vec<Self::FlagType> {
        match self {
            Self::All => vec![Flag::C, Flag::N, Flag::V, Flag::Z],
            Self::Nz => vec![Flag::N, Flag::Z],
            Self::Nvz => vec![Flag::N, Flag::V, Flag::Z],
            Self::Cnz => vec![Flag::C, Flag::N, Flag::Z],
        }
    }
}

impl TryFrom<FlagWriteId> for FlagWrite {
    type Error = ();

    fn try_from(value: FlagWriteId) -> Result<Self, Self::Error> {
        match value.0 {
            1 => Ok(Self::All),
            2 => Ok(Self::Nz),
            3 => Ok(Self::Nvz),
            4 => Ok(Self::Cnz),
            _ => Err(()),
        }
    }
}
