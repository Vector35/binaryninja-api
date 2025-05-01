use binaryninja::architecture;
use binaryninja::architecture::{ImplicitRegisterExtend, RegisterId};

use binaryninja::low_level_il::LowLevelILRegister;
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    Pc,
    Sp,
    Sr,
    Cg,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl TryFrom<RegisterId> for Register {
    type Error = ();

    fn try_from(id: RegisterId) -> Result<Self, Self::Error> {
        // TODO: we should return separate errors if the id is between 0x7fff_ffff and 0xffff_ffff
        // vs outside of that range. Temporary registers have have the high bit set which we
        // shouldn't get, unless there is a bug in core. An id that isn't within that range but we
        // don't handle is a bug in the architecture.
        match id.0 {
            0 => Ok(Self::Pc),
            1 => Ok(Self::Sp),
            2 => Ok(Self::Sr),
            3 => Ok(Self::Cg),
            4 => Ok(Self::R4),
            5 => Ok(Self::R5),
            6 => Ok(Self::R6),
            7 => Ok(Self::R7),
            8 => Ok(Self::R8),
            9 => Ok(Self::R9),
            10 => Ok(Self::R10),
            11 => Ok(Self::R11),
            12 => Ok(Self::R12),
            13 => Ok(Self::R13),
            14 => Ok(Self::R14),
            15 => Ok(Self::R15),
            _ => Err(()),
        }
    }
}

// TODO: Get rid of this and lift all u32 vals to a proper register id.
impl TryFrom<u32> for Register {
    type Error = ();

    fn try_from(id: u32) -> Result<Self, Self::Error> {
        Register::try_from(RegisterId(id))
    }
}

impl architecture::Register for Register {
    type InfoType = Self;

    fn name(&self) -> Cow<'_, str> {
        match self {
            Self::Pc => "pc".into(),
            Self::Sp => "sp".into(),
            Self::Sr => "sr".into(),
            Self::Cg => "cg".into(),
            Self::R4
            | Self::R5
            | Self::R6
            | Self::R7
            | Self::R8
            | Self::R9
            | Self::R10
            | Self::R11
            | Self::R12
            | Self::R13
            | Self::R14
            | Self::R15 => format!("r{}", self.id()).into(),
        }
    }

    fn info(&self) -> Self::InfoType {
        *self
    }

    fn id(&self) -> RegisterId {
        match self {
            Self::Pc => 0,
            Self::Sp => 1,
            Self::Sr => 2,
            Self::Cg => 3,
            Self::R4 => 4,
            Self::R5 => 5,
            Self::R6 => 6,
            Self::R7 => 7,
            Self::R8 => 8,
            Self::R9 => 9,
            Self::R10 => 10,
            Self::R11 => 11,
            Self::R12 => 12,
            Self::R13 => 13,
            Self::R14 => 14,
            Self::R15 => 15,
        }
        .into()
    }
}

impl architecture::RegisterInfo for Register {
    type RegType = Self;

    fn parent(&self) -> Option<Self::RegType> {
        None
    }

    fn size(&self) -> usize {
        2
    }

    fn offset(&self) -> usize {
        0
    }

    fn implicit_extend(&self) -> ImplicitRegisterExtend {
        ImplicitRegisterExtend::NoExtend
    }
}

impl From<Register> for LowLevelILRegister<Register> {
    fn from(register: Register) -> Self {
        LowLevelILRegister::ArchReg(register)
    }
}
