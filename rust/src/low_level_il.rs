// Copyright 2021-2025 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::borrow::Cow;
use std::fmt;

// TODO : provide some way to forbid emitting register reads for certain registers
// also writing for certain registers (e.g. zero register must prohibit il.set_reg and il.reg
// (replace with nop or const(0) respectively)
// requirements on load/store memory address sizes?
// can reg/set_reg be used with sizes that differ from what is in BNRegisterInfo?

use crate::architecture::{Architecture, Flag, RegisterId};
use crate::architecture::{CoreRegister, Register as ArchReg};
use crate::function::Location;

pub mod block;
pub mod expression;
pub mod function;
pub mod instruction;
pub mod lifting;
pub mod operation;

use self::expression::*;
use self::function::*;
use self::instruction::*;

/// Regular low-level IL, if you are not modifying the functions IL or needing SSA, use this.
pub type LowLevelILRegularFunction = LowLevelILFunction<Finalized, NonSSA>;
pub type LowLevelILRegularInstruction<'a> = LowLevelILInstruction<'a, Finalized, NonSSA>;
pub type LowLevelILRegularInstructionKind<'a> = LowLevelILInstructionKind<'a, Finalized, NonSSA>;
pub type LowLevelILRegularExpression<'a, ReturnType> =
    LowLevelILExpression<'a, Finalized, NonSSA, ReturnType>;
pub type LowLevelILRegularExpressionKind<'a> = LowLevelILExpressionKind<'a, Finalized, NonSSA>;

/// Mutable low-level IL, used when lifting in architectures and modifying IL in workflow activities.
pub type LowLevelILMutableFunction = LowLevelILFunction<Mutable, NonSSA>;
pub type LowLevelILMutableExpression<'a, ReturnType> =
    LowLevelILExpression<'a, Mutable, NonSSA, ReturnType>;

/// SSA Variant of low-level IL, this can never be mutated directly.
pub type LowLevelILSSAFunction = LowLevelILFunction<Finalized, SSA>;

#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LowLevelILTempRegister {
    /// The temporary id for the register, this will **NOT** be the referenced id in the core.
    ///
    /// Do not attempt to pass this to the core. Use [`LowLevelILTempRegister::id`] instead.
    temp_id: RegisterId,
}

impl LowLevelILTempRegister {
    pub fn new(temp_id: u32) -> Self {
        Self {
            temp_id: RegisterId(temp_id),
        }
    }

    pub fn from_id(id: RegisterId) -> Option<Self> {
        match id.is_temporary() {
            true => {
                let temp_id = RegisterId(id.0 & 0x7fff_ffff);
                Some(Self { temp_id })
            }
            false => None,
        }
    }

    /// The temporary registers core id, with the temporary bit set.
    pub fn id(&self) -> RegisterId {
        RegisterId(self.temp_id.0 | 0x8000_0000)
    }
}

impl fmt::Debug for LowLevelILTempRegister {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "temp{}", self.temp_id)
    }
}

impl TryFrom<RegisterId> for LowLevelILTempRegister {
    type Error = ();

    fn try_from(value: RegisterId) -> Result<Self, Self::Error> {
        Self::from_id(value).ok_or(())
    }
}

impl From<u32> for LowLevelILTempRegister {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum LowLevelILRegisterKind<R: ArchReg> {
    Arch(R),
    Temp(LowLevelILTempRegister),
}

impl<R: ArchReg> LowLevelILRegisterKind<R> {
    pub fn from_raw(arch: &impl Architecture<Register = R>, val: RegisterId) -> Option<Self> {
        match val.is_temporary() {
            true => {
                let temp_reg = LowLevelILTempRegister::from_id(val)?;
                Some(LowLevelILRegisterKind::Temp(temp_reg))
            }
            false => {
                let arch_reg = arch.register_from_id(val)?;
                Some(LowLevelILRegisterKind::Arch(arch_reg))
            }
        }
    }

    pub fn from_temp(temp: impl Into<LowLevelILTempRegister>) -> Self {
        LowLevelILRegisterKind::Temp(temp.into())
    }

    pub fn id(&self) -> RegisterId {
        match *self {
            LowLevelILRegisterKind::Arch(ref r) => r.id(),
            LowLevelILRegisterKind::Temp(temp) => temp.id(),
        }
    }

    pub fn name(&self) -> Cow<str> {
        match *self {
            LowLevelILRegisterKind::Arch(ref r) => r.name(),
            LowLevelILRegisterKind::Temp(temp) => Cow::Owned(format!("temp{}", temp.temp_id)),
        }
    }
}

impl<R: ArchReg> fmt::Debug for LowLevelILRegisterKind<R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LowLevelILRegisterKind::Arch(ref r) => r.fmt(f),
            LowLevelILRegisterKind::Temp(id) => id.fmt(f),
        }
    }
}

impl From<LowLevelILTempRegister> for LowLevelILRegisterKind<CoreRegister> {
    fn from(reg: LowLevelILTempRegister) -> Self {
        LowLevelILRegisterKind::Temp(reg)
    }
}

#[derive(Copy, Clone, Debug)]
pub enum LowLevelILSSARegisterKind<R: ArchReg> {
    Full {
        kind: LowLevelILRegisterKind<R>,
        version: u32,
    },
    Partial {
        full_reg: CoreRegister,
        partial_reg: CoreRegister,
        version: u32,
    },
}

impl<R: ArchReg> LowLevelILSSARegisterKind<R> {
    pub fn new_full(kind: LowLevelILRegisterKind<R>, version: u32) -> Self {
        Self::Full { kind, version }
    }

    pub fn new_partial(full_reg: CoreRegister, partial_reg: CoreRegister, version: u32) -> Self {
        Self::Partial {
            full_reg,
            partial_reg,
            version,
        }
    }

    pub fn version(&self) -> u32 {
        match *self {
            LowLevelILSSARegisterKind::Full { version, .. }
            | LowLevelILSSARegisterKind::Partial { version, .. } => version,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct LowLevelILSSAFlag<F: Flag> {
    pub flag: F,
    pub version: u32,
}

impl<F: Flag> LowLevelILSSAFlag<F> {
    pub fn new(flag: F, version: u32) -> Self {
        Self { flag, version }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum VisitorAction {
    Descend,
    Sibling,
    Halt,
}
