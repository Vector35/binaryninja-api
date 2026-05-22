// Copyright 2021-2026 Vector 35 Inc.
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
use std::collections::HashSet;
use std::fmt;
use std::fmt::{Debug, Display};
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

impl Debug for LowLevelILTempRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "temp{}", self.temp_id)
    }
}

impl Display for LowLevelILTempRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
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

    pub fn name(&self) -> Cow<'_, str> {
        match *self {
            LowLevelILRegisterKind::Arch(ref r) => r.name(),
            LowLevelILRegisterKind::Temp(temp) => Cow::Owned(format!("temp{}", temp.temp_id)),
        }
    }
}

impl<R: ArchReg> Debug for LowLevelILRegisterKind<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            LowLevelILRegisterKind::Arch(ref r) => r.fmt(f),
            LowLevelILRegisterKind::Temp(ref id) => Debug::fmt(id, f),
        }
    }
}

impl<R: ArchReg> Display for LowLevelILRegisterKind<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            LowLevelILRegisterKind::Arch(ref r) => write!(f, "{}", r.name()),
            LowLevelILRegisterKind::Temp(ref id) => Display::fmt(id, f),
        }
    }
}

impl From<LowLevelILTempRegister> for LowLevelILRegisterKind<CoreRegister> {
    fn from(reg: LowLevelILTempRegister) -> Self {
        LowLevelILRegisterKind::Temp(reg)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct LowLevelILSSARegister<R: ArchReg> {
    pub reg: LowLevelILRegisterKind<R>,
    /// The SSA version of the register.
    pub version: u32,
}

impl<R: ArchReg> LowLevelILSSARegister<R> {
    pub fn new(reg: LowLevelILRegisterKind<R>, version: u32) -> Self {
        Self { reg, version }
    }

    pub fn name(&self) -> Cow<'_, str> {
        self.reg.name()
    }

    pub fn id(&self) -> RegisterId {
        self.reg.id()
    }
}

impl<R: ArchReg> Display for LowLevelILSSARegister<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.reg, self.version)
    }
}

/// The kind of SSA register.
///
/// An SSA register can exist in two states:
///
/// - Full, e.g. `eax` on x86
/// - Partial, e.g. `al` on x86
///
/// If you intend to query for the ssa uses or definitions you must retrieve the physical register
/// using the function [`LowLevelILSSARegisterKind::physical_reg`] which will give you the actual
/// [`LowLevelILSSARegister`].
#[derive(Copy, Clone, Debug)]
pub enum LowLevelILSSARegisterKind<R: ArchReg> {
    /// A full register is one that is not aliasing another, such as `eax` on x86 or `rax` on x86_64.
    Full(LowLevelILSSARegister<R>),
    Partial {
        /// This is the non-aliased register.
        ///
        /// This register is what is used for dataflow, otherwise the backing storage of aliased registers
        /// like `al` on x86 would contain separate value information from the physical register `eax`.
        ///
        /// NOTE: While this is a [`LowLevelILSSARegister`] temporary registers are not allowed in partial
        /// assignments, so this will always be an actual architecture register.
        full_reg: LowLevelILSSARegister<R>,
        /// This is the aliased register.
        ///
        /// On x86 if the register `al` is used that would be considered a partial register, with the
        /// full register `eax` being used as the backing storage.
        partial_reg: CoreRegister,
    },
}

impl<R: ArchReg> LowLevelILSSARegisterKind<R> {
    pub fn new_full(kind: LowLevelILRegisterKind<R>, version: u32) -> Self {
        Self::Full(LowLevelILSSARegister::new(kind, version))
    }

    pub fn new_partial(
        full_reg: LowLevelILRegisterKind<R>,
        version: u32,
        partial_reg: CoreRegister,
    ) -> Self {
        Self::Partial {
            full_reg: LowLevelILSSARegister::new(full_reg, version),
            partial_reg,
        }
    }

    /// This is the non-aliased register used. This should be called when you intend to actually
    /// query for SSA dataflow information, as a partial register is prohibited from being used.
    ///
    /// # Example
    ///
    /// On x86 `al` in the LLIL SSA will have a physical register of `eax`.
    pub fn physical_reg(&self) -> LowLevelILSSARegister<R> {
        match *self {
            LowLevelILSSARegisterKind::Full(reg) => reg,
            LowLevelILSSARegisterKind::Partial { full_reg, .. } => full_reg,
        }
    }

    /// Gets the displayable register, for partial this will be the partial register name.
    ///
    /// # Example
    ///
    /// On x86 this will display "al" not "eax".
    pub fn name(&self) -> Cow<'_, str> {
        match *self {
            LowLevelILSSARegisterKind::Full(ref reg) => reg.reg.name(),
            LowLevelILSSARegisterKind::Partial {
                ref partial_reg, ..
            } => partial_reg.name(),
        }
    }
}

impl<R: ArchReg> AsRef<LowLevelILSSARegister<R>> for LowLevelILSSARegisterKind<R> {
    fn as_ref(&self) -> &LowLevelILSSARegister<R> {
        match self {
            LowLevelILSSARegisterKind::Full(reg) => reg,
            LowLevelILSSARegisterKind::Partial { full_reg, .. } => full_reg,
        }
    }
}

impl<R: ArchReg> From<LowLevelILSSARegister<R>> for LowLevelILSSARegisterKind<R> {
    fn from(value: LowLevelILSSARegister<R>) -> Self {
        LowLevelILSSARegisterKind::Full(value)
    }
}

impl<R: ArchReg> From<LowLevelILSSARegisterKind<R>> for LowLevelILSSARegister<R> {
    fn from(value: LowLevelILSSARegisterKind<R>) -> Self {
        match value {
            LowLevelILSSARegisterKind::Full(reg) => reg,
            LowLevelILSSARegisterKind::Partial { full_reg, .. } => full_reg,
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

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum ILInstructionAttribute {
    ILAllowDeadStoreElimination,
    ILPreventDeadStoreElimination,
    MLILAssumePossibleUse,
    MLILUnknownSize,
    SrcInstructionUsesPointerAuth,
    ILPreventAliasAnalysis,
    ILIsCFGProtected,
    MLILPossiblyUnusedIntermediate,
    HLILFoldableExpr,
    HLILInvertableCondition,
    HLILEarlyReturnPossible,
    HLILSwitchRecoveryPossible,
    ILTransparentCopy,
}

impl ILInstructionAttribute {
    pub fn value(&self) -> u32 {
        match self {
            Self::ILAllowDeadStoreElimination => 1,
            Self::ILPreventDeadStoreElimination => 2,
            Self::MLILAssumePossibleUse => 4,
            Self::MLILUnknownSize => 8,
            Self::SrcInstructionUsesPointerAuth => 16,
            Self::ILPreventAliasAnalysis => 32,
            Self::ILIsCFGProtected => 64,
            Self::MLILPossiblyUnusedIntermediate => 128,
            Self::HLILFoldableExpr => 256,
            Self::HLILInvertableCondition => 512,
            Self::HLILEarlyReturnPossible => 1024,
            Self::HLILSwitchRecoveryPossible => 2048,
            Self::ILTransparentCopy => 4096,
        }
    }
}

pub type ILInstructionAttributeSet = HashSet<ILInstructionAttribute>;
