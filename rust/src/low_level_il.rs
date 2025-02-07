// Copyright 2021-2024 Vector 35 Inc.
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

use std::fmt;

// TODO : provide some way to forbid emitting register reads for certain registers
// also writing for certain registers (e.g. zero register must prohibit il.set_reg and il.reg
// (replace with nop or const(0) respectively)
// requirements on load/store memory address sizes?
// can reg/set_reg be used with sizes that differ from what is in BNRegisterInfo?

use crate::architecture::Register as ArchReg;
use crate::architecture::{Architecture, RegisterId};
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

pub type MutableLiftedILFunction<Arch> = LowLevelILFunction<Arch, Mutable, NonSSA<LiftedNonSSA>>;
pub type LiftedILFunction<Arch> = LowLevelILFunction<Arch, Finalized, NonSSA<LiftedNonSSA>>;
pub type MutableLiftedILExpr<'a, Arch, ReturnType> =
    LowLevelILExpression<'a, Arch, Mutable, NonSSA<LiftedNonSSA>, ReturnType>;
pub type RegularLowLevelILFunction<Arch> =
    LowLevelILFunction<Arch, Finalized, NonSSA<RegularNonSSA>>;
pub type RegularLowLevelILInstruction<'a, Arch> =
    LowLevelILInstruction<'a, Arch, Finalized, NonSSA<RegularNonSSA>>;
pub type RegularLowLevelILInstructionKind<'a, Arch> =
    LowLevelILInstructionKind<'a, Arch, Finalized, NonSSA<RegularNonSSA>>;
pub type RegularLowLevelILExpression<'a, Arch, ReturnType> =
    LowLevelILExpression<'a, Arch, Finalized, NonSSA<RegularNonSSA>, ReturnType>;
pub type RegularLowLevelILExpressionKind<'a, Arch> =
    LowLevelILExpressionKind<'a, Arch, Finalized, NonSSA<RegularNonSSA>>;
pub type LowLevelILSSAFunction<Arch> = LowLevelILFunction<Arch, Finalized, SSA>;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum LowLevelILRegister<R: ArchReg> {
    ArchReg(R),
    // TODO: Might want to be changed to TempRegisterId.
    // TODO: If we do that then we would need to get rid of `Register::id()`
    Temp(u32),
}

impl<R: ArchReg> LowLevelILRegister<R> {
    fn id(&self) -> RegisterId {
        match *self {
            LowLevelILRegister::ArchReg(ref r) => r.id(),
            LowLevelILRegister::Temp(id) => RegisterId(0x8000_0000 | id),
        }
    }
}

impl<R: ArchReg> fmt::Debug for LowLevelILRegister<R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LowLevelILRegister::ArchReg(ref r) => write!(f, "{}", r.name().as_ref()),
            LowLevelILRegister::Temp(id) => write!(f, "temp{}", id),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum LowLevelILSSARegister<R: ArchReg> {
    Full(LowLevelILRegister<R>, u32), // no such thing as partial access to a temp register, I think
    Partial(R, u32, R),               // partial accesses only possible for arch registers, I think
}

impl<R: ArchReg> LowLevelILSSARegister<R> {
    pub fn version(&self) -> u32 {
        match *self {
            LowLevelILSSARegister::Full(_, ver) | LowLevelILSSARegister::Partial(_, ver, _) => ver,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum VisitorAction {
    Descend,
    Sibling,
    Halt,
}
