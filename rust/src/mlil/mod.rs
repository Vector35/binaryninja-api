// Copyright 2021 Vector 35 Inc.
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

use crate::architecture::Architecture;
use crate::architecture::Register as ArchReg;
use crate::function::Location;

mod block;
mod expression;
mod function;
mod instruction;
mod lifting;
pub mod operation;

pub use self::expression::*;
pub use self::function::*;
pub use self::instruction::*;
pub use self::lifting::{ExpressionBuilder, Label, Liftable, LiftableWithSize, RegisterOrConstant};

pub use self::block::Block as MediumLevelBlock;
pub use self::block::BlockIter as MediumLevelBlockIter;

pub type Lifter<Arch> = Function<Arch, Mutable, NonSSA<LiftedNonSSA>>;
pub type LiftedFunction<Arch> = Function<Arch, Finalized, NonSSA<LiftedNonSSA>>;
pub type LiftedExpr<'a, Arch> = Expression<'a, Arch, Mutable, NonSSA<LiftedNonSSA>, ValueExpr>;
pub type RegularFunction<Arch> = Function<Arch, Finalized, NonSSA<RegularNonSSA>>;
pub type SSAFunction<Arch> = Function<Arch, Finalized, SSA>;

#[derive(Copy, Clone)]
pub enum Register<R: ArchReg> {
    ArchReg(R),
    Temp(u32),
}

impl<R: ArchReg> Register<R> {
    fn id(&self) -> u32 {
        match *self {
            Register::ArchReg(ref r) => r.id(),
            Register::Temp(id) => 0x8000_0000 | id,
        }
    }
}

impl<R: ArchReg> fmt::Debug for Register<R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Register::ArchReg(ref r) => write!(f, "{}", r.name().as_ref()),
            Register::Temp(id) => write!(f, "temp{}", id),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum SSARegister<R: ArchReg> {
    Full(Register<R>, u32),
    // no such thing as partial access to a temp register, I think
    Partial(R, u32, R), // partial accesses only possible for arch registers, I think
}

impl<R: ArchReg> SSARegister<R> {
    pub fn version(&self) -> u32 {
        match *self {
            SSARegister::Full(_, ver) | SSARegister::Partial(_, ver, _) => ver,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum VisitorAction {
    Descend,
    Sibling,
    Halt,
}
