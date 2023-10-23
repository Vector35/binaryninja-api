use std::fmt;

use crate::architecture::Architecture;
use crate::function::Location;
use crate::types::Variable;

mod block;
mod expression;
mod function;
mod instruction;
mod operation;

pub use self::block::*;
pub use self::expression::*;
pub use self::function::*;
pub use self::instruction::*;
pub use self::operation::*;

pub use self::block::Block as MediumLevelBlock;
pub use self::block::BlockIter as MediumLevelBlockIter;

// TODO: implement non-Finalized form?
/// Medium level Il in non-SSA form
pub type RegularFunction<Arch> = Function<Arch, Finalized, NonSSA<RegularNonSSA>>;
/// Medium level Il in SSA form
/// NOTE ssa form is read-only, aka always Finalized
pub type SSAFunction<Arch> = Function<Arch, Finalized, SSA>;
