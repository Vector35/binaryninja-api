use std::fmt;

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

/// Medium level Il in non-SSA form
pub type RegularFunction = Function<NonSSA>;
/// Medium level Il in SSA form
pub type SSAFunction = Function<SSA>;
