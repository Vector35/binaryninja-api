use std::fmt::Debug;

mod block;
mod function;
mod instruction;
mod lift;
pub mod operation;

pub use self::block::*;
pub use self::function::*;
pub use self::instruction::*;
pub use self::lift::*;

use binaryninjacore_sys::BNMediumLevelILInstruction;

// don't allow the user to implement those traits for custom types
trait Sealed {}

#[allow(private_bounds)]
pub trait InstructionTrait: Sealed + Sized + Clone + Debug + InstructionTraitFromRaw {
    fn name(&self) -> &'static str;
}

// don't allow the user to call this function directly
trait InstructionTraitFromRaw: Sized {
    fn from_operation(op: BNMediumLevelILInstruction) -> Option<Self>;
}

#[allow(private_bounds)]
pub trait InstructionLiftedTrait<I: Form>: Sealed + Sized + Clone + Debug {
    fn name(&self) -> &'static str;
    fn from_instruction(inst: &MediumLevelILInstruction<I>) -> Self;
    fn operands(&self) -> Vec<(&'static str, MediumLevelILLiftedOperand<I>)>;
}

#[allow(private_bounds)]
pub trait Form: Sealed + Sized + Clone + std::fmt::Debug {
    type Instruction: InstructionTrait;
    type InstructionLifted: InstructionLiftedTrait<Self>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SSA;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonSSA;

impl Sealed for SSA {}
impl Sealed for NonSSA {}

impl Form for NonSSA {
    type Instruction = MediumLevelILInstructionKindNonSSA;
    type InstructionLifted = MediumLevelILLiftedInstructionKindNonSSA;
}

impl Form for SSA {
    type Instruction = MediumLevelILInstructionKindSSA;
    type InstructionLifted = MediumLevelILLiftedInstructionKindSSA;
}
