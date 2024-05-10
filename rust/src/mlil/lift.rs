use std::collections::BTreeMap;

use crate::mlil::MediumLevelILInstructionKindSSA;
use crate::operand_iter::OperandIter;
use crate::rc::Ref;
use crate::types::{
    ConstantData, ILIntrinsic, RegisterValue, RegisterValueType, SSAVariable, Variable,
};

use super::operation::*;
use super::{
    Form, InstructionLiftedTrait, MediumLevelILFunction, MediumLevelILInstruction,
    MediumLevelILInstructionKindNonSSA, NonSSA, Sealed, SSA,
};

use strum::IntoStaticStr;

#[derive(Clone, Debug, IntoStaticStr)]
pub enum MediumLevelILLiftedOperand<I: Form> {
    ConstantData(ConstantData),
    Intrinsic(ILIntrinsic),
    Expr(MediumLevelILLiftedInstruction<I>),
    ExprList(Vec<MediumLevelILLiftedInstruction<I>>),
    Float(f64),
    Int(u64),
    IntList(Vec<u64>),
    TargetMap(BTreeMap<u64, u64>),
    Var(Variable),
    VarList(Vec<Variable>),
    VarSsa(SSAVariable),
    VarSsaList(Vec<SSAVariable>),
}

#[derive(Clone, Debug)]
pub struct MediumLevelILLiftedInstruction<I: Form> {
    pub function: Ref<MediumLevelILFunction<I>>,
    pub address: u64,
    pub index: usize,
    pub size: usize,
    pub kind: I::InstructionLifted,
}

macro_rules! construct_common {
    ($form:ident, $instruction:ident, $lifted:ident) => {
        fn common_operands(
            &self,
        ) -> Option<Vec<(&'static str, MediumLevelILLiftedOperand<$form>)>> {
            use MediumLevelILLiftedOperand as Operand;
            Some(match self {
                Self::Nop | Self::Noret | Self::Bp | Self::Undef | Self::Unimpl => vec![],
                Self::If(op) => vec![
                    ("condition", Operand::Expr(*op.condition.clone())),
                    ("dest_true", Operand::Int(op.dest_true)),
                    ("dest_false", Operand::Int(op.dest_false)),
                ],
                Self::FloatConst(op) => vec![("constant", Operand::Float(op.constant))],
                Self::Const(op) | Self::ConstPtr(op) | Self::Import(op) => {
                    vec![("constant", Operand::Int(op.constant))]
                }
                Self::ExternPtr(op) => vec![
                    ("constant", Operand::Int(op.constant)),
                    ("offset", Operand::Int(op.offset)),
                ],
                Self::ConstData(op) => vec![(
                    "constant_data",
                    Operand::ConstantData(op.constant_data.clone()),
                )],
                Self::Jump(op) | Self::RetHint(op) => {
                    vec![("dest", Operand::Expr(*op.dest.clone()))]
                }
                Self::JumpTo(op) => vec![
                    ("dest", Operand::Expr(*op.dest.clone())),
                    ("targets", Operand::TargetMap(op.targets.clone())),
                ],
                Self::Goto(op) => vec![("dest", Operand::Int(op.dest))],
                Self::MemPhi(op) => vec![
                    ("dest_memory", Operand::Int(op.dest_memory)),
                    ("src_memory", Operand::IntList(op.src_memory.clone())),
                ],
                Self::Add(op)
                | Self::Sub(op)
                | Self::And(op)
                | Self::Or(op)
                | Self::Xor(op)
                | Self::Lsl(op)
                | Self::Lsr(op)
                | Self::Asr(op)
                | Self::Rol(op)
                | Self::Ror(op)
                | Self::Mul(op)
                | Self::MuluDp(op)
                | Self::MulsDp(op)
                | Self::Divu(op)
                | Self::DivuDp(op)
                | Self::Divs(op)
                | Self::DivsDp(op)
                | Self::Modu(op)
                | Self::ModuDp(op)
                | Self::Mods(op)
                | Self::ModsDp(op)
                | Self::CmpE(op)
                | Self::CmpNe(op)
                | Self::CmpSlt(op)
                | Self::CmpUlt(op)
                | Self::CmpSle(op)
                | Self::CmpUle(op)
                | Self::CmpSge(op)
                | Self::CmpUge(op)
                | Self::CmpSgt(op)
                | Self::CmpUgt(op)
                | Self::TestBit(op)
                | Self::AddOverflow(op)
                | Self::FcmpE(op)
                | Self::FcmpNe(op)
                | Self::FcmpLt(op)
                | Self::FcmpLe(op)
                | Self::FcmpGe(op)
                | Self::FcmpGt(op)
                | Self::FcmpO(op)
                | Self::FcmpUo(op)
                | Self::Fadd(op)
                | Self::Fsub(op)
                | Self::Fmul(op)
                | Self::Fdiv(op) => vec![
                    ("left", Operand::Expr(*op.left.clone())),
                    ("right", Operand::Expr(*op.right.clone())),
                ],
                Self::Adc(op) | Self::Sbb(op) | Self::Rlc(op) | Self::Rrc(op) => vec![
                    ("left", Operand::Expr(*op.left.clone())),
                    ("right", Operand::Expr(*op.right.clone())),
                    ("carry", Operand::Expr(*op.carry.clone())),
                ],
                Self::Neg(op)
                | Self::Not(op)
                | Self::Sx(op)
                | Self::Zx(op)
                | Self::LowPart(op)
                | Self::BoolToInt(op)
                | Self::UnimplMem(op)
                | Self::Fsqrt(op)
                | Self::Fneg(op)
                | Self::Fabs(op)
                | Self::FloatToInt(op)
                | Self::IntToFloat(op)
                | Self::FloatConv(op)
                | Self::RoundToInt(op)
                | Self::Floor(op)
                | Self::Ceil(op)
                | Self::Ftrunc(op) => {
                    vec![("src", Operand::Expr(*op.src.clone()))]
                }
                Self::Ret(op) => vec![("src", Operand::ExprList(op.src.clone()))],
                Self::SeparateParamList(op) => {
                    vec![("params", Operand::ExprList(op.params.clone()))]
                }
                Self::SharedParamSlot(op) => vec![("params", Operand::ExprList(op.params.clone()))],
                Self::AddressOf(op) => vec![("src", Operand::Var(op.src))],
                Self::AddressOfField(op) => vec![
                    ("src", Operand::Var(op.src)),
                    ("offset", Operand::Int(op.offset)),
                ],
                Self::Trap(op) => vec![("vector", Operand::Int(op.vector))],

                _ => return None,
            })
        }

        fn common_from_instruction(inst: &MediumLevelILInstruction<$form>) -> Option<Self> {
            use $instruction as UnLifted;
            use $lifted as Lifted;
            Some(match &inst.kind {
                UnLifted::Nop => Lifted::Nop,
                UnLifted::Noret => Lifted::Noret,
                UnLifted::Bp => Lifted::Bp,
                UnLifted::Undef => Lifted::Undef,
                UnLifted::Unimpl => Lifted::Unimpl,
                UnLifted::If(op) => Lifted::If(op.lift(inst)),
                UnLifted::FloatConst(op) => Lifted::FloatConst(*op),
                UnLifted::Const(op) => Lifted::Const(*op),
                UnLifted::ConstPtr(op) => Lifted::ConstPtr(*op),
                UnLifted::Import(op) => Lifted::Import(*op),
                UnLifted::ExternPtr(op) => Lifted::ExternPtr(*op),
                UnLifted::ConstData(op) => Lifted::ConstData(op.lift(inst)),
                UnLifted::Jump(op) => Lifted::Jump(op.lift(inst)),
                UnLifted::RetHint(op) => Lifted::RetHint(op.lift(inst)),
                UnLifted::JumpTo(op) => Lifted::JumpTo(op.lift(inst)),
                UnLifted::Goto(op) => Lifted::Goto(*op),
                UnLifted::Add(op) => Lifted::Add(op.lift(inst)),
                UnLifted::Sub(op) => Lifted::Sub(op.lift(inst)),
                UnLifted::And(op) => Lifted::And(op.lift(inst)),
                UnLifted::Or(op) => Lifted::Or(op.lift(inst)),
                UnLifted::Xor(op) => Lifted::Xor(op.lift(inst)),
                UnLifted::Lsl(op) => Lifted::Lsl(op.lift(inst)),
                UnLifted::Lsr(op) => Lifted::Lsr(op.lift(inst)),
                UnLifted::Asr(op) => Lifted::Asr(op.lift(inst)),
                UnLifted::Rol(op) => Lifted::Rol(op.lift(inst)),
                UnLifted::Ror(op) => Lifted::Ror(op.lift(inst)),
                UnLifted::Mul(op) => Lifted::Mul(op.lift(inst)),
                UnLifted::MuluDp(op) => Lifted::MuluDp(op.lift(inst)),
                UnLifted::MulsDp(op) => Lifted::MulsDp(op.lift(inst)),
                UnLifted::Divu(op) => Lifted::Divu(op.lift(inst)),
                UnLifted::DivuDp(op) => Lifted::DivuDp(op.lift(inst)),
                UnLifted::Divs(op) => Lifted::Divs(op.lift(inst)),
                UnLifted::DivsDp(op) => Lifted::DivsDp(op.lift(inst)),
                UnLifted::Modu(op) => Lifted::Modu(op.lift(inst)),
                UnLifted::ModuDp(op) => Lifted::ModuDp(op.lift(inst)),
                UnLifted::Mods(op) => Lifted::Mods(op.lift(inst)),
                UnLifted::ModsDp(op) => Lifted::ModsDp(op.lift(inst)),
                UnLifted::CmpE(op) => Lifted::CmpE(op.lift(inst)),
                UnLifted::CmpNe(op) => Lifted::CmpNe(op.lift(inst)),
                UnLifted::CmpSlt(op) => Lifted::CmpSlt(op.lift(inst)),
                UnLifted::CmpUlt(op) => Lifted::CmpUlt(op.lift(inst)),
                UnLifted::CmpSle(op) => Lifted::CmpSle(op.lift(inst)),
                UnLifted::CmpUle(op) => Lifted::CmpUle(op.lift(inst)),
                UnLifted::CmpSge(op) => Lifted::CmpSge(op.lift(inst)),
                UnLifted::CmpUge(op) => Lifted::CmpUge(op.lift(inst)),
                UnLifted::CmpSgt(op) => Lifted::CmpSgt(op.lift(inst)),
                UnLifted::CmpUgt(op) => Lifted::CmpUgt(op.lift(inst)),
                UnLifted::TestBit(op) => Lifted::TestBit(op.lift(inst)),
                UnLifted::AddOverflow(op) => Lifted::AddOverflow(op.lift(inst)),
                UnLifted::FcmpE(op) => Lifted::FcmpE(op.lift(inst)),
                UnLifted::FcmpNe(op) => Lifted::FcmpNe(op.lift(inst)),
                UnLifted::FcmpLt(op) => Lifted::FcmpLt(op.lift(inst)),
                UnLifted::FcmpLe(op) => Lifted::FcmpLe(op.lift(inst)),
                UnLifted::FcmpGe(op) => Lifted::FcmpGe(op.lift(inst)),
                UnLifted::FcmpGt(op) => Lifted::FcmpGt(op.lift(inst)),
                UnLifted::FcmpO(op) => Lifted::FcmpO(op.lift(inst)),
                UnLifted::FcmpUo(op) => Lifted::FcmpUo(op.lift(inst)),
                UnLifted::Fadd(op) => Lifted::Fadd(op.lift(inst)),
                UnLifted::Fsub(op) => Lifted::Fsub(op.lift(inst)),
                UnLifted::Fmul(op) => Lifted::Fmul(op.lift(inst)),
                UnLifted::Fdiv(op) => Lifted::Fdiv(op.lift(inst)),
                UnLifted::Adc(op) => Lifted::Adc(op.lift(inst)),
                UnLifted::Sbb(op) => Lifted::Sbb(op.lift(inst)),
                UnLifted::Rlc(op) => Lifted::Rlc(op.lift(inst)),
                UnLifted::Rrc(op) => Lifted::Rrc(op.lift(inst)),
                UnLifted::Neg(op) => Lifted::Neg(op.lift(inst)),
                UnLifted::Not(op) => Lifted::Not(op.lift(inst)),
                UnLifted::Sx(op) => Lifted::Sx(op.lift(inst)),
                UnLifted::Zx(op) => Lifted::Zx(op.lift(inst)),
                UnLifted::LowPart(op) => Lifted::LowPart(op.lift(inst)),
                UnLifted::BoolToInt(op) => Lifted::BoolToInt(op.lift(inst)),
                UnLifted::UnimplMem(op) => Lifted::UnimplMem(op.lift(inst)),
                UnLifted::Fsqrt(op) => Lifted::Fsqrt(op.lift(inst)),
                UnLifted::Fneg(op) => Lifted::Fneg(op.lift(inst)),
                UnLifted::Fabs(op) => Lifted::Fabs(op.lift(inst)),
                UnLifted::FloatToInt(op) => Lifted::FloatToInt(op.lift(inst)),
                UnLifted::IntToFloat(op) => Lifted::IntToFloat(op.lift(inst)),
                UnLifted::FloatConv(op) => Lifted::FloatConv(op.lift(inst)),
                UnLifted::RoundToInt(op) => Lifted::RoundToInt(op.lift(inst)),
                UnLifted::Floor(op) => Lifted::Floor(op.lift(inst)),
                UnLifted::Ceil(op) => Lifted::Ceil(op.lift(inst)),
                UnLifted::Ftrunc(op) => Lifted::Ftrunc(op.lift(inst)),
                UnLifted::Ret(op) => Lifted::Ret(op.lift(inst)),

                UnLifted::MemPhi(op) => Lifted::MemPhi(op.lift(inst)),
                UnLifted::SeparateParamList(op) => Lifted::SeparateParamList(op.lift(inst)),
                UnLifted::SharedParamSlot(op) => Lifted::SharedParamSlot(op.lift(inst)),

                UnLifted::AddressOf(op) => Lifted::AddressOf(*op),
                UnLifted::AddressOfField(op) => Lifted::AddressOfField(*op),
                UnLifted::Trap(op) => Lifted::Trap(*op),

                _ => return None,
            })
        }
    };
}

#[derive(Clone, Debug, IntoStaticStr)]
pub enum MediumLevelILLiftedInstructionKindNonSSA {
    Nop,
    Noret,
    Bp,
    Undef,
    Unimpl,
    If(LiftedIf<NonSSA>),
    FloatConst(FloatConst),
    Const(Constant),
    ConstPtr(Constant),
    Import(Constant),
    ExternPtr(ExternPtr),
    ConstData(LiftedConstData),
    Jump(LiftedJump<NonSSA>),
    RetHint(LiftedJump<NonSSA>),
    JumpTo(LiftedJumpTo<NonSSA>),
    Goto(Goto),
    Add(LiftedBinaryOp<NonSSA>),
    Sub(LiftedBinaryOp<NonSSA>),
    And(LiftedBinaryOp<NonSSA>),
    Or(LiftedBinaryOp<NonSSA>),
    Xor(LiftedBinaryOp<NonSSA>),
    Lsl(LiftedBinaryOp<NonSSA>),
    Lsr(LiftedBinaryOp<NonSSA>),
    Asr(LiftedBinaryOp<NonSSA>),
    Rol(LiftedBinaryOp<NonSSA>),
    Ror(LiftedBinaryOp<NonSSA>),
    Mul(LiftedBinaryOp<NonSSA>),
    MuluDp(LiftedBinaryOp<NonSSA>),
    MulsDp(LiftedBinaryOp<NonSSA>),
    Divu(LiftedBinaryOp<NonSSA>),
    DivuDp(LiftedBinaryOp<NonSSA>),
    Divs(LiftedBinaryOp<NonSSA>),
    DivsDp(LiftedBinaryOp<NonSSA>),
    Modu(LiftedBinaryOp<NonSSA>),
    ModuDp(LiftedBinaryOp<NonSSA>),
    Mods(LiftedBinaryOp<NonSSA>),
    ModsDp(LiftedBinaryOp<NonSSA>),
    CmpE(LiftedBinaryOp<NonSSA>),
    CmpNe(LiftedBinaryOp<NonSSA>),
    CmpSlt(LiftedBinaryOp<NonSSA>),
    CmpUlt(LiftedBinaryOp<NonSSA>),
    CmpSle(LiftedBinaryOp<NonSSA>),
    CmpUle(LiftedBinaryOp<NonSSA>),
    CmpSge(LiftedBinaryOp<NonSSA>),
    CmpUge(LiftedBinaryOp<NonSSA>),
    CmpSgt(LiftedBinaryOp<NonSSA>),
    CmpUgt(LiftedBinaryOp<NonSSA>),
    TestBit(LiftedBinaryOp<NonSSA>),
    AddOverflow(LiftedBinaryOp<NonSSA>),
    FcmpE(LiftedBinaryOp<NonSSA>),
    FcmpNe(LiftedBinaryOp<NonSSA>),
    FcmpLt(LiftedBinaryOp<NonSSA>),
    FcmpLe(LiftedBinaryOp<NonSSA>),
    FcmpGe(LiftedBinaryOp<NonSSA>),
    FcmpGt(LiftedBinaryOp<NonSSA>),
    FcmpO(LiftedBinaryOp<NonSSA>),
    FcmpUo(LiftedBinaryOp<NonSSA>),
    Fadd(LiftedBinaryOp<NonSSA>),
    Fsub(LiftedBinaryOp<NonSSA>),
    Fmul(LiftedBinaryOp<NonSSA>),
    Fdiv(LiftedBinaryOp<NonSSA>),
    Adc(LiftedBinaryOpCarry<NonSSA>),
    Sbb(LiftedBinaryOpCarry<NonSSA>),
    Rlc(LiftedBinaryOpCarry<NonSSA>),
    Rrc(LiftedBinaryOpCarry<NonSSA>),
    Neg(LiftedUnaryOp<NonSSA>),
    Not(LiftedUnaryOp<NonSSA>),
    Sx(LiftedUnaryOp<NonSSA>),
    Zx(LiftedUnaryOp<NonSSA>),
    LowPart(LiftedUnaryOp<NonSSA>),
    BoolToInt(LiftedUnaryOp<NonSSA>),
    UnimplMem(LiftedUnaryOp<NonSSA>),
    Fsqrt(LiftedUnaryOp<NonSSA>),
    Fneg(LiftedUnaryOp<NonSSA>),
    Fabs(LiftedUnaryOp<NonSSA>),
    FloatToInt(LiftedUnaryOp<NonSSA>),
    IntToFloat(LiftedUnaryOp<NonSSA>),
    FloatConv(LiftedUnaryOp<NonSSA>),
    RoundToInt(LiftedUnaryOp<NonSSA>),
    Floor(LiftedUnaryOp<NonSSA>),
    Ceil(LiftedUnaryOp<NonSSA>),
    Ftrunc(LiftedUnaryOp<NonSSA>),
    Ret(LiftedRet<NonSSA>),

    MemPhi(LiftedMemPhi),
    SeparateParamList(LiftedSeparateParamList<NonSSA>),
    SharedParamSlot(LiftedSharedParamSlot<NonSSA>),

    AddressOf(Var),
    AddressOfField(Field),
    Trap(Trap),

    Var(Var),
    VarField(Field),
    Store(LiftedStore),
    StoreStruct(LiftedStoreStruct),
    SetVar(LiftedSetVar),
    SetVarField(LiftedSetVarField),
    FreeVarSlot(FreeVarSlot),
    VarSplit(VarSplit),
    SetVarSplit(LiftedSetVarSplit),
    Call(LiftedCall),
    CallUntyped(LiftedCallUntyped),
    Tailcall(LiftedCall),
    Syscall(LiftedSyscall),
    SyscallUntyped(LiftedSyscallUntyped),
    Intrinsic(LiftedIntrinsic),
    TailcallUntyped(LiftedCallUntyped),
    Load(LiftedUnaryOp<NonSSA>),
    LoadStruct(LiftedLoadStruct),
}

impl Sealed for MediumLevelILLiftedInstructionKindNonSSA {}
impl MediumLevelILLiftedInstructionKindNonSSA {
    construct_common!(
        NonSSA,
        MediumLevelILInstructionKindNonSSA,
        MediumLevelILLiftedInstructionKindNonSSA
    );
    fn this_operands(&self) -> Vec<(&'static str, MediumLevelILLiftedOperand<NonSSA>)> {
        use MediumLevelILLiftedInstructionKindNonSSA::*;
        use MediumLevelILLiftedOperand as Operand;
        match self {
            StoreStruct(op) => vec![
                ("dest", Operand::Expr(*op.dest.clone())),
                ("offset", Operand::Int(op.offset)),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            Store(op) => vec![
                ("dest", Operand::Expr(*op.dest.clone())),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            FreeVarSlot(op) => vec![("dest", Operand::Var(op.dest))],
            SetVarField(op) => vec![
                ("dest", Operand::Var(op.dest)),
                ("offset", Operand::Int(op.offset)),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            SetVar(op) => vec![
                ("dest", Operand::Var(op.dest)),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            VarSplit(op) => vec![
                ("high", Operand::Var(op.high)),
                ("low", Operand::Var(op.low)),
            ],
            SetVarSplit(op) => vec![
                ("high", Operand::Var(op.high)),
                ("low", Operand::Var(op.low)),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            Call(op) | Tailcall(op) => vec![
                ("output", Operand::VarList(op.output.clone())),
                ("dest", Operand::Expr(*op.dest.clone())),
                ("params", Operand::ExprList(op.params.clone())),
            ],
            Syscall(op) => vec![
                ("output", Operand::VarList(op.output.clone())),
                ("params", Operand::ExprList(op.params.clone())),
            ],
            Intrinsic(op) => vec![
                ("output", Operand::VarList(op.output.clone())),
                ("intrinsic", Operand::Intrinsic(op.intrinsic)),
                ("params", Operand::ExprList(op.params.clone())),
            ],
            CallUntyped(op) | TailcallUntyped(op) => vec![
                ("output", Operand::VarList(op.output.clone())),
                ("dest", Operand::Expr(*op.dest.clone())),
                ("params", Operand::ExprList(op.params.clone())),
                ("stack", Operand::Expr(*op.stack.clone())),
            ],
            SyscallUntyped(op) => vec![
                ("output", Operand::VarList(op.output.clone())),
                ("params", Operand::ExprList(op.params.clone())),
                ("stack", Operand::Expr(*op.stack.clone())),
            ],
            Load(op) => vec![("src", Operand::Expr(*op.src.clone()))],
            LoadStruct(op) => vec![
                ("src", Operand::Expr(*op.src.clone())),
                ("offset", Operand::Int(op.offset)),
            ],
            Var(op) => vec![("src", Operand::Var(op.src))],
            VarField(op) => vec![
                ("src", Operand::Var(op.src)),
                ("offset", Operand::Int(op.offset)),
            ],
            _ => unreachable!(),
        }
    }
    fn this_from_instruction(inst: &MediumLevelILInstruction<NonSSA>) -> Self {
        use MediumLevelILInstructionKindNonSSA::*;
        use MediumLevelILLiftedInstructionKindNonSSA as Lifted;
        match &inst.kind {
            Var(op) => Lifted::Var(*op),
            VarField(op) => Lifted::VarField(*op),
            Store(op) => Lifted::Store(op.lift(inst)),
            StoreStruct(op) => Lifted::StoreStruct(op.lift(inst)),
            SetVar(op) => Lifted::SetVar(op.lift(inst)),
            SetVarField(op) => Lifted::SetVarField(op.lift(inst)),
            FreeVarSlot(op) => Lifted::FreeVarSlot(*op),
            VarSplit(op) => Lifted::VarSplit(*op),
            SetVarSplit(op) => Lifted::SetVarSplit(op.lift(inst)),
            Call(op) => Lifted::Call(op.lift(inst)),
            CallUntyped(op) => Lifted::CallUntyped(op.lift(inst)),
            Tailcall(op) => Lifted::Tailcall(op.lift(inst)),
            Syscall(op) => Lifted::Syscall(op.lift(inst)),
            SyscallUntyped(op) => Lifted::SyscallUntyped(op.lift(inst)),
            Intrinsic(op) => Lifted::Intrinsic(op.lift(inst)),
            TailcallUntyped(op) => Lifted::TailcallUntyped(op.lift(inst)),
            Load(op) => Lifted::Load(op.lift(inst)),
            LoadStruct(op) => Lifted::LoadStruct(op.lift(inst)),
            _ => unreachable!(),
        }
    }
}

impl InstructionLiftedTrait<NonSSA> for MediumLevelILLiftedInstructionKindNonSSA {
    fn name(&self) -> &'static str {
        self.into()
    }

    fn from_instruction(inst: &MediumLevelILInstruction<NonSSA>) -> Self {
        Self::common_from_instruction(inst).unwrap_or_else(|| Self::this_from_instruction(inst))
    }

    fn operands(&self) -> Vec<(&'static str, MediumLevelILLiftedOperand<NonSSA>)> {
        self.common_operands()
            .unwrap_or_else(|| self.this_operands())
    }
}

#[derive(Clone, Debug, IntoStaticStr)]
pub enum MediumLevelILLiftedInstructionKindSSA {
    Nop,
    Noret,
    Bp,
    Undef,
    Unimpl,
    If(LiftedIf<SSA>),
    FloatConst(FloatConst),
    Const(Constant),
    ConstPtr(Constant),
    Import(Constant),
    ExternPtr(ExternPtr),
    ConstData(LiftedConstData),
    Jump(LiftedJump<SSA>),
    RetHint(LiftedJump<SSA>),
    JumpTo(LiftedJumpTo<SSA>),
    Goto(Goto),
    Add(LiftedBinaryOp<SSA>),
    Sub(LiftedBinaryOp<SSA>),
    And(LiftedBinaryOp<SSA>),
    Or(LiftedBinaryOp<SSA>),
    Xor(LiftedBinaryOp<SSA>),
    Lsl(LiftedBinaryOp<SSA>),
    Lsr(LiftedBinaryOp<SSA>),
    Asr(LiftedBinaryOp<SSA>),
    Rol(LiftedBinaryOp<SSA>),
    Ror(LiftedBinaryOp<SSA>),
    Mul(LiftedBinaryOp<SSA>),
    MuluDp(LiftedBinaryOp<SSA>),
    MulsDp(LiftedBinaryOp<SSA>),
    Divu(LiftedBinaryOp<SSA>),
    DivuDp(LiftedBinaryOp<SSA>),
    Divs(LiftedBinaryOp<SSA>),
    DivsDp(LiftedBinaryOp<SSA>),
    Modu(LiftedBinaryOp<SSA>),
    ModuDp(LiftedBinaryOp<SSA>),
    Mods(LiftedBinaryOp<SSA>),
    ModsDp(LiftedBinaryOp<SSA>),
    CmpE(LiftedBinaryOp<SSA>),
    CmpNe(LiftedBinaryOp<SSA>),
    CmpSlt(LiftedBinaryOp<SSA>),
    CmpUlt(LiftedBinaryOp<SSA>),
    CmpSle(LiftedBinaryOp<SSA>),
    CmpUle(LiftedBinaryOp<SSA>),
    CmpSge(LiftedBinaryOp<SSA>),
    CmpUge(LiftedBinaryOp<SSA>),
    CmpSgt(LiftedBinaryOp<SSA>),
    CmpUgt(LiftedBinaryOp<SSA>),
    TestBit(LiftedBinaryOp<SSA>),
    AddOverflow(LiftedBinaryOp<SSA>),
    FcmpE(LiftedBinaryOp<SSA>),
    FcmpNe(LiftedBinaryOp<SSA>),
    FcmpLt(LiftedBinaryOp<SSA>),
    FcmpLe(LiftedBinaryOp<SSA>),
    FcmpGe(LiftedBinaryOp<SSA>),
    FcmpGt(LiftedBinaryOp<SSA>),
    FcmpO(LiftedBinaryOp<SSA>),
    FcmpUo(LiftedBinaryOp<SSA>),
    Fadd(LiftedBinaryOp<SSA>),
    Fsub(LiftedBinaryOp<SSA>),
    Fmul(LiftedBinaryOp<SSA>),
    Fdiv(LiftedBinaryOp<SSA>),
    Adc(LiftedBinaryOpCarry<SSA>),
    Sbb(LiftedBinaryOpCarry<SSA>),
    Rlc(LiftedBinaryOpCarry<SSA>),
    Rrc(LiftedBinaryOpCarry<SSA>),
    Neg(LiftedUnaryOp<SSA>),
    Not(LiftedUnaryOp<SSA>),
    Sx(LiftedUnaryOp<SSA>),
    Zx(LiftedUnaryOp<SSA>),
    LowPart(LiftedUnaryOp<SSA>),
    BoolToInt(LiftedUnaryOp<SSA>),
    UnimplMem(LiftedUnaryOp<SSA>),
    Fsqrt(LiftedUnaryOp<SSA>),
    Fneg(LiftedUnaryOp<SSA>),
    Fabs(LiftedUnaryOp<SSA>),
    FloatToInt(LiftedUnaryOp<SSA>),
    IntToFloat(LiftedUnaryOp<SSA>),
    FloatConv(LiftedUnaryOp<SSA>),
    RoundToInt(LiftedUnaryOp<SSA>),
    Floor(LiftedUnaryOp<SSA>),
    Ceil(LiftedUnaryOp<SSA>),
    Ftrunc(LiftedUnaryOp<SSA>),
    Ret(LiftedRet<SSA>),

    MemPhi(LiftedMemPhi),
    SeparateParamList(LiftedSeparateParamList<SSA>),
    SharedParamSlot(LiftedSharedParamSlot<SSA>),

    AddressOf(Var),
    AddressOfField(Field),
    Trap(Trap),

    VarSsa(VarSsa),
    VarSsaField(VarSsaField),
    StoreSsa(LiftedStoreSsa),
    StoreStructSsa(LiftedStoreStructSsa),
    SetVarSsa(LiftedSetVarSsa),
    SetVarSsaField(LiftedSetVarSsaField),
    FreeVarSlotSsa(FreeVarSlotSsa),
    VarSplitSsa(VarSplitSsa),
    SetVarSplitSsa(LiftedSetVarSplitSsa),
    CallSsa(LiftedCallSsa),
    CallUntypedSsa(LiftedCallUntypedSsa),
    TailcallSsa(LiftedCallSsa),
    SyscallSsa(LiftedSyscallSsa),
    SyscallUntypedSsa(LiftedSyscallUntypedSsa),
    IntrinsicSsa(LiftedIntrinsicSsa),
    TailcallUntypedSsa(LiftedCallUntypedSsa),
    LoadSsa(LiftedLoadSsa),
    LoadStructSsa(LiftedLoadStructSsa),

    SetVarAliased(LiftedSetVarAliased),
    SetVarAliasedField(LiftedSetVarSsaField),
    VarPhi(LiftedVarPhi),
    VarAliased(VarSsa),
    VarAliasedField(VarSsaField),
}

impl Sealed for MediumLevelILLiftedInstructionKindSSA {}
impl MediumLevelILLiftedInstructionKindSSA {
    construct_common!(
        SSA,
        MediumLevelILInstructionKindSSA,
        MediumLevelILLiftedInstructionKindSSA
    );
    fn this_operands(&self) -> Vec<(&'static str, MediumLevelILLiftedOperand<SSA>)> {
        use MediumLevelILLiftedInstructionKindSSA::*;
        use MediumLevelILLiftedOperand as Operand;
        match self {
            StoreSsa(op) => vec![
                ("dest", Operand::Expr(*op.dest.clone())),
                ("dest_memory", Operand::Int(op.dest_memory)),
                ("src_memory", Operand::Int(op.src_memory)),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            StoreStructSsa(op) => vec![
                ("dest", Operand::Expr(*op.dest.clone())),
                ("offset", Operand::Int(op.offset)),
                ("dest_memory", Operand::Int(op.dest_memory)),
                ("src_memory", Operand::Int(op.src_memory)),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            FreeVarSlotSsa(op) => vec![
                ("dest", Operand::VarSsa(op.dest)),
                ("prev", Operand::VarSsa(op.prev)),
            ],
            SetVarSsaField(op) | SetVarAliasedField(op) => vec![
                ("dest", Operand::VarSsa(op.dest)),
                ("prev", Operand::VarSsa(op.prev)),
                ("offset", Operand::Int(op.offset)),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            SetVarAliased(op) => vec![
                ("dest", Operand::VarSsa(op.dest)),
                ("prev", Operand::VarSsa(op.prev)),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            SetVarSsa(op) => vec![
                ("dest", Operand::VarSsa(op.dest)),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            VarPhi(op) => vec![
                ("dest", Operand::VarSsa(op.dest)),
                ("src", Operand::VarSsaList(op.src.clone())),
            ],
            VarSplitSsa(op) => vec![
                ("high", Operand::VarSsa(op.high)),
                ("low", Operand::VarSsa(op.low)),
            ],
            SetVarSplitSsa(op) => vec![
                ("high", Operand::VarSsa(op.high)),
                ("low", Operand::VarSsa(op.low)),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            IntrinsicSsa(op) => vec![
                ("output", Operand::VarSsaList(op.output.clone())),
                ("intrinsic", Operand::Intrinsic(op.intrinsic)),
                ("params", Operand::ExprList(op.params.clone())),
            ],
            CallSsa(op) | TailcallSsa(op) => vec![
                ("output", Operand::VarSsaList(op.output.clone())),
                ("dest", Operand::Expr(*op.dest.clone())),
                ("params", Operand::ExprList(op.params.clone())),
                ("src_memory", Operand::Int(op.src_memory)),
            ],
            CallUntypedSsa(op) | TailcallUntypedSsa(op) => vec![
                ("output", Operand::VarSsaList(op.output.clone())),
                ("dest", Operand::Expr(*op.dest.clone())),
                ("params", Operand::ExprList(op.params.clone())),
                ("stack", Operand::Expr(*op.stack.clone())),
            ],
            SyscallSsa(op) => vec![
                ("output", Operand::VarSsaList(op.output.clone())),
                ("params", Operand::ExprList(op.params.clone())),
                ("src_memory", Operand::Int(op.src_memory)),
            ],
            SyscallUntypedSsa(op) => vec![
                ("output", Operand::VarSsaList(op.output.clone())),
                ("params", Operand::ExprList(op.params.clone())),
                ("stack", Operand::Expr(*op.stack.clone())),
            ],
            LoadStructSsa(op) => vec![
                ("src", Operand::Expr(*op.src.clone())),
                ("offset", Operand::Int(op.offset)),
                ("src_memory", Operand::Int(op.src_memory)),
            ],
            LoadSsa(op) => vec![
                ("src", Operand::Expr(*op.src.clone())),
                ("src_memory", Operand::Int(op.src_memory)),
            ],
            VarSsa(op) | VarAliased(op) => vec![("src", Operand::VarSsa(op.src))],
            VarSsaField(op) | VarAliasedField(op) => vec![
                ("src", Operand::VarSsa(op.src)),
                ("offset", Operand::Int(op.offset)),
            ],
            _ => unreachable!(),
        }
    }
    fn this_from_instruction(inst: &MediumLevelILInstruction<SSA>) -> Self {
        use MediumLevelILInstructionKindSSA::*;
        use MediumLevelILLiftedInstructionKindSSA as Lifted;
        match &inst.kind {
            VarSsa(op) => Lifted::VarSsa(*op),
            VarSsaField(op) => Lifted::VarSsaField(*op),
            StoreSsa(op) => Lifted::StoreSsa(op.lift(inst)),
            StoreStructSsa(op) => Lifted::StoreStructSsa(op.lift(inst)),
            SetVarSsa(op) => Lifted::SetVarSsa(op.lift(inst)),
            SetVarSsaField(op) => Lifted::SetVarSsaField(op.lift(inst)),
            FreeVarSlotSsa(op) => Lifted::FreeVarSlotSsa(*op),
            VarSplitSsa(op) => Lifted::VarSplitSsa(*op),
            SetVarSplitSsa(op) => Lifted::SetVarSplitSsa(op.lift(inst)),
            CallSsa(op) => Lifted::CallSsa(op.lift(inst)),
            CallUntypedSsa(op) => Lifted::CallUntypedSsa(op.lift(inst)),
            TailcallSsa(op) => Lifted::TailcallSsa(op.lift(inst)),
            SyscallSsa(op) => Lifted::SyscallSsa(op.lift(inst)),
            SyscallUntypedSsa(op) => Lifted::SyscallUntypedSsa(op.lift(inst)),
            IntrinsicSsa(op) => Lifted::IntrinsicSsa(op.lift(inst)),
            TailcallUntypedSsa(op) => Lifted::TailcallUntypedSsa(op.lift(inst)),
            LoadSsa(op) => Lifted::LoadSsa(op.lift(inst)),
            LoadStructSsa(op) => Lifted::LoadStructSsa(op.lift(inst)),

            SetVarAliased(op) => Lifted::SetVarAliased(op.lift(inst)),
            SetVarAliasedField(op) => Lifted::SetVarAliasedField(op.lift(inst)),
            VarPhi(op) => Lifted::VarPhi(op.lift(inst)),
            VarAliased(op) => Lifted::VarAliased(*op),
            VarAliasedField(op) => Lifted::VarAliasedField(*op),
            _ => unreachable!(),
        }
    }
}

impl InstructionLiftedTrait<SSA> for MediumLevelILLiftedInstructionKindSSA {
    fn name(&self) -> &'static str {
        self.into()
    }

    fn from_instruction(inst: &MediumLevelILInstruction<SSA>) -> Self {
        Self::common_from_instruction(inst).unwrap_or_else(|| Self::this_from_instruction(inst))
    }

    fn operands(&self) -> Vec<(&'static str, MediumLevelILLiftedOperand<SSA>)> {
        self.common_operands()
            .unwrap_or_else(|| self.this_operands())
    }
}

impl<I: Form> MediumLevelILLiftedInstruction<I> {
    pub fn name(&self) -> &'static str {
        self.kind.name()
    }
    pub fn operands(&self) -> Vec<(&'static str, MediumLevelILLiftedOperand<I>)> {
        self.kind.operands()
    }
}

impl MediumLevelILOperationIf {
    pub fn lift<I: Form>(&self, inst: &MediumLevelILInstruction<I>) -> LiftedIf<I> {
        LiftedIf {
            condition: inst.lift_operand(self.condition),
            dest_true: self.dest_true,
            dest_false: self.dest_false,
        }
    }
}
impl ConstData {
    pub fn lift<I: Form>(&self, inst: &MediumLevelILInstruction<I>) -> LiftedConstData {
        LiftedConstData {
            constant_data: ConstantData::new(
                inst.function.get_function(),
                RegisterValue {
                    state: RegisterValueType::from_raw_value(self.constant_data_kind).unwrap(),
                    value: self.constant_data_value,
                    offset: 0,
                    size: self.size,
                },
            ),
        }
    }
}
impl Jump {
    pub fn lift<I: Form>(&self, inst: &MediumLevelILInstruction<I>) -> LiftedJump<I> {
        LiftedJump {
            dest: inst.lift_operand(self.dest),
        }
    }
}
impl JumpTo {
    pub fn lift<I: Form>(&self, inst: &MediumLevelILInstruction<I>) -> LiftedJumpTo<I> {
        LiftedJumpTo {
            dest: inst.lift_operand(self.dest),
            targets: OperandIter::new(&*inst.function, self.first_operand, self.num_operands)
                .pairs()
                .collect(),
        }
    }
}
impl StoreSsa {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedStoreSsa {
        LiftedStoreSsa {
            dest: inst.lift_operand(self.dest),
            dest_memory: self.dest_memory,
            src_memory: self.src_memory,
            src: inst.lift_operand(self.src),
        }
    }
}

impl StoreStructSsa {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedStoreStructSsa {
        LiftedStoreStructSsa {
            dest: inst.lift_operand(self.dest),
            offset: self.offset,
            dest_memory: self.dest_memory,
            src_memory: self.src_memory,
            src: inst.lift_operand(self.src),
        }
    }
}
impl StoreStruct {
    pub fn lift(&self, inst: &MediumLevelILInstruction<NonSSA>) -> LiftedStoreStruct {
        LiftedStoreStruct {
            dest: inst.lift_operand(self.dest),
            offset: self.offset,
            src: inst.lift_operand(self.src),
        }
    }
}
impl Store {
    pub fn lift(&self, inst: &MediumLevelILInstruction<NonSSA>) -> LiftedStore {
        LiftedStore {
            dest: inst.lift_operand(self.dest),
            src: inst.lift_operand(self.src),
        }
    }
}
impl SetVarField {
    pub fn lift(&self, inst: &MediumLevelILInstruction<NonSSA>) -> LiftedSetVarField {
        LiftedSetVarField {
            dest: self.dest,
            offset: self.offset,
            src: inst.lift_operand(self.src),
        }
    }
}
impl SetVar {
    pub fn lift(&self, inst: &MediumLevelILInstruction<NonSSA>) -> LiftedSetVar {
        LiftedSetVar {
            dest: self.dest,
            src: inst.lift_operand(self.src),
        }
    }
}
impl SetVarSsaField {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedSetVarSsaField {
        LiftedSetVarSsaField {
            dest: self.dest,
            prev: self.prev,
            offset: self.offset,
            src: inst.lift_operand(self.src),
        }
    }
}
impl SetVarAliased {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedSetVarAliased {
        LiftedSetVarAliased {
            dest: self.dest,
            prev: self.prev,
            src: inst.lift_operand(self.src),
        }
    }
}
impl SetVarSsa {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedSetVarSsa {
        LiftedSetVarSsa {
            dest: self.dest,
            src: inst.lift_operand(self.src),
        }
    }
}
impl VarPhi {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedVarPhi {
        LiftedVarPhi {
            dest: self.dest,
            src: OperandIter::new(&*inst.function, self.first_operand, self.num_operands)
                .ssa_vars()
                .collect(),
        }
    }
}
impl MemPhi {
    pub fn lift<I: Form>(&self, inst: &MediumLevelILInstruction<I>) -> LiftedMemPhi {
        LiftedMemPhi {
            dest_memory: self.dest_memory,
            src_memory: OperandIter::new(&*inst.function, self.first_operand, self.num_operands)
                .collect(),
        }
    }
}
impl SetVarSplit {
    pub fn lift(&self, inst: &MediumLevelILInstruction<NonSSA>) -> LiftedSetVarSplit {
        LiftedSetVarSplit {
            high: self.high,
            low: self.low,
            src: inst.lift_operand(self.src),
        }
    }
}
impl SetVarSplitSsa {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedSetVarSplitSsa {
        LiftedSetVarSplitSsa {
            high: self.high,
            low: self.low,
            src: inst.lift_operand(self.src),
        }
    }
}
impl UnaryOp {
    pub fn lift<I: Form>(&self, inst: &MediumLevelILInstruction<I>) -> LiftedUnaryOp<I> {
        LiftedUnaryOp {
            src: inst.lift_operand(self.src),
        }
    }
}
impl BinaryOp {
    pub fn lift<I: Form>(&self, inst: &MediumLevelILInstruction<I>) -> LiftedBinaryOp<I> {
        LiftedBinaryOp {
            left: inst.lift_operand(self.left),
            right: inst.lift_operand(self.right),
        }
    }
}
impl BinaryOpCarry {
    pub fn lift<I: Form>(&self, inst: &MediumLevelILInstruction<I>) -> LiftedBinaryOpCarry<I> {
        LiftedBinaryOpCarry {
            left: inst.lift_operand(self.left),
            right: inst.lift_operand(self.right),
            carry: inst.lift_operand(self.carry),
        }
    }
}
impl Call {
    pub fn lift(&self, inst: &MediumLevelILInstruction<NonSSA>) -> LiftedCall {
        LiftedCall {
            output: OperandIter::new(&*inst.function, self.first_output, self.num_outputs)
                .vars()
                .collect(),
            dest: inst.lift_operand(self.dest),
            params: OperandIter::new(&*inst.function, self.first_param, self.num_params)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
        }
    }
}
impl CallSsa {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedCallSsa {
        LiftedCallSsa {
            output: inst.get_call_output_ssa(self.output).collect(),
            dest: inst.lift_operand(self.dest),
            params: OperandIter::new(&*inst.function, self.first_param, self.num_params)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
            src_memory: self.src_memory,
        }
    }
}
impl CallUntyped {
    pub fn lift(&self, inst: &MediumLevelILInstruction<NonSSA>) -> LiftedCallUntyped {
        LiftedCallUntyped {
            output: inst.get_call_output(self.output).collect(),
            dest: inst.lift_operand(self.dest),
            params: inst
                .get_call_params(self.params)
                .map(|expr| expr.lift())
                .collect(),
            stack: inst.lift_operand(self.stack),
        }
    }
}
impl CallUntypedSsa {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedCallUntypedSsa {
        LiftedCallUntypedSsa {
            output: inst.get_call_output_ssa(self.output).collect(),
            dest: inst.lift_operand(self.dest),
            params: inst
                .get_call_params_ssa(self.params)
                .map(|param| param.lift())
                .collect(),
            stack: inst.lift_operand(self.stack),
        }
    }
}
impl Intrinsic {
    pub fn lift(&self, inst: &MediumLevelILInstruction<NonSSA>) -> LiftedIntrinsic {
        LiftedIntrinsic {
            output: OperandIter::new(&*inst.function, self.first_output, self.num_outputs)
                .vars()
                .collect(),
            intrinsic: ILIntrinsic::new(inst.function.get_function().arch(), self.intrinsic),
            params: OperandIter::new(&*inst.function, self.first_param, self.num_params)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
        }
    }
}
impl Syscall {
    pub fn lift(&self, inst: &MediumLevelILInstruction<NonSSA>) -> LiftedSyscall {
        LiftedSyscall {
            output: OperandIter::new(&*inst.function, self.first_output, self.num_outputs)
                .vars()
                .collect(),
            params: OperandIter::new(&*inst.function, self.first_param, self.num_params)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
        }
    }
}
impl IntrinsicSsa {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedIntrinsicSsa {
        LiftedIntrinsicSsa {
            output: OperandIter::new(&*inst.function, self.first_output, self.num_outputs)
                .ssa_vars()
                .collect(),
            intrinsic: ILIntrinsic::new(inst.function.get_function().arch(), self.intrinsic),
            params: OperandIter::new(&*inst.function, self.first_param, self.num_params)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
        }
    }
}

impl SyscallSsa {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedSyscallSsa {
        LiftedSyscallSsa {
            output: inst.get_call_output_ssa(self.output).collect(),
            params: OperandIter::new(&*inst.function, self.first_param, self.num_params)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
            src_memory: self.src_memory,
        }
    }
}
impl SyscallUntypedSsa {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedSyscallUntypedSsa {
        LiftedSyscallUntypedSsa {
            output: inst.get_call_output_ssa(self.output).collect(),
            params: inst
                .get_call_params_ssa(self.params)
                .map(|param| param.lift())
                .collect(),
            stack: inst.lift_operand(self.stack),
        }
    }
}

impl SyscallUntyped {
    pub fn lift(&self, inst: &MediumLevelILInstruction<NonSSA>) -> LiftedSyscallUntyped {
        LiftedSyscallUntyped {
            output: inst.get_call_output(self.output).collect(),
            params: inst
                .get_call_params(self.params)
                .map(|param| param.lift())
                .collect(),
            stack: inst.lift_operand(self.stack),
        }
    }
}

impl LoadStruct {
    pub fn lift(&self, inst: &MediumLevelILInstruction<NonSSA>) -> LiftedLoadStruct {
        LiftedLoadStruct {
            src: inst.lift_operand(self.src),
            offset: self.offset,
        }
    }
}
impl LoadStructSsa {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedLoadStructSsa {
        LiftedLoadStructSsa {
            src: inst.lift_operand(self.src),
            offset: self.offset,
            src_memory: self.src_memory,
        }
    }
}
impl LoadSsa {
    pub fn lift(&self, inst: &MediumLevelILInstruction<SSA>) -> LiftedLoadSsa {
        LiftedLoadSsa {
            src: inst.lift_operand(self.src),
            src_memory: self.src_memory,
        }
    }
}
impl Ret {
    pub fn lift<I: Form>(&self, inst: &MediumLevelILInstruction<I>) -> LiftedRet<I> {
        LiftedRet {
            src: OperandIter::new(&*inst.function, self.first_operand, self.num_operands)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
        }
    }
}
impl SeparateParamList {
    pub fn lift<I: Form>(&self, inst: &MediumLevelILInstruction<I>) -> LiftedSeparateParamList<I> {
        LiftedSeparateParamList {
            params: OperandIter::new(&*inst.function, self.first_param, self.num_params)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
        }
    }
}
impl SharedParamSlot {
    pub fn lift<I: Form>(&self, inst: &MediumLevelILInstruction<I>) -> LiftedSharedParamSlot<I> {
        LiftedSharedParamSlot {
            params: OperandIter::new(&*inst.function, self.first_param, self.num_params)
                .exprs()
                .map(|expr| expr.lift())
                .collect(),
        }
    }
}
