use std::collections::BTreeMap;

use crate::operand_iter::OperandIter;
use crate::rc::Ref;
use crate::types::{
    ConstantData, ILIntrinsic, RegisterValue, RegisterValueType, SSAVariable, Variable,
};

use super::operation::*;
use super::MediumLevelILFunction;
use super::*;

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
    pub kind: MediumLevelILLiftedInstructionKind<I>,
}

#[derive(Clone, Debug, IntoStaticStr)]
pub enum MediumLevelILLiftedInstructionKind<I: Form> {
    Nop,
    Noret,
    Bp,
    Undef,
    Unimpl,
    If(LiftedIf<I>),
    FloatConst(FloatConst),
    Const(Constant),
    ConstPtr(Constant),
    Import(Constant),
    ExternPtr(ExternPtr),
    ConstData(LiftedConstData),
    Jump(LiftedJump<I>),
    RetHint(LiftedJump<I>),
    JumpTo(LiftedJumpTo<I>),
    Goto(Goto),
    Add(LiftedBinaryOp<I>),
    Sub(LiftedBinaryOp<I>),
    And(LiftedBinaryOp<I>),
    Or(LiftedBinaryOp<I>),
    Xor(LiftedBinaryOp<I>),
    Lsl(LiftedBinaryOp<I>),
    Lsr(LiftedBinaryOp<I>),
    Asr(LiftedBinaryOp<I>),
    Rol(LiftedBinaryOp<I>),
    Ror(LiftedBinaryOp<I>),
    Mul(LiftedBinaryOp<I>),
    MuluDp(LiftedBinaryOp<I>),
    MulsDp(LiftedBinaryOp<I>),
    Divu(LiftedBinaryOp<I>),
    DivuDp(LiftedBinaryOp<I>),
    Divs(LiftedBinaryOp<I>),
    DivsDp(LiftedBinaryOp<I>),
    Modu(LiftedBinaryOp<I>),
    ModuDp(LiftedBinaryOp<I>),
    Mods(LiftedBinaryOp<I>),
    ModsDp(LiftedBinaryOp<I>),
    CmpE(LiftedBinaryOp<I>),
    CmpNe(LiftedBinaryOp<I>),
    CmpSlt(LiftedBinaryOp<I>),
    CmpUlt(LiftedBinaryOp<I>),
    CmpSle(LiftedBinaryOp<I>),
    CmpUle(LiftedBinaryOp<I>),
    CmpSge(LiftedBinaryOp<I>),
    CmpUge(LiftedBinaryOp<I>),
    CmpSgt(LiftedBinaryOp<I>),
    CmpUgt(LiftedBinaryOp<I>),
    TestBit(LiftedBinaryOp<I>),
    AddOverflow(LiftedBinaryOp<I>),
    FcmpE(LiftedBinaryOp<I>),
    FcmpNe(LiftedBinaryOp<I>),
    FcmpLt(LiftedBinaryOp<I>),
    FcmpLe(LiftedBinaryOp<I>),
    FcmpGe(LiftedBinaryOp<I>),
    FcmpGt(LiftedBinaryOp<I>),
    FcmpO(LiftedBinaryOp<I>),
    FcmpUo(LiftedBinaryOp<I>),
    Fadd(LiftedBinaryOp<I>),
    Fsub(LiftedBinaryOp<I>),
    Fmul(LiftedBinaryOp<I>),
    Fdiv(LiftedBinaryOp<I>),
    Adc(LiftedBinaryOpCarry<I>),
    Sbb(LiftedBinaryOpCarry<I>),
    Rlc(LiftedBinaryOpCarry<I>),
    Rrc(LiftedBinaryOpCarry<I>),
    Neg(LiftedUnaryOp<I>),
    Not(LiftedUnaryOp<I>),
    Sx(LiftedUnaryOp<I>),
    Zx(LiftedUnaryOp<I>),
    LowPart(LiftedUnaryOp<I>),
    BoolToInt(LiftedUnaryOp<I>),
    UnimplMem(LiftedUnaryOp<I>),
    Fsqrt(LiftedUnaryOp<I>),
    Fneg(LiftedUnaryOp<I>),
    Fabs(LiftedUnaryOp<I>),
    FloatToInt(LiftedUnaryOp<I>),
    IntToFloat(LiftedUnaryOp<I>),
    FloatConv(LiftedUnaryOp<I>),
    RoundToInt(LiftedUnaryOp<I>),
    Floor(LiftedUnaryOp<I>),
    Ceil(LiftedUnaryOp<I>),
    Ftrunc(LiftedUnaryOp<I>),
    Ret(LiftedRet<I>),

    MemPhi(LiftedMemPhi),
    SeparateParamList(LiftedSeparateParamList<I>),
    SharedParamSlot(LiftedSharedParamSlot<I>),

    AddressOf(Var),
    AddressOfField(Field),
    Trap(Trap),

    Form(I::InstructionLifted),
}

#[derive(Clone, Debug, IntoStaticStr)]
pub enum MediumLevelILLiftedInstructionKindNonSSA {
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
impl InstructionLiftedTrait<NonSSA> for MediumLevelILLiftedInstructionKindNonSSA {
    fn name(&self) -> &'static str {
        self.into()
    }

    fn from_instruction(
        inst: &MediumLevelILInstruction<NonSSA>,
        kind: &MediumLevelILInstructionKindNonSSA,
    ) -> Self {
        use MediumLevelILInstructionKindNonSSA::*;
        use MediumLevelILLiftedInstructionKindNonSSA as Lifted;
        match kind {
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
        }
    }

    fn operands(&self) -> Vec<(&'static str, MediumLevelILLiftedOperand<NonSSA>)> {
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
        }
    }
}

#[derive(Clone, Debug, IntoStaticStr)]
pub enum MediumLevelILLiftedInstructionKindSSA {
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
impl InstructionLiftedTrait<SSA> for MediumLevelILLiftedInstructionKindSSA {
    fn name(&self) -> &'static str {
        self.into()
    }

    fn from_instruction(inst: &MediumLevelILInstruction<SSA>, kind: &<SSA as Form>::Instruction) -> Self {
        use MediumLevelILInstructionKindSSA::*;
        use MediumLevelILLiftedInstructionKindSSA as Lifted;
        match kind {
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
        }
    }

    fn operands(&self) -> Vec<(&'static str, MediumLevelILLiftedOperand<SSA>)> {
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
        }
    }
}

impl<I: Form> MediumLevelILLiftedInstructionKind<I> {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Form(op) => op.name(),
            _ => self.into()
        }
    }

    pub fn operands(&self) -> Vec<(&'static str, MediumLevelILLiftedOperand<I>)> {
        use MediumLevelILLiftedInstructionKind::*;
        use MediumLevelILLiftedOperand as Operand;
        match self {
            Nop | Noret | Bp | Undef | Unimpl => vec![],
            If(op) => vec![
                ("condition", Operand::Expr(*op.condition.clone())),
                ("dest_true", Operand::Int(op.dest_true)),
                ("dest_false", Operand::Int(op.dest_false)),
            ],
            FloatConst(op) => vec![("constant", Operand::Float(op.constant))],
            Const(op) | ConstPtr(op) | Import(op) => vec![("constant", Operand::Int(op.constant))],
            ExternPtr(op) => vec![
                ("constant", Operand::Int(op.constant)),
                ("offset", Operand::Int(op.offset)),
            ],
            ConstData(op) => vec![(
                "constant_data",
                Operand::ConstantData(op.constant_data.clone()),
            )],
            Jump(op) | RetHint(op) => vec![("dest", Operand::Expr(*op.dest.clone()))],
            JumpTo(op) => vec![
                ("dest", Operand::Expr(*op.dest.clone())),
                ("targets", Operand::TargetMap(op.targets.clone())),
            ],
            Goto(op) => vec![("dest", Operand::Int(op.dest))],
            MemPhi(op) => vec![
                ("dest_memory", Operand::Int(op.dest_memory)),
                ("src_memory", Operand::IntList(op.src_memory.clone())),
            ],
            Add(op) | Sub(op) | And(op) | Or(op) | Xor(op) | Lsl(op) | Lsr(op) | Asr(op)
            | Rol(op) | Ror(op) | Mul(op) | MuluDp(op) | MulsDp(op) | Divu(op) | DivuDp(op)
            | Divs(op) | DivsDp(op) | Modu(op) | ModuDp(op) | Mods(op) | ModsDp(op) | CmpE(op)
            | CmpNe(op) | CmpSlt(op) | CmpUlt(op) | CmpSle(op) | CmpUle(op) | CmpSge(op)
            | CmpUge(op) | CmpSgt(op) | CmpUgt(op) | TestBit(op) | AddOverflow(op) | FcmpE(op)
            | FcmpNe(op) | FcmpLt(op) | FcmpLe(op) | FcmpGe(op) | FcmpGt(op) | FcmpO(op)
            | FcmpUo(op) | Fadd(op) | Fsub(op) | Fmul(op) | Fdiv(op) => vec![
                ("left", Operand::Expr(*op.left.clone())),
                ("right", Operand::Expr(*op.right.clone())),
            ],
            Adc(op) | Sbb(op) | Rlc(op) | Rrc(op) => vec![
                ("left", Operand::Expr(*op.left.clone())),
                ("right", Operand::Expr(*op.right.clone())),
                ("carry", Operand::Expr(*op.carry.clone())),
            ],
            Neg(op) | Not(op) | Sx(op) | Zx(op) | LowPart(op) | BoolToInt(op) | UnimplMem(op)
            | Fsqrt(op) | Fneg(op) | Fabs(op) | FloatToInt(op) | IntToFloat(op) | FloatConv(op)
            | RoundToInt(op) | Floor(op) | Ceil(op) | Ftrunc(op) => {
                vec![("src", Operand::Expr(*op.src.clone()))]
            }
            Ret(op) => vec![("src", Operand::ExprList(op.src.clone()))],
            SeparateParamList(op) => vec![("params", Operand::ExprList(op.params.clone()))],
            SharedParamSlot(op) => vec![("params", Operand::ExprList(op.params.clone()))],
            AddressOf(op) => vec![("src", Operand::Var(op.src))],
            AddressOfField(op) => vec![
                ("src", Operand::Var(op.src)),
                ("offset", Operand::Int(op.offset)),
            ],
            Trap(op) => vec![("vector", Operand::Int(op.vector))],

            Form(op) => op.operands(),
        }
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
