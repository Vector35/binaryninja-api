use std::collections::HashMap;

use crate::rc::Ref;
use crate::types;
use crate::types::ILIntrinsic;
use crate::types::{SSAVariable, Variable};

use super::operation::*;
use super::MediumLevelILFunction;

#[derive(Clone)]
pub enum MediumLevelILLiftedOperand {
    ConstantData(types::ConstantData),
    Intrinsic(ILIntrinsic),
    Expr(MediumLevelILLiftedInstruction),
    ExprList(Vec<MediumLevelILLiftedInstruction>),
    Float(f64),
    Int(u64),
    IntList(Vec<u64>),
    TargetMap(HashMap<u64, u64>),
    Var(Variable),
    VarList(Vec<Variable>),
    VarSsa(SSAVariable),
    VarSsaList(Vec<SSAVariable>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct MediumLevelILLiftedInstruction {
    pub function: Ref<MediumLevelILFunction>,
    pub address: u64,
    pub kind: MediumLevelILLiftedInstructionKind,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MediumLevelILLiftedInstructionKind {
    Nop,
    Noret,
    Bp,
    Undef,
    Unimpl,
    If(LiftedIf),
    FloatConst(FloatConst),
    Const(Constant),
    ConstPtr(Constant),
    Import(Constant),
    ExternPtr(ExternPtr),
    ConstData(LiftedConstantData),
    Jump(LiftedJump),
    RetHint(LiftedJump),
    StoreSsa(LiftedStoreSsa),
    StoreStructSsa(LiftedStoreStructSsa),
    StoreStruct(LiftedStoreStruct),
    Store(LiftedStore),
    JumpTo(LiftedJumpTo),
    Goto(Goto),
    FreeVarSlot(FreeVarSlot),
    SetVarField(LiftedSetVarField),
    SetVar(LiftedSetVar),
    FreeVarSlotSsa(FreeVarSlotSsa),
    SetVarSsaField(LiftedSetVarSsaField),
    SetVarAliasedField(LiftedSetVarSsaField),
    SetVarAliased(LiftedSetVarAliased),
    SetVarSsa(LiftedSetVarSsa),
    VarPhi(LiftedVarPhi),
    MemPhi(LiftedMemPhi),
    VarSplit(VarSplit),
    SetVarSplit(LiftedSetVarSplit),
    VarSplitSsa(VarSplitSsa),
    SetVarSplitSsa(LiftedSetVarSplitSsa),
    Add(LiftedBinaryOp),
    Sub(LiftedBinaryOp),
    And(LiftedBinaryOp),
    Or(LiftedBinaryOp),
    Xor(LiftedBinaryOp),
    Lsl(LiftedBinaryOp),
    Lsr(LiftedBinaryOp),
    Asr(LiftedBinaryOp),
    Rol(LiftedBinaryOp),
    Ror(LiftedBinaryOp),
    Mul(LiftedBinaryOp),
    MuluDp(LiftedBinaryOp),
    MulsDp(LiftedBinaryOp),
    Divu(LiftedBinaryOp),
    DivuDp(LiftedBinaryOp),
    Divs(LiftedBinaryOp),
    DivsDp(LiftedBinaryOp),
    Modu(LiftedBinaryOp),
    ModuDp(LiftedBinaryOp),
    Mods(LiftedBinaryOp),
    ModsDp(LiftedBinaryOp),
    CmpE(LiftedBinaryOp),
    CmpNe(LiftedBinaryOp),
    CmpSlt(LiftedBinaryOp),
    CmpUlt(LiftedBinaryOp),
    CmpSle(LiftedBinaryOp),
    CmpUle(LiftedBinaryOp),
    CmpSge(LiftedBinaryOp),
    CmpUge(LiftedBinaryOp),
    CmpSgt(LiftedBinaryOp),
    CmpUgt(LiftedBinaryOp),
    TestBit(LiftedBinaryOp),
    AddOverflow(LiftedBinaryOp),
    FcmpE(LiftedBinaryOp),
    FcmpNe(LiftedBinaryOp),
    FcmpLt(LiftedBinaryOp),
    FcmpLe(LiftedBinaryOp),
    FcmpGe(LiftedBinaryOp),
    FcmpGt(LiftedBinaryOp),
    FcmpO(LiftedBinaryOp),
    FcmpUo(LiftedBinaryOp),
    Fadd(LiftedBinaryOp),
    Fsub(LiftedBinaryOp),
    Fmul(LiftedBinaryOp),
    Fdiv(LiftedBinaryOp),
    Adc(LiftedBinaryOpCarry),
    Sbb(LiftedBinaryOpCarry),
    Rlc(LiftedBinaryOpCarry),
    Rrc(LiftedBinaryOpCarry),
    Call(LiftedCall),
    Tailcall(LiftedCall),
    Intrinsic(LiftedIntrinsic),
    Syscall(LiftedSyscallCall),
    IntrinsicSsa(LiftedIntrinsicSsa),
    CallSsa(LiftedCallSsa),
    TailcallSsa(LiftedCallSsa),
    CallUntypedSsa(LiftedCallUntypedSsa),
    TailcallUntypedSsa(LiftedCallUntypedSsa),
    SyscallSsa(LiftedSyscallSsa),
    SyscallUntypedSsa(LiftedSyscallUntypedSsa),
    CallUntyped(LiftedCallUntyped),
    TailcallUntyped(LiftedCallUntyped),
    SyscallUntyped(LiftedSyscallUntyped),
    SeparateParamList(LiftedSeparateParamList),
    SharedParamSlot(LiftedSharedParamSlot),
    Neg(LiftedUnaryOp),
    Not(LiftedUnaryOp),
    Sx(LiftedUnaryOp),
    Zx(LiftedUnaryOp),
    LowPart(LiftedUnaryOp),
    BoolToInt(LiftedUnaryOp),
    UnimplMem(LiftedUnaryOp),
    Fsqrt(LiftedUnaryOp),
    Fneg(LiftedUnaryOp),
    Fabs(LiftedUnaryOp),
    FloatToInt(LiftedUnaryOp),
    IntToFloat(LiftedUnaryOp),
    FloatConv(LiftedUnaryOp),
    RoundToInt(LiftedUnaryOp),
    Floor(LiftedUnaryOp),
    Ceil(LiftedUnaryOp),
    Ftrunc(LiftedUnaryOp),
    Load(LiftedUnaryOp),
    LoadStruct(LiftedLoadStruct),
    LoadStructSsa(LiftedLoadStructSsa),
    LoadSsa(LiftedLoadSsa),
    Ret(LiftedRet),
    Var(Var),
    AddressOf(Var),
    VarField(Field),
    AddressOfField(Field),
    VarSsa(VarSsa),
    VarAliased(VarSsa),
    VarSsaField(VarSsaField),
    VarAliasedField(VarSsaField),
    Trap(Trap),
}

impl MediumLevelILLiftedInstruction {
    pub fn operands(&self) -> Vec<(&'static str, MediumLevelILLiftedOperand)> {
        use MediumLevelILLiftedInstructionKind::*;
        use MediumLevelILLiftedOperand as Operand;
        match &self.kind {
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
            StoreStruct(op) => vec![
                ("dest", Operand::Expr(*op.dest.clone())),
                ("offset", Operand::Int(op.offset)),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            Store(op) => vec![
                ("dest", Operand::Expr(*op.dest.clone())),
                ("src", Operand::Expr(*op.src.clone())),
            ],
            JumpTo(op) => vec![
                ("dest", Operand::Expr(*op.dest.clone())),
                ("targets", Operand::TargetMap(op.targets.clone())),
            ],
            Goto(op) => vec![("dest", Operand::Int(op.dest))],
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
            MemPhi(op) => vec![
                ("dest_memory", Operand::Int(op.dest_memory)),
                ("src_memory", Operand::IntList(op.src_memory.clone())),
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
            VarSplitSsa(op) => vec![
                ("high", Operand::VarSsa(op.high)),
                ("low", Operand::VarSsa(op.low)),
            ],
            SetVarSplitSsa(op) => vec![
                ("high", Operand::VarSsa(op.high)),
                ("low", Operand::VarSsa(op.low)),
                ("src", Operand::Expr(*op.src.clone())),
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
            Neg(op) | Not(op) | Sx(op) | Zx(op) | LowPart(op) | BoolToInt(op) | UnimplMem(op)
            | Fsqrt(op) | Fneg(op) | Fabs(op) | FloatToInt(op) | IntToFloat(op) | FloatConv(op)
            | RoundToInt(op) | Floor(op) | Ceil(op) | Ftrunc(op) | Load(op) => {
                vec![("src", Operand::Expr(*op.src.clone()))]
            }
            LoadStruct(op) => vec![
                ("src", Operand::Expr(*op.src.clone())),
                ("offset", Operand::Int(op.offset)),
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
            Ret(op) => vec![("src", Operand::ExprList(op.src.clone()))],
            SeparateParamList(op) => vec![("params", Operand::ExprList(op.params.clone()))],
            SharedParamSlot(op) => vec![("params", Operand::ExprList(op.params.clone()))],
            Var(op) | AddressOf(op) => vec![("src", Operand::Var(op.src))],
            VarField(op) | AddressOfField(op) => vec![
                ("src", Operand::Var(op.src)),
                ("offset", Operand::Int(op.offset)),
            ],
            VarSsa(op) | VarAliased(op) => vec![("src", Operand::VarSsa(op.src))],
            VarSsaField(op) | VarAliasedField(op) => vec![
                ("src", Operand::VarSsa(op.src)),
                ("offset", Operand::Int(op.offset)),
            ],
            Trap(op) => vec![("vector", Operand::Int(op.vector))],
        }
    }
}
