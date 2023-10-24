use crate::types::{SSAVariable, Variable};

use super::*;

#[derive(Debug, Clone)]
pub enum ExprLifted {
    Nop,
    NoRet,
    Bp,
    Undef,
    Unimpl,
    BinaryOpCarry {
        op_type: BinaryOpCarryType,
        left: Box<ExprLifted>,
        right: Box<ExprLifted>,
        carry: Box<ExprLifted>,
    },
    BinaryOp {
        op_type: BinaryOpType,
        left: Box<ExprLifted>,
        right: Box<ExprLifted>,
    },
    CallSSA {
        op_type: CallSSAType,
        output: Vec<SSAVariable>,
        dest: Box<ExprLifted>,
        params: Vec<ExprLifted>,
        src_memory: u64,
    },
    Call {
        op_type: CallType,
        output: Vec<Variable>,
        dest: Box<ExprLifted>,
        params: Vec<ExprLifted>,
    },
    CallUntypedSSA {
        op_type: CallUntypedSSAType,
        dest: Box<ExprLifted>,
        stack: Box<ExprLifted>,
        output: Vec<SSAVariable>,
        params: Vec<SSAVariable>,
    },
    CallUntyped {
        op_type: CallUntypedType,
        dest: Box<ExprLifted>,
        stack: Box<ExprLifted>,
        output: Vec<Variable>,
        params: Vec<Variable>,
    },
    Const {
        op_type: ConstType,
        constant: u64,
    },
    ConstData {
        //constant_data: TODO,
    },
    ExternPtr {
        constant: u64,
        offset: u64,
    },
    FloatConst {
        constant: f64,
    },
    FreeVarSlotSSA {
        dest: SSAVariable,
        prev: SSAVariable,
    },
    FreeVarSlot {
        dest: Variable,
    },
    Goto {
        dest: u64,
    },
    If {
        condition: Box<ExprLifted>,
        dest_true: u64,
        dest_false: u64,
    },
    IntrinsicSSA {
        //intrinsic: TODO,
        params: Vec<ExprLifted>,
        output: Vec<SSAVariable>,
    },
    Intrinsic {
        params: Vec<ExprLifted>,
        output: Vec<Variable>,
    },
    Jump {
        op_type: JumpType,
        dest: Box<ExprLifted>,
    },
    JumpTo {
        dest: Box<ExprLifted>,
        targets: Box<[(u64, u64)]>,
    },
    UnaryOp {
        op_type: UnaryOpType,
        src: Box<ExprLifted>,
    },
    Load {
        src: Box<ExprLifted>,
    },
    LoadSSA {
        src: Box<ExprLifted>,
        src_memory: u64,
    },
    LoadStruct {
        src: Box<ExprLifted>,
        offset: u64,
    },
    LoadStructSSA {
        src: Box<ExprLifted>,
        offset: u64,
        src_memory: u64,
    },
    MemPhi {
        dest_memory: u64,
        src_memory: Box<[u64]>,
    },
    Ret {
        src: Vec<ExprLifted>,
    },
    SetVarSSA {
        dest: SSAVariable,
        src: Box<ExprLifted>,
    },
    SetVar {
        dest: Variable,
        src: Box<ExprLifted>,
    },
    SetVarAliased {
        dest: SSAVariable,
        prev: SSAVariable,
        src: Box<ExprLifted>,
    },
    SetVarFieldSSA {
        op_type: SetVarFieldSSAType,
        dest: SSAVariable,
        prev: SSAVariable,
        offset: u64,
        src: Box<ExprLifted>,
    },
    SetVarField {
        dest: Variable,
        offset: u64,
        src: Box<ExprLifted>,
    },
    SetVarSplitSSA {
        high: SSAVariable,
        low: SSAVariable,
        src: Box<ExprLifted>,
    },
    SetVarSplit {
        high: Variable,
        low: Variable,
        src: Box<ExprLifted>,
    },
    StoreSSA {
        dest: Box<ExprLifted>,
        dest_memory: u64,
        src_memory: u64,
        src: Box<ExprLifted>,
    },
    Store {
        dest: Box<ExprLifted>,
        src: Box<ExprLifted>,
    },
    StoreStructSSA {
        dest: Box<ExprLifted>,
        offset: u64,
        dest_memory: u64,
        src_memory: u64,
        src: Box<ExprLifted>,
    },
    StoreStruct {
        dest: Box<ExprLifted>,
        offset: u64,
        src: Box<ExprLifted>,
    },
    SyscallSSA {
        output: Vec<SSAVariable>,
        params: Vec<ExprLifted>,
        src_memory: u64,
    },
    Syscall {
        output: Vec<Variable>,
        params: Vec<ExprLifted>,
    },
    SyscallUntypedSSA {
        stack: Box<ExprLifted>,
        output: Vec<SSAVariable>,
        params: Vec<SSAVariable>,
    },
    SyscallUntyped {
        stack: Box<ExprLifted>,
        output: Vec<Variable>,
        params: Vec<Variable>,
    },
    Trap {
        vector: u64,
    },
    VarSSA {
        op_type: VarSSAType,
        src: SSAVariable,
    },
    Var {
        src: Variable,
    },
    AddressOf {
        src: Variable,
    },
    VarFieldSSA {
        op_type: VarFieldSSAType,
        src: SSAVariable,
        offset: u64,
    },
    VarField {
        src: Variable,
        offset: u64,
    },
    AddressOfField {
        src: Variable,
        offset: u64,
    },
    VarPhi {
        dest: SSAVariable,
        src: Vec<SSAVariable>,
    },
    VarSplitSSA {
        high: SSAVariable,
        low: SSAVariable,
    },
    VarSplit {
        high: Variable,
        low: Variable,
    },
}

impl ExprLifted {
    pub(crate) unsafe fn new(info: ExprInfo) -> Self {
        match info {
            ExprInfo::Nop(_op) => Self::Nop,
            ExprInfo::NoRet(_op) => Self::NoRet,
            ExprInfo::Bp(_op) => Self::Bp,
            ExprInfo::Undef(_op) => Self::Undef,
            ExprInfo::Unimpl(_op) => Self::Unimpl,
            ExprInfo::BinaryOpCarry(op) => Self::BinaryOpCarry {
                left: Box::new(op.left().lift()),
                right: Box::new(op.right().lift()),
                carry: Box::new(op.carry().lift()),
                op_type: op.op_type(),
            },
            ExprInfo::BinaryOp(op) => Self::BinaryOp {
                left: Box::new(op.left().lift()),
                right: Box::new(op.right().lift()),
                op_type: op.op_type(),
            },
            ExprInfo::Call(op) => Self::Call {
                output: op.output().collect(),
                dest: Box::new(op.dest().lift()),
                params: op.params().map(|x| x.lift()).collect(),
                op_type: op.op_type(),
            },
            ExprInfo::CallSSA(op) => Self::CallSSA {
                output: op.output().collect(),
                dest: Box::new(op.dest().lift()),
                params: op.params().map(|x| x.lift()).collect(),
                src_memory: op.src_memory(),
                op_type: op.op_type(),
            },
            ExprInfo::CallUntyped(op) => Self::CallUntyped {
                output: op.output().collect(),
                dest: Box::new(op.dest().lift()),
                params: op.params().collect(),
                stack: Box::new(op.stack().lift()),
                op_type: op.op_type(),
            },
            ExprInfo::CallUntypedSSA(op) => Self::CallUntypedSSA {
                output: op.output().collect(),
                dest: Box::new(op.dest().lift()),
                params: op.params().collect(),
                stack: Box::new(op.stack().lift()),
                op_type: op.op_type(),
            },
            ExprInfo::Const(op) => Self::Const {
                constant: op.constant(),
                op_type: op.op_type(),
            },
            ExprInfo::ConstData(_op) => Self::ConstData {},
            ExprInfo::ExternPtr(op) => Self::ExternPtr {
                constant: op.constant(),
                offset: op.offset(),
            },
            ExprInfo::FloatConst(op) => Self::FloatConst {
                constant: op.constant(),
            },
            ExprInfo::FreeVarSlot(op) => Self::FreeVarSlot { dest: op.dest() },
            ExprInfo::FreeVarSlotSSA(op) => Self::FreeVarSlotSSA {
                dest: op.dest(),
                prev: op.prev(),
            },
            ExprInfo::Goto(op) => Self::Goto { dest: op.dest() },
            ExprInfo::If(op) => Self::If {
                condition: Box::new(op.condition().lift()),
                dest_true: op.dest_true(),
                dest_false: op.dest_false(),
            },
            ExprInfo::Intrinsic(op) => Self::Intrinsic {
                output: op.output().collect(),
                params: op.params().map(|x| x.lift()).collect(),
            },
            ExprInfo::IntrinsicSSA(op) => Self::IntrinsicSSA {
                output: op.output().collect(),
                params: op.params().map(|x| x.lift()).collect(),
            },
            ExprInfo::Jump(op) => Self::Jump {
                dest: Box::new(op.dest().lift()),
                op_type: op.op_type(),
            },
            ExprInfo::JumpTo(op) => Self::JumpTo {
                dest: Box::new(op.dest().lift()),
                targets: op.targets().collect(),
            },
            ExprInfo::UnaryOp(op) => Self::UnaryOp {
                src: Box::new(op.src().lift()),
                op_type: op.op_type(),
            },
            ExprInfo::Load(op) => Self::Load {
                src: Box::new(op.src().lift()),
            },
            ExprInfo::LoadSSA(op) => Self::LoadSSA {
                src: Box::new(op.src().lift()),
                src_memory: op.src_memory(),
            },
            ExprInfo::LoadStruct(op) => Self::LoadStruct {
                src: Box::new(op.src().lift()),
                offset: op.offset(),
            },
            ExprInfo::LoadStructSSA(op) => Self::LoadStructSSA {
                src: Box::new(op.src().lift()),
                offset: op.offset(),
                src_memory: op.src_memory(),
            },
            ExprInfo::MemPhi(op) => Self::MemPhi {
                dest_memory: op.dest_memory(),
                src_memory: op.src_memory().collect(),
            },
            ExprInfo::Ret(op) => Self::Ret {
                src: op.src().map(|x| x.lift()).collect(),
            },
            ExprInfo::SetVar(op) => Self::SetVar {
                dest: op.dest(),
                src: Box::new(op.src().lift()),
            },
            ExprInfo::SetVarSSA(op) => Self::SetVarSSA {
                dest: op.dest(),
                src: Box::new(op.src().lift()),
            },
            ExprInfo::SetVarAliased(op) => Self::SetVarAliased {
                dest: op.dest(),
                prev: op.prev(),
                src: Box::new(op.src().lift()),
            },
            ExprInfo::SetVarField(op) => Self::SetVarField {
                dest: op.dest(),
                offset: op.offset(),
                src: Box::new(op.src().lift()),
            },
            ExprInfo::SetVarFieldSSA(op) => Self::SetVarFieldSSA {
                dest: op.dest(),
                prev: op.prev(),
                offset: op.offset(),
                src: Box::new(op.src().lift()),
                op_type: op.op_type(),
            },
            ExprInfo::SetVarSplit(op) => Self::SetVarSplit {
                high: op.high(),
                low: op.low(),
                src: Box::new(op.src().lift()),
            },
            ExprInfo::SetVarSplitSSA(op) => Self::SetVarSplitSSA {
                high: op.high(),
                low: op.low(),
                src: Box::new(op.src().lift()),
            },
            ExprInfo::Store(op) => Self::Store {
                dest: Box::new(op.dest().lift()),
                src: Box::new(op.src().lift()),
            },
            ExprInfo::StoreSSA(op) => Self::StoreSSA {
                dest: Box::new(op.dest().lift()),
                dest_memory: op.dest_memory(),
                src_memory: op.src_memory(),
                src: Box::new(op.src().lift()),
            },
            ExprInfo::StoreStruct(op) => Self::StoreStruct {
                dest: Box::new(op.dest().lift()),
                offset: op.offset(),
                src: Box::new(op.src().lift()),
            },
            ExprInfo::StoreStructSSA(op) => Self::StoreStructSSA {
                dest: Box::new(op.dest().lift()),
                offset: op.offset(),
                dest_memory: op.dest_memory(),
                src_memory: op.src_memory(),
                src: Box::new(op.src().lift()),
            },
            ExprInfo::Syscall(op) => Self::Syscall {
                output: op.output().collect(),
                params: op.params().map(|x| x.lift()).collect(),
            },
            ExprInfo::SyscallSSA(op) => Self::SyscallSSA {
                output: op.output().collect(),
                params: op.params().map(|x| x.lift()).collect(),
                src_memory: op.src_memory(),
            },
            ExprInfo::SyscallUntyped(op) => Self::SyscallUntyped {
                output: op.output().collect(),
                params: op.params().collect(),
                stack: Box::new(op.stack().lift()),
            },
            ExprInfo::SyscallUntypedSSA(op) => Self::SyscallUntypedSSA {
                output: op.output().collect(),
                params: op.params().collect(),
                stack: Box::new(op.stack().lift()),
            },
            ExprInfo::Trap(op) => Self::Trap {
                vector: op.vector(),
            },
            ExprInfo::Var(op) => Self::Var { src: op.src() },
            ExprInfo::AddressOf(op) => Self::AddressOf { src: op.src() },
            ExprInfo::VarSSA(op) => Self::VarSSA {
                src: op.src(),
                op_type: op.op_type(),
            },
            ExprInfo::VarField(op) => Self::VarField {
                src: op.src(),
                offset: op.offset(),
            },
            ExprInfo::AddressOfField(op) => Self::AddressOfField {
                src: op.src(),
                offset: op.offset(),
            },
            ExprInfo::VarFieldSSA(op) => Self::VarFieldSSA {
                src: op.src(),
                offset: op.offset(),
                op_type: op.op_type(),
            },
            ExprInfo::VarPhi(op) => Self::VarPhi {
                dest: op.dest(),
                src: op.src().collect(),
            },
            ExprInfo::VarSplit(op) => Self::VarSplit {
                high: op.high(),
                low: op.low(),
            },
            ExprInfo::VarSplitSSA(op) => Self::VarSplitSSA {
                high: op.high(),
                low: op.low(),
            },
        }
    }
}
