use core::fmt;

use binaryninjacore_sys::BNMediumLevelILInstruction;

use super::*;

pub enum ExprInfo {
    Nop(Operation<operation::NoArgs>),
    NoRet(Operation<operation::NoArgs>),
    Bp(Operation<operation::NoArgs>),
    Undef(Operation<operation::NoArgs>),
    Unimpl(Operation<operation::NoArgs>),
    BinaryOpCarry(Operation<operation::BinaryOpCarry>),
    BinaryOp(Operation<operation::BinaryOp>),
    Call(Operation<operation::Call>),
    CallSSA(Operation<operation::CallSSA>),
    CallUntyped(Operation<operation::CallUntyped>),
    CallUntypedSSA(Operation<operation::CallUntypedSSA>),
    Const(Operation<operation::Const>),
    ConstData(Operation<operation::ConstData>),
    ExternPtr(Operation<operation::ExternPtr>),
    FloatConst(Operation<operation::FloatConst>),
    FreeVarSlot(Operation<operation::FreeVarSlot>),
    FreeVarSlotSSA(Operation<operation::FreeVarSlotSSA>),
    Goto(Operation<operation::Goto>),
    If(Operation<operation::If>),
    Intrinsic(Operation<operation::Intrinsic>),
    IntrinsicSSA(Operation<operation::IntrinsicSSA>),
    Jump(Operation<operation::Jump>),
    JumpTo(Operation<operation::JumpTo>),
    UnaryOp(Operation<operation::UnaryOp>),
    Load(Operation<operation::Load>),
    LoadSSA(Operation<operation::LoadSSA>),
    LoadStruct(Operation<operation::LoadStruct>),
    LoadStructSSA(Operation<operation::LoadStructSSA>),
    MemPhi(Operation<operation::MemPhi>),
    Ret(Operation<operation::Ret>),
    SetVar(Operation<operation::SetVar>),
    SetVarSSA(Operation<operation::SetVarSSA>),
    SetVarAliased(Operation<operation::SetVarAliased>),
    SetVarField(Operation<operation::SetVarField>),
    SetVarFieldSSA(Operation<operation::SetVarFieldSSA>),
    SetVarSplit(Operation<operation::SetVarSplit>),
    SetVarSplitSSA(Operation<operation::SetVarSplitSSA>),
    Store(Operation<operation::Store>),
    StoreSSA(Operation<operation::StoreSSA>),
    StoreStruct(Operation<operation::StoreStruct>),
    StoreStructSSA(Operation<operation::StoreStructSSA>),
    Syscall(Operation<operation::Syscall>),
    SyscallSSA(Operation<operation::SyscallSSA>),
    SyscallUntyped(Operation<operation::SyscallUntyped>),
    SyscallUntypedSSA(Operation<operation::SyscallUntypedSSA>),
    Trap(Operation<operation::Trap>),
    Var(Operation<operation::Var>),
    AddressOf(Operation<operation::AddressOf>),
    VarSSA(Operation<operation::VarSSA>),
    VarField(Operation<operation::VarField>),
    AddressOfField(Operation<operation::AddressOfField>),
    VarFieldSSA(Operation<operation::VarFieldSSA>),
    VarPhi(Operation<operation::VarPhi>),
    VarSplit(Operation<operation::VarSplit>),
    VarSplitSSA(Operation<operation::VarSplitSSA>),
}

impl fmt::Debug for ExprInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ExprInfo::*;

        match self {
            Nop(_) => f.write_str("nop"),

            SetVar(op) => write!(f, "{:?} = {:?}", op.dest(), op.src()),
            SetVarSSA(op) => write!(f, "{:?} = {:?}", op.dest(), op.src()),

            SetVarField(op) => {
                let dest = op.dest();
                let src = op.src();
                let offset = op.offset();
                write!(f, "{dest:?}@{offset} = {src:?}")
            }
            SetVarFieldSSA(op) => {
                let dest = op.dest();
                let src = op.src();
                let offset = op.offset();
                write!(f, "{dest:?}@{offset} = {src:?}")
            }

            SetVarSplit(op) => {
                let high = op.high();
                let low = op.low();
                let src = op.src();
                write!(f, "({low:?}, {high:?}) = {src:?}")
            }
            SetVarSplitSSA(op) => {
                let high = op.high();
                let low = op.low();
                let src = op.src();
                write!(f, "({low:?}, {high:?}) = {src:?}")
            }

            Store(op) => {
                let dest = op.dest();
                let src = op.src();
                let size = op.size();
                write!(f, "store({dest:?}.{size}) = {src:?}")
            }
            StoreSSA(op) => {
                let dest = op.dest();
                let src = op.src();
                let size = op.size();
                write!(f, "store({dest:?}.{size}) = {src:?}")
            }

            Jump(op) => write!(f, "jump({:?})", op.dest()),
            JumpTo(op) => write!(f, "jump_to({:?})", op.dest()),

            Call(op) => {
                let dest = op.dest();
                let params: Vec<_> = op.params().collect();
                let output: Vec<_> = op.output().collect();
                write!(f, "{output:?} = call({dest:?}, {params:?})")
            }
            CallSSA(op) => {
                let dest = op.dest();
                let params: Vec<_> = op.params().collect();
                let output: Vec<_> = op.output().collect();
                write!(f, "{output:?} = call({dest:?}, {params:?})")
            }

            CallUntyped(op) => {
                let dest = op.dest();
                let params: Vec<_> = op.params().collect();
                let output: Vec<_> = op.output().collect();
                write!(f, "{output:?} = call_untyped({dest:?}, {params:?})")
            }
            CallUntypedSSA(op) => {
                let dest = op.dest();
                let params: Vec<_> = op.params().collect();
                let output: Vec<_> = op.output().collect();
                write!(f, "{output:?} = call_untyped({dest:?}, {params:?})")
            }

            Syscall(op) => {
                let params: Vec<_> = op.params().collect();
                let output: Vec<_> = op.output().collect();
                write!(f, "{output:?} = syscall({params:?})")
            }
            SyscallSSA(op) => {
                let params: Vec<_> = op.params().collect();
                let output: Vec<_> = op.output().collect();
                write!(f, "{output:?} = syscall({params:?})")
            }

            SyscallUntyped(op) => {
                let params: Vec<_> = op.params().collect();
                let output: Vec<_> = op.output().collect();
                write!(f, "{output:?} = syscall_untyped({params:?})")
            }
            SyscallUntypedSSA(op) => {
                let params: Vec<_> = op.params().collect();
                let output: Vec<_> = op.output().collect();
                write!(f, "{output:?} = syscall_untyped({params:?})")
            }

            Ret(op) => write!(f, "return({:?})", op.src().collect::<Vec<_>>()),
            NoRet(_op) => write!(f, "return"),
            If(op) => {
                let cond = op.condition();
                let dest_true = op.dest_true();
                let dest_false = op.dest_false();
                write!(f, "if({cond:?}) {dest_true:?} else {dest_false:?}")
            }
            Goto(op) => write!(f, "goto(0x{:x})", op.dest()),
            Bp(_op) => f.write_str("bp"),
            Trap(_op) => f.write_str("trap"),

            Intrinsic(_op) => todo!(),
            IntrinsicSSA(_) => todo!(),

            Undef(..) => f.write_str("undefined"),

            Unimpl(..) => f.write_str("unimplemented"),

            BinaryOp(op) => {
                let operation = op.op_type();
                let size = op.size();
                let left = op.left();
                let right = op.right();

                write!(f, "{operation:?}({size}, {left:?}, {right:?})",)
            }

            Const(op) => write!(f, "const({:?}, 0x{:x})", op.op_type(), op.constant()),

            FloatConst(op) => write!(f, "{}", op.constant()),

            ExternPtr(op) => write!(f, "ext@(0x{:x})", op.constant()),

            // TODO implement ConstData type
            ConstData(_) => f.write_str("ConstData"),

            Load(op) => {
                let source = op.src();
                let size = op.size();
                write!(f, "[{source:?}].{size}")
            }
            LoadSSA(op) => {
                let source = op.src();
                let size = op.size();
                write!(f, "[{source:?}].{size}")
            }

            LoadStruct(op) => {
                let source = op.src();
                let size = op.size();
                let offset = op.offset();
                write!(f, "[{source:?} @ {offset}].{size}")
            }
            LoadStructSSA(op) => {
                let source = op.src();
                let size = op.size();
                let offset = op.offset();
                write!(f, "[{source:?} @ {offset}].{size}")
            }

            BinaryOpCarry(op) => {
                let operation = op.op_type();
                let size = op.size();
                let left = op.left();
                let right = op.right();
                let carry = op.carry();
                write!(
                    f,
                    "{operation:?}({size}, {left:?}, {right:?}, carry: {carry:?})",
                )
            }

            UnaryOp(op) => {
                let operation = op.op_type();
                let size = op.size();
                let src = op.src();

                write!(f, "{operation:?}({size}, {src:?})",)
            }

            Var(op) => {
                let size = op.size();
                let src = op.src();
                write!(f, "var({size}, {src:?})",)
            }
            VarSSA(op) => {
                let size = op.size();
                let src = op.src();
                write!(f, "var({size}, {src:?})",)
            }

            AddressOf(op) => {
                let size = op.size();
                let src = op.src();
                write!(f, "address_of({size}, {src:?})",)
            }

            VarField(op) => {
                let size = op.size();
                let src = op.src();
                let offset = op.offset();
                write!(f, "var_field({size}, {src:?}, {offset})",)
            }
            VarFieldSSA(op) => {
                let size = op.size();
                let src = op.src();
                let offset = op.offset();
                write!(f, "var_field({size}, {src:?}, {offset})",)
            }

            AddressOfField(op) => {
                let size = op.size();
                let src = op.src();
                let offset = op.offset();
                write!(f, "address_of_field({size}, {src:?}, {offset})",)
            }

            VarSplit(op) => {
                let size = op.size();
                let low = op.low();
                let high = op.high();
                write!(f, "var({size}, {low:?}, {high:?})",)
            }
            VarSplitSSA(op) => {
                let size = op.size();
                let low = op.low();
                let high = op.high();
                write!(f, "var({size}, {low:?}, {high:?})",)
            }

            SetVarAliased(expr) => write!(f, "{:?} = {:?}", expr.dest(), expr.src()),
            VarPhi(expr) => {
                let dest = expr.dest();
                let srcs: Vec<_> = expr.src().collect();
                write!(f, "{dest:?} = {srcs:?}")
            }
            MemPhi(expr) => {
                let dest = expr.dest_memory();
                let srcs: Vec<_> = expr.src_memory().collect();
                write!(f, "0x{dest:x} = {srcs:?}")
            }

            FreeVarSlot(_) => todo!(),
            FreeVarSlotSSA(_) => todo!(),

            StoreStruct(_) => todo!(),
            StoreStructSSA(_) => todo!(),
        }
    }
}

impl ExprInfo {
    pub(crate) unsafe fn new(function: &Function, op: BNMediumLevelILInstruction) -> Self {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        match op.operation {
            MLIL_NOP => Self::Nop(Operation::new(function, op)),
            MLIL_NORET => Self::NoRet(Operation::new(function, op)),
            MLIL_BP => Self::Bp(Operation::new(function, op)),
            MLIL_UNDEF => Self::Undef(Operation::new(function, op)),
            MLIL_UNIMPL => Self::Unimpl(Operation::new(function, op)),
            MLIL_ADC | MLIL_SBB | MLIL_RLC | MLIL_RRC => {
                Self::BinaryOpCarry(Operation::new(function, op))
            }
            MLIL_ADD | MLIL_SUB | MLIL_AND | MLIL_OR | MLIL_XOR | MLIL_LSL | MLIL_LSR
            | MLIL_ASR | MLIL_ROL | MLIL_ROR | MLIL_MUL | MLIL_MULU_DP | MLIL_MULS_DP
            | MLIL_DIVU | MLIL_DIVU_DP | MLIL_DIVS | MLIL_DIVS_DP | MLIL_MODU | MLIL_MODU_DP
            | MLIL_MODS | MLIL_MODS_DP | MLIL_CMP_E | MLIL_CMP_NE | MLIL_CMP_SLT | MLIL_CMP_ULT
            | MLIL_CMP_SLE | MLIL_CMP_ULE | MLIL_CMP_SGE | MLIL_CMP_UGE | MLIL_CMP_SGT
            | MLIL_CMP_UGT | MLIL_TEST_BIT | MLIL_ADD_OVERFLOW | MLIL_FCMP_E | MLIL_FCMP_NE
            | MLIL_FCMP_LT | MLIL_FCMP_LE | MLIL_FCMP_GE | MLIL_FCMP_GT | MLIL_FCMP_O
            | MLIL_FCMP_UO | MLIL_FADD | MLIL_FSUB | MLIL_FMUL | MLIL_FDIV => {
                Self::BinaryOp(Operation::new(function, op))
            }
            MLIL_CALL | MLIL_TAILCALL => Self::Call(Operation::new(function, op)),
            MLIL_CALL_SSA | MLIL_TAILCALL_SSA => Self::CallSSA(Operation::new(function, op)),
            MLIL_CALL_UNTYPED | MLIL_TAILCALL_UNTYPED => {
                Self::CallUntyped(Operation::new(function, op))
            }
            MLIL_CALL_UNTYPED_SSA | MLIL_TAILCALL_UNTYPED_SSA => {
                Self::CallUntypedSSA(Operation::new(function, op))
            }
            MLIL_CONST | MLIL_CONST_PTR | MLIL_IMPORT => Self::Const(Operation::new(function, op)),
            MLIL_CONST_DATA => Self::ConstData(Operation::new(function, op)),
            MLIL_EXTERN_PTR => Self::ExternPtr(Operation::new(function, op)),
            MLIL_FLOAT_CONST => Self::FloatConst(Operation::new(function, op)),
            MLIL_FREE_VAR_SLOT => Self::FreeVarSlot(Operation::new(function, op)),
            MLIL_FREE_VAR_SLOT_SSA => Self::FreeVarSlotSSA(Operation::new(function, op)),
            MLIL_GOTO => Self::Goto(Operation::new(function, op)),
            MLIL_IF => Self::If(Operation::new(function, op)),
            MLIL_INTRINSIC => Self::Intrinsic(Operation::new(function, op)),
            MLIL_INTRINSIC_SSA => Self::IntrinsicSSA(Operation::new(function, op)),
            MLIL_JUMP | MLIL_RET_HINT => Self::Jump(Operation::new(function, op)),
            MLIL_JUMP_TO => Self::JumpTo(Operation::new(function, op)),
            MLIL_NEG | MLIL_NOT | MLIL_SX | MLIL_ZX | MLIL_LOW_PART | MLIL_BOOL_TO_INT
            | MLIL_UNIMPL_MEM | MLIL_FSQRT | MLIL_FNEG | MLIL_FABS | MLIL_FLOAT_TO_INT
            | MLIL_INT_TO_FLOAT | MLIL_FLOAT_CONV | MLIL_ROUND_TO_INT | MLIL_FLOOR | MLIL_CEIL
            | MLIL_FTRUNC => Self::UnaryOp(Operation::new(function, op)),
            MLIL_LOAD => Self::Load(Operation::new(function, op)),
            MLIL_LOAD_SSA => Self::LoadSSA(Operation::new(function, op)),
            MLIL_LOAD_STRUCT => Self::LoadStruct(Operation::new(function, op)),
            MLIL_LOAD_STRUCT_SSA => Self::LoadStructSSA(Operation::new(function, op)),
            MLIL_MEM_PHI => Self::MemPhi(Operation::new(function, op)),
            MLIL_RET => Self::Ret(Operation::new(function, op)),
            MLIL_SET_VAR => Self::SetVar(Operation::new(function, op)),
            MLIL_SET_VAR_SSA => Self::SetVarSSA(Operation::new(function, op)),
            MLIL_SET_VAR_ALIASED => Self::SetVarAliased(Operation::new(function, op)),
            MLIL_SET_VAR_FIELD => Self::SetVarField(Operation::new(function, op)),
            MLIL_SET_VAR_SSA_FIELD | MLIL_SET_VAR_ALIASED_FIELD => {
                Self::SetVarFieldSSA(Operation::new(function, op))
            }
            MLIL_SET_VAR_SPLIT => Self::SetVarSplit(Operation::new(function, op)),
            MLIL_SET_VAR_SPLIT_SSA => Self::SetVarSplitSSA(Operation::new(function, op)),
            MLIL_STORE => Self::Store(Operation::new(function, op)),
            MLIL_STORE_SSA => Self::StoreSSA(Operation::new(function, op)),
            MLIL_STORE_STRUCT => Self::StoreStruct(Operation::new(function, op)),
            MLIL_STORE_STRUCT_SSA => Self::StoreStructSSA(Operation::new(function, op)),
            MLIL_SYSCALL => Self::Syscall(Operation::new(function, op)),
            MLIL_SYSCALL_SSA => Self::SyscallSSA(Operation::new(function, op)),
            MLIL_SYSCALL_UNTYPED => Self::SyscallUntyped(Operation::new(function, op)),
            MLIL_SYSCALL_UNTYPED_SSA => Self::SyscallUntypedSSA(Operation::new(function, op)),
            MLIL_TRAP => Self::Trap(Operation::new(function, op)),
            MLIL_VAR => Self::Var(Operation::new(function, op)),
            MLIL_ADDRESS_OF => Self::AddressOf(Operation::new(function, op)),
            MLIL_VAR_SSA | MLIL_VAR_ALIASED => Self::VarSSA(Operation::new(function, op)),
            MLIL_VAR_FIELD => Self::VarField(Operation::new(function, op)),
            MLIL_ADDRESS_OF_FIELD => Self::AddressOfField(Operation::new(function, op)),
            MLIL_VAR_SSA_FIELD | MLIL_VAR_ALIASED_FIELD => {
                Self::VarFieldSSA(Operation::new(function, op))
            }
            MLIL_VAR_PHI => Self::VarPhi(Operation::new(function, op)),
            MLIL_VAR_SPLIT => Self::VarSplit(Operation::new(function, op)),
            MLIL_VAR_SPLIT_SSA => Self::VarSplitSSA(Operation::new(function, op)),

            MLIL_CALL_OUTPUT | MLIL_CALL_PARAM | MLIL_CALL_PARAM_SSA | MLIL_CALL_OUTPUT_SSA => {
                unimplemented!()
            }
        }
    }
}
