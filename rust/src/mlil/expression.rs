use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNMediumLevelILInstruction;

use core::fmt;
use core::marker::PhantomData;

use crate::rc::Ref;

use super::operation;
use super::operation::Operation;
use super::*;

// used as a marker for Expressions that can produce a value
#[derive(Copy, Clone, Debug)]
pub struct ValueExpr;

// used as a marker for Expressions that can not produce a value
#[derive(Copy, Clone, Debug)]
pub struct VoidExpr;

pub trait ExpressionResultType: 'static {}
impl ExpressionResultType for ValueExpr {}
impl ExpressionResultType for VoidExpr {}

pub struct Expression<F, R>
where
    F: FunctionForm,
    R: ExpressionResultType,
{
    pub(crate) function: Ref<Function<F>>,
    pub(crate) expr_idx: usize,

    // tag the 'return' type of this expression
    pub(crate) _ty: PhantomData<R>,
}

impl<F, R> Expression<F, R>
where
    F: FunctionForm,
    R: ExpressionResultType,
{
    pub(crate) fn new(function: &Function<F>, expr_idx: usize) -> Self {
        Self {
            function: function.to_owned(),
            expr_idx,
            _ty: PhantomData,
        }
    }

    pub fn index(&self) -> usize {
        self.expr_idx
    }
}

fn common_info<F: FunctionForm>(
    function: &Function<F>,
    op: BNMediumLevelILInstruction,
) -> ExprInfo<F> {
    use binaryninjacore_sys::BNMediumLevelILOperation::*;

    match op.operation {
        MLIL_ADDRESS_OF => ExprInfo::AddressOf(Operation::new(function, op)),
        MLIL_ADDRESS_OF_FIELD => ExprInfo::AddressOfField(Operation::new(function, op)),
        MLIL_CONST => ExprInfo::Const(Operation::new(function, op)),
        MLIL_CONST_PTR => ExprInfo::ConstPtr(Operation::new(function, op)),
        MLIL_CONST_DATA => ExprInfo::ConstData(Operation::new(function, op)),
        MLIL_FLOAT_CONST => ExprInfo::FloatConst(Operation::new(function, op)),
        MLIL_IMPORT => ExprInfo::Import(Operation::new(function, op)),
        MLIL_EXTERN_PTR => ExprInfo::ExternPtr(Operation::new(function, op)),

        // MLIL_ADD_OVERFLOW => ExprInfo::AddOverflow(Operation::new(function, op)), // TODO
        MLIL_ADD => ExprInfo::Add(Operation::new(function, op)),
        MLIL_SUB => ExprInfo::Sub(Operation::new(function, op)),
        MLIL_AND => ExprInfo::And(Operation::new(function, op)),
        MLIL_OR => ExprInfo::Or(Operation::new(function, op)),
        MLIL_XOR => ExprInfo::Xor(Operation::new(function, op)),
        MLIL_LSL => ExprInfo::Lsl(Operation::new(function, op)),
        MLIL_LSR => ExprInfo::Lsr(Operation::new(function, op)),
        MLIL_ASR => ExprInfo::Asr(Operation::new(function, op)),
        MLIL_ROL => ExprInfo::Rol(Operation::new(function, op)),
        MLIL_ROR => ExprInfo::Ror(Operation::new(function, op)),
        MLIL_MUL => ExprInfo::Mul(Operation::new(function, op)),
        MLIL_MULU_DP => ExprInfo::MuluDp(Operation::new(function, op)),
        MLIL_MULS_DP => ExprInfo::MulsDp(Operation::new(function, op)),
        MLIL_DIVU => ExprInfo::Divu(Operation::new(function, op)),
        MLIL_DIVS => ExprInfo::Divs(Operation::new(function, op)),
        MLIL_MODU => ExprInfo::Modu(Operation::new(function, op)),
        MLIL_MODS => ExprInfo::Mods(Operation::new(function, op)),
        MLIL_FCMP_E => ExprInfo::FcmpE(Operation::new(function, op)),
        MLIL_FCMP_NE => ExprInfo::FcmpNe(Operation::new(function, op)),
        MLIL_FCMP_LT => ExprInfo::FcmpLt(Operation::new(function, op)),
        MLIL_FCMP_LE => ExprInfo::FcmpLe(Operation::new(function, op)),
        MLIL_FCMP_GE => ExprInfo::FcmpGe(Operation::new(function, op)),
        MLIL_FCMP_GT => ExprInfo::FcmpGt(Operation::new(function, op)),
        MLIL_FCMP_O => ExprInfo::FcmpO(Operation::new(function, op)),
        MLIL_FCMP_UO => ExprInfo::FcmpUo(Operation::new(function, op)),
        MLIL_FADD => ExprInfo::Fadd(Operation::new(function, op)),
        MLIL_FSUB => ExprInfo::Fsub(Operation::new(function, op)),
        MLIL_FMUL => ExprInfo::Fmul(Operation::new(function, op)),
        MLIL_FDIV => ExprInfo::Fdiv(Operation::new(function, op)),

        MLIL_CMP_E => ExprInfo::CmpE(Operation::new(function, op)),
        MLIL_CMP_NE => ExprInfo::CmpNe(Operation::new(function, op)),
        MLIL_CMP_SLT => ExprInfo::CmpSlt(Operation::new(function, op)),
        MLIL_CMP_ULT => ExprInfo::CmpUlt(Operation::new(function, op)),
        MLIL_CMP_SLE => ExprInfo::CmpSle(Operation::new(function, op)),
        MLIL_CMP_ULE => ExprInfo::CmpUle(Operation::new(function, op)),
        MLIL_CMP_SGE => ExprInfo::CmpSge(Operation::new(function, op)),
        MLIL_CMP_UGE => ExprInfo::CmpUge(Operation::new(function, op)),
        MLIL_CMP_SGT => ExprInfo::CmpSgt(Operation::new(function, op)),
        MLIL_CMP_UGT => ExprInfo::CmpUgt(Operation::new(function, op)),

        MLIL_DIVU_DP => ExprInfo::DivuDp(Operation::new(function, op)),
        MLIL_DIVS_DP => ExprInfo::DivsDp(Operation::new(function, op)),
        MLIL_MODU_DP => ExprInfo::ModuDp(Operation::new(function, op)),
        MLIL_MODS_DP => ExprInfo::ModsDp(Operation::new(function, op)),

        MLIL_ADC => ExprInfo::Adc(Operation::new(function, op)),
        MLIL_SBB => ExprInfo::Sbb(Operation::new(function, op)),
        MLIL_RLC => ExprInfo::Rlc(Operation::new(function, op)),
        MLIL_RRC => ExprInfo::Rrc(Operation::new(function, op)),

        MLIL_NEG => ExprInfo::Neg(Operation::new(function, op)),
        MLIL_NOT => ExprInfo::Not(Operation::new(function, op)),
        MLIL_SX => ExprInfo::Sx(Operation::new(function, op)),
        MLIL_ZX => ExprInfo::Zx(Operation::new(function, op)),
        MLIL_LOW_PART => ExprInfo::LowPart(Operation::new(function, op)),
        MLIL_FSQRT => ExprInfo::Fsqrt(Operation::new(function, op)),
        MLIL_FNEG => ExprInfo::Fneg(Operation::new(function, op)),
        MLIL_FABS => ExprInfo::Fabs(Operation::new(function, op)),
        MLIL_FLOAT_TO_INT => ExprInfo::FloatToInt(Operation::new(function, op)),
        MLIL_INT_TO_FLOAT => ExprInfo::IntToFloat(Operation::new(function, op)),
        MLIL_FLOAT_CONV => ExprInfo::FloatConv(Operation::new(function, op)),
        MLIL_ROUND_TO_INT => ExprInfo::RoundToInt(Operation::new(function, op)),
        MLIL_FLOOR => ExprInfo::Floor(Operation::new(function, op)),
        MLIL_CEIL => ExprInfo::Ceil(Operation::new(function, op)),
        MLIL_FTRUNC => ExprInfo::Ftrunc(Operation::new(function, op)),

        // MLIL_TEST_BIT => ExprInfo::TestBit(Operation::new(function, op)), // TODO
        MLIL_BOOL_TO_INT => ExprInfo::BoolToInt(Operation::new(function, op)),

        MLIL_UNIMPL => ExprInfo::Unimpl(Operation::new(function, op)),
        MLIL_UNIMPL_MEM => ExprInfo::UnimplMem(Operation::new(function, op)),

        _ => {
            #[cfg(debug_assertions)]
            {
                error!(
                    "Got unexpected operation {:?} in value expr at 0x{:x}",
                    op.operation, op.address
                );
            }

            ExprInfo::Undef(Operation::new(function, op))
        }
    }
}

impl Expression<NonSSA, ValueExpr> {
    pub fn info(&self) -> ExprInfo<NonSSA> {
        unsafe {
            let op = BNGetMediumLevelILByIndex(self.function.handle, self.expr_idx);
            self.info_from_op(op)
        }
    }

    pub(crate) unsafe fn info_from_op(&self, op: BNMediumLevelILInstruction) -> ExprInfo<NonSSA> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        match op.operation {
            MLIL_VAR => ExprInfo::Var(Operation::new(&self.function, op)),
            MLIL_VAR_FIELD => ExprInfo::VarField(Operation::new(&self.function, op)),
            MLIL_VAR_SPLIT => ExprInfo::VarSplit(Operation::new(&self.function, op)),
            MLIL_LOAD => ExprInfo::Load(Operation::new(&self.function, op)),
            MLIL_LOAD_STRUCT => ExprInfo::LoadStruct(Operation::new(&self.function, op)),
            // NOTE the MLIL_CALL_* only exists inside a call, those are never
            // accessed directly, because the call impl returns the dest
            // from those and not the expr directly.
            MLIL_CALL_OUTPUT | MLIL_CALL_PARAM => unreachable!(),
            _ => common_info(&self.function, op),
        }
    }
}

impl Expression<SSA, ValueExpr> {
    pub fn info(&self) -> ExprInfo<SSA> {
        unsafe {
            let op = BNGetMediumLevelILByIndex(self.function.handle, self.expr_idx);
            self.info_from_op(op)
        }
    }

    pub(crate) unsafe fn info_from_op(&self, op: BNMediumLevelILInstruction) -> ExprInfo<SSA> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        match op.operation {
            MLIL_VAR_SSA | MLIL_VAR_ALIASED => ExprInfo::Var(Operation::new(&self.function, op)),
            MLIL_VAR_ALIASED_FIELD => ExprInfo::VarField(Operation::new(&self.function, op)),
            MLIL_VAR_SPLIT_SSA => ExprInfo::VarSplit(Operation::new(&self.function, op)),
            MLIL_LOAD_SSA => ExprInfo::Load(Operation::new(&self.function, op)),
            MLIL_LOAD_STRUCT_SSA => ExprInfo::LoadStruct(Operation::new(&self.function, op)),
            // NOTE the MLIL_CALL_* only exists inside a call, those are never
            // accessed directly, because the call impl returns the dest
            // from those and not the expr directly.
            MLIL_CALL_PARAM_SSA | MLIL_CALL_OUTPUT_SSA => unreachable!(),
            _ => common_info(&self.function, op),
        }
    }
}

impl fmt::Debug for Expression<NonSSA, ValueExpr> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let op_info = self.info();
        write!(f, "<expr {}: {:?}>", self.expr_idx, op_info)
    }
}

pub enum ExprInfo<F>
where
    F: FunctionForm,
{
    Const(Operation<F, operation::Const>),
    ConstPtr(Operation<F, operation::Const>),
    ConstData(Operation<F, operation::ConstData>),
    FloatConst(Operation<F, operation::FloatConst>),
    Import(Operation<F, operation::Const>),
    ExternPtr(Operation<F, operation::ExternPtr>),

    Load(Operation<F, operation::Load>),
    LoadStruct(Operation<F, operation::LoadStruct>),

    Var(Operation<F, operation::Var>),
    AddressOf(Operation<F, operation::Var>),
    VarField(Operation<F, operation::VarField>),
    AddressOfField(Operation<F, operation::VarField>),
    VarSplit(Operation<F, operation::VarSplit>),

    //AddOverflow(Operation<F, operation::BinaryOp>), // TODO
    Add(Operation<F, operation::BinaryOp>),
    Sub(Operation<F, operation::BinaryOp>),
    And(Operation<F, operation::BinaryOp>),
    Or(Operation<F, operation::BinaryOp>),
    Xor(Operation<F, operation::BinaryOp>),
    Lsl(Operation<F, operation::BinaryOp>),
    Lsr(Operation<F, operation::BinaryOp>),
    Asr(Operation<F, operation::BinaryOp>),
    Rol(Operation<F, operation::BinaryOp>),
    Ror(Operation<F, operation::BinaryOp>),
    Mul(Operation<F, operation::BinaryOp>),
    MuluDp(Operation<F, operation::BinaryOp>),
    MulsDp(Operation<F, operation::BinaryOp>),
    Divu(Operation<F, operation::BinaryOp>),
    Divs(Operation<F, operation::BinaryOp>),
    Modu(Operation<F, operation::BinaryOp>),
    Mods(Operation<F, operation::BinaryOp>),
    TestBit(Operation<F, operation::BinaryOp>),
    FcmpE(Operation<F, operation::BinaryOp>),
    FcmpNe(Operation<F, operation::BinaryOp>),
    FcmpLt(Operation<F, operation::BinaryOp>),
    FcmpLe(Operation<F, operation::BinaryOp>),
    FcmpGe(Operation<F, operation::BinaryOp>),
    FcmpGt(Operation<F, operation::BinaryOp>),
    FcmpO(Operation<F, operation::BinaryOp>),
    FcmpUo(Operation<F, operation::BinaryOp>),
    Fadd(Operation<F, operation::BinaryOp>),
    Fsub(Operation<F, operation::BinaryOp>),
    Fmul(Operation<F, operation::BinaryOp>),
    Fdiv(Operation<F, operation::BinaryOp>),

    CmpE(Operation<F, operation::BinaryOp>),
    CmpNe(Operation<F, operation::BinaryOp>),
    CmpSlt(Operation<F, operation::BinaryOp>),
    CmpUlt(Operation<F, operation::BinaryOp>),
    CmpSle(Operation<F, operation::BinaryOp>),
    CmpUle(Operation<F, operation::BinaryOp>),
    CmpSge(Operation<F, operation::BinaryOp>),
    CmpUge(Operation<F, operation::BinaryOp>),
    CmpSgt(Operation<F, operation::BinaryOp>),
    CmpUgt(Operation<F, operation::BinaryOp>),

    DivuDp(Operation<F, operation::BinaryOp>),
    DivsDp(Operation<F, operation::BinaryOp>),
    ModuDp(Operation<F, operation::BinaryOp>),
    ModsDp(Operation<F, operation::BinaryOp>),

    Adc(Operation<F, operation::BinaryOpCarry>),
    Sbb(Operation<F, operation::BinaryOpCarry>),
    Rlc(Operation<F, operation::BinaryOpCarry>),
    Rrc(Operation<F, operation::BinaryOpCarry>),

    Neg(Operation<F, operation::UnaryOp>),
    Not(Operation<F, operation::UnaryOp>),
    Sx(Operation<F, operation::UnaryOp>),
    Zx(Operation<F, operation::UnaryOp>),
    LowPart(Operation<F, operation::UnaryOp>),
    Fsqrt(Operation<F, operation::UnaryOp>),
    Fneg(Operation<F, operation::UnaryOp>),
    Fabs(Operation<F, operation::UnaryOp>),
    FloatToInt(Operation<F, operation::UnaryOp>),
    IntToFloat(Operation<F, operation::UnaryOp>),
    FloatConv(Operation<F, operation::UnaryOp>),
    RoundToInt(Operation<F, operation::UnaryOp>),
    Floor(Operation<F, operation::UnaryOp>),
    Ceil(Operation<F, operation::UnaryOp>),
    Ftrunc(Operation<F, operation::UnaryOp>),

    //TestBit(Operation<F, operation::TestBit>), // TODO
    BoolToInt(Operation<F, operation::UnaryOp>),

    Unimpl(Operation<F, operation::NoArgs>),
    UnimplMem(Operation<F, operation::UnaryOp>),

    Undef(Operation<F, operation::NoArgs>),
}

impl fmt::Debug for ExprInfo<NonSSA> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ExprInfo::*;

        match self {
            Undef(..) => f.write_str("undefined"),

            Unimpl(..) => f.write_str("unimplemented"),

            CmpE(op) | CmpNe(op) | CmpSlt(op) | CmpUlt(op) | CmpSle(op) | CmpUle(op)
            | CmpSge(op) | CmpUge(op) | CmpSgt(op) | CmpUgt(op) => {
                let operation = op.op.operation;
                let size = op.size();
                let left = op.left();
                let right = op.right();

                write!(f, "{operation:?}({size}, {left:?}, {right:?})",)
            }

            Const(op) | ConstPtr(op) => write!(f, "0x{:x}", op.constant()),

            FloatConst(op) => write!(f, "{}", op.constant()),

            Import(op) => write!(f, "@(0x{:x})", op.constant()),

            ExternPtr(op) => write!(f, "ext@(0x{:x})", op.constant()),

            // TODO implement ConstData type
            ConstData(_) => f.write_str("ConstData"),

            Load(op) => {
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

            Adc(op) | Sbb(op) | Rlc(op) | Rrc(op) => {
                let operation = op.op.operation;
                let size = op.size();
                let left = op.left();
                let right = op.right();
                let carry = op.carry();
                write!(
                    f,
                    "{operation:?}({size}, {left:?}, {right:?}, carry: {carry:?})",
                )
            }

            FcmpE(op) | FcmpNe(op) | FcmpLt(op) | FcmpLe(op) | FcmpGe(op) | FcmpGt(op)
            | FcmpO(op) | FcmpUo(op) | Fadd(op) | Fsub(op) | Fmul(op) | Fdiv(op) | Add(op)
            | Sub(op) | And(op) | Or(op) | Xor(op) | Lsl(op) | Lsr(op) | Asr(op) | Rol(op)
            | Ror(op) | Mul(op) | MuluDp(op) | MulsDp(op) | Divu(op) | Divs(op) | Modu(op)
            | Mods(op) => {
                let operation = op.op.operation;
                let size = op.size();
                let left = op.left();
                let right = op.right();
                write!(f, "{operation:?}({size}, {left:?}, {right:?})",)
            }

            DivuDp(op) | DivsDp(op) | ModuDp(op) | ModsDp(op) => {
                let operation = op.op.operation;
                let size = op.size();
                let left = op.left();
                let right = op.right();

                write!(f, "{operation:?}({size}, {left:?}, {right:?})",)
            }

            Fsqrt(op) | Fneg(op) | Fabs(op) | FloatToInt(op) | IntToFloat(op) | FloatConv(op)
            | RoundToInt(op) | Floor(op) | Ceil(op) | Ftrunc(op) | Neg(op) | Not(op) | Sx(op)
            | Zx(op) | LowPart(op) | BoolToInt(op) => {
                let operation = op.op.operation;
                let size = op.size();
                let src = op.src();

                write!(f, "{operation:?}({size}, {src:?})",)
            }

            Var(op) | AddressOf(op) => {
                let size = op.size();
                let src = op.src();
                write!(f, "var({size}, {src:?})",)
            }

            VarField(op) | AddressOfField(op) => {
                let size = op.size();
                let src = op.src();
                let offset = op.offset();
                write!(f, "var({size}, {src:?}, {offset})",)
            }

            VarSplit(op) => {
                let size = op.size();
                let low = op.low();
                let high = op.high();
                write!(f, "var({size}, {low:?}, {high:?})",)
            }

            // TODO implement TestBit
            TestBit(_) => f.write_str("TestBit"),

            UnimplMem(op) => write!(f, "unimplemented_mem({:?})", op.src()),
        }
    }
}
