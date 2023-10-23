use binaryninjacore_sys::BNGetMediumLevelILByIndex;
use binaryninjacore_sys::BNMediumLevelILInstruction;

use core::fmt;
use core::marker::PhantomData;

use super::operation;
use super::operation::Operation;
use super::*;

use crate::architecture::Architecture;

// used as a marker for Expressions that can produce a value
#[derive(Copy, Clone, Debug)]
pub struct ValueExpr;

// used as a marker for Expressions that can not produce a value
#[derive(Copy, Clone, Debug)]
pub struct VoidExpr;

pub trait ExpressionResultType: 'static {}
impl ExpressionResultType for ValueExpr {}
impl ExpressionResultType for VoidExpr {}

pub struct Expression<'func, A, M, F, R>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    pub(crate) function: &'func Function<A, M, F>,
    pub(crate) expr_idx: usize,

    // tag the 'return' type of this expression
    pub(crate) _ty: PhantomData<R>,
}

impl<'func, A, M, F, R> Expression<'func, A, M, F, R>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    R: ExpressionResultType,
{
    pub(crate) fn new(function: &'func Function<A, M, F>, expr_idx: usize) -> Self {
        Self {
            function,
            expr_idx,
            _ty: PhantomData,
        }
    }

    pub fn index(&self) -> usize {
        self.expr_idx
    }
}

fn common_info<'func, A, M, F>(
    function: &'func Function<A, M, F>,
    op: BNMediumLevelILInstruction,
) -> ExprInfo<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
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

impl<'func, A, M, V> Expression<'func, A, M, NonSSA<V>, ValueExpr>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn info(&self) -> ExprInfo<'func, A, M, NonSSA<V>> {
        unsafe {
            let op = BNGetMediumLevelILByIndex(self.function.handle, self.expr_idx);
            self.info_from_op(op)
        }
    }

    pub(crate) unsafe fn info_from_op(
        &self,
        op: BNMediumLevelILInstruction,
    ) -> ExprInfo<'func, A, M, NonSSA<V>> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        match op.operation {
            MLIL_VAR => ExprInfo::Var(Operation::new(self.function, op)),
            MLIL_VAR_FIELD => ExprInfo::VarField(Operation::new(self.function, op)),
            MLIL_VAR_SPLIT => ExprInfo::VarSplit(Operation::new(self.function, op)),
            MLIL_LOAD => ExprInfo::Load(Operation::new(self.function, op)),
            MLIL_LOAD_STRUCT => ExprInfo::LoadStruct(Operation::new(self.function, op)),
            // NOTE the MLIL_CALL_* only exists inside a call, those are never
            // accessed directly, because the call impl returns the dest
            // from those and not the expr directly.
            MLIL_CALL_OUTPUT | MLIL_CALL_PARAM => unreachable!(),
            _ => common_info(&self.function, op),
        }
    }
}

impl<'func, A, M> Expression<'func, A, M, SSA, ValueExpr>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn info(&self) -> ExprInfo<'func, A, M, SSA> {
        unsafe {
            let op = BNGetMediumLevelILByIndex(self.function.handle, self.expr_idx);
            self.info_from_op(op)
        }
    }

    pub(crate) unsafe fn info_from_op(
        &self,
        op: BNMediumLevelILInstruction,
    ) -> ExprInfo<'func, A, M, SSA> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        match op.operation {
            MLIL_VAR_SSA | MLIL_VAR_ALIASED => ExprInfo::Var(Operation::new(self.function, op)),
            MLIL_VAR_ALIASED_FIELD => ExprInfo::VarField(Operation::new(self.function, op)),
            MLIL_VAR_SPLIT_SSA => ExprInfo::VarSplit(Operation::new(self.function, op)),
            MLIL_LOAD_SSA => ExprInfo::Load(Operation::new(self.function, op)),
            MLIL_LOAD_STRUCT_SSA => ExprInfo::LoadStruct(Operation::new(self.function, op)),
            // NOTE the MLIL_CALL_* only exists inside a call, those are never
            // accessed directly, because the call impl returns the dest
            // from those and not the expr directly.
            MLIL_CALL_PARAM_SSA | MLIL_CALL_OUTPUT_SSA => unreachable!(),
            _ => common_info(&self.function, op),
        }
    }
}

impl<'func, A, M, V> fmt::Debug for Expression<'func, A, M, NonSSA<V>, ValueExpr>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let op_info = self.info();
        write!(f, "<expr {}: {:?}>", self.expr_idx, op_info)
    }
}

pub enum ExprInfo<'func, A, M, F>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    Const(Operation<'func, A, M, F, operation::Const>),
    ConstPtr(Operation<'func, A, M, F, operation::Const>),
    ConstData(Operation<'func, A, M, F, operation::ConstData>),
    FloatConst(Operation<'func, A, M, F, operation::FloatConst>),
    Import(Operation<'func, A, M, F, operation::Const>),
    ExternPtr(Operation<'func, A, M, F, operation::ExternPtr>),

    Load(Operation<'func, A, M, F, operation::Load>),
    LoadStruct(Operation<'func, A, M, F, operation::LoadStruct>),

    Var(Operation<'func, A, M, F, operation::Var>),
    AddressOf(Operation<'func, A, M, F, operation::Var>),
    VarField(Operation<'func, A, M, F, operation::VarField>),
    AddressOfField(Operation<'func, A, M, F, operation::VarField>),
    VarSplit(Operation<'func, A, M, F, operation::VarSplit>),

    //AddOverflow(Operation<'func, A, M, F, operation::BinaryOp>), // TODO
    Add(Operation<'func, A, M, F, operation::BinaryOp>),
    Sub(Operation<'func, A, M, F, operation::BinaryOp>),
    And(Operation<'func, A, M, F, operation::BinaryOp>),
    Or(Operation<'func, A, M, F, operation::BinaryOp>),
    Xor(Operation<'func, A, M, F, operation::BinaryOp>),
    Lsl(Operation<'func, A, M, F, operation::BinaryOp>),
    Lsr(Operation<'func, A, M, F, operation::BinaryOp>),
    Asr(Operation<'func, A, M, F, operation::BinaryOp>),
    Rol(Operation<'func, A, M, F, operation::BinaryOp>),
    Ror(Operation<'func, A, M, F, operation::BinaryOp>),
    Mul(Operation<'func, A, M, F, operation::BinaryOp>),
    MuluDp(Operation<'func, A, M, F, operation::BinaryOp>),
    MulsDp(Operation<'func, A, M, F, operation::BinaryOp>),
    Divu(Operation<'func, A, M, F, operation::BinaryOp>),
    Divs(Operation<'func, A, M, F, operation::BinaryOp>),
    Modu(Operation<'func, A, M, F, operation::BinaryOp>),
    Mods(Operation<'func, A, M, F, operation::BinaryOp>),
    TestBit(Operation<'func, A, M, F, operation::BinaryOp>),
    FcmpE(Operation<'func, A, M, F, operation::BinaryOp>),
    FcmpNe(Operation<'func, A, M, F, operation::BinaryOp>),
    FcmpLt(Operation<'func, A, M, F, operation::BinaryOp>),
    FcmpLe(Operation<'func, A, M, F, operation::BinaryOp>),
    FcmpGe(Operation<'func, A, M, F, operation::BinaryOp>),
    FcmpGt(Operation<'func, A, M, F, operation::BinaryOp>),
    FcmpO(Operation<'func, A, M, F, operation::BinaryOp>),
    FcmpUo(Operation<'func, A, M, F, operation::BinaryOp>),
    Fadd(Operation<'func, A, M, F, operation::BinaryOp>),
    Fsub(Operation<'func, A, M, F, operation::BinaryOp>),
    Fmul(Operation<'func, A, M, F, operation::BinaryOp>),
    Fdiv(Operation<'func, A, M, F, operation::BinaryOp>),

    CmpE(Operation<'func, A, M, F, operation::BinaryOp>),
    CmpNe(Operation<'func, A, M, F, operation::BinaryOp>),
    CmpSlt(Operation<'func, A, M, F, operation::BinaryOp>),
    CmpUlt(Operation<'func, A, M, F, operation::BinaryOp>),
    CmpSle(Operation<'func, A, M, F, operation::BinaryOp>),
    CmpUle(Operation<'func, A, M, F, operation::BinaryOp>),
    CmpSge(Operation<'func, A, M, F, operation::BinaryOp>),
    CmpUge(Operation<'func, A, M, F, operation::BinaryOp>),
    CmpSgt(Operation<'func, A, M, F, operation::BinaryOp>),
    CmpUgt(Operation<'func, A, M, F, operation::BinaryOp>),

    DivuDp(Operation<'func, A, M, F, operation::BinaryOp>),
    DivsDp(Operation<'func, A, M, F, operation::BinaryOp>),
    ModuDp(Operation<'func, A, M, F, operation::BinaryOp>),
    ModsDp(Operation<'func, A, M, F, operation::BinaryOp>),

    Adc(Operation<'func, A, M, F, operation::BinaryOpCarry>),
    Sbb(Operation<'func, A, M, F, operation::BinaryOpCarry>),
    Rlc(Operation<'func, A, M, F, operation::BinaryOpCarry>),
    Rrc(Operation<'func, A, M, F, operation::BinaryOpCarry>),

    Neg(Operation<'func, A, M, F, operation::UnaryOp>),
    Not(Operation<'func, A, M, F, operation::UnaryOp>),
    Sx(Operation<'func, A, M, F, operation::UnaryOp>),
    Zx(Operation<'func, A, M, F, operation::UnaryOp>),
    LowPart(Operation<'func, A, M, F, operation::UnaryOp>),
    Fsqrt(Operation<'func, A, M, F, operation::UnaryOp>),
    Fneg(Operation<'func, A, M, F, operation::UnaryOp>),
    Fabs(Operation<'func, A, M, F, operation::UnaryOp>),
    FloatToInt(Operation<'func, A, M, F, operation::UnaryOp>),
    IntToFloat(Operation<'func, A, M, F, operation::UnaryOp>),
    FloatConv(Operation<'func, A, M, F, operation::UnaryOp>),
    RoundToInt(Operation<'func, A, M, F, operation::UnaryOp>),
    Floor(Operation<'func, A, M, F, operation::UnaryOp>),
    Ceil(Operation<'func, A, M, F, operation::UnaryOp>),
    Ftrunc(Operation<'func, A, M, F, operation::UnaryOp>),

    //TestBit(Operation<'func, A, M, F, operation::TestBit>), // TODO
    BoolToInt(Operation<'func, A, M, F, operation::UnaryOp>),

    Unimpl(Operation<'func, A, M, F, operation::NoArgs>),
    UnimplMem(Operation<'func, A, M, F, operation::UnaryOp>),

    Undef(Operation<'func, A, M, F, operation::NoArgs>),
}

impl<'func, A, M, V> fmt::Debug for ExprInfo<'func, A, M, NonSSA<V>>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
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
