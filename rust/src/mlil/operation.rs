use binaryninjacore_sys::BNMediumLevelILInstruction;

use core::marker::PhantomData;

use crate::types::SSAVariable;

use super::*;

pub struct Operation<'func, A, M, F, O>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    pub(crate) function: &'func Function<A, M, F>,
    pub(crate) op: BNMediumLevelILInstruction,
    _args: PhantomData<O>,
}

impl<'func, A, M, F, O> Operation<'func, A, M, F, O>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    pub(crate) fn new(function: &'func Function<A, M, F>, op: BNMediumLevelILInstruction) -> Self {
        Self {
            function,
            op,
            _args: PhantomData,
        }
    }

    pub fn address(&self) -> u64 {
        self.op.address
    }

    pub fn size(&self) -> usize {
        self.op.size
    }

    fn get_expr(&self, operand_index: usize) -> Expression<'func, A, M, F, ValueExpr> {
        Expression::new(self.function, self.op.operands[operand_index] as usize)
    }

    fn get_int(&self, operand_index: usize) -> u64 {
        // TODO check mask...
        self.op.operands[operand_index]
    }

    fn get_list(
        &self,
        operand_index1: usize,
        operand_index2: usize,
    ) -> impl Iterator<Item = u64> + 'func {
        // TODO use `BNMediumLevelILGetOperandList` like python?
        let mut number = self.op.operands[operand_index1] as usize;
        let mut current_index = self.op.operands[operand_index2] as usize;
        // variable that the closure can capture
        let handle = self.function.handle;
        core::iter::from_fn(move || {
            let current =
                unsafe { binaryninjacore_sys::BNGetMediumLevelILByIndex(handle, current_index) };
            let consume = if number > 5 {
                // there is more to the list
                number -= 4;
                current_index = current.operands[4] as usize;
                4
            } else {
                // last part of the list, there is no next
                core::mem::take(&mut number)
            };
            if consume == 0 {
                None
            } else {
                Some((current.operands, consume))
            }
        })
        .flat_map(|(list, len)| list.into_iter().take(len))
    }

    fn get_int_list(
        &self,
        operand_index1: usize,
        operand_index2: usize,
    ) -> impl Iterator<Item = u64> + 'func {
        self.get_list(operand_index1, operand_index2)
    }

    fn get_float(&self, operand_index: usize) -> f64 {
        let value = self.get_int(operand_index);
        match self.size() {
            4 => f32::from_bits(value as u32) as f64,
            8 => f64::from_bits(value),
            // TODO how to handle this value?
            _ => f64::from_bits(value),
        }
    }

    // TODO implement ConstData type and get function
    //fn get_constant_data(&self, _operand_index1: usize, _operand_index2: usize) -> ConstantData {
    //    //let state = variable.RegisterValueType(self.instr.operands[operand_index1])
    //    //let value = self.instr.operands[operand_index2]
    //    //ConstantData(value, 0, state, core.max_confidence, self.size(), self.function.source_function)
    //}

    fn get_expr_list(
        &self,
        operand_index1: usize,
        operand_index2: usize,
    ) -> impl Iterator<Item = Expression<'func, A, M, F, ValueExpr>> + 'func {
        self.get_list(operand_index1, operand_index2)
            .map(|idx| Expression::new(self.function, idx as usize))
    }

    fn get_target_map(
        &self,
        operand_index1: usize,
        operand_index2: usize,
    ) -> impl Iterator<Item = (u64, u64)> + 'func {
        let mut vars = self.get_list(operand_index1, operand_index2);
        core::iter::from_fn(move || {
            let first = vars.next()?;
            let second = vars.next().unwrap();
            Some((first, second))
        })
    }

    // TODO implement Intrinsic
    //fn get_intrinsic(&self, _operand_index: usize) -> Intrinsic {
    //    todo!()
    //}
}

fn get_raw_operation<'func, A, M, F, O>(
    function: &'func Function<A, M, F>,
    idx: usize,
) -> Operation<'func, A, M, F, O>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    O: OperationArguments,
{
    use binaryninjacore_sys::BNGetMediumLevelILByIndex;
    let op = unsafe { BNGetMediumLevelILByIndex(function.handle, idx) };
    Operation {
        function,
        op,
        _args: PhantomData,
    }
}

impl<'func, A, M, V, O> Operation<'func, A, M, NonSSA<V>, O>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
    O: OperationArguments,
{
    fn get_var(&self, operand_index: usize) -> Variable {
        use binaryninjacore_sys::BNFromVariableIdentifier;
        let var_id = self.op.operands[operand_index];
        unsafe {
            let var_raw = BNFromVariableIdentifier(var_id);
            Variable::from_raw(var_raw)
        }
    }

    fn get_var_list(
        &self,
        operand_index1: usize,
        operand_index2: usize,
    ) -> impl Iterator<Item = Variable> + 'func {
        self.get_list(operand_index1, operand_index2)
            .map(|id| unsafe {
                let raw_var = binaryninjacore_sys::BNFromVariableIdentifier(id);
                Variable::from_raw(raw_var)
            })
    }

    fn get_call_output(&self, operand_index: usize) -> impl Iterator<Item = Variable> + 'func {
        use binaryninjacore_sys::BNMediumLevelILOperation;
        let op: Self = get_raw_operation(self.function, self.op.operands[operand_index] as usize);
        assert_eq!(op.op.operation, BNMediumLevelILOperation::MLIL_CALL_OUTPUT);
        op.get_var_list(0, 1)
    }

    fn get_call_params(&self, operand_index: usize) -> impl Iterator<Item = Variable> + 'func {
        use binaryninjacore_sys::BNMediumLevelILOperation;
        let op: Self = get_raw_operation(self.function, self.op.operands[operand_index] as usize);
        assert_eq!(op.op.operation, BNMediumLevelILOperation::MLIL_CALL_PARAM);
        op.get_var_list(0, 1)
    }
}

impl<'func, A, M, O> Operation<'func, A, M, SSA, O>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    O: OperationArguments,
{
    fn get_var_ssa(&self, operand_index1: usize, operand_index2: usize) -> SSAVariable {
        let var_id = self.op.operands[operand_index1];
        let version = self.op.operands[operand_index2];
        let var_raw = unsafe { binaryninjacore_sys::BNFromVariableIdentifier(var_id) };
        let var = unsafe { Variable::from_raw(var_raw) };
        SSAVariable::new(var, version as usize)
    }

    fn get_var_ssa_list(
        &self,
        operand_index1: usize,
        operand_index2: usize,
    ) -> impl Iterator<Item = SSAVariable> + 'func {
        let mut vars = self.get_list(operand_index1, operand_index2);
        core::iter::from_fn(move || unsafe {
            let var_id = vars.next()?;
            let var_raw = binaryninjacore_sys::BNFromVariableIdentifier(var_id);
            let version = vars.next().unwrap();
            Some(SSAVariable::new(
                Variable::from_raw(var_raw),
                version as usize,
            ))
        })
    }

    fn get_call_output_ssa(
        &self,
        operand_index: usize,
    ) -> impl Iterator<Item = SSAVariable> + 'func {
        use binaryninjacore_sys::BNMediumLevelILOperation;
        let op: Self = get_raw_operation(self.function, self.op.operands[operand_index] as usize);
        assert_eq!(
            op.op.operation,
            BNMediumLevelILOperation::MLIL_CALL_OUTPUT_SSA
        );
        op.get_var_ssa_list(0, 1)
    }

    fn get_call_params_ssa(
        &self,
        operand_index: usize,
    ) -> impl Iterator<Item = SSAVariable> + 'func {
        use binaryninjacore_sys::BNMediumLevelILOperation;
        let op: Self = get_raw_operation(self.function, self.op.operands[operand_index] as usize);
        assert_eq!(
            op.op.operation,
            BNMediumLevelILOperation::MLIL_CALL_PARAM_SSA
        );
        op.get_var_ssa_list(0, 1)
    }
}

// ADC, SBB, RLC, RRC,
pub struct BinaryOpCarry;

impl<'func, A, M, F> Operation<'func, A, M, F, BinaryOpCarry>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn left(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(0)
    }

    pub fn right(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(1)
    }

    pub fn carry(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(2)
    }
}

// ADD, SUB, AND, OR, XOR, LSL, LSR, ASR, ROL, ROR, MUL, MULU_DP, MULS_DP, DIVU, DIVU_DP, DIVS, DIVS_DP, MODU, MODU_DP, MODS, MODS_DP, CMP_E, CMP_NE, CMP_SLT, CMP_ULT, CMP_SLE, CMP_ULE, CMP_SGE, CMP_UGE, CMP_SGT, CMP_UGT, TEST_BIT, ADD_OVERFLOW, FCMP_E, FCMP_NE, FCMP_LT, FCMP_LE, FCMP_GE, FCMP_GT, FCMP_O, FCMP_UO, FADD, FSUB, FMUL, FDIV,
pub struct BinaryOp;

impl<'func, A, M, F> Operation<'func, A, M, F, BinaryOp>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn left(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(0)
    }

    pub fn right(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(1)
    }
}

// CALL, TAILCALL, CALL_SSA, TAILCALL_SSA,
pub struct Call;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, Call>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn output(&self) -> impl Iterator<Item = Variable> + 'func {
        self.get_var_list(0, 1)
    }

    pub fn dest(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        self.get_expr(2)
    }

    pub fn params(
        &self,
    ) -> impl Iterator<Item = Expression<'func, A, M, NonSSA<V>, ValueExpr>> + 'func {
        self.get_expr_list(3, 4)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, Call>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn output(&self) -> impl Iterator<Item = SSAVariable> + 'func {
        self.get_call_output_ssa(0)
    }

    pub fn dest(&self) -> Expression<'func, A, M, SSA, ValueExpr> {
        self.get_expr(1)
    }

    pub fn params(&self) -> impl Iterator<Item = Expression<'func, A, M, SSA, ValueExpr>> + 'func {
        self.get_expr_list(2, 3)
    }

    pub fn src_memory(&self) -> u64 {
        self.get_int(4)
    }
}

// CALL_UNTYPED, TAILCALL_UNTYPED, CALL_UNTYPED_SSA, TAILCALL_UNTYPED_SSA,
pub struct CallUntyped;

impl<'func, A, M, F> Operation<'func, A, M, F, CallUntyped>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(1)
    }

    pub fn stack(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(3)
    }
}

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, CallUntyped>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn output(&self) -> impl Iterator<Item = Variable> + 'func {
        self.get_call_output(0)
    }

    pub fn params(&self) -> impl Iterator<Item = Variable> + 'func {
        self.get_call_params(2)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, CallUntyped>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn output(&self) -> impl Iterator<Item = SSAVariable> + 'func {
        self.get_call_output_ssa(0)
    }

    pub fn params(&self) -> impl Iterator<Item = SSAVariable> + 'func {
        self.get_call_params_ssa(2)
    }
}

// CONST, CONST_PTR, IMPORT,
pub struct Const;

impl<'func, A, M, F> Operation<'func, A, M, F, Const>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn constant(&self) -> u64 {
        self.get_int(0)
    }
}

// CONST_DATA,
pub struct ConstData;

impl<'func, A, M, F> Operation<'func, A, M, F, ConstData>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    // TODO implement ConstantData
    //pub fn constant_data(&self) -> ! {
    //    self.get_constant_data(0, 1)
    //}
}

// EXTERN_PTR,
pub struct ExternPtr;

impl<'func, A, M, F> Operation<'func, A, M, F, ExternPtr>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn constant(&self) -> u64 {
        self.get_int(0)
    }

    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
}

// FLOAT_CONST,
pub struct FloatConst;

impl<'func, A, M, F> Operation<'func, A, M, F, FloatConst>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn constant(&self) -> f64 {
        self.get_float(0)
    }
}

// FREE_VAR_SLOT, FREE_VAR_SLOT_SSA
pub struct FreeVarSlot;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, FreeVarSlot>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn dest(&self) -> Variable {
        self.get_var(0)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, FreeVarSlot>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn dest(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }

    pub fn prev(&self) -> SSAVariable {
        self.get_var_ssa(0, 2)
    }
}

// GOTO,
pub struct Goto;

impl<'func, A, M, F> Operation<'func, A, M, F, Goto>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest(&self) -> u64 {
        self.get_int(0)
    }
}

// IF,
pub struct If;

impl<'func, A, M, F> Operation<'func, A, M, F, If>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn condition(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(0)
    }

    pub fn dest_true(&self) -> u64 {
        self.get_int(1)
    }

    pub fn dest_false(&self) -> u64 {
        self.get_int(2)
    }
}

// INTRINSIC, INTRINSIC_SSA,
pub struct Intrinsic;

impl<'func, A, M, F> Operation<'func, A, M, F, Intrinsic>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    // TODO implement Intrinsic
    //pub fn intrinsic(&self) -> Intrinsic {
    //    self.get_intrinsic(2)
    //}

    pub fn params(&self) -> impl Iterator<Item = Expression<'func, A, M, F, ValueExpr>> + 'func {
        self.get_expr_list(3, 4)
    }
}

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, Intrinsic>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn output(&self) -> impl Iterator<Item = Variable> + 'func {
        self.get_var_list(0, 1)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, Intrinsic>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn output(&self) -> impl Iterator<Item = SSAVariable> + 'func {
        self.get_var_ssa_list(0, 1)
    }
}

// JUMP, RET_HINT,
pub struct Jump;

impl<'func, A, M, F> Operation<'func, A, M, F, Jump>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(0)
    }
}

// JUMP_TO,
pub struct JumpTo;

impl<'func, A, M, F> Operation<'func, A, M, F, JumpTo>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(0)
    }

    pub fn targets(&self) -> impl Iterator<Item = (u64, u64)> + 'func {
        self.get_target_map(1, 2)
    }
}

// NEG, NOT, SX, ZX, LOW_PART, BOOL_TO_INT, UNIMPL_MEM, FSQRT, FNEG, FABS, FLOAT_TO_INT, INT_TO_FLOAT, FLOAT_CONV, ROUND_TO_INT, FLOOR, CEIL, FTRUNC,
pub struct UnaryOp;

impl<'func, A, M, F> Operation<'func, A, M, F, UnaryOp>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn src(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(0)
    }
}

// LOAD, LOAD_SSA,
pub struct Load;

impl<'func, A, M, F> Operation<'func, A, M, F, Load>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn src(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(0)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, Load>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn src_memory(&self) -> u64 {
        self.get_int(1)
    }
}

// LOAD_STRUCT, LOAD_STRUCT_SSA,
pub struct LoadStruct;

impl<'func, A, M, F> Operation<'func, A, M, F, LoadStruct>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn src(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(0)
    }

    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, LoadStruct>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn src_memory(&self) -> u64 {
        self.get_int(2)
    }
}

// MEM_PHI,
pub struct MemPhi;

impl<'func, A, M> Operation<'func, A, M, SSA, MemPhi>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn dest_memory(&self) -> u64 {
        self.get_int(0)
    }

    pub fn src_memory(&self) -> impl Iterator<Item = u64> + 'func {
        self.get_int_list(1, 2)
    }
}

// NOP, NORET, BP, UNDEF, UNIMPL,
pub struct NoArgs;

// RET,
pub struct Ret;

impl<'func, A, M, F> Operation<'func, A, M, F, Ret>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn src(&self) -> impl Iterator<Item = Expression<'func, A, M, F, ValueExpr>> + 'func {
        self.get_expr_list(0, 1)
    }
}

// SET_VAR, SET_VAR_SSA,
pub struct SetVar;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, SetVar>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn dest(&self) -> Variable {
        self.get_var(0)
    }

    pub fn src(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        self.get_expr(1)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, SetVar>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn dest(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }

    pub fn src(&self) -> Expression<'func, A, M, SSA, ValueExpr> {
        self.get_expr(2)
    }
}

// SET_VAR_ALIASED,
pub struct SetVarAliased;

impl<'func, A, M> Operation<'func, A, M, SSA, SetVarAliased>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn dest(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }

    pub fn prev(&self) -> SSAVariable {
        self.get_var_ssa(0, 2)
    }

    pub fn src(&self) -> Expression<'func, A, M, SSA, ValueExpr> {
        self.get_expr(2)
    }
}

// SET_VAR_FIELD, SET_VAR_SSA_FIELD, SET_VAR_ALIASED_FIELD,
pub struct SetVarField;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, SetVarField>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn dest(&self) -> Variable {
        self.get_var(0)
    }

    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }

    pub fn src(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        self.get_expr(2)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, SetVarField>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn dest(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }

    pub fn prev(&self) -> SSAVariable {
        self.get_var_ssa(0, 2)
    }

    pub fn offset(&self) -> u64 {
        self.get_int(2)
    }

    pub fn src(&self) -> Expression<'func, A, M, SSA, ValueExpr> {
        self.get_expr(3)
    }
}

// SET_VAR_SPLIT, SET_VAR_SPLIT_SSA,
pub struct SetVarSplit;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, SetVarSplit>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn high(&self) -> Variable {
        self.get_var(0)
    }

    pub fn low(&self) -> Variable {
        self.get_var(1)
    }

    pub fn src(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        self.get_expr(2)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, SetVarSplit>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn high(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }

    pub fn low(&self) -> SSAVariable {
        self.get_var_ssa(2, 3)
    }

    pub fn src(&self) -> Expression<'func, A, M, SSA, ValueExpr> {
        self.get_expr(4)
    }
}

// STORE, STORE_SSA,
pub struct Store;

impl<'func, A, M, F> Operation<'func, A, M, F, Store>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(0)
    }
}

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, Store>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn src(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        self.get_expr(1)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, Store>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn dest_memory(&self) -> u64 {
        self.get_int(1)
    }

    pub fn src_memory(&self) -> u64 {
        self.get_int(2)
    }

    pub fn src(&self) -> Expression<'func, A, M, SSA, ValueExpr> {
        self.get_expr(3)
    }
}

// STORE_STRUCT, STORE_STRUCT_SSA,
pub struct StoreStruct;

impl<'func, A, M, F> Operation<'func, A, M, F, StoreStruct>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn dest(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(0)
    }

    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
}

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, StoreStruct>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn src(&self) -> Expression<'func, A, M, NonSSA<V>, ValueExpr> {
        self.get_expr(2)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, StoreStruct>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn dest_memory(&self) -> u64 {
        self.get_int(2)
    }

    pub fn src_memory(&self) -> u64 {
        self.get_int(3)
    }

    pub fn src(&self) -> Expression<'func, A, M, SSA, ValueExpr> {
        self.get_expr(4)
    }
}

// SYSCALL, SYSCALL_SSA
pub struct Syscall;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, Syscall>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn output(&self) -> impl Iterator<Item = Variable> + 'func {
        self.get_var_list(0, 1)
    }

    pub fn params(
        &self,
    ) -> impl Iterator<Item = Expression<'func, A, M, NonSSA<V>, ValueExpr>> + 'func {
        self.get_expr_list(2, 3)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, Syscall>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn output(&self) -> impl Iterator<Item = SSAVariable> + 'func {
        self.get_call_output_ssa(0)
    }

    pub fn params(&self) -> impl Iterator<Item = Expression<'func, A, M, SSA, ValueExpr>> + 'func {
        self.get_expr_list(1, 2)
    }

    pub fn src_memory(&self) -> u64 {
        self.get_int(3)
    }
}

// SYSCALL_UNTYPED, SYSCALL_UNTYPED_SSA,
pub struct SyscallUntyped;

impl<'func, A, M, F> Operation<'func, A, M, F, SyscallUntyped>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn stack(&self) -> Expression<'func, A, M, F, ValueExpr> {
        self.get_expr(2)
    }
}

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, SyscallUntyped>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn output(&self) -> impl Iterator<Item = Variable> + 'func {
        self.get_call_output(0)
    }

    pub fn params(&self) -> impl Iterator<Item = Variable> + 'func {
        self.get_call_params(1)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, SyscallUntyped>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn output(&self) -> impl Iterator<Item = SSAVariable> + 'func {
        self.get_call_output_ssa(0)
    }

    pub fn params(&self) -> impl Iterator<Item = SSAVariable> + 'func {
        self.get_call_params_ssa(1)
    }
}

// TRAP,
pub struct Trap;

impl<'func, A, M, F> Operation<'func, A, M, F, Trap>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
{
    pub fn vector(&self) -> u64 {
        self.get_int(0)
    }
}

// VAR, ADDRESS_OF, VAR_SSA, VAR_ALIASED,
pub struct Var;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, Var>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn src(&self) -> Variable {
        self.get_var(0)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, Var>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn src(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }
}

// VAR_FIELD, ADDRESS_OF_FIELD, VAR_SSA_FIELD, VAR_ALIASED_FIELD,
pub struct VarField;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, VarField>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn src(&self) -> Variable {
        self.get_var(0)
    }

    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, VarField>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn src(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }

    pub fn offset(&self) -> u64 {
        self.get_int(2)
    }
}

// VAR_PHI,
pub struct VarPhi;

impl<'func, A, M> Operation<'func, A, M, SSA, VarPhi>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn dest(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }

    pub fn src(&self) -> impl Iterator<Item = SSAVariable> + 'func {
        self.get_var_ssa_list(2, 3)
    }
}

// VAR_SPLIT, VAR_SPLIT_SSA,
pub struct VarSplit;

impl<'func, A, M, V> Operation<'func, A, M, NonSSA<V>, VarSplit>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    V: NonSSAVariant,
{
    pub fn high(&self) -> Variable {
        self.get_var(0)
    }

    pub fn low(&self) -> Variable {
        self.get_var(1)
    }
}

impl<'func, A, M> Operation<'func, A, M, SSA, VarSplit>
where
    A: 'func + Architecture,
    M: FunctionMutability,
{
    pub fn high(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }

    pub fn low(&self) -> SSAVariable {
        self.get_var_ssa(2, 3)
    }
}

pub trait OperationArguments: 'static {}

// CALL_OUTPUT, CALL_OUTPUT_SSA, CALL_PARAM, CALL_PARAM_SSA,
// NOTE CALL_OUTPUT* and CALL_PARAM* are never return directly
//
impl OperationArguments for BinaryOpCarry {}
impl OperationArguments for BinaryOp {}
impl OperationArguments for Const {}
impl OperationArguments for ConstData {}
impl OperationArguments for ExternPtr {}
impl OperationArguments for FloatConst {}
impl OperationArguments for FreeVarSlot {}
impl OperationArguments for Goto {}
impl OperationArguments for If {}
impl OperationArguments for Intrinsic {}
impl OperationArguments for Jump {}
impl OperationArguments for JumpTo {}
impl OperationArguments for UnaryOp {}
impl OperationArguments for Load {}
impl OperationArguments for LoadStruct {}
impl OperationArguments for MemPhi {}
impl OperationArguments for NoArgs {}
impl OperationArguments for Ret {}
impl OperationArguments for SetVar {}
impl OperationArguments for SetVarAliased {}
impl OperationArguments for SetVarField {}
impl OperationArguments for SetVarSplit {}
impl OperationArguments for Store {}
impl OperationArguments for StoreStruct {}
impl OperationArguments for Syscall {}
impl OperationArguments for SyscallUntyped {}
impl OperationArguments for Call {}
impl OperationArguments for CallUntyped {}
impl OperationArguments for Trap {}
impl OperationArguments for Var {}
impl OperationArguments for VarField {}
impl OperationArguments for VarPhi {}
impl OperationArguments for VarSplit {}
