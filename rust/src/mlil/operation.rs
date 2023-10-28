use binaryninjacore_sys::BNMediumLevelILInstruction;
use binaryninjacore_sys::BNMediumLevelILOperation;

use core::marker::PhantomData;

use crate::{rc::Ref, types::SSAVariable};

use super::*;

pub struct Operation<O: OperationArguments> {
    pub(crate) function: Ref<MediumLevelILFunction>,
    pub(crate) op: BNMediumLevelILInstruction,
    _args: PhantomData<O>,
}

impl<O: OperationArguments> Operation<O> {
    pub(crate) fn new(function: &MediumLevelILFunction, op: BNMediumLevelILInstruction) -> Self {
        Self {
            function: function.to_owned(),
            op,
            _args: PhantomData,
        }
    }

    pub fn operation(&self) -> BNMediumLevelILOperation {
        self.op.operation
    }

    pub fn address(&self) -> u64 {
        self.op.address
    }

    pub fn size(&self) -> usize {
        self.op.size
    }

    fn get_expr(&self, operand_index: usize) -> Expression {
        Expression::new(&self.function, self.op.operands[operand_index] as usize)
    }

    fn get_int(&self, operand_index: usize) -> u64 {
        // TODO check mask...
        self.op.operands[operand_index]
    }

    fn get_list(&self, operand_index1: usize, operand_index2: usize) -> impl Iterator<Item = u64> {
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
    ) -> impl Iterator<Item = u64> {
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
    ) -> impl Iterator<Item = Expression> {
        // variable to be moved
        let function = self.function.to_owned();
        self.get_list(operand_index1, operand_index2)
            .map(move |idx| Expression::new(&function, idx as usize))
    }

    fn get_target_map(
        &self,
        operand_index1: usize,
        operand_index2: usize,
    ) -> impl Iterator<Item = (u64, u64)> {
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

fn get_raw_operation<O: OperationArguments>(
    function: &MediumLevelILFunction,
    idx: usize,
) -> Operation<O> {
    use binaryninjacore_sys::BNGetMediumLevelILByIndex;
    let op = unsafe { BNGetMediumLevelILByIndex(function.handle, idx) };
    Operation {
        function: function.to_owned(),
        op,
        _args: PhantomData,
    }
}

impl<O: OperationArguments> Operation<O> {
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
    ) -> impl Iterator<Item = Variable> {
        self.get_list(operand_index1, operand_index2)
            .map(|id| unsafe {
                let raw_var = binaryninjacore_sys::BNFromVariableIdentifier(id);
                Variable::from_raw(raw_var)
            })
    }

    fn get_call_output(&self, operand_index: usize) -> impl Iterator<Item = Variable> {
        let op: Self = get_raw_operation(&self.function, self.op.operands[operand_index] as usize);
        assert_eq!(op.op.operation, BNMediumLevelILOperation::MLIL_CALL_OUTPUT);
        op.get_var_list(0, 1)
    }

    fn get_call_params(&self, operand_index: usize) -> impl Iterator<Item = Variable> {
        let op: Self = get_raw_operation(&self.function, self.op.operands[operand_index] as usize);
        assert_eq!(op.op.operation, BNMediumLevelILOperation::MLIL_CALL_PARAM);
        op.get_var_list(0, 1)
    }

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
    ) -> impl Iterator<Item = SSAVariable> {
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

    fn get_call_output_ssa(&self, operand_index: usize) -> impl Iterator<Item = SSAVariable> {
        let op: Self = get_raw_operation(&self.function, self.op.operands[operand_index] as usize);
        assert_eq!(
            op.op.operation,
            BNMediumLevelILOperation::MLIL_CALL_OUTPUT_SSA
        );
        op.get_var_ssa_list(0, 1)
    }

    fn get_call_params_ssa(&self, operand_index: usize) -> impl Iterator<Item = SSAVariable> {
        let op: Self = get_raw_operation(&self.function, self.op.operands[operand_index] as usize);
        assert_eq!(
            op.op.operation,
            BNMediumLevelILOperation::MLIL_CALL_PARAM_SSA
        );
        op.get_var_ssa_list(0, 1)
    }
}

// NOP, NORET, BP, UNDEF, UNIMPL
pub struct NoArgs;
impl Operation<NoArgs> {}

// ADC, SBB, RLC, RRC
pub struct BinaryOpCarry;
impl Operation<BinaryOpCarry> {
    pub fn left(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn right(&self) -> Expression {
        self.get_expr(1)
    }
    pub fn carry(&self) -> Expression {
        self.get_expr(2)
    }
    pub fn op_type(&self) -> BinaryOpCarryType {
        self.operation().try_into().unwrap()
    }
}

// ADD, SUB, AND, OR, XOR, LSL, LSR, ASR, ROL, ROR, MUL, MULU_DP, MULS_DP, DIVU, DIVU_DP, DIVS, DIVS_DP, MODU, MODU_DP, MODS, MODS_DP, CMP_E, CMP_NE, CMP_SLT, CMP_ULT, CMP_SLE, CMP_ULE, CMP_SGE, CMP_UGE, CMP_SGT, CMP_UGT, TEST_BIT, ADD_OVERFLOW, FCMP_E, FCMP_NE, FCMP_LT, FCMP_LE, FCMP_GE, FCMP_GT, FCMP_O, FCMP_UO, FADD, FSUB, FMUL, FDIV
pub struct BinaryOp;
impl Operation<BinaryOp> {
    pub fn left(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn right(&self) -> Expression {
        self.get_expr(1)
    }
    pub fn op_type(&self) -> BinaryOpType {
        self.operation().try_into().unwrap()
    }
}

// CALL, TAILCALL
pub struct Call;
impl Operation<Call> {
    pub fn output(&self) -> impl Iterator<Item = Variable> {
        self.get_var_list(0, 1)
    }
    pub fn dest(&self) -> Expression {
        self.get_expr(2)
    }
    pub fn params(&self) -> impl Iterator<Item = Expression> {
        self.get_expr_list(3, 4)
    }
    pub fn op_type(&self) -> CallType {
        self.operation().try_into().unwrap()
    }
}

// CALL_SSA, TAILCALL_SSA
pub struct CallSSA;
impl Operation<CallSSA> {
    pub fn output(&self) -> impl Iterator<Item = SSAVariable> {
        self.get_call_output_ssa(0)
    }
    pub fn dest(&self) -> Expression {
        self.get_expr(1)
    }
    pub fn params(&self) -> impl Iterator<Item = Expression> {
        self.get_expr_list(2, 3)
    }
    pub fn src_memory(&self) -> u64 {
        self.get_int(4)
    }
    pub fn op_type(&self) -> CallSSAType {
        self.operation().try_into().unwrap()
    }
}

// CALL_UNTYPED, TAILCALL_UNTYPED
pub struct CallUntyped;
impl Operation<CallUntyped> {
    pub fn output(&self) -> impl Iterator<Item = Variable> {
        self.get_call_output(0)
    }
    pub fn dest(&self) -> Expression {
        self.get_expr(1)
    }
    pub fn params(&self) -> impl Iterator<Item = Variable> {
        self.get_call_params(2)
    }
    pub fn stack(&self) -> Expression {
        self.get_expr(3)
    }
    pub fn op_type(&self) -> CallUntypedType {
        self.operation().try_into().unwrap()
    }
}

// CALL_UNTYPED_SSA, TAILCALL_UNTYPED_SSA
pub struct CallUntypedSSA;
impl Operation<CallUntypedSSA> {
    pub fn output(&self) -> impl Iterator<Item = SSAVariable> {
        self.get_call_output_ssa(0)
    }
    pub fn dest(&self) -> Expression {
        self.get_expr(1)
    }
    pub fn params(&self) -> impl Iterator<Item = SSAVariable> {
        self.get_call_params_ssa(2)
    }
    pub fn stack(&self) -> Expression {
        self.get_expr(3)
    }
    pub fn op_type(&self) -> CallUntypedSSAType {
        self.operation().try_into().unwrap()
    }
}

// CONST, CONST_PTR, IMPORT
pub struct Const;
impl Operation<Const> {
    pub fn constant(&self) -> u64 {
        self.get_int(0)
    }
    pub fn op_type(&self) -> ConstType {
        self.operation().try_into().unwrap()
    }
}

// CONST_DATA
pub struct ConstData;
impl Operation<ConstData> {
    // TODO
}

// EXTERN_PTR
pub struct ExternPtr;
impl Operation<ExternPtr> {
    pub fn constant(&self) -> u64 {
        self.get_int(0)
    }
    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
}

// FLOAT_CONST
pub struct FloatConst;
impl Operation<FloatConst> {
    pub fn constant(&self) -> f64 {
        self.get_float(0)
    }
}

// FREE_VAR_SLOT
pub struct FreeVarSlot;
impl Operation<FreeVarSlot> {
    pub fn dest(&self) -> Variable {
        self.get_var(0)
    }
}

// FREE_VAR_SLOT_SSA
pub struct FreeVarSlotSSA;
impl Operation<FreeVarSlotSSA> {
    pub fn dest(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }
    pub fn prev(&self) -> SSAVariable {
        self.get_var_ssa(0, 2)
    }
}

// GOTO
pub struct Goto;
impl Operation<Goto> {
    pub fn dest(&self) -> u64 {
        self.get_int(0)
    }
}

// IF
pub struct If;
impl Operation<If> {
    pub fn condition(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn dest_true(&self) -> u64 {
        self.get_int(1)
    }
    pub fn dest_false(&self) -> u64 {
        self.get_int(2)
    }
}

// INTRINSIC
pub struct Intrinsic;
impl Operation<Intrinsic> {
    //TODO
    pub fn output(&self) -> impl Iterator<Item = Variable> {
        self.get_var_list(0, 1)
    }
    pub fn params(&self) -> impl Iterator<Item = Expression> {
        self.get_expr_list(3, 4)
    }
}

// INTRINSIC_SSA
pub struct IntrinsicSSA;
impl Operation<IntrinsicSSA> {
    //TODO
    pub fn output(&self) -> impl Iterator<Item = SSAVariable> {
        self.get_var_ssa_list(0, 1)
    }
    pub fn params(&self) -> impl Iterator<Item = Expression> {
        self.get_expr_list(3, 4)
    }
}

// JUMP, RET_HINT
pub struct Jump;
impl Operation<Jump> {
    pub fn dest(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn op_type(&self) -> JumpType {
        self.operation().try_into().unwrap()
    }
}

// JUMP_TO
pub struct JumpTo;
impl Operation<JumpTo> {
    pub fn dest(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn targets(&self) -> impl Iterator<Item = (u64, u64)> {
        self.get_target_map(1, 2)
    }
}

// NEG, NOT, SX, ZX, LOW_PART, BOOL_TO_INT, UNIMPL_MEM, FSQRT, FNEG, FABS, FLOAT_TO_INT, INT_TO_FLOAT, FLOAT_CONV, ROUND_TO_INT, FLOOR, CEIL, FTRUNC
pub struct UnaryOp;
impl Operation<UnaryOp> {
    pub fn src(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn op_type(&self) -> UnaryOpType {
        self.operation().try_into().unwrap()
    }
}

// LOAD
pub struct Load;
impl Operation<Load> {
    pub fn src(&self) -> Expression {
        self.get_expr(0)
    }
}

// LOAD_SSA
pub struct LoadSSA;
impl Operation<LoadSSA> {
    pub fn src(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn src_memory(&self) -> u64 {
        self.get_int(1)
    }
}

// LOAD_STRUCT
pub struct LoadStruct;
impl Operation<LoadStruct> {
    pub fn src(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
}

// LOAD_STRUCT_SSA
pub struct LoadStructSSA;
impl Operation<LoadStructSSA> {
    pub fn src(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
    pub fn src_memory(&self) -> u64 {
        self.get_int(2)
    }
}

// MEM_PHI
pub struct MemPhi;
impl Operation<MemPhi> {
    pub fn dest_memory(&self) -> u64 {
        self.get_int(0)
    }
    pub fn src_memory(&self) -> impl Iterator<Item = u64> {
        self.get_int_list(1, 2)
    }
}

// RET
pub struct Ret;
impl Operation<Ret> {
    pub fn src(&self) -> impl Iterator<Item = Expression> {
        self.get_expr_list(0, 1)
    }
}

// SET_VAR
pub struct SetVar;
impl Operation<SetVar> {
    pub fn dest(&self) -> Variable {
        self.get_var(0)
    }
    pub fn src(&self) -> Expression {
        self.get_expr(1)
    }
}

// SET_VAR_SSA
pub struct SetVarSSA;
impl Operation<SetVarSSA> {
    pub fn dest(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }
    pub fn src(&self) -> Expression {
        self.get_expr(2)
    }
}

// SET_VAR_ALIASED
pub struct SetVarAliased;
impl Operation<SetVarAliased> {
    pub fn dest(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }
    pub fn prev(&self) -> SSAVariable {
        self.get_var_ssa(0, 2)
    }
    pub fn src(&self) -> Expression {
        self.get_expr(2)
    }
}

// SET_VAR_FIELD
pub struct SetVarField;
impl Operation<SetVarField> {
    pub fn dest(&self) -> Variable {
        self.get_var(0)
    }
    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
    pub fn src(&self) -> Expression {
        self.get_expr(2)
    }
}

// SET_VAR_SSA_FIELD, SET_VAR_ALIASED_FIELD
pub struct SetVarFieldSSA;
impl Operation<SetVarFieldSSA> {
    pub fn dest(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }
    pub fn prev(&self) -> SSAVariable {
        self.get_var_ssa(0, 2)
    }
    pub fn offset(&self) -> u64 {
        self.get_int(2)
    }
    pub fn src(&self) -> Expression {
        self.get_expr(3)
    }
    pub fn op_type(&self) -> SetVarFieldSSAType {
        self.operation().try_into().unwrap()
    }
}

// SET_VAR_SPLIT
pub struct SetVarSplit;
impl Operation<SetVarSplit> {
    pub fn high(&self) -> Variable {
        self.get_var(0)
    }
    pub fn low(&self) -> Variable {
        self.get_var(1)
    }
    pub fn src(&self) -> Expression {
        self.get_expr(2)
    }
}

// SET_VAR_SPLIT_SSA
pub struct SetVarSplitSSA;
impl Operation<SetVarSplitSSA> {
    pub fn high(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }
    pub fn low(&self) -> SSAVariable {
        self.get_var_ssa(2, 3)
    }
    pub fn src(&self) -> Expression {
        self.get_expr(4)
    }
}

// STORE
pub struct Store;
impl Operation<Store> {
    pub fn dest(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn src(&self) -> Expression {
        self.get_expr(1)
    }
}

// STORE_SSA
pub struct StoreSSA;
impl Operation<StoreSSA> {
    pub fn dest(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn dest_memory(&self) -> u64 {
        self.get_int(1)
    }
    pub fn src_memory(&self) -> u64 {
        self.get_int(2)
    }
    pub fn src(&self) -> Expression {
        self.get_expr(3)
    }
}

// STORE_STRUCT
pub struct StoreStruct;
impl Operation<StoreStruct> {
    pub fn dest(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
    pub fn src(&self) -> Expression {
        self.get_expr(2)
    }
}

// STORE_STRUCT_SSA
pub struct StoreStructSSA;
impl Operation<StoreStructSSA> {
    pub fn dest(&self) -> Expression {
        self.get_expr(0)
    }
    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
    pub fn dest_memory(&self) -> u64 {
        self.get_int(2)
    }
    pub fn src_memory(&self) -> u64 {
        self.get_int(3)
    }
    pub fn src(&self) -> Expression {
        self.get_expr(4)
    }
}

// SYSCALL
pub struct Syscall;
impl Operation<Syscall> {
    pub fn output(&self) -> impl Iterator<Item = Variable> {
        self.get_var_list(0, 1)
    }
    pub fn params(&self) -> impl Iterator<Item = Expression> {
        self.get_expr_list(2, 3)
    }
}

// SYSCALL_SSA
pub struct SyscallSSA;
impl Operation<SyscallSSA> {
    pub fn output(&self) -> impl Iterator<Item = SSAVariable> {
        self.get_call_output_ssa(0)
    }
    pub fn params(&self) -> impl Iterator<Item = Expression> {
        self.get_expr_list(1, 2)
    }
    pub fn src_memory(&self) -> u64 {
        self.get_int(3)
    }
}

// SYSCALL_UNTYPED
pub struct SyscallUntyped;
impl Operation<SyscallUntyped> {
    pub fn output(&self) -> impl Iterator<Item = Variable> {
        self.get_call_output(0)
    }
    pub fn params(&self) -> impl Iterator<Item = Variable> {
        self.get_call_params(1)
    }
    pub fn stack(&self) -> Expression {
        self.get_expr(2)
    }
}

// SYSCALL_UNTYPED_SSA
pub struct SyscallUntypedSSA;
impl Operation<SyscallUntypedSSA> {
    pub fn output(&self) -> impl Iterator<Item = SSAVariable> {
        self.get_call_output_ssa(0)
    }
    pub fn params(&self) -> impl Iterator<Item = SSAVariable> {
        self.get_call_params_ssa(1)
    }
    pub fn stack(&self) -> Expression {
        self.get_expr(2)
    }
}

// TRAP
pub struct Trap;
impl Operation<Trap> {
    pub fn vector(&self) -> u64 {
        self.get_int(0)
    }
}

// VAR
pub struct Var;
impl Operation<Var> {
    pub fn src(&self) -> Variable {
        self.get_var(0)
    }
}

// ADDRESS_OF
pub struct AddressOf;
impl Operation<AddressOf> {
    pub fn src(&self) -> Variable {
        self.get_var(0)
    }
}

// VAR_SSA, VAR_ALIASED
pub struct VarSSA;
impl Operation<VarSSA> {
    pub fn src(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }
    pub fn op_type(&self) -> VarSSAType {
        self.operation().try_into().unwrap()
    }
}

// VAR_FIELD
pub struct VarField;
impl Operation<VarField> {
    pub fn src(&self) -> Variable {
        self.get_var(0)
    }
    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
}

// ADDRESS_OF_FIELD
pub struct AddressOfField;
impl Operation<AddressOfField> {
    pub fn src(&self) -> Variable {
        self.get_var(0)
    }
    pub fn offset(&self) -> u64 {
        self.get_int(1)
    }
}

// VAR_SSA_FIELD, VAR_ALIASED_FIELD
pub struct VarFieldSSA;
impl Operation<VarFieldSSA> {
    pub fn src(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }
    pub fn offset(&self) -> u64 {
        self.get_int(2)
    }
    pub fn op_type(&self) -> VarFieldSSAType {
        self.operation().try_into().unwrap()
    }
}

// VAR_PHI
pub struct VarPhi;
impl Operation<VarPhi> {
    pub fn dest(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }
    pub fn src(&self) -> impl Iterator<Item = SSAVariable> {
        self.get_var_ssa_list(2, 3)
    }
}

// VAR_SPLIT
pub struct VarSplit;
impl Operation<VarSplit> {
    pub fn high(&self) -> Variable {
        self.get_var(0)
    }
    pub fn low(&self) -> Variable {
        self.get_var(1)
    }
}

// VAR_SPLIT_SSA
pub struct VarSplitSSA;
impl Operation<VarSplitSSA> {
    pub fn high(&self) -> SSAVariable {
        self.get_var_ssa(0, 1)
    }
    pub fn low(&self) -> SSAVariable {
        self.get_var_ssa(2, 3)
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum BinaryOpCarryType {
    Adc,
    Sbb,
    Rlc,
    Rrc,
}

impl TryFrom<BNMediumLevelILOperation> for BinaryOpCarryType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_ADC => Self::Adc,
            MLIL_SBB => Self::Sbb,
            MLIL_RLC => Self::Rlc,
            MLIL_RRC => Self::Rrc,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum BinaryOpType {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Lsl,
    Lsr,
    Asr,
    Rol,
    Ror,
    Mul,
    MuluDp,
    MulsDp,
    Divu,
    DivuDp,
    Divs,
    DivsDp,
    Modu,
    ModuDp,
    Mods,
    ModsDp,
    CmpE,
    CmpNe,
    CmpSlt,
    CmpUlt,
    CmpSle,
    CmpUle,
    CmpSge,
    CmpUge,
    CmpSgt,
    CmpUgt,
    TestBit,
    AddOverflow,
    FcmpE,
    FcmpNe,
    FcmpLt,
    FcmpLe,
    FcmpGe,
    FcmpGt,
    FcmpO,
    FcmpUo,
    Fadd,
    Fsub,
    Fmul,
    Fdiv,
}

impl TryFrom<BNMediumLevelILOperation> for BinaryOpType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_ADD => Self::Add,
            MLIL_SUB => Self::Sub,
            MLIL_AND => Self::And,
            MLIL_OR => Self::Or,
            MLIL_XOR => Self::Xor,
            MLIL_LSL => Self::Lsl,
            MLIL_LSR => Self::Lsr,
            MLIL_ASR => Self::Asr,
            MLIL_ROL => Self::Rol,
            MLIL_ROR => Self::Ror,
            MLIL_MUL => Self::Mul,
            MLIL_MULU_DP => Self::MuluDp,
            MLIL_MULS_DP => Self::MulsDp,
            MLIL_DIVU => Self::Divu,
            MLIL_DIVU_DP => Self::DivuDp,
            MLIL_DIVS => Self::Divs,
            MLIL_DIVS_DP => Self::DivsDp,
            MLIL_MODU => Self::Modu,
            MLIL_MODU_DP => Self::ModuDp,
            MLIL_MODS => Self::Mods,
            MLIL_MODS_DP => Self::ModsDp,
            MLIL_CMP_E => Self::CmpE,
            MLIL_CMP_NE => Self::CmpNe,
            MLIL_CMP_SLT => Self::CmpSlt,
            MLIL_CMP_ULT => Self::CmpUlt,
            MLIL_CMP_SLE => Self::CmpSle,
            MLIL_CMP_ULE => Self::CmpUle,
            MLIL_CMP_SGE => Self::CmpSge,
            MLIL_CMP_UGE => Self::CmpUge,
            MLIL_CMP_SGT => Self::CmpSgt,
            MLIL_CMP_UGT => Self::CmpUgt,
            MLIL_TEST_BIT => Self::TestBit,
            MLIL_ADD_OVERFLOW => Self::AddOverflow,
            MLIL_FCMP_E => Self::FcmpE,
            MLIL_FCMP_NE => Self::FcmpNe,
            MLIL_FCMP_LT => Self::FcmpLt,
            MLIL_FCMP_LE => Self::FcmpLe,
            MLIL_FCMP_GE => Self::FcmpGe,
            MLIL_FCMP_GT => Self::FcmpGt,
            MLIL_FCMP_O => Self::FcmpO,
            MLIL_FCMP_UO => Self::FcmpUo,
            MLIL_FADD => Self::Fadd,
            MLIL_FSUB => Self::Fsub,
            MLIL_FMUL => Self::Fmul,
            MLIL_FDIV => Self::Fdiv,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum CallType {
    Call,
    Tailcall,
}

impl TryFrom<BNMediumLevelILOperation> for CallType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_CALL => Self::Call,
            MLIL_TAILCALL => Self::Tailcall,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum CallSSAType {
    Call,
    Tailcall,
}

impl TryFrom<BNMediumLevelILOperation> for CallSSAType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_CALL_SSA => Self::Call,
            MLIL_TAILCALL_SSA => Self::Tailcall,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum CallUntypedType {
    Call,
    TailCall,
}

impl TryFrom<BNMediumLevelILOperation> for CallUntypedType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_CALL_UNTYPED => Self::Call,
            MLIL_TAILCALL_UNTYPED => Self::TailCall,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum CallUntypedSSAType {
    Call,
    Tailcall,
}

impl TryFrom<BNMediumLevelILOperation> for CallUntypedSSAType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_CALL_UNTYPED_SSA => Self::Call,
            MLIL_TAILCALL_UNTYPED_SSA => Self::Tailcall,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum ConstType {
    Const,
    ConstPtr,
    Import,
}

impl TryFrom<BNMediumLevelILOperation> for ConstType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_CONST => Self::Const,
            MLIL_CONST_PTR => Self::ConstPtr,
            MLIL_IMPORT => Self::Import,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum JumpType {
    Jump,
    RetHint,
}

impl TryFrom<BNMediumLevelILOperation> for JumpType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_JUMP => Self::Jump,
            MLIL_RET_HINT => Self::RetHint,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum UnaryOpType {
    Neg,
    Not,
    Sx,
    Zx,
    LowPart,
    BoolToInt,
    UnimplMem,
    Fsqrt,
    Fneg,
    Fabs,
    FloatToInt,
    IntToFloat,
    FloatConv,
    RoundToInt,
    Floor,
    Ceil,
    Ftrunc,
}

impl TryFrom<BNMediumLevelILOperation> for UnaryOpType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_NEG => Self::Neg,
            MLIL_NOT => Self::Not,
            MLIL_SX => Self::Sx,
            MLIL_ZX => Self::Zx,
            MLIL_LOW_PART => Self::LowPart,
            MLIL_BOOL_TO_INT => Self::BoolToInt,
            MLIL_UNIMPL_MEM => Self::UnimplMem,
            MLIL_FSQRT => Self::Fsqrt,
            MLIL_FNEG => Self::Fneg,
            MLIL_FABS => Self::Fabs,
            MLIL_FLOAT_TO_INT => Self::FloatToInt,
            MLIL_INT_TO_FLOAT => Self::IntToFloat,
            MLIL_FLOAT_CONV => Self::FloatConv,
            MLIL_ROUND_TO_INT => Self::RoundToInt,
            MLIL_FLOOR => Self::Floor,
            MLIL_CEIL => Self::Ceil,
            MLIL_FTRUNC => Self::Ftrunc,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum SetVarFieldSSAType {
    SetVar,
    SetVarAliased,
}

impl TryFrom<BNMediumLevelILOperation> for SetVarFieldSSAType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_SET_VAR_SSA_FIELD => Self::SetVar,
            MLIL_SET_VAR_ALIASED_FIELD => Self::SetVarAliased,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum VarSSAType {
    Var,
    VarAliased,
}

impl TryFrom<BNMediumLevelILOperation> for VarSSAType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_VAR_SSA => Self::Var,
            MLIL_VAR_ALIASED => Self::VarAliased,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum VarFieldSSAType {
    VarField,
    VarAliasedField,
}

impl TryFrom<BNMediumLevelILOperation> for VarFieldSSAType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_VAR_SSA_FIELD => Self::VarField,
            MLIL_VAR_ALIASED_FIELD => Self::VarAliasedField,
            _ => return Err(()),
        })
    }
}
pub trait OperationArguments: 'static {}

// CALL_OUTPUT, CALL_OUTPUT_SSA, CALL_PARAM, CALL_PARAM_SSA,
// NOTE CALL_OUTPUT* and CALL_PARAM* are never return directly
//
impl OperationArguments for NoArgs {}
impl OperationArguments for AddressOf {}
impl OperationArguments for AddressOfField {}
impl OperationArguments for BinaryOpCarry {}
impl OperationArguments for BinaryOp {}
impl OperationArguments for Const {}
impl OperationArguments for ConstData {}
impl OperationArguments for ExternPtr {}
impl OperationArguments for FloatConst {}
impl OperationArguments for FreeVarSlot {}
impl OperationArguments for FreeVarSlotSSA {}
impl OperationArguments for Goto {}
impl OperationArguments for If {}
impl OperationArguments for Intrinsic {}
impl OperationArguments for IntrinsicSSA {}
impl OperationArguments for Jump {}
impl OperationArguments for JumpTo {}
impl OperationArguments for UnaryOp {}
impl OperationArguments for Load {}
impl OperationArguments for LoadSSA {}
impl OperationArguments for LoadStruct {}
impl OperationArguments for LoadStructSSA {}
impl OperationArguments for MemPhi {}
impl OperationArguments for Ret {}
impl OperationArguments for SetVar {}
impl OperationArguments for SetVarSSA {}
impl OperationArguments for SetVarAliased {}
impl OperationArguments for SetVarField {}
impl OperationArguments for SetVarFieldSSA {}
impl OperationArguments for SetVarSplit {}
impl OperationArguments for SetVarSplitSSA {}
impl OperationArguments for Store {}
impl OperationArguments for StoreSSA {}
impl OperationArguments for StoreStruct {}
impl OperationArguments for StoreStructSSA {}
impl OperationArguments for Syscall {}
impl OperationArguments for SyscallSSA {}
impl OperationArguments for SyscallUntyped {}
impl OperationArguments for SyscallUntypedSSA {}
impl OperationArguments for Call {}
impl OperationArguments for CallSSA {}
impl OperationArguments for CallUntyped {}
impl OperationArguments for CallUntypedSSA {}
impl OperationArguments for Trap {}
impl OperationArguments for Var {}
impl OperationArguments for VarSSA {}
impl OperationArguments for VarField {}
impl OperationArguments for VarFieldSSA {}
impl OperationArguments for VarPhi {}
impl OperationArguments for VarSplit {}
impl OperationArguments for VarSplitSSA {}
