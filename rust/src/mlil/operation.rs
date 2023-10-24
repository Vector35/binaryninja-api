use binaryninjacore_sys::BNMediumLevelILInstruction;
use binaryninjacore_sys::BNMediumLevelILOperation;

use core::marker::PhantomData;

use crate::{rc::Ref, types::SSAVariable};

use super::*;

pub struct Operation<O: OperationArguments> {
    pub(crate) function: Ref<Function>,
    pub(crate) op: BNMediumLevelILInstruction,
    _args: PhantomData<O>,
}

impl<O: OperationArguments> Operation<O> {
    pub(crate) fn new(function: &Function, op: BNMediumLevelILInstruction) -> Self {
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

fn get_raw_operation<O: OperationArguments>(function: &Function, idx: usize) -> Operation<O> {
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

// NOP
pub struct Nop;
impl Operation<Nop> {}

// NORET
pub struct NoRet;
impl Operation<NoRet> {}

// BP
pub struct Bp;
impl Operation<Bp> {}

// UNDEF
pub struct Undef;
impl Operation<Undef> {}

// UNIMPL
pub struct Unimpl;
impl Operation<Unimpl> {}

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
    ADC,
    SBB,
    RLC,
    RRC,
}

impl TryFrom<BNMediumLevelILOperation> for BinaryOpCarryType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_ADC => Self::ADC,
            MLIL_SBB => Self::SBB,
            MLIL_RLC => Self::RLC,
            MLIL_RRC => Self::RRC,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum BinaryOpType {
    ADD,
    SUB,
    AND,
    OR,
    XOR,
    LSL,
    LSR,
    ASR,
    ROL,
    ROR,
    MUL,
    MULU_DP,
    MULS_DP,
    DIVU,
    DIVU_DP,
    DIVS,
    DIVS_DP,
    MODU,
    MODU_DP,
    MODS,
    MODS_DP,
    CMP_E,
    CMP_NE,
    CMP_SLT,
    CMP_ULT,
    CMP_SLE,
    CMP_ULE,
    CMP_SGE,
    CMP_UGE,
    CMP_SGT,
    CMP_UGT,
    TEST_BIT,
    ADD_OVERFLOW,
    FCMP_E,
    FCMP_NE,
    FCMP_LT,
    FCMP_LE,
    FCMP_GE,
    FCMP_GT,
    FCMP_O,
    FCMP_UO,
    FADD,
    FSUB,
    FMUL,
    FDIV,
}

impl TryFrom<BNMediumLevelILOperation> for BinaryOpType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_ADD => Self::ADD,
            MLIL_SUB => Self::SUB,
            MLIL_AND => Self::AND,
            MLIL_OR => Self::OR,
            MLIL_XOR => Self::XOR,
            MLIL_LSL => Self::LSL,
            MLIL_LSR => Self::LSR,
            MLIL_ASR => Self::ASR,
            MLIL_ROL => Self::ROL,
            MLIL_ROR => Self::ROR,
            MLIL_MUL => Self::MUL,
            MLIL_MULU_DP => Self::MULU_DP,
            MLIL_MULS_DP => Self::MULS_DP,
            MLIL_DIVU => Self::DIVU,
            MLIL_DIVU_DP => Self::DIVU_DP,
            MLIL_DIVS => Self::DIVS,
            MLIL_DIVS_DP => Self::DIVS_DP,
            MLIL_MODU => Self::MODU,
            MLIL_MODU_DP => Self::MODU_DP,
            MLIL_MODS => Self::MODS,
            MLIL_MODS_DP => Self::MODS_DP,
            MLIL_CMP_E => Self::CMP_E,
            MLIL_CMP_NE => Self::CMP_NE,
            MLIL_CMP_SLT => Self::CMP_SLT,
            MLIL_CMP_ULT => Self::CMP_ULT,
            MLIL_CMP_SLE => Self::CMP_SLE,
            MLIL_CMP_ULE => Self::CMP_ULE,
            MLIL_CMP_SGE => Self::CMP_SGE,
            MLIL_CMP_UGE => Self::CMP_UGE,
            MLIL_CMP_SGT => Self::CMP_SGT,
            MLIL_CMP_UGT => Self::CMP_UGT,
            MLIL_TEST_BIT => Self::TEST_BIT,
            MLIL_ADD_OVERFLOW => Self::ADD_OVERFLOW,
            MLIL_FCMP_E => Self::FCMP_E,
            MLIL_FCMP_NE => Self::FCMP_NE,
            MLIL_FCMP_LT => Self::FCMP_LT,
            MLIL_FCMP_LE => Self::FCMP_LE,
            MLIL_FCMP_GE => Self::FCMP_GE,
            MLIL_FCMP_GT => Self::FCMP_GT,
            MLIL_FCMP_O => Self::FCMP_O,
            MLIL_FCMP_UO => Self::FCMP_UO,
            MLIL_FADD => Self::FADD,
            MLIL_FSUB => Self::FSUB,
            MLIL_FMUL => Self::FMUL,
            MLIL_FDIV => Self::FDIV,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum CallType {
    CALL,
    TAILCALL,
}

impl TryFrom<BNMediumLevelILOperation> for CallType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_CALL => Self::CALL,
            MLIL_TAILCALL => Self::TAILCALL,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum CallSSAType {
    CALL_SSA,
    TAILCALL_SSA,
}

impl TryFrom<BNMediumLevelILOperation> for CallSSAType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_CALL_SSA => Self::CALL_SSA,
            MLIL_TAILCALL_SSA => Self::TAILCALL_SSA,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum CallUntypedType {
    CALL_UNTYPED,
    TAILCALL_UNTYPED,
}

impl TryFrom<BNMediumLevelILOperation> for CallUntypedType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_CALL_UNTYPED => Self::CALL_UNTYPED,
            MLIL_TAILCALL_UNTYPED => Self::TAILCALL_UNTYPED,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum CallUntypedSSAType {
    CALL_UNTYPED_SSA,
    TAILCALL_UNTYPED_SSA,
}

impl TryFrom<BNMediumLevelILOperation> for CallUntypedSSAType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_CALL_UNTYPED_SSA => Self::CALL_UNTYPED_SSA,
            MLIL_TAILCALL_UNTYPED_SSA => Self::TAILCALL_UNTYPED_SSA,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum ConstType {
    CONST,
    CONST_PTR,
    IMPORT,
}

impl TryFrom<BNMediumLevelILOperation> for ConstType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_CONST => Self::CONST,
            MLIL_CONST_PTR => Self::CONST_PTR,
            MLIL_IMPORT => Self::IMPORT,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum JumpType {
    JUMP,
    RET_HINT,
}

impl TryFrom<BNMediumLevelILOperation> for JumpType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_JUMP => Self::JUMP,
            MLIL_RET_HINT => Self::RET_HINT,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum UnaryOpType {
    NEG,
    NOT,
    SX,
    ZX,
    LOW_PART,
    BOOL_TO_INT,
    UNIMPL_MEM,
    FSQRT,
    FNEG,
    FABS,
    FLOAT_TO_INT,
    INT_TO_FLOAT,
    FLOAT_CONV,
    ROUND_TO_INT,
    FLOOR,
    CEIL,
    FTRUNC,
}

impl TryFrom<BNMediumLevelILOperation> for UnaryOpType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_NEG => Self::NEG,
            MLIL_NOT => Self::NOT,
            MLIL_SX => Self::SX,
            MLIL_ZX => Self::ZX,
            MLIL_LOW_PART => Self::LOW_PART,
            MLIL_BOOL_TO_INT => Self::BOOL_TO_INT,
            MLIL_UNIMPL_MEM => Self::UNIMPL_MEM,
            MLIL_FSQRT => Self::FSQRT,
            MLIL_FNEG => Self::FNEG,
            MLIL_FABS => Self::FABS,
            MLIL_FLOAT_TO_INT => Self::FLOAT_TO_INT,
            MLIL_INT_TO_FLOAT => Self::INT_TO_FLOAT,
            MLIL_FLOAT_CONV => Self::FLOAT_CONV,
            MLIL_ROUND_TO_INT => Self::ROUND_TO_INT,
            MLIL_FLOOR => Self::FLOOR,
            MLIL_CEIL => Self::CEIL,
            MLIL_FTRUNC => Self::FTRUNC,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum SetVarFieldSSAType {
    SET_VAR_SSA_FIELD,
    SET_VAR_ALIASED_FIELD,
}

impl TryFrom<BNMediumLevelILOperation> for SetVarFieldSSAType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_SET_VAR_SSA_FIELD => Self::SET_VAR_SSA_FIELD,
            MLIL_SET_VAR_ALIASED_FIELD => Self::SET_VAR_ALIASED_FIELD,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum VarSSAType {
    VAR_SSA,
    VAR_ALIASED,
}

impl TryFrom<BNMediumLevelILOperation> for VarSSAType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_VAR_SSA => Self::VAR_SSA,
            MLIL_VAR_ALIASED => Self::VAR_ALIASED,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum VarFieldSSAType {
    VAR_SSA_FIELD,
    VAR_ALIASED_FIELD,
}

impl TryFrom<BNMediumLevelILOperation> for VarFieldSSAType {
    type Error = ();
    fn try_from(value: BNMediumLevelILOperation) -> Result<Self, Self::Error> {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;
        Ok(match value {
            MLIL_VAR_SSA_FIELD => Self::VAR_SSA_FIELD,
            MLIL_VAR_ALIASED_FIELD => Self::VAR_ALIASED_FIELD,
            _ => return Err(()),
        })
    }
}
pub trait OperationArguments: 'static {}

// CALL_OUTPUT, CALL_OUTPUT_SSA, CALL_PARAM, CALL_PARAM_SSA,
// NOTE CALL_OUTPUT* and CALL_PARAM* are never return directly
//
impl OperationArguments for Nop {}
impl OperationArguments for NoRet {}
impl OperationArguments for Bp {}
impl OperationArguments for Undef {}
impl OperationArguments for Unimpl {}
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
