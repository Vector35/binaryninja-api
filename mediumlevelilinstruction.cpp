// Copyright (c) 2015-2019 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#ifdef BINARYNINJACORE_LIBRARY
#include "mediumlevelilfunction.h"
#include "mediumlevelilssafunction.h"
#include "lowlevelilfunction.h"
using namespace BinaryNinjaCore;
#else
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"
#include "lowlevelilinstruction.h"
using namespace BinaryNinja;
#endif

using namespace std;


unordered_map<MediumLevelILOperandUsage, MediumLevelILOperandType>
	MediumLevelILInstructionBase::operandTypeForUsage = {
		{SourceExprMediumLevelOperandUsage, ExprMediumLevelOperand},
		{SourceVariableMediumLevelOperandUsage, VariableMediumLevelOperand},
		{SourceSSAVariableMediumLevelOperandUsage, SSAVariableMediumLevelOperand},
		{PartialSSAVariableSourceMediumLevelOperandUsage, SSAVariableMediumLevelOperand},
		{DestExprMediumLevelOperandUsage, ExprMediumLevelOperand},
		{DestVariableMediumLevelOperandUsage, VariableMediumLevelOperand},
		{DestSSAVariableMediumLevelOperandUsage, SSAVariableMediumLevelOperand},
		{LeftExprMediumLevelOperandUsage, ExprMediumLevelOperand},
		{RightExprMediumLevelOperandUsage, ExprMediumLevelOperand},
		{CarryExprMediumLevelOperandUsage, ExprMediumLevelOperand},
		{StackExprMediumLevelOperandUsage, ExprMediumLevelOperand},
		{ConditionExprMediumLevelOperandUsage, ExprMediumLevelOperand},
		{HighVariableMediumLevelOperandUsage, VariableMediumLevelOperand},
		{LowVariableMediumLevelOperandUsage, VariableMediumLevelOperand},
		{HighSSAVariableMediumLevelOperandUsage, VariableMediumLevelOperand},
		{LowSSAVariableMediumLevelOperandUsage, VariableMediumLevelOperand},
		{OffsetMediumLevelOperandUsage, IntegerMediumLevelOperand},
		{ConstantMediumLevelOperandUsage, IntegerMediumLevelOperand},
		{VectorMediumLevelOperandUsage, IntegerMediumLevelOperand},
		{IntrinsicMediumLevelOperandUsage, IntrinsicMediumLevelOperand},
		{TargetMediumLevelOperandUsage, IndexMediumLevelOperand},
		{TrueTargetMediumLevelOperandUsage, IndexMediumLevelOperand},
		{FalseTargetMediumLevelOperandUsage, IndexMediumLevelOperand},
		{DestMemoryVersionMediumLevelOperandUsage, IndexMediumLevelOperand},
		{SourceMemoryVersionMediumLevelOperandUsage, IndexMediumLevelOperand},
		{TargetsMediumLevelOperandUsage, IndexMapMediumLevelOperand},
		{SourceMemoryVersionsMediumLevelOperandUsage, IndexListMediumLevelOperand},
		{OutputVariablesMediumLevelOperandUsage, VariableListMediumLevelOperand},
		{OutputVariablesSubExprMediumLevelOperandUsage, VariableListMediumLevelOperand},
		{OutputSSAVariablesMediumLevelOperandUsage, SSAVariableListMediumLevelOperand},
		{OutputSSAVariablesSubExprMediumLevelOperandUsage, SSAVariableListMediumLevelOperand},
		{OutputSSAMemoryVersionMediumLevelOperandUsage, IndexMediumLevelOperand},
		{ParameterExprsMediumLevelOperandUsage, ExprListMediumLevelOperand},
		{SourceExprsMediumLevelOperandUsage, ExprListMediumLevelOperand},
		{ParameterVariablesMediumLevelOperandUsage, VariableListMediumLevelOperand},
		{ParameterSSAVariablesMediumLevelOperandUsage, SSAVariableListMediumLevelOperand},
		{ParameterSSAMemoryVersionMediumLevelOperandUsage, IndexMediumLevelOperand},
		{SourceSSAVariablesMediumLevelOperandUsages, SSAVariableListMediumLevelOperand}
	};


unordered_map<BNMediumLevelILOperation, vector<MediumLevelILOperandUsage>>
	MediumLevelILInstructionBase::operationOperandUsage = {
		{MLIL_NOP, {}},
		{MLIL_NORET, {}},
		{MLIL_BP, {}},
		{MLIL_UNDEF, {}},
		{MLIL_UNIMPL, {}},
		{MLIL_SET_VAR, {DestVariableMediumLevelOperandUsage, SourceExprMediumLevelOperandUsage}},
		{MLIL_SET_VAR_FIELD, {DestVariableMediumLevelOperandUsage, OffsetMediumLevelOperandUsage,
			SourceExprMediumLevelOperandUsage}},
		{MLIL_SET_VAR_SPLIT, {HighVariableMediumLevelOperandUsage, LowVariableMediumLevelOperandUsage,
			SourceExprMediumLevelOperandUsage}},
		{MLIL_SET_VAR_SSA, {DestSSAVariableMediumLevelOperandUsage, SourceExprMediumLevelOperandUsage}},
		{MLIL_SET_VAR_SSA_FIELD, {DestSSAVariableMediumLevelOperandUsage, PartialSSAVariableSourceMediumLevelOperandUsage,
			OffsetMediumLevelOperandUsage, SourceExprMediumLevelOperandUsage}},
		{MLIL_SET_VAR_SPLIT_SSA, {HighSSAVariableMediumLevelOperandUsage, LowSSAVariableMediumLevelOperandUsage,
			SourceExprMediumLevelOperandUsage}},
		{MLIL_SET_VAR_ALIASED, {DestSSAVariableMediumLevelOperandUsage, PartialSSAVariableSourceMediumLevelOperandUsage,
			SourceExprMediumLevelOperandUsage}},
		{MLIL_SET_VAR_ALIASED_FIELD, {DestSSAVariableMediumLevelOperandUsage, PartialSSAVariableSourceMediumLevelOperandUsage,
			OffsetMediumLevelOperandUsage, SourceExprMediumLevelOperandUsage}},
		{MLIL_LOAD, {SourceExprMediumLevelOperandUsage}},
		{MLIL_LOAD_STRUCT, {SourceExprMediumLevelOperandUsage, OffsetMediumLevelOperandUsage}},
		{MLIL_LOAD_SSA, {SourceExprMediumLevelOperandUsage, SourceMemoryVersionMediumLevelOperandUsage}},
		{MLIL_LOAD_STRUCT_SSA, {SourceExprMediumLevelOperandUsage, OffsetMediumLevelOperandUsage,
			SourceMemoryVersionMediumLevelOperandUsage}},
		{MLIL_STORE, {DestExprMediumLevelOperandUsage, SourceExprMediumLevelOperandUsage}},
		{MLIL_STORE_STRUCT, {DestExprMediumLevelOperandUsage, OffsetMediumLevelOperandUsage,
			SourceExprMediumLevelOperandUsage}},
		{MLIL_STORE_SSA, {DestExprMediumLevelOperandUsage, DestMemoryVersionMediumLevelOperandUsage,
			SourceMemoryVersionMediumLevelOperandUsage, SourceExprMediumLevelOperandUsage}},
		{MLIL_STORE_STRUCT_SSA, {DestExprMediumLevelOperandUsage, OffsetMediumLevelOperandUsage,
			DestMemoryVersionMediumLevelOperandUsage, SourceMemoryVersionMediumLevelOperandUsage,
			SourceExprMediumLevelOperandUsage}},
		{MLIL_VAR, {SourceVariableMediumLevelOperandUsage}},
		{MLIL_VAR_FIELD, {SourceVariableMediumLevelOperandUsage, OffsetMediumLevelOperandUsage}},
		{MLIL_VAR_SPLIT, {HighVariableMediumLevelOperandUsage, LowVariableMediumLevelOperandUsage}},
		{MLIL_VAR_SSA, {SourceSSAVariableMediumLevelOperandUsage}},
		{MLIL_VAR_SSA_FIELD, {SourceSSAVariableMediumLevelOperandUsage, OffsetMediumLevelOperandUsage}},
		{MLIL_VAR_ALIASED, {SourceSSAVariableMediumLevelOperandUsage}},
		{MLIL_VAR_ALIASED_FIELD, {SourceSSAVariableMediumLevelOperandUsage, OffsetMediumLevelOperandUsage}},
		{MLIL_VAR_SPLIT_SSA, {HighSSAVariableMediumLevelOperandUsage, LowSSAVariableMediumLevelOperandUsage}},
		{MLIL_ADDRESS_OF, {SourceVariableMediumLevelOperandUsage}},
		{MLIL_ADDRESS_OF_FIELD, {SourceVariableMediumLevelOperandUsage, OffsetMediumLevelOperandUsage}},
		{MLIL_JUMP, {DestExprMediumLevelOperandUsage}},
		{MLIL_JUMP_TO, {DestExprMediumLevelOperandUsage, TargetsMediumLevelOperandUsage}},
		{MLIL_RET_HINT, {DestExprMediumLevelOperandUsage}},
		{MLIL_CALL, {OutputVariablesMediumLevelOperandUsage, DestExprMediumLevelOperandUsage,
			ParameterExprsMediumLevelOperandUsage}},
		{MLIL_CALL_UNTYPED, {OutputVariablesSubExprMediumLevelOperandUsage, DestExprMediumLevelOperandUsage,
			ParameterVariablesMediumLevelOperandUsage}},
		{MLIL_SYSCALL, {OutputVariablesMediumLevelOperandUsage, ParameterExprsMediumLevelOperandUsage}},
		{MLIL_SYSCALL_UNTYPED, {OutputVariablesSubExprMediumLevelOperandUsage,
			ParameterVariablesMediumLevelOperandUsage, StackExprMediumLevelOperandUsage}},
		{MLIL_TAILCALL, {OutputVariablesMediumLevelOperandUsage, DestExprMediumLevelOperandUsage,
			ParameterExprsMediumLevelOperandUsage}},
		{MLIL_TAILCALL_UNTYPED, {OutputVariablesSubExprMediumLevelOperandUsage, DestExprMediumLevelOperandUsage,
			ParameterVariablesMediumLevelOperandUsage}},
		{MLIL_CALL_SSA, {OutputSSAVariablesSubExprMediumLevelOperandUsage,
			OutputSSAMemoryVersionMediumLevelOperandUsage, DestExprMediumLevelOperandUsage,
			ParameterExprsMediumLevelOperandUsage, SourceMemoryVersionMediumLevelOperandUsage}},
		{MLIL_CALL_UNTYPED_SSA, {OutputSSAVariablesSubExprMediumLevelOperandUsage,
			OutputSSAMemoryVersionMediumLevelOperandUsage, DestExprMediumLevelOperandUsage,
			ParameterSSAVariablesMediumLevelOperandUsage, ParameterSSAMemoryVersionMediumLevelOperandUsage,
			StackExprMediumLevelOperandUsage}},
		{MLIL_SYSCALL_SSA, {OutputSSAVariablesSubExprMediumLevelOperandUsage,
			OutputSSAMemoryVersionMediumLevelOperandUsage, ParameterExprsMediumLevelOperandUsage,
			SourceMemoryVersionMediumLevelOperandUsage}},
		{MLIL_SYSCALL_UNTYPED_SSA, {OutputSSAVariablesSubExprMediumLevelOperandUsage,
			OutputSSAMemoryVersionMediumLevelOperandUsage, ParameterSSAVariablesMediumLevelOperandUsage,
			ParameterSSAMemoryVersionMediumLevelOperandUsage, StackExprMediumLevelOperandUsage}},
		{MLIL_TAILCALL_SSA, {OutputSSAVariablesSubExprMediumLevelOperandUsage,
			OutputSSAMemoryVersionMediumLevelOperandUsage, DestExprMediumLevelOperandUsage,
			ParameterExprsMediumLevelOperandUsage, SourceMemoryVersionMediumLevelOperandUsage}},
		{MLIL_TAILCALL_UNTYPED_SSA, {OutputSSAVariablesSubExprMediumLevelOperandUsage,
			OutputSSAMemoryVersionMediumLevelOperandUsage, DestExprMediumLevelOperandUsage,
			ParameterSSAVariablesMediumLevelOperandUsage, ParameterSSAMemoryVersionMediumLevelOperandUsage,
			StackExprMediumLevelOperandUsage}},
		{MLIL_RET, {SourceExprsMediumLevelOperandUsage}},
		{MLIL_IF, {ConditionExprMediumLevelOperandUsage, TrueTargetMediumLevelOperandUsage,
			FalseTargetMediumLevelOperandUsage}},
		{MLIL_GOTO, {TargetMediumLevelOperandUsage}},
		{MLIL_INTRINSIC, {OutputVariablesMediumLevelOperandUsage, IntrinsicMediumLevelOperandUsage,
			ParameterExprsMediumLevelOperandUsage}},
		{MLIL_INTRINSIC_SSA, {OutputSSAVariablesMediumLevelOperandUsage, IntrinsicMediumLevelOperandUsage,
			ParameterExprsMediumLevelOperandUsage}},
		{MLIL_FREE_VAR_SLOT, {DestVariableMediumLevelOperandUsage}},
		{MLIL_FREE_VAR_SLOT_SSA, {DestSSAVariableMediumLevelOperandUsage, PartialSSAVariableSourceMediumLevelOperandUsage}},
		{MLIL_TRAP, {VectorMediumLevelOperandUsage}},
		{MLIL_VAR_PHI, {DestSSAVariableMediumLevelOperandUsage, SourceSSAVariablesMediumLevelOperandUsages}},
		{MLIL_MEM_PHI, {DestMemoryVersionMediumLevelOperandUsage, SourceMemoryVersionsMediumLevelOperandUsage}},
		{MLIL_CONST, {ConstantMediumLevelOperandUsage}},
		{MLIL_CONST_PTR, {ConstantMediumLevelOperandUsage}},
		{MLIL_EXTERN_PTR, {ConstantMediumLevelOperandUsage, OffsetMediumLevelOperandUsage}},
		{MLIL_FLOAT_CONST, {ConstantMediumLevelOperandUsage}},
		{MLIL_IMPORT, {ConstantMediumLevelOperandUsage}},
		{MLIL_ADD, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_SUB, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_AND, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_OR, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_XOR, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_LSL, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_LSR, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_ASR, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_ROL, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_ROR, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_MUL, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_MULU_DP, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_MULS_DP, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_DIVU, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_DIVS, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_MODU, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_MODS, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_CMP_E, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_CMP_NE, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_CMP_SLT, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_CMP_ULT, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_CMP_SLE, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_CMP_ULE, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_CMP_SGE, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_CMP_UGE, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_CMP_SGT, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_CMP_UGT, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_TEST_BIT, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_ADD_OVERFLOW, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_ADC, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage,
			CarryExprMediumLevelOperandUsage}},
		{MLIL_SBB, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage,
			CarryExprMediumLevelOperandUsage}},
		{MLIL_RLC, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage,
			CarryExprMediumLevelOperandUsage}},
		{MLIL_RRC, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage,
			CarryExprMediumLevelOperandUsage}},
		{MLIL_DIVU_DP, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_DIVS_DP, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_MODU_DP, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_MODS_DP, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_NEG, {SourceExprMediumLevelOperandUsage}},
		{MLIL_NOT, {SourceExprMediumLevelOperandUsage}},
		{MLIL_SX, {SourceExprMediumLevelOperandUsage}},
		{MLIL_ZX, {SourceExprMediumLevelOperandUsage}},
		{MLIL_LOW_PART, {SourceExprMediumLevelOperandUsage}},
		{MLIL_BOOL_TO_INT, {SourceExprMediumLevelOperandUsage}},
		{MLIL_UNIMPL_MEM, {SourceExprMediumLevelOperandUsage}},
		{MLIL_FADD, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_FSUB, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_FMUL, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_FDIV, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_FSQRT, {SourceExprMediumLevelOperandUsage}},
		{MLIL_FNEG, {SourceExprMediumLevelOperandUsage}},
		{MLIL_FABS, {SourceExprMediumLevelOperandUsage}},
		{MLIL_FLOAT_TO_INT, {SourceExprMediumLevelOperandUsage}},
		{MLIL_INT_TO_FLOAT, {SourceExprMediumLevelOperandUsage}},
		{MLIL_FLOAT_CONV, {SourceExprMediumLevelOperandUsage}},
		{MLIL_ROUND_TO_INT, {SourceExprMediumLevelOperandUsage}},
		{MLIL_FLOOR, {SourceExprMediumLevelOperandUsage}},
		{MLIL_CEIL, {SourceExprMediumLevelOperandUsage}},
		{MLIL_FTRUNC, {SourceExprMediumLevelOperandUsage}},
		{MLIL_FCMP_E, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_FCMP_NE, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_FCMP_LT, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_FCMP_LE, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_FCMP_GE, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_FCMP_GT, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_FCMP_O, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}},
		{MLIL_FCMP_UO, {LeftExprMediumLevelOperandUsage, RightExprMediumLevelOperandUsage}}
	};


static unordered_map<BNMediumLevelILOperation, unordered_map<MediumLevelILOperandUsage, size_t>> GetOperandIndexForOperandUsages()
{
	unordered_map<BNMediumLevelILOperation, unordered_map<MediumLevelILOperandUsage, size_t>> result;
	result.reserve(MediumLevelILInstructionBase::operationOperandUsage.size());
	for (auto& operation : MediumLevelILInstructionBase::operationOperandUsage)
	{
		result[operation.first] = unordered_map<MediumLevelILOperandUsage, size_t>();
		result[operation.first].reserve(operation.second.size());
		size_t operand = 0;
		for (auto usage : operation.second)
		{
			result[operation.first][usage] = operand;
			switch (usage)
			{
			case PartialSSAVariableSourceMediumLevelOperandUsage:
				// SSA variables are usually two slots, but this one has a previously defined
				// variables and thus only takes one slot
				operand++;
				break;
			case OutputVariablesSubExprMediumLevelOperandUsage:
			case ParameterVariablesMediumLevelOperandUsage:
				// Represented as subexpression, so only takes one slot even though it is a list
				operand++;
				break;
			case OutputSSAVariablesSubExprMediumLevelOperandUsage:
				// OutputSSAMemoryVersionMediumLevelOperandUsage follows at same operand
				break;
			case ParameterSSAVariablesMediumLevelOperandUsage:
				// ParameterSSAMemoryVersionMediumLevelOperandUsage follows at same operand
				break;
			default:
				switch (MediumLevelILInstructionBase::operandTypeForUsage[usage])
				{
				case SSAVariableMediumLevelOperand:
				case IndexListMediumLevelOperand:
				case IndexMapMediumLevelOperand:
				case VariableListMediumLevelOperand:
				case SSAVariableListMediumLevelOperand:
				case ExprListMediumLevelOperand:
					// SSA variables and lists take two operand slots
					operand += 2;
					break;
				default:
					operand++;
					break;
				}
				break;
			}
		}
	}
	return result;
}


unordered_map<BNMediumLevelILOperation, unordered_map<MediumLevelILOperandUsage, size_t>>
	MediumLevelILInstructionBase::operationOperandIndex = GetOperandIndexForOperandUsages();


SSAVariable::SSAVariable(): version(0)
{
}


SSAVariable::SSAVariable(const Variable& v, size_t i): var(v), version(i)
{
}


SSAVariable::SSAVariable(const SSAVariable& v): var(v.var), version(v.version)
{
}


SSAVariable& SSAVariable::operator=(const SSAVariable& v)
{
	var = v.var;
	version = v.version;
	return *this;
}


bool SSAVariable::operator==(const SSAVariable& v) const
{
	if (var != v.var)
		return false;
	return version == v.version;
}


bool SSAVariable::operator!=(const SSAVariable& v) const
{
	return !((*this) == v);
}


bool SSAVariable::operator<(const SSAVariable& v) const
{
	if (var < v.var)
		return true;
	if (v.var < var)
		return false;
	return version < v.version;
}


bool MediumLevelILIntegerList::ListIterator::operator==(const ListIterator& a) const
{
	return count == a.count;
}


bool MediumLevelILIntegerList::ListIterator::operator!=(const ListIterator& a) const
{
	return count != a.count;
}


bool MediumLevelILIntegerList::ListIterator::operator<(const ListIterator& a) const
{
	return count > a.count;
}


MediumLevelILIntegerList::ListIterator& MediumLevelILIntegerList::ListIterator::operator++()
{
	count--;
	if (count == 0)
		return *this;

	operand++;
	if (operand >= 4)
	{
		operand = 0;
#ifdef BINARYNINJACORE_LIBRARY
		instr = &function->GetRawExpr((size_t)instr->operands[4]);
#else
		instr = function->GetRawExpr((size_t)instr.operands[4]);
#endif
	}
	return *this;
}


uint64_t MediumLevelILIntegerList::ListIterator::operator*()
{
#ifdef BINARYNINJACORE_LIBRARY
	return instr->operands[operand];
#else
	return instr.operands[operand];
#endif
}


MediumLevelILIntegerList::MediumLevelILIntegerList(MediumLevelILFunction* func,
	const BNMediumLevelILInstruction& instr, size_t count)
{
	m_start.function = func;
#ifdef BINARYNINJACORE_LIBRARY
	m_start.instr = &instr;
#else
	m_start.instr = instr;
#endif
	m_start.operand = 0;
	m_start.count = count;
}


MediumLevelILIntegerList::const_iterator MediumLevelILIntegerList::begin() const
{
	return m_start;
}


MediumLevelILIntegerList::const_iterator MediumLevelILIntegerList::end() const
{
	const_iterator result;
	result.function = m_start.function;
	result.operand = 0;
	result.count = 0;
	return result;
}


size_t MediumLevelILIntegerList::size() const
{
	return m_start.count;
}


uint64_t MediumLevelILIntegerList::operator[](size_t i) const
{
	if (i >= size())
		throw MediumLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


MediumLevelILIntegerList::operator vector<uint64_t>() const
{
	vector<uint64_t> result;
	for (auto i : *this)
		result.push_back(i);
	return result;
}


size_t MediumLevelILIndexList::ListIterator::operator*()
{
	return (size_t)*pos;
}


MediumLevelILIndexList::MediumLevelILIndexList(MediumLevelILFunction* func,
	const BNMediumLevelILInstruction& instr, size_t count): m_list(func, instr, count)
{
}


MediumLevelILIndexList::const_iterator MediumLevelILIndexList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


MediumLevelILIndexList::const_iterator MediumLevelILIndexList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t MediumLevelILIndexList::size() const
{
	return m_list.size();
}


size_t MediumLevelILIndexList::operator[](size_t i) const
{
	if (i >= size())
		throw MediumLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


MediumLevelILIndexList::operator vector<size_t>() const
{
	vector<size_t> result;
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const pair<uint64_t, size_t> MediumLevelILIndexMap::ListIterator::operator*()
{
	MediumLevelILIntegerList::const_iterator cur = pos;
	uint64_t value = *cur;
	++cur;
	size_t target = (size_t)*cur;
	return pair<uint64_t, size_t>(value, target);
}


MediumLevelILIndexMap::MediumLevelILIndexMap(MediumLevelILFunction* func,
	const BNMediumLevelILInstruction& instr, size_t count): m_list(func, instr, count & (~1))
{
}


MediumLevelILIndexMap::const_iterator MediumLevelILIndexMap::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


MediumLevelILIndexMap::const_iterator MediumLevelILIndexMap::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t MediumLevelILIndexMap::size() const
{
	return m_list.size() / 2;
}


size_t MediumLevelILIndexMap::operator[](uint64_t value) const
{
	for (auto iter = begin(); iter != end(); ++iter)
	{
		if ((*iter).first == value)
			return (*iter).second;
	}
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILIndexMap::operator map<uint64_t, size_t>() const
{
	map<uint64_t, size_t> result;
	for (auto& i : *this)
		result[i.first] = i.second;
	return result;
}


const Variable MediumLevelILVariableList::ListIterator::operator*()
{
	return Variable::FromIdentifier(*pos);
}


MediumLevelILVariableList::MediumLevelILVariableList(MediumLevelILFunction* func,
	const BNMediumLevelILInstruction& instr, size_t count): m_list(func, instr, count)
{
}


MediumLevelILVariableList::const_iterator MediumLevelILVariableList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


MediumLevelILVariableList::const_iterator MediumLevelILVariableList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t MediumLevelILVariableList::size() const
{
	return m_list.size();
}


const Variable MediumLevelILVariableList::operator[](size_t i) const
{
	if (i >= size())
		throw MediumLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


MediumLevelILVariableList::operator vector<Variable>() const
{
	vector<Variable> result;
	for (auto& i : *this)
		result.push_back(i);
	return result;
}


const SSAVariable MediumLevelILSSAVariableList::ListIterator::operator*()
{
	MediumLevelILIntegerList::const_iterator cur = pos;
	Variable var = Variable::FromIdentifier(*cur);
	++cur;
	size_t version = (size_t)*cur;
	return SSAVariable(var, version);
}


MediumLevelILSSAVariableList::MediumLevelILSSAVariableList(MediumLevelILFunction* func,
	const BNMediumLevelILInstruction& instr, size_t count): m_list(func, instr, count & (~1))
{
}


MediumLevelILSSAVariableList::const_iterator MediumLevelILSSAVariableList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


MediumLevelILSSAVariableList::const_iterator MediumLevelILSSAVariableList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t MediumLevelILSSAVariableList::size() const
{
	return m_list.size() / 2;
}


const SSAVariable MediumLevelILSSAVariableList::operator[](size_t i) const
{
	if (i >= size())
		throw MediumLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


MediumLevelILSSAVariableList::operator vector<SSAVariable>() const
{
	vector<SSAVariable> result;
	for (auto& i : *this)
		result.push_back(i);
	return result;
}


const MediumLevelILInstruction MediumLevelILInstructionList::ListIterator::operator*()
{
	return MediumLevelILInstruction(pos.GetFunction(), pos.GetFunction()->GetRawExpr((size_t)*pos),
		(size_t)*pos, instructionIndex);
}


MediumLevelILInstructionList::MediumLevelILInstructionList(MediumLevelILFunction* func,
	const BNMediumLevelILInstruction& instr, size_t count, size_t instrIndex):
	m_list(func, instr, count), m_instructionIndex(instrIndex)
{
}


MediumLevelILInstructionList::const_iterator MediumLevelILInstructionList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	result.instructionIndex = m_instructionIndex;
	return result;
}


MediumLevelILInstructionList::const_iterator MediumLevelILInstructionList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	result.instructionIndex = m_instructionIndex;
	return result;
}


size_t MediumLevelILInstructionList::size() const
{
	return m_list.size();
}


const MediumLevelILInstruction MediumLevelILInstructionList::operator[](size_t i) const
{
	if (i >= size())
		throw MediumLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


MediumLevelILInstructionList::operator vector<MediumLevelILInstruction>() const
{
	vector<MediumLevelILInstruction> result;
	for (auto& i : *this)
		result.push_back(i);
	return result;
}


MediumLevelILOperand::MediumLevelILOperand(const MediumLevelILInstruction& instr,
	MediumLevelILOperandUsage usage, size_t operandIndex):
	m_instr(instr), m_usage(usage), m_operandIndex(operandIndex)
{
	auto i = MediumLevelILInstructionBase::operandTypeForUsage.find(m_usage);
	if (i == MediumLevelILInstructionBase::operandTypeForUsage.end())
		throw MediumLevelILInstructionAccessException();
	m_type = i->second;
}


uint64_t MediumLevelILOperand::GetInteger() const
{
	if (m_type != IntegerMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsInteger(m_operandIndex);
}


size_t MediumLevelILOperand::GetIndex() const
{
	if (m_type != IndexMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	if ((m_usage == OutputSSAMemoryVersionMediumLevelOperandUsage) ||
		(m_usage == ParameterSSAMemoryVersionMediumLevelOperandUsage))
		return m_instr.GetRawOperandAsExpr(m_operandIndex).GetRawOperandAsIndex(0);
	return m_instr.GetRawOperandAsIndex(m_operandIndex);
}


uint32_t MediumLevelILOperand::GetIntrinsic() const
{
	if (m_type != IntrinsicMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return (uint32_t)m_instr.GetRawOperandAsInteger(m_operandIndex);
}


MediumLevelILInstruction MediumLevelILOperand::GetExpr() const
{
	if (m_type != ExprMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsExpr(m_operandIndex);
}


Variable MediumLevelILOperand::GetVariable() const
{
	if (m_type != VariableMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsVariable(m_operandIndex);
}


SSAVariable MediumLevelILOperand::GetSSAVariable() const
{
	if (m_type != SSAVariableMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	if (m_usage == PartialSSAVariableSourceMediumLevelOperandUsage)
		return m_instr.GetRawOperandAsPartialSSAVariableSource(m_operandIndex - 2);
	return m_instr.GetRawOperandAsSSAVariable(m_operandIndex);
}


MediumLevelILIndexList MediumLevelILOperand::GetIndexList() const
{
	if (m_type != IndexListMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsIndexList(m_operandIndex);
}


MediumLevelILIndexMap MediumLevelILOperand::GetIndexMap() const
{
	if (m_type != IndexMapMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsIndexMap(m_operandIndex);
}


MediumLevelILVariableList MediumLevelILOperand::GetVariableList() const
{
	if (m_type != VariableListMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	if ((m_usage == OutputVariablesSubExprMediumLevelOperandUsage) ||
		(m_usage == ParameterVariablesMediumLevelOperandUsage))
		return m_instr.GetRawOperandAsExpr(m_operandIndex).GetRawOperandAsVariableList(0);
	return m_instr.GetRawOperandAsVariableList(m_operandIndex);
}


MediumLevelILSSAVariableList MediumLevelILOperand::GetSSAVariableList() const
{
	if (m_type != SSAVariableListMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	if ((m_usage == OutputSSAVariablesSubExprMediumLevelOperandUsage) ||
		(m_usage == ParameterSSAVariablesMediumLevelOperandUsage))
		return m_instr.GetRawOperandAsExpr(m_operandIndex).GetRawOperandAsSSAVariableList(1);
	return m_instr.GetRawOperandAsSSAVariableList(m_operandIndex);
}


MediumLevelILInstructionList MediumLevelILOperand::GetExprList() const
{
	if (m_type != ExprListMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsExprList(m_operandIndex);
}


const MediumLevelILOperand MediumLevelILOperandList::ListIterator::operator*()
{
	MediumLevelILOperandUsage usage = *pos;
	auto i = owner->m_operandIndexMap.find(usage);
	if (i == owner->m_operandIndexMap.end())
		throw MediumLevelILInstructionAccessException();
	return MediumLevelILOperand(owner->m_instr, usage, i->second);
}


MediumLevelILOperandList::MediumLevelILOperandList(const MediumLevelILInstruction& instr,
	const vector<MediumLevelILOperandUsage>& usageList,
	const unordered_map<MediumLevelILOperandUsage, size_t>& operandIndexMap):
	m_instr(instr), m_usageList(usageList), m_operandIndexMap(operandIndexMap)
{
}


MediumLevelILOperandList::const_iterator MediumLevelILOperandList::begin() const
{
	const_iterator result;
	result.owner = this;
	result.pos = m_usageList.begin();
	return result;
}


MediumLevelILOperandList::const_iterator MediumLevelILOperandList::end() const
{
	const_iterator result;
	result.owner = this;
	result.pos = m_usageList.end();
	return result;
}


size_t MediumLevelILOperandList::size() const
{
	return m_usageList.size();
}


const MediumLevelILOperand MediumLevelILOperandList::operator[](size_t i) const
{
	MediumLevelILOperandUsage usage = m_usageList[i];
	auto indexMap = m_operandIndexMap.find(usage);
	if (indexMap == m_operandIndexMap.end())
		throw MediumLevelILInstructionAccessException();
	return MediumLevelILOperand(m_instr, usage, indexMap->second);
}


MediumLevelILOperandList::operator vector<MediumLevelILOperand>() const
{
	vector<MediumLevelILOperand> result;
	for (auto& i : *this)
		result.push_back(i);
	return result;
}


MediumLevelILInstruction::MediumLevelILInstruction()
{
	operation = MLIL_UNDEF;
	sourceOperand = BN_INVALID_OPERAND;
	size = 0;
	address = 0;
	function = nullptr;
	exprIndex = BN_INVALID_EXPR;
	instructionIndex = BN_INVALID_EXPR;
}


MediumLevelILInstruction::MediumLevelILInstruction(MediumLevelILFunction* func,
	const BNMediumLevelILInstruction& instr, size_t expr, size_t instrIdx)
{
	operation = instr.operation;
	sourceOperand = instr.sourceOperand;
	size = instr.size;
	operands[0] = instr.operands[0];
	operands[1] = instr.operands[1];
	operands[2] = instr.operands[2];
	operands[3] = instr.operands[3];
	operands[4] = instr.operands[4];
	address = instr.address;
	function = func;
	exprIndex = expr;
	instructionIndex = instrIdx;
}


MediumLevelILInstruction::MediumLevelILInstruction(const MediumLevelILInstructionBase& instr)
{
	operation = instr.operation;
	sourceOperand = instr.sourceOperand;
	size = instr.size;
	operands[0] = instr.operands[0];
	operands[1] = instr.operands[1];
	operands[2] = instr.operands[2];
	operands[3] = instr.operands[3];
	operands[4] = instr.operands[4];
	address = instr.address;
	function = instr.function;
	exprIndex = instr.exprIndex;
	instructionIndex = instr.instructionIndex;
}


MediumLevelILOperandList MediumLevelILInstructionBase::GetOperands() const
{
	auto usage = operationOperandUsage.find(operation);
	if (usage == operationOperandUsage.end())
		throw MediumLevelILInstructionAccessException();
	auto operandIndex = operationOperandIndex.find(operation);
	if (operandIndex == operationOperandIndex.end())
		throw MediumLevelILInstructionAccessException();
	return MediumLevelILOperandList(*(const MediumLevelILInstruction*)this, usage->second, operandIndex->second);
}


uint64_t MediumLevelILInstructionBase::GetRawOperandAsInteger(size_t operand) const
{
	return operands[operand];
}


size_t MediumLevelILInstructionBase::GetRawOperandAsIndex(size_t operand) const
{
	return (size_t)operands[operand];
}


MediumLevelILInstruction MediumLevelILInstructionBase::GetRawOperandAsExpr(size_t operand) const
{
	return MediumLevelILInstruction(function, function->GetRawExpr(operands[operand]), operands[operand], instructionIndex);
}


Variable MediumLevelILInstructionBase::GetRawOperandAsVariable(size_t operand) const
{
	return Variable::FromIdentifier(operands[operand]);
}


SSAVariable MediumLevelILInstructionBase::GetRawOperandAsSSAVariable(size_t operand) const
{
	return SSAVariable(Variable::FromIdentifier(operands[operand]), (size_t)operands[operand + 1]);
}


SSAVariable MediumLevelILInstructionBase::GetRawOperandAsPartialSSAVariableSource(size_t operand) const
{
	return SSAVariable(Variable::FromIdentifier(operands[operand]), (size_t)operands[operand + 2]);
}


MediumLevelILIndexList MediumLevelILInstructionBase::GetRawOperandAsIndexList(size_t operand) const
{
	return MediumLevelILIndexList(function, function->GetRawExpr(operands[operand + 1]), operands[operand]);
}


MediumLevelILIndexMap MediumLevelILInstructionBase::GetRawOperandAsIndexMap(size_t operand) const
{
	return MediumLevelILIndexMap(function, function->GetRawExpr(operands[operand + 1]), operands[operand]);
}


MediumLevelILVariableList MediumLevelILInstructionBase::GetRawOperandAsVariableList(size_t operand) const
{
	return MediumLevelILVariableList(function, function->GetRawExpr(operands[operand + 1]), operands[operand]);
}


MediumLevelILSSAVariableList MediumLevelILInstructionBase::GetRawOperandAsSSAVariableList(size_t operand) const
{
	return MediumLevelILSSAVariableList(function, function->GetRawExpr(operands[operand + 1]), operands[operand]);
}


MediumLevelILInstructionList MediumLevelILInstructionBase::GetRawOperandAsExprList(size_t operand) const
{
	return MediumLevelILInstructionList(function, function->GetRawExpr(operands[operand + 1]), operands[operand],
		instructionIndex);
}


void MediumLevelILInstructionBase::UpdateRawOperand(size_t operandIndex, ExprId value)
{
	operands[operandIndex] = value;
	function->UpdateInstructionOperand(exprIndex, operandIndex, value);
}


void MediumLevelILInstructionBase::UpdateRawOperandAsSSAVariableList(size_t operandIndex, const vector<SSAVariable>& vars)
{
	UpdateRawOperand(operandIndex, vars.size() * 2);
	UpdateRawOperand(operandIndex + 1, function->AddSSAVariableList(vars));
}


void MediumLevelILInstructionBase::UpdateRawOperandAsExprList(size_t operandIndex, const vector<MediumLevelILInstruction>& exprs)
{
	vector<ExprId> exprIndexList;
	for (auto& i : exprs)
		exprIndexList.push_back((ExprId)i.exprIndex);
	UpdateRawOperand(operandIndex, exprIndexList.size());
	UpdateRawOperand(operandIndex + 1, function->AddOperandList(exprIndexList));
}


void MediumLevelILInstructionBase::UpdateRawOperandAsExprList(size_t operandIndex, const vector<ExprId>& exprs)
{
	UpdateRawOperand(operandIndex, exprs.size());
	UpdateRawOperand(operandIndex + 1, function->AddOperandList(exprs));
}


RegisterValue MediumLevelILInstructionBase::GetValue() const
{
	return function->GetExprValue(*(const MediumLevelILInstruction*)this);
}


PossibleValueSet MediumLevelILInstructionBase::GetPossibleValues() const
{
	return function->GetPossibleExprValues(*(const MediumLevelILInstruction*)this);
}


Confidence<Ref<Type>> MediumLevelILInstructionBase::GetType() const
{
	return function->GetExprType(*(const MediumLevelILInstruction*)this);
}


size_t MediumLevelILInstructionBase::GetSSAVarVersion(const Variable& var)
{
	return function->GetSSAVarVersionAtInstruction(var, instructionIndex);
}


size_t MediumLevelILInstructionBase::GetSSAMemoryVersion()
{
	return function->GetSSAMemoryVersionAtInstruction(instructionIndex);
}


Variable MediumLevelILInstructionBase::GetVariableForRegister(uint32_t reg)
{
	return function->GetVariableForRegisterAtInstruction(reg, instructionIndex);
}


Variable MediumLevelILInstructionBase::GetVariableForFlag(uint32_t flag)
{
	return function->GetVariableForFlagAtInstruction(flag, instructionIndex);
}


Variable MediumLevelILInstructionBase::GetVariableForStackLocation(int64_t offset)
{
	return function->GetVariableForStackLocationAtInstruction(offset, instructionIndex);
}


PossibleValueSet MediumLevelILInstructionBase::GetPossibleSSAVarValues(const SSAVariable& var)
{
	return function->GetPossibleSSAVarValues(var, instructionIndex);
}


RegisterValue MediumLevelILInstructionBase::GetRegisterValue(uint32_t reg)
{
	return function->GetRegisterValueAtInstruction(reg, instructionIndex);
}


RegisterValue MediumLevelILInstructionBase::GetRegisterValueAfter(uint32_t reg)
{
	return function->GetRegisterValueAfterInstruction(reg, instructionIndex);
}


PossibleValueSet MediumLevelILInstructionBase::GetPossibleRegisterValues(uint32_t reg)
{
	return function->GetPossibleRegisterValuesAtInstruction(reg, instructionIndex);
}


PossibleValueSet MediumLevelILInstructionBase::GetPossibleRegisterValuesAfter(uint32_t reg)
{
	return function->GetPossibleRegisterValuesAfterInstruction(reg, instructionIndex);
}


RegisterValue MediumLevelILInstructionBase::GetFlagValue(uint32_t flag)
{
	return function->GetFlagValueAtInstruction(flag, instructionIndex);
}


RegisterValue MediumLevelILInstructionBase::GetFlagValueAfter(uint32_t flag)
{
	return function->GetFlagValueAfterInstruction(flag, instructionIndex);
}


PossibleValueSet MediumLevelILInstructionBase::GetPossibleFlagValues(uint32_t flag)
{
	return function->GetPossibleFlagValuesAtInstruction(flag, instructionIndex);
}


PossibleValueSet MediumLevelILInstructionBase::GetPossibleFlagValuesAfter(uint32_t flag)
{
	return function->GetPossibleFlagValuesAfterInstruction(flag, instructionIndex);
}


RegisterValue MediumLevelILInstructionBase::GetStackContents(int32_t offset, size_t len)
{
	return function->GetStackContentsAtInstruction(offset, len, instructionIndex);
}


RegisterValue MediumLevelILInstructionBase::GetStackContentsAfter(int32_t offset, size_t len)
{
	return function->GetStackContentsAfterInstruction(offset, len, instructionIndex);
}


PossibleValueSet MediumLevelILInstructionBase::GetPossibleStackContents(int32_t offset, size_t len)
{
	return function->GetPossibleStackContentsAtInstruction(offset, len, instructionIndex);
}


PossibleValueSet MediumLevelILInstructionBase::GetPossibleStackContentsAfter(int32_t offset, size_t len)
{
	return function->GetPossibleStackContentsAfterInstruction(offset, len, instructionIndex);
}


BNILBranchDependence MediumLevelILInstructionBase::GetBranchDependence(size_t branchInstr)
{
	return function->GetBranchDependenceAtInstruction(instructionIndex, branchInstr);
}


BNILBranchDependence MediumLevelILInstructionBase::GetBranchDependence(const MediumLevelILInstruction& branch)
{
	return GetBranchDependence(branch.instructionIndex);
}


unordered_map<size_t, BNILBranchDependence> MediumLevelILInstructionBase::GetAllBranchDependence()
{
	return function->GetAllBranchDependenceAtInstruction(instructionIndex);
}


size_t MediumLevelILInstructionBase::GetSSAInstructionIndex() const
{
	return function->GetSSAInstructionIndex(instructionIndex);
}


size_t MediumLevelILInstructionBase::GetNonSSAInstructionIndex() const
{
	return function->GetNonSSAInstructionIndex(instructionIndex);
}


size_t MediumLevelILInstructionBase::GetSSAExprIndex() const
{
	return function->GetSSAExprIndex(exprIndex);
}


size_t MediumLevelILInstructionBase::GetNonSSAExprIndex() const
{
	return function->GetNonSSAExprIndex(exprIndex);
}


MediumLevelILInstruction MediumLevelILInstructionBase::GetSSAForm() const
{
	Ref<MediumLevelILFunction> ssa = function->GetSSAForm().GetPtr();
	if (!ssa)
		return *this;
	size_t expr = GetSSAExprIndex();
	size_t instr = GetSSAInstructionIndex();
	return MediumLevelILInstruction(ssa, ssa->GetRawExpr(expr), expr, instr);
}


MediumLevelILInstruction MediumLevelILInstructionBase::GetNonSSAForm() const
{
	Ref<MediumLevelILFunction> nonSsa = function->GetNonSSAForm();
	if (!nonSsa)
		return *this;
	size_t expr = GetNonSSAExprIndex();
	size_t instr = GetNonSSAInstructionIndex();
	return MediumLevelILInstruction(nonSsa, nonSsa->GetRawExpr(expr), expr, instr);
}


size_t MediumLevelILInstructionBase::GetLowLevelILInstructionIndex() const
{
	return function->GetLowLevelILInstructionIndex(instructionIndex);
}


size_t MediumLevelILInstructionBase::GetLowLevelILExprIndex() const
{
	return function->GetLowLevelILExprIndex(exprIndex);
}


bool MediumLevelILInstructionBase::HasLowLevelIL() const
{
	Ref<LowLevelILFunction> func = function->GetLowLevelIL();
	if (!func)
		return false;
	return GetLowLevelILExprIndex() < func->GetExprCount();
}


LowLevelILInstruction MediumLevelILInstructionBase::GetLowLevelIL() const
{
	Ref<LowLevelILFunction> func = function->GetLowLevelIL();
	if (!func)
		throw LowLevelILInstructionAccessException();
	size_t expr = GetLowLevelILExprIndex();
	if (GetLowLevelILExprIndex() >= func->GetExprCount())
		throw LowLevelILInstructionAccessException();
	return func->GetExpr(expr);
}


void MediumLevelILInstructionBase::MarkInstructionForRemoval()
{
	function->MarkInstructionForRemoval(instructionIndex);
}


void MediumLevelILInstructionBase::Replace(ExprId expr)
{
	function->ReplaceExpr(exprIndex, expr);
}


void MediumLevelILInstruction::VisitExprs(const std::function<bool(const MediumLevelILInstruction& expr)>& func) const
{
	if (!func(*this))
		return;
	switch (operation)
	{
	case MLIL_SET_VAR:
		GetSourceExpr<MLIL_SET_VAR>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_SSA:
		GetSourceExpr<MLIL_SET_VAR_SSA>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_ALIASED:
		GetSourceExpr<MLIL_SET_VAR_ALIASED>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_SPLIT:
		GetSourceExpr<MLIL_SET_VAR_SPLIT>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_SPLIT_SSA:
		GetSourceExpr<MLIL_SET_VAR_SPLIT_SSA>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_FIELD:
		GetSourceExpr<MLIL_SET_VAR_FIELD>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_SSA_FIELD:
		GetSourceExpr<MLIL_SET_VAR_SSA_FIELD>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_ALIASED_FIELD:
		GetSourceExpr<MLIL_SET_VAR_ALIASED_FIELD>().VisitExprs(func);
		break;
	case MLIL_CALL:
		GetDestExpr<MLIL_CALL>().VisitExprs(func);
		for (auto& i : GetParameterExprs<MLIL_CALL>())
			i.VisitExprs(func);
		break;
	case MLIL_CALL_UNTYPED:
		GetDestExpr<MLIL_CALL_UNTYPED>().VisitExprs(func);
		break;
	case MLIL_CALL_SSA:
		GetDestExpr<MLIL_CALL_SSA>().VisitExprs(func);
		for (auto& i : GetParameterExprs<MLIL_CALL_SSA>())
			i.VisitExprs(func);
		break;
	case MLIL_CALL_UNTYPED_SSA:
		GetDestExpr<MLIL_CALL_UNTYPED_SSA>().VisitExprs(func);
		break;
	case MLIL_SYSCALL:
		for (auto& i : GetParameterExprs<MLIL_SYSCALL>())
			i.VisitExprs(func);
		break;
	case MLIL_SYSCALL_SSA:
		for (auto& i : GetParameterExprs<MLIL_SYSCALL_SSA>())
			i.VisitExprs(func);
		break;
	case MLIL_TAILCALL:
		GetDestExpr<MLIL_TAILCALL>().VisitExprs(func);
		for (auto& i : GetParameterExprs<MLIL_TAILCALL>())
			i.VisitExprs(func);
		break;
	case MLIL_TAILCALL_UNTYPED:
		GetDestExpr<MLIL_TAILCALL_UNTYPED>().VisitExprs(func);
		break;
	case MLIL_TAILCALL_SSA:
		GetDestExpr<MLIL_TAILCALL_SSA>().VisitExprs(func);
		for (auto& i : GetParameterExprs<MLIL_TAILCALL_SSA>())
			i.VisitExprs(func);
		break;
	case MLIL_TAILCALL_UNTYPED_SSA:
		GetDestExpr<MLIL_TAILCALL_UNTYPED_SSA>().VisitExprs(func);
		break;
	case MLIL_RET:
		for (auto& i : GetSourceExprs<MLIL_RET>())
			i.VisitExprs(func);
		break;
	case MLIL_STORE:
		GetDestExpr<MLIL_STORE>().VisitExprs(func);
		GetSourceExpr<MLIL_STORE>().VisitExprs(func);
		break;
	case MLIL_STORE_STRUCT:
		GetDestExpr<MLIL_STORE_STRUCT>().VisitExprs(func);
		GetSourceExpr<MLIL_STORE_STRUCT>().VisitExprs(func);
		break;
	case MLIL_STORE_SSA:
		GetDestExpr<MLIL_STORE_SSA>().VisitExprs(func);
		GetSourceExpr<MLIL_STORE_SSA>().VisitExprs(func);
		break;
	case MLIL_STORE_STRUCT_SSA:
		GetDestExpr<MLIL_STORE_STRUCT_SSA>().VisitExprs(func);
		GetSourceExpr<MLIL_STORE_STRUCT_SSA>().VisitExprs(func);
		break;
	case MLIL_NEG:
	case MLIL_NOT:
	case MLIL_SX:
	case MLIL_ZX:
	case MLIL_LOW_PART:
	case MLIL_BOOL_TO_INT:
	case MLIL_JUMP:
	case MLIL_JUMP_TO:
	case MLIL_RET_HINT:
	case MLIL_IF:
	case MLIL_UNIMPL_MEM:
	case MLIL_LOAD:
	case MLIL_LOAD_STRUCT:
	case MLIL_LOAD_SSA:
	case MLIL_LOAD_STRUCT_SSA:
	case MLIL_FSQRT:
	case MLIL_FNEG:
	case MLIL_FABS:
	case MLIL_FLOAT_TO_INT:
	case MLIL_INT_TO_FLOAT:
	case MLIL_FLOAT_CONV:
	case MLIL_ROUND_TO_INT:
	case MLIL_FLOOR:
	case MLIL_CEIL:
	case MLIL_FTRUNC:
		AsOneOperand().GetSourceExpr().VisitExprs(func);
		break;
	case MLIL_ADD:
	case MLIL_SUB:
	case MLIL_AND:
	case MLIL_OR:
	case MLIL_XOR:
	case MLIL_LSL:
	case MLIL_LSR:
	case MLIL_ASR:
	case MLIL_ROL:
	case MLIL_ROR:
	case MLIL_MUL:
	case MLIL_MULU_DP:
	case MLIL_MULS_DP:
	case MLIL_DIVU:
	case MLIL_DIVS:
	case MLIL_MODU:
	case MLIL_MODS:
	case MLIL_DIVU_DP:
	case MLIL_DIVS_DP:
	case MLIL_MODU_DP:
	case MLIL_MODS_DP:
	case MLIL_CMP_E:
	case MLIL_CMP_NE:
	case MLIL_CMP_SLT:
	case MLIL_CMP_ULT:
	case MLIL_CMP_SLE:
	case MLIL_CMP_ULE:
	case MLIL_CMP_SGE:
	case MLIL_CMP_UGE:
	case MLIL_CMP_SGT:
	case MLIL_CMP_UGT:
	case MLIL_TEST_BIT:
	case MLIL_ADD_OVERFLOW:
	case MLIL_FADD:
	case MLIL_FSUB:
	case MLIL_FMUL:
	case MLIL_FDIV:
	case MLIL_FCMP_E:
	case MLIL_FCMP_NE:
	case MLIL_FCMP_LT:
	case MLIL_FCMP_LE:
	case MLIL_FCMP_GE:
	case MLIL_FCMP_GT:
	case MLIL_FCMP_O:
	case MLIL_FCMP_UO:
		AsTwoOperand().GetLeftExpr().VisitExprs(func);
		AsTwoOperand().GetRightExpr().VisitExprs(func);
		break;
	case MLIL_ADC:
	case MLIL_SBB:
	case MLIL_RLC:
	case MLIL_RRC:
		AsTwoOperandWithCarry().GetLeftExpr().VisitExprs(func);
		AsTwoOperandWithCarry().GetRightExpr().VisitExprs(func);
		AsTwoOperandWithCarry().GetCarryExpr().VisitExprs(func);
		break;
	case MLIL_INTRINSIC:
		for (auto& i : GetParameterExprs<MLIL_INTRINSIC>())
			i.VisitExprs(func);
		break;
	case MLIL_INTRINSIC_SSA:
		for (auto& i : GetParameterExprs<MLIL_INTRINSIC_SSA>())
			i.VisitExprs(func);
		break;
	default:
		break;
	}
}


ExprId MediumLevelILInstruction::CopyTo(MediumLevelILFunction* dest) const
{
	return CopyTo(dest, [&](const MediumLevelILInstruction& subExpr) {
		return subExpr.CopyTo(dest);
	});
}


ExprId MediumLevelILInstruction::CopyTo(MediumLevelILFunction* dest,
	const std::function<ExprId(const MediumLevelILInstruction& subExpr)>& subExprHandler) const
{
	vector<ExprId> params;
	BNMediumLevelILLabel* labelA;
	BNMediumLevelILLabel* labelB;
	switch (operation)
	{
	case MLIL_NOP:
		return dest->Nop(*this);
	case MLIL_SET_VAR:
		return dest->SetVar(size, GetDestVariable<MLIL_SET_VAR>(),
			subExprHandler(GetSourceExpr<MLIL_SET_VAR>()), *this);
	case MLIL_SET_VAR_SSA:
		return dest->SetVarSSA(size, GetDestSSAVariable<MLIL_SET_VAR_SSA>(),
			subExprHandler(GetSourceExpr<MLIL_SET_VAR_SSA>()), *this);
	case MLIL_SET_VAR_ALIASED:
		return dest->SetVarAliased(size, GetDestSSAVariable<MLIL_SET_VAR_ALIASED>().var,
			GetDestSSAVariable<MLIL_SET_VAR_ALIASED>().version,
			GetSourceSSAVariable<MLIL_SET_VAR_ALIASED>().version,
			subExprHandler(GetSourceExpr<MLIL_SET_VAR_ALIASED>()), *this);
	case MLIL_SET_VAR_SPLIT:
		return dest->SetVarSplit(size, GetHighVariable<MLIL_SET_VAR_SPLIT>(),
			GetLowVariable<MLIL_SET_VAR_SPLIT>(),
			subExprHandler(GetSourceExpr<MLIL_SET_VAR_SPLIT>()), *this);
	case MLIL_SET_VAR_SPLIT_SSA:
		return dest->SetVarSSASplit(size, GetHighSSAVariable<MLIL_SET_VAR_SPLIT_SSA>(),
			GetLowSSAVariable<MLIL_SET_VAR_SPLIT_SSA>(),
			subExprHandler(GetSourceExpr<MLIL_SET_VAR_SPLIT_SSA>()), *this);
	case MLIL_SET_VAR_FIELD:
		return dest->SetVarField(size, GetDestVariable<MLIL_SET_VAR_FIELD>(),
			GetOffset<MLIL_SET_VAR_FIELD>(), subExprHandler(GetSourceExpr<MLIL_SET_VAR_FIELD>()), *this);
	case MLIL_SET_VAR_SSA_FIELD:
		return dest->SetVarSSAField(size, GetDestSSAVariable<MLIL_SET_VAR_SSA_FIELD>().var,
			GetDestSSAVariable<MLIL_SET_VAR_SSA_FIELD>().version,
			GetSourceSSAVariable<MLIL_SET_VAR_SSA_FIELD>().version,
			GetOffset<MLIL_SET_VAR_SSA_FIELD>(),
			subExprHandler(GetSourceExpr<MLIL_SET_VAR_SSA_FIELD>()), *this);
	case MLIL_SET_VAR_ALIASED_FIELD:
		return dest->SetVarAliasedField(size, GetDestSSAVariable<MLIL_SET_VAR_ALIASED_FIELD>().var,
			GetDestSSAVariable<MLIL_SET_VAR_ALIASED_FIELD>().version,
			GetSourceSSAVariable<MLIL_SET_VAR_ALIASED_FIELD>().version,
			GetOffset<MLIL_SET_VAR_ALIASED_FIELD>(),
			subExprHandler(GetSourceExpr<MLIL_SET_VAR_ALIASED_FIELD>()), *this);
	case MLIL_VAR:
		return dest->Var(size, GetSourceVariable<MLIL_VAR>(), *this);
	case MLIL_VAR_FIELD:
		return dest->VarField(size, GetSourceVariable<MLIL_VAR_FIELD>(),
			GetOffset<MLIL_VAR_FIELD>(), *this);
	case MLIL_VAR_SPLIT:
		return dest->VarSplit(size, GetHighVariable<MLIL_VAR_SPLIT>(),
			GetLowVariable<MLIL_VAR_SPLIT>(), *this);
	case MLIL_VAR_SSA:
		return dest->VarSSA(size, GetSourceSSAVariable<MLIL_VAR_SSA>(), *this);
	case MLIL_VAR_SSA_FIELD:
		return dest->VarSSAField(size, GetSourceSSAVariable<MLIL_VAR_SSA_FIELD>(),
			GetOffset<MLIL_VAR_SSA_FIELD>(), *this);
	case MLIL_VAR_ALIASED:
		return dest->VarAliased(size, GetSourceSSAVariable<MLIL_VAR_ALIASED>().var,
			GetSourceSSAVariable<MLIL_VAR_ALIASED>().version, *this);
	case MLIL_VAR_ALIASED_FIELD:
		return dest->VarAliasedField(size, GetSourceSSAVariable<MLIL_VAR_ALIASED_FIELD>().var,
			GetSourceSSAVariable<MLIL_VAR_ALIASED_FIELD>().version,
			GetOffset<MLIL_VAR_ALIASED_FIELD>(), *this);
	case MLIL_VAR_SPLIT_SSA:
		return dest->VarSplitSSA(size, GetHighSSAVariable<MLIL_VAR_SPLIT_SSA>(),
			GetLowSSAVariable<MLIL_VAR_SPLIT_SSA>(), *this);
	case MLIL_ADDRESS_OF:
		return dest->AddressOf(GetSourceVariable<MLIL_ADDRESS_OF>(), *this);
	case MLIL_ADDRESS_OF_FIELD:
		return dest->AddressOfField(GetSourceVariable<MLIL_ADDRESS_OF_FIELD>(),
			GetOffset<MLIL_ADDRESS_OF_FIELD>(), *this);
	case MLIL_CALL:
		for (auto& i : GetParameterExprs<MLIL_CALL>())
			params.push_back(subExprHandler(i));
		return dest->Call(GetOutputVariables<MLIL_CALL>(), subExprHandler(GetDestExpr<MLIL_CALL>()),
			params, *this);
	case MLIL_CALL_UNTYPED:
		return dest->CallUntyped(GetOutputVariables<MLIL_CALL_UNTYPED>(),
			subExprHandler(GetDestExpr<MLIL_CALL_UNTYPED>()), GetParameterVariables<MLIL_CALL_UNTYPED>(),
			subExprHandler(GetStackExpr<MLIL_CALL_UNTYPED>()), *this);
	case MLIL_CALL_SSA:
		for (auto& i : GetParameterExprs<MLIL_CALL_SSA>())
			params.push_back(subExprHandler(i));
		return dest->CallSSA(GetOutputSSAVariables<MLIL_CALL_SSA>(), subExprHandler(GetDestExpr<MLIL_CALL_SSA>()),
			params, GetDestMemoryVersion<MLIL_CALL_SSA>(), GetSourceMemoryVersion<MLIL_CALL_SSA>(), *this);
	case MLIL_CALL_UNTYPED_SSA:
		return dest->CallUntypedSSA(GetOutputSSAVariables<MLIL_CALL_UNTYPED_SSA>(),
			subExprHandler(GetDestExpr<MLIL_CALL_UNTYPED_SSA>()),
			GetParameterSSAVariables<MLIL_CALL_UNTYPED_SSA>(),
			GetDestMemoryVersion<MLIL_CALL_UNTYPED_SSA>(),
			GetSourceMemoryVersion<MLIL_CALL_UNTYPED_SSA>(),
			subExprHandler(GetStackExpr<MLIL_CALL_UNTYPED_SSA>()), *this);
	case MLIL_SYSCALL:
		for (auto& i : GetParameterExprs<MLIL_SYSCALL>())
			params.push_back(subExprHandler(i));
		return dest->Syscall(GetOutputVariables<MLIL_SYSCALL>(), params, *this);
	case MLIL_SYSCALL_UNTYPED:
		return dest->SyscallUntyped(GetOutputVariables<MLIL_SYSCALL_UNTYPED>(),
			GetParameterVariables<MLIL_SYSCALL_UNTYPED>(),
			subExprHandler(GetStackExpr<MLIL_SYSCALL_UNTYPED>()), *this);
	case MLIL_SYSCALL_SSA:
		for (auto& i : GetParameterExprs<MLIL_SYSCALL_SSA>())
			params.push_back(subExprHandler(i));
		return dest->SyscallSSA(GetOutputSSAVariables<MLIL_SYSCALL_SSA>(), params,
			GetDestMemoryVersion<MLIL_SYSCALL_SSA>(), GetSourceMemoryVersion<MLIL_SYSCALL_SSA>(), *this);
	case MLIL_SYSCALL_UNTYPED_SSA:
		return dest->SyscallUntypedSSA(GetOutputSSAVariables<MLIL_SYSCALL_UNTYPED_SSA>(),
			GetParameterSSAVariables<MLIL_SYSCALL_UNTYPED_SSA>(),
			GetDestMemoryVersion<MLIL_SYSCALL_UNTYPED_SSA>(),
			GetSourceMemoryVersion<MLIL_SYSCALL_UNTYPED_SSA>(),
			subExprHandler(GetStackExpr<MLIL_SYSCALL_UNTYPED_SSA>()), *this);
	case MLIL_TAILCALL:
		for (auto& i : GetParameterExprs<MLIL_TAILCALL>())
			params.push_back(subExprHandler(i));
		return dest->TailCall(GetOutputVariables<MLIL_TAILCALL>(), subExprHandler(GetDestExpr<MLIL_TAILCALL>()),
			params, *this);
	case MLIL_TAILCALL_UNTYPED:
		return dest->TailCallUntyped(GetOutputVariables<MLIL_TAILCALL_UNTYPED>(),
			subExprHandler(GetDestExpr<MLIL_TAILCALL_UNTYPED>()), GetParameterVariables<MLIL_TAILCALL_UNTYPED>(),
			subExprHandler(GetStackExpr<MLIL_TAILCALL_UNTYPED>()), *this);
	case MLIL_TAILCALL_SSA:
		for (auto& i : GetParameterExprs<MLIL_TAILCALL_SSA>())
			params.push_back(subExprHandler(i));
		return dest->TailCallSSA(GetOutputSSAVariables<MLIL_TAILCALL_SSA>(), subExprHandler(GetDestExpr<MLIL_TAILCALL_SSA>()),
			params, GetDestMemoryVersion<MLIL_TAILCALL_SSA>(), GetSourceMemoryVersion<MLIL_TAILCALL_SSA>(), *this);
	case MLIL_TAILCALL_UNTYPED_SSA:
		return dest->TailCallUntypedSSA(GetOutputSSAVariables<MLIL_TAILCALL_UNTYPED_SSA>(),
			subExprHandler(GetDestExpr<MLIL_TAILCALL_UNTYPED_SSA>()),
			GetParameterSSAVariables<MLIL_TAILCALL_UNTYPED_SSA>(),
			GetDestMemoryVersion<MLIL_TAILCALL_UNTYPED_SSA>(),
			GetSourceMemoryVersion<MLIL_TAILCALL_UNTYPED_SSA>(),
			subExprHandler(GetStackExpr<MLIL_TAILCALL_UNTYPED_SSA>()), *this);
	case MLIL_RET:
		for (auto& i : GetSourceExprs<MLIL_RET>())
			params.push_back(subExprHandler(i));
		return dest->Return(params, *this);
	case MLIL_NORET:
		return dest->NoReturn(*this);
	case MLIL_STORE:
		return dest->Store(size, subExprHandler(GetDestExpr<MLIL_STORE>()),
			subExprHandler(GetSourceExpr<MLIL_STORE>()), *this);
	case MLIL_STORE_STRUCT:
		return dest->StoreStruct(size, subExprHandler(GetDestExpr<MLIL_STORE_STRUCT>()),
			GetOffset<MLIL_STORE_STRUCT>(), subExprHandler(GetSourceExpr<MLIL_STORE_STRUCT>()), *this);
	case MLIL_STORE_SSA:
		return dest->StoreSSA(size, subExprHandler(GetDestExpr<MLIL_STORE_SSA>()),
			GetDestMemoryVersion<MLIL_STORE_SSA>(), GetSourceMemoryVersion<MLIL_STORE_SSA>(),
			subExprHandler(GetSourceExpr<MLIL_STORE_SSA>()), *this);
	case MLIL_STORE_STRUCT_SSA:
		return dest->StoreStructSSA(size, subExprHandler(GetDestExpr<MLIL_STORE_STRUCT_SSA>()),
			GetOffset<MLIL_STORE_STRUCT_SSA>(),
			GetDestMemoryVersion<MLIL_STORE_STRUCT_SSA>(), GetSourceMemoryVersion<MLIL_STORE_STRUCT_SSA>(),
			subExprHandler(GetSourceExpr<MLIL_STORE_STRUCT_SSA>()), *this);
	case MLIL_LOAD:
		return dest->Load(size, subExprHandler(GetSourceExpr<MLIL_LOAD>()), *this);
	case MLIL_LOAD_STRUCT:
		return dest->LoadStruct(size, subExprHandler(GetSourceExpr<MLIL_LOAD_STRUCT>()),
			GetOffset<MLIL_LOAD_STRUCT>(), *this);
	case MLIL_LOAD_SSA:
		return dest->LoadSSA(size, subExprHandler(GetSourceExpr<MLIL_LOAD_SSA>()),
			GetSourceMemoryVersion<MLIL_LOAD_SSA>(), *this);
	case MLIL_LOAD_STRUCT_SSA:
		return dest->LoadStructSSA(size, subExprHandler(GetSourceExpr<MLIL_LOAD_STRUCT_SSA>()),
			GetOffset<MLIL_LOAD_STRUCT_SSA>(), GetSourceMemoryVersion<MLIL_LOAD_STRUCT_SSA>(), *this);
	case MLIL_NEG:
	case MLIL_NOT:
	case MLIL_SX:
	case MLIL_ZX:
	case MLIL_LOW_PART:
	case MLIL_BOOL_TO_INT:
	case MLIL_JUMP:
	case MLIL_RET_HINT:
	case MLIL_UNIMPL_MEM:
	case MLIL_FSQRT:
	case MLIL_FNEG:
	case MLIL_FABS:
	case MLIL_FLOAT_TO_INT:
	case MLIL_INT_TO_FLOAT:
	case MLIL_FLOAT_CONV:
	case MLIL_ROUND_TO_INT:
	case MLIL_FLOOR:
	case MLIL_CEIL:
	case MLIL_FTRUNC:
		return dest->AddExprWithLocation(operation, *this, size,
			subExprHandler(AsOneOperand().GetSourceExpr()));
	case MLIL_ADD:
	case MLIL_SUB:
	case MLIL_AND:
	case MLIL_OR:
	case MLIL_XOR:
	case MLIL_LSL:
	case MLIL_LSR:
	case MLIL_ASR:
	case MLIL_ROL:
	case MLIL_ROR:
	case MLIL_MUL:
	case MLIL_MULU_DP:
	case MLIL_MULS_DP:
	case MLIL_DIVU:
	case MLIL_DIVS:
	case MLIL_MODU:
	case MLIL_MODS:
	case MLIL_DIVU_DP:
	case MLIL_DIVS_DP:
	case MLIL_MODU_DP:
	case MLIL_MODS_DP:
	case MLIL_CMP_E:
	case MLIL_CMP_NE:
	case MLIL_CMP_SLT:
	case MLIL_CMP_ULT:
	case MLIL_CMP_SLE:
	case MLIL_CMP_ULE:
	case MLIL_CMP_SGE:
	case MLIL_CMP_UGE:
	case MLIL_CMP_SGT:
	case MLIL_CMP_UGT:
	case MLIL_TEST_BIT:
	case MLIL_ADD_OVERFLOW:
	case MLIL_FADD:
	case MLIL_FSUB:
	case MLIL_FMUL:
	case MLIL_FDIV:
	case MLIL_FCMP_E:
	case MLIL_FCMP_NE:
	case MLIL_FCMP_LT:
	case MLIL_FCMP_LE:
	case MLIL_FCMP_GE:
	case MLIL_FCMP_GT:
	case MLIL_FCMP_O:
	case MLIL_FCMP_UO:
		return dest->AddExprWithLocation(operation, *this, size,
			subExprHandler(AsTwoOperand().GetLeftExpr()), subExprHandler(AsTwoOperand().GetRightExpr()));
	case MLIL_ADC:
	case MLIL_SBB:
	case MLIL_RLC:
	case MLIL_RRC:
		return dest->AddExprWithLocation(operation, *this, size,
			subExprHandler(AsTwoOperandWithCarry().GetLeftExpr()),
			subExprHandler(AsTwoOperandWithCarry().GetRightExpr()),
			subExprHandler(AsTwoOperandWithCarry().GetCarryExpr()));
	case MLIL_JUMP_TO:
		{
			map<uint64_t, BNMediumLevelILLabel*> labelList;
			for (auto target : GetTargets<MLIL_JUMP_TO>())
			{
				labelA = dest->GetLabelForSourceInstruction(target.second);
				if (!labelA)
					return dest->Jump(subExprHandler(GetDestExpr<MLIL_JUMP_TO>()), *this);
				labelList[target.first] = labelA;
			}
			return dest->JumpTo(subExprHandler(GetDestExpr<MLIL_JUMP_TO>()), labelList, *this);
		}
	case MLIL_GOTO:
		labelA = dest->GetLabelForSourceInstruction(GetTarget<MLIL_GOTO>());
		if (!labelA)
		{
			return dest->Jump(dest->ConstPointer(function->GetArchitecture()->GetAddressSize(),
				function->GetInstruction(GetTarget<MLIL_GOTO>()).address), *this);
		}
		return dest->Goto(*labelA, *this);
	case MLIL_IF:
		labelA = dest->GetLabelForSourceInstruction(GetTrueTarget<MLIL_IF>());
		labelB = dest->GetLabelForSourceInstruction(GetFalseTarget<MLIL_IF>());
		if ((!labelA) || (!labelB))
			return dest->Undefined(*this);
		return dest->If(subExprHandler(GetConditionExpr<MLIL_IF>()), *labelA, *labelB, *this);
	case MLIL_CONST:
		return dest->Const(size, GetConstant<MLIL_CONST>(), *this);
	case MLIL_CONST_PTR:
		return dest->ConstPointer(size, GetConstant<MLIL_CONST_PTR>(), *this);
	case MLIL_EXTERN_PTR:
		return dest->ExternPointer(size, GetConstant<MLIL_EXTERN_PTR>(), GetOffset<MLIL_EXTERN_PTR>(), *this);
	case MLIL_FLOAT_CONST:
		return dest->FloatConstRaw(size, GetConstant<MLIL_FLOAT_CONST>(), *this);
	case MLIL_IMPORT:
		return dest->ImportedAddress(size, GetConstant<MLIL_IMPORT>(), *this);
	case MLIL_BP:
		return dest->Breakpoint(*this);
	case MLIL_TRAP:
		return dest->Trap(GetVector<MLIL_TRAP>(), *this);
	case MLIL_INTRINSIC:
		for (auto& i : GetParameterExprs<MLIL_INTRINSIC>())
			params.push_back(subExprHandler(i));
		return dest->Intrinsic(GetOutputVariables<MLIL_INTRINSIC>(),
			GetIntrinsic<MLIL_INTRINSIC>(), params, *this);
	case MLIL_INTRINSIC_SSA:
		for (auto& i : GetParameterExprs<MLIL_INTRINSIC_SSA>())
			params.push_back(subExprHandler(i));
		return dest->IntrinsicSSA(GetOutputSSAVariables<MLIL_INTRINSIC_SSA>(),
			GetIntrinsic<MLIL_INTRINSIC_SSA>(), params, *this);
	case MLIL_FREE_VAR_SLOT:
		return dest->FreeVarSlot(GetDestVariable<MLIL_FREE_VAR_SLOT>(), *this);
	case MLIL_FREE_VAR_SLOT_SSA:
		return dest->FreeVarSlotSSA(GetDestSSAVariable<MLIL_FREE_VAR_SLOT_SSA>().var,
			GetDestSSAVariable<MLIL_FREE_VAR_SLOT_SSA>().version,
			GetSourceSSAVariable<MLIL_FREE_VAR_SLOT_SSA>().version, *this);
	case MLIL_UNDEF:
		return dest->Undefined(*this);
	case MLIL_UNIMPL:
		return dest->Unimplemented(*this);
	default:
		throw MediumLevelILInstructionAccessException();
	}
}


bool MediumLevelILInstruction::GetOperandIndexForUsage(MediumLevelILOperandUsage usage, size_t& operandIndex) const
{
	auto operationIter = MediumLevelILInstructionBase::operationOperandIndex.find(operation);
	if (operationIter == MediumLevelILInstructionBase::operationOperandIndex.end())
		return false;
	auto usageIter = operationIter->second.find(usage);
	if (usageIter == operationIter->second.end())
		return false;
	operandIndex = usageIter->second;
	return true;
}


MediumLevelILInstruction MediumLevelILInstruction::GetSourceExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceExprMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


Variable MediumLevelILInstruction::GetSourceVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceVariableMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsVariable(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


SSAVariable MediumLevelILInstruction::GetSourceSSAVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceSSAVariableMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAVariable(operandIndex);
	if (GetOperandIndexForUsage(PartialSSAVariableSourceMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsPartialSSAVariableSource(operandIndex - 2);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILInstruction MediumLevelILInstruction::GetDestExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(DestExprMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


Variable MediumLevelILInstruction::GetDestVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(DestVariableMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsVariable(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


SSAVariable MediumLevelILInstruction::GetDestSSAVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(DestSSAVariableMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAVariable(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILInstruction MediumLevelILInstruction::GetLeftExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(LeftExprMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILInstruction MediumLevelILInstruction::GetRightExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(RightExprMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILInstruction MediumLevelILInstruction::GetCarryExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(CarryExprMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILInstruction MediumLevelILInstruction::GetStackExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(StackExprMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILInstruction MediumLevelILInstruction::GetConditionExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ConditionExprMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


Variable MediumLevelILInstruction::GetHighVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(HighVariableMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsVariable(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


Variable MediumLevelILInstruction::GetLowVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(LowVariableMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsVariable(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


SSAVariable MediumLevelILInstruction::GetHighSSAVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(HighSSAVariableMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAVariable(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


SSAVariable MediumLevelILInstruction::GetLowSSAVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(LowSSAVariableMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAVariable(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


uint64_t MediumLevelILInstruction::GetOffset() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(OffsetMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


int64_t MediumLevelILInstruction::GetConstant() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ConstantMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


int64_t MediumLevelILInstruction::GetVector() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(VectorMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


uint32_t MediumLevelILInstruction::GetIntrinsic() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(IntrinsicMediumLevelOperandUsage, operandIndex))
		return (uint32_t)GetRawOperandAsInteger(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


size_t MediumLevelILInstruction::GetTarget() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(TargetMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


size_t MediumLevelILInstruction::GetTrueTarget() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(TrueTargetMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


size_t MediumLevelILInstruction::GetFalseTarget() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(FalseTargetMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


size_t MediumLevelILInstruction::GetDestMemoryVersion() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(DestMemoryVersionMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
	if (GetOperandIndexForUsage(OutputSSAMemoryVersionMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsIndex(0);
	throw MediumLevelILInstructionAccessException();
}


size_t MediumLevelILInstruction::GetSourceMemoryVersion() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceMemoryVersionMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
	if (GetOperandIndexForUsage(ParameterSSAMemoryVersionMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsIndex(0);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILIndexMap MediumLevelILInstruction::GetTargets() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(TargetsMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndexMap(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILIndexList MediumLevelILInstruction::GetSourceMemoryVersions() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceMemoryVersionsMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndexList(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILVariableList MediumLevelILInstruction::GetOutputVariables() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(OutputVariablesMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsVariableList(operandIndex);
	if (GetOperandIndexForUsage(OutputVariablesSubExprMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsVariableList(0);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILSSAVariableList MediumLevelILInstruction::GetOutputSSAVariables() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(OutputSSAVariablesMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAVariableList(operandIndex);
	if (GetOperandIndexForUsage(OutputSSAVariablesSubExprMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsSSAVariableList(1);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILInstructionList MediumLevelILInstruction::GetParameterExprs() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ParameterExprsMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExprList(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILInstructionList MediumLevelILInstruction::GetSourceExprs() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceExprsMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExprList(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILVariableList MediumLevelILInstruction::GetParameterVariables() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ParameterVariablesMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsVariableList(0);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILSSAVariableList MediumLevelILInstruction::GetParameterSSAVariables() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ParameterSSAVariablesMediumLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex).GetRawOperandAsSSAVariableList(1);
	throw MediumLevelILInstructionAccessException();
}


MediumLevelILSSAVariableList MediumLevelILInstruction::GetSourceSSAVariables() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceSSAVariablesMediumLevelOperandUsages, operandIndex))
		return GetRawOperandAsSSAVariableList(operandIndex);
	throw MediumLevelILInstructionAccessException();
}


ExprId MediumLevelILFunction::Nop(const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_NOP, loc, 0);
}


ExprId MediumLevelILFunction::SetVar(size_t size, const Variable& dest, ExprId src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR, loc, size, dest.ToIdentifier(), src);
}


ExprId MediumLevelILFunction::SetVarField(size_t size, const Variable& dest, uint64_t offset, ExprId src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_FIELD, loc, size, dest.ToIdentifier(), offset, src);
}


ExprId MediumLevelILFunction::SetVarSplit(size_t size, const Variable& high, const Variable& low, ExprId src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_SPLIT, loc, size, high.ToIdentifier(), low.ToIdentifier(), src);
}


ExprId MediumLevelILFunction::SetVarSSA(size_t size, const SSAVariable& dest, ExprId src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_SSA, loc, size, dest.var.ToIdentifier(), dest.version, src);
}


ExprId MediumLevelILFunction::SetVarSSAField(size_t size, const Variable& dest,
	size_t newVersion, size_t prevVersion, uint64_t offset, ExprId src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_SSA_FIELD, loc, size, dest.ToIdentifier(), newVersion, prevVersion,
		offset, src);
}


ExprId MediumLevelILFunction::SetVarSSASplit(size_t size, const SSAVariable& high, const SSAVariable& low,
	ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_SPLIT_SSA, loc, size, high.var.ToIdentifier(), high.version,
		low.var.ToIdentifier(), low.version, src);
}


ExprId MediumLevelILFunction::SetVarAliased(size_t size, const Variable& dest,
	size_t newMemVersion, size_t prevMemVersion,
	ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_ALIASED, loc, size, dest.ToIdentifier(),
		newMemVersion, prevMemVersion, src);
}


ExprId MediumLevelILFunction::SetVarAliasedField(size_t size, const Variable& dest,
	size_t newMemVersion, size_t prevMemVersion,
	uint64_t offset, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_ALIASED_FIELD, loc, size, dest.ToIdentifier(),
		newMemVersion, prevMemVersion, offset, src);
}


ExprId MediumLevelILFunction::Load(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LOAD, loc, size, src);
}


ExprId MediumLevelILFunction::LoadStruct(size_t size, ExprId src, uint64_t offset,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LOAD_STRUCT, loc, size, src, offset);
}


ExprId MediumLevelILFunction::LoadSSA(size_t size, ExprId src, size_t memVersion,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LOAD_SSA, loc, size, src, memVersion);
}


ExprId MediumLevelILFunction::LoadStructSSA(size_t size, ExprId src, uint64_t offset, size_t memVersion,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LOAD_STRUCT_SSA, loc, size, src, offset, memVersion);
}


ExprId MediumLevelILFunction::Store(size_t size, ExprId dest, ExprId src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_STORE, loc, size, dest, src);
}


ExprId MediumLevelILFunction::StoreStruct(size_t size, ExprId dest, uint64_t offset, ExprId src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_STORE_STRUCT, loc, size, dest, offset, src);
}


ExprId MediumLevelILFunction::StoreSSA(size_t size, ExprId dest,
	size_t newMemVersion, size_t prevMemVersion, ExprId src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_STORE_SSA, loc, size, dest, newMemVersion, prevMemVersion, src);
}


ExprId MediumLevelILFunction::StoreStructSSA(size_t size, ExprId dest, uint64_t offset,
	size_t newMemVersion, size_t prevMemVersion, ExprId src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_STORE_STRUCT_SSA, loc, size, dest, offset, newMemVersion, prevMemVersion, src);
}


ExprId MediumLevelILFunction::Var(size_t size, const Variable& src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR, loc, size, src.ToIdentifier());
}


ExprId MediumLevelILFunction::VarField(size_t size, const Variable& src, uint64_t offset,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_FIELD, loc, size, src.ToIdentifier(), offset);
}


ExprId MediumLevelILFunction::VarSplit(size_t size, const Variable& high, const Variable& low,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_SPLIT, loc, size, high.ToIdentifier(), low.ToIdentifier());
}


ExprId MediumLevelILFunction::VarSSA(size_t size, const SSAVariable& src,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_SSA, loc, size, src.var.ToIdentifier(), src.version);
}


ExprId MediumLevelILFunction::VarSSAField(size_t size, const SSAVariable& src, uint64_t offset,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_SSA_FIELD, loc, size, src.var.ToIdentifier(), src.version, offset);
}


ExprId MediumLevelILFunction::VarAliased(size_t size, const Variable& src, size_t memVersion,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_ALIASED, loc, size, src.ToIdentifier(), memVersion);
}


ExprId MediumLevelILFunction::VarAliasedField(size_t size, const Variable& src,
	size_t memVersion, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_ALIASED_FIELD, loc, size, src.ToIdentifier(), memVersion, offset);
}


ExprId MediumLevelILFunction::VarSplitSSA(size_t size, const SSAVariable& high, const SSAVariable& low,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_SPLIT_SSA, loc, size, high.var.ToIdentifier(), high.version,
		low.var.ToIdentifier(), low.version);
}


ExprId MediumLevelILFunction::AddressOf(const Variable& var, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ADDRESS_OF, loc, 0, var.ToIdentifier());
}


ExprId MediumLevelILFunction::AddressOfField(const Variable& var, uint64_t offset,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ADDRESS_OF_FIELD, loc, 0, var.ToIdentifier(), offset);
}


ExprId MediumLevelILFunction::Const(size_t size, uint64_t val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CONST, loc, size, val);
}


ExprId MediumLevelILFunction::ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CONST_PTR, loc, size, val);
}


ExprId MediumLevelILFunction::ExternPointer(size_t size, uint64_t val, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_EXTERN_PTR, loc, size, val, offset);
}


ExprId MediumLevelILFunction::FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FLOAT_CONST, loc, size, val);
}


ExprId MediumLevelILFunction::FloatConstSingle(float val, const ILSourceLocation& loc)
{
	union
	{
		float f;
		uint32_t i;
	} bits;
	bits.f = val;
	return AddExprWithLocation(MLIL_FLOAT_CONST, loc, 4, bits.i);
}


ExprId MediumLevelILFunction::FloatConstDouble(double val, const ILSourceLocation& loc)
{
	union
	{
		double f;
		uint64_t i;
	} bits;
	bits.f = val;
	return AddExprWithLocation(MLIL_FLOAT_CONST, loc, 8, bits.i);
}


ExprId MediumLevelILFunction::ImportedAddress(size_t size, uint64_t val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_IMPORT, loc, size, val);
}


ExprId MediumLevelILFunction::Add(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ADD, loc, size, left, right);
}


ExprId MediumLevelILFunction::AddWithCarry(size_t size, ExprId left, ExprId right, ExprId carry,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ADC, loc, size, left, right, carry);
}


ExprId MediumLevelILFunction::Sub(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SUB, loc, size, left, right);
}


ExprId MediumLevelILFunction::SubWithBorrow(size_t size, ExprId left, ExprId right, ExprId carry,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SBB, loc, size, left, right, carry);
}


ExprId MediumLevelILFunction::And(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_AND, loc, size, left, right);
}


ExprId MediumLevelILFunction::Or(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_OR, loc, size, left, right);
}


ExprId MediumLevelILFunction::Xor(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_XOR, loc, size, left, right);
}


ExprId MediumLevelILFunction::ShiftLeft(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LSL, loc, size, left, right);
}


ExprId MediumLevelILFunction::LogicalShiftRight(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LSR, loc, size, left, right);
}


ExprId MediumLevelILFunction::ArithShiftRight(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ASR, loc, size, left, right);
}


ExprId MediumLevelILFunction::RotateLeft(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ROL, loc, size, left, right);
}


ExprId MediumLevelILFunction::RotateLeftCarry(size_t size, ExprId left, ExprId right, ExprId carry,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_RRC, loc, size, left, right, carry);
}


ExprId MediumLevelILFunction::RotateRight(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ROR, loc, size, left, right);
}


ExprId MediumLevelILFunction::RotateRightCarry(size_t size, ExprId left, ExprId right, ExprId carry,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_RRC, loc, size, left, right, carry);
}


ExprId MediumLevelILFunction::Mult(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MUL, loc, size, left, right);
}


ExprId MediumLevelILFunction::MultDoublePrecSigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MULS_DP, loc, size, left, right);
}


ExprId MediumLevelILFunction::MultDoublePrecUnsigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MULU_DP, loc, size, left, right);
}


ExprId MediumLevelILFunction::DivSigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_DIVS, loc, size, left, right);
}


ExprId MediumLevelILFunction::DivUnsigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_DIVU, loc, size, left, right);
}


ExprId MediumLevelILFunction::DivDoublePrecSigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_DIVS_DP, loc, size, left, right);
}


ExprId MediumLevelILFunction::DivDoublePrecUnsigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_DIVU_DP, loc, size, left, right);
}


ExprId MediumLevelILFunction::ModSigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MODS, loc, size, left, right);
}


ExprId MediumLevelILFunction::ModUnsigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MODU, loc, size, left, right);
}


ExprId MediumLevelILFunction::ModDoublePrecSigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MODS_DP, loc, size, left, right);
}


ExprId MediumLevelILFunction::ModDoublePrecUnsigned(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MODU_DP, loc, size, left, right);
}


ExprId MediumLevelILFunction::Neg(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_NEG, loc, size, src);
}


ExprId MediumLevelILFunction::Not(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_NOT, loc, size, src);
}


ExprId MediumLevelILFunction::SignExtend(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SX, loc, size, src);
}


ExprId MediumLevelILFunction::ZeroExtend(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ZX, loc, size, src);
}


ExprId MediumLevelILFunction::LowPart(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LOW_PART, loc, size, src);
}


ExprId MediumLevelILFunction::Jump(ExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_JUMP, loc, 0, dest);
}


ExprId MediumLevelILFunction::JumpTo(ExprId dest, const map<uint64_t, BNMediumLevelILLabel*>& targets,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_JUMP_TO, loc, 0, dest, targets.size() * 2, AddLabelMap(targets));
}


ExprId MediumLevelILFunction::ReturnHint(ExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_RET_HINT, loc, 0, dest);
}


ExprId MediumLevelILFunction::Call(const vector<Variable>& output, ExprId dest,
	const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CALL, loc, 0, output.size(), AddVariableList(output), dest,
		params.size(), AddOperandList(params));
}


ExprId MediumLevelILFunction::CallUntyped(const vector<Variable>& output, ExprId dest,
	const vector<Variable>& params, ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CALL_UNTYPED, loc, 0,
		AddExprWithLocation(MLIL_CALL_OUTPUT, loc, 0, output.size(), AddVariableList(output)), dest,
		AddExprWithLocation(MLIL_CALL_PARAM, loc, 0, params.size(), AddVariableList(params)), stack);
}


ExprId MediumLevelILFunction::Syscall(const vector<Variable>& output, const vector<ExprId>& params,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SYSCALL, loc, 0, output.size(), AddVariableList(output),
		params.size(), AddOperandList(params));
}


ExprId MediumLevelILFunction::SyscallUntyped(const vector<Variable>& output, const vector<Variable>& params,
	ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SYSCALL_UNTYPED, loc, 0,
		AddExprWithLocation(MLIL_CALL_OUTPUT, loc, 0, output.size(), AddVariableList(output)),
		AddExprWithLocation(MLIL_CALL_PARAM, loc, 0, params.size(), AddVariableList(params)), stack);
}


ExprId MediumLevelILFunction::TailCall(const vector<Variable>& output, ExprId dest,
	const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TAILCALL, loc, 0, output.size(), AddVariableList(output), dest,
		params.size(), AddOperandList(params));
}


ExprId MediumLevelILFunction::TailCallUntyped(const vector<Variable>& output, ExprId dest,
	const vector<Variable>& params, ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TAILCALL_UNTYPED, loc, 0,
		AddExprWithLocation(MLIL_CALL_OUTPUT, loc, 0, output.size(), AddVariableList(output)), dest,
		AddExprWithLocation(MLIL_CALL_PARAM, loc, 0, params.size(), AddVariableList(params)), stack);
}


ExprId MediumLevelILFunction::CallSSA(const vector<SSAVariable>& output, ExprId dest, const vector<ExprId>& params,
	size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CALL_SSA, loc, 0,
		AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, newMemVersion,
			output.size() * 2, AddSSAVariableList(output)), dest,
		params.size(), AddOperandList(params), prevMemVersion);
}


ExprId MediumLevelILFunction::CallUntypedSSA(const vector<SSAVariable>& output, ExprId dest,
	const vector<SSAVariable>& params, size_t newMemVersion, size_t prevMemVersion,
	ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CALL_UNTYPED_SSA, loc, 0,
		AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, newMemVersion,
			output.size() * 2, AddSSAVariableList(output)), dest,
		AddExprWithLocation(MLIL_CALL_PARAM_SSA, loc, 0, prevMemVersion,
			params.size() * 2, AddSSAVariableList(params)), stack);
}


ExprId MediumLevelILFunction::SyscallSSA(const vector<SSAVariable>& output, const vector<ExprId>& params,
	size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SYSCALL_SSA, loc, 0,
		AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, newMemVersion,
			output.size() * 2, AddSSAVariableList(output)),
		params.size(), AddOperandList(params), prevMemVersion);
}


ExprId MediumLevelILFunction::SyscallUntypedSSA(const vector<SSAVariable>& output,
	const vector<SSAVariable>& params, size_t newMemVersion, size_t prevMemVersion,
	ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SYSCALL_UNTYPED_SSA, loc, 0,
		AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, newMemVersion,
			output.size() * 2, AddSSAVariableList(output)),
		AddExprWithLocation(MLIL_CALL_PARAM_SSA, loc, 0, prevMemVersion,
			params.size() * 2, AddSSAVariableList(params)), stack);
}


ExprId MediumLevelILFunction::TailCallSSA(const vector<SSAVariable>& output, ExprId dest, const vector<ExprId>& params,
	size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TAILCALL_SSA, loc, 0,
		AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, newMemVersion,
			output.size() * 2, AddSSAVariableList(output)), dest,
		params.size(), AddOperandList(params), prevMemVersion);
}


ExprId MediumLevelILFunction::TailCallUntypedSSA(const vector<SSAVariable>& output, ExprId dest,
	const vector<SSAVariable>& params, size_t newMemVersion, size_t prevMemVersion,
	ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TAILCALL_UNTYPED_SSA, loc, 0,
		AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, newMemVersion,
			output.size() * 2, AddSSAVariableList(output)), dest,
		AddExprWithLocation(MLIL_CALL_PARAM_SSA, loc, 0, prevMemVersion,
			params.size() * 2, AddSSAVariableList(params)), stack);
}


ExprId MediumLevelILFunction::Return(const vector<ExprId>& sources, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_RET, loc, 0, sources.size(), AddOperandList(sources));
}


ExprId MediumLevelILFunction::NoReturn(const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_NORET, loc, 0);
}


ExprId MediumLevelILFunction::CompareEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_E, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareNotEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_NE, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareSignedLessThan(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_SLT, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareUnsignedLessThan(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_ULT, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareSignedLessEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_SLE, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareUnsignedLessEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_ULE, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareSignedGreaterEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_SGE, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareUnsignedGreaterEqual(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_UGE, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareSignedGreaterThan(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_SGT, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareUnsignedGreaterThan(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_UGT, loc, size, left, right);
}


ExprId MediumLevelILFunction::TestBit(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TEST_BIT, loc, size, left, right);
}


ExprId MediumLevelILFunction::BoolToInt(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_BOOL_TO_INT, loc, size, src);
}


ExprId MediumLevelILFunction::AddOverflow(size_t size, ExprId left, ExprId right,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ADD_OVERFLOW, loc, size, left, right);
}


ExprId MediumLevelILFunction::Breakpoint(const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_BP, loc, 0);
}


ExprId MediumLevelILFunction::Trap(int64_t vector, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TRAP, loc, 0, vector);
}


ExprId MediumLevelILFunction::Intrinsic(const vector<Variable>& outputs, uint32_t intrinsic,
	const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_INTRINSIC, loc, 0, outputs.size(), AddVariableList(outputs),
		intrinsic, params.size(), AddOperandList(params));
}


ExprId MediumLevelILFunction::IntrinsicSSA(const vector<SSAVariable>& outputs, uint32_t intrinsic,
	const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_INTRINSIC_SSA, loc, 0, outputs.size() * 2, AddSSAVariableList(outputs),
		intrinsic, params.size(), AddOperandList(params));
}


ExprId MediumLevelILFunction::FreeVarSlot(const Variable& var, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FREE_VAR_SLOT, loc, 0, var.ToIdentifier());
}


ExprId MediumLevelILFunction::FreeVarSlotSSA(const Variable& var, size_t newVersion, size_t prevVersion,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FREE_VAR_SLOT_SSA, loc, 0, var.ToIdentifier(), newVersion, prevVersion);
}


ExprId MediumLevelILFunction::Undefined(const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_UNDEF, loc, 0);
}


ExprId MediumLevelILFunction::Unimplemented(const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_UNIMPL, loc, 0);
}


ExprId MediumLevelILFunction::UnimplementedMemoryRef(size_t size, ExprId target,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_UNIMPL_MEM, loc, size, target);
}


ExprId MediumLevelILFunction::VarPhi(const SSAVariable& dest, const vector<SSAVariable>& sources,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_PHI, loc, 0, dest.var.ToIdentifier(), dest.version,
		sources.size() * 2, AddSSAVariableList(sources));
}


ExprId MediumLevelILFunction::MemoryPhi(size_t destMemVersion, const vector<size_t>& sourceMemVersions,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MEM_PHI, loc, 0, destMemVersion,
		sourceMemVersions.size(), AddIndexList(sourceMemVersions));
}


ExprId MediumLevelILFunction::FloatAdd(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FADD, loc, size, a, b);
}


ExprId MediumLevelILFunction::FloatSub(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FSUB, loc, size, a, b);
}


ExprId MediumLevelILFunction::FloatMult(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FMUL, loc, size, a, b);
}


ExprId MediumLevelILFunction::FloatDiv(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FDIV, loc, size, a, b);
}


ExprId MediumLevelILFunction::FloatSqrt(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FSQRT, loc, size, a);
}


ExprId MediumLevelILFunction::FloatNeg(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FNEG, loc, size, a);
}


ExprId MediumLevelILFunction::FloatAbs(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FABS, loc, size, a);
}


ExprId MediumLevelILFunction::FloatToInt(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FLOAT_TO_INT, loc, size, a);
}


ExprId MediumLevelILFunction::IntToFloat(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_INT_TO_FLOAT, loc, size, a);
}


ExprId MediumLevelILFunction::FloatConvert(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FLOAT_CONV, loc, size, a);
}


ExprId MediumLevelILFunction::RoundToInt(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ROUND_TO_INT, loc, size, a);
}


ExprId MediumLevelILFunction::Floor(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FLOOR, loc, size, a);
}


ExprId MediumLevelILFunction::Ceil(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CEIL, loc, size, a);
}


ExprId MediumLevelILFunction::FloatTrunc(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FTRUNC, loc, size, a);
}


ExprId MediumLevelILFunction::FloatCompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_E, loc, size, a, b);
}


ExprId MediumLevelILFunction::FloatCompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_NE, loc, size, a, b);
}


ExprId MediumLevelILFunction::FloatCompareLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_LT, loc, size, a, b);
}


ExprId MediumLevelILFunction::FloatCompareLessEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_LE, loc, size, a, b);
}


ExprId MediumLevelILFunction::FloatCompareGreaterEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_GE, loc, size, a, b);
}


ExprId MediumLevelILFunction::FloatCompareGreaterThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_GT, loc, size, a, b);
}


ExprId MediumLevelILFunction::FloatCompareOrdered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_O, loc, size, a, b);
}


ExprId MediumLevelILFunction::FloatCompareUnordered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_UO, loc, size, a, b);
}
