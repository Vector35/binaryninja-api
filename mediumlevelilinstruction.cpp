// Copyright (c) 2015-2026 Vector 35 Inc
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

#include <algorithm>
#include <array>
#include <cstring>
#include <initializer_list>

#include "sharedilinstruction.h"

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

#ifndef BINARYNINJACORE_LIBRARY
using namespace std;
#endif

namespace {

struct OperandUsageType
{
	MediumLevelILOperandUsage usage;
	MediumLevelILOperandType type;

	constexpr auto operator<=>(const OperandUsageType& other) const
	{
		return usage <=> other.usage;
	}
};

// BEGIN GENERATED mlil-operand-tables: from api/il, do not edit
static constexpr std::array s_operandTypeForUsage = {
	OperandUsageType{DestVariableMediumLevelOperandUsage, VariableMediumLevelOperand},
	OperandUsageType{SourceExprMediumLevelOperandUsage, ExprMediumLevelOperand},
	OperandUsageType{OffsetMediumLevelOperandUsage, IntegerMediumLevelOperand},
	OperandUsageType{HighVariableMediumLevelOperandUsage, VariableMediumLevelOperand},
	OperandUsageType{LowVariableMediumLevelOperandUsage, VariableMediumLevelOperand},
	OperandUsageType{SourceVariableMediumLevelOperandUsage, VariableMediumLevelOperand},
	OperandUsageType{ConstraintMediumLevelOperandUsage, ConstraintMediumLevelOperand},
	OperandUsageType{ForceVersionReasonMediumLevelOperandUsage, ForceVersionReasonMediumLevelOperand},
	OperandUsageType{DestExprMediumLevelOperandUsage, ExprMediumLevelOperand},
	OperandUsageType{ConstantMediumLevelOperandUsage, IntegerMediumLevelOperand},
	OperandUsageType{ConstantDataMediumLevelOperandUsage, ConstantDataMediumLevelOperand},
	OperandUsageType{LeftExprMediumLevelOperandUsage, ExprMediumLevelOperand},
	OperandUsageType{RightExprMediumLevelOperandUsage, ExprMediumLevelOperand},
	OperandUsageType{CarryExprMediumLevelOperandUsage, ExprMediumLevelOperand},
	OperandUsageType{TargetsMediumLevelOperandUsage, IndexMapMediumLevelOperand},
	OperandUsageType{OutputExprsMediumLevelOperandUsage, ExprListMediumLevelOperand},
	OperandUsageType{ParameterExprsMediumLevelOperandUsage, ExprListMediumLevelOperand},
	OperandUsageType{UntypedParameterExprsMediumLevelOperandUsage, ExprListMediumLevelOperand},
	OperandUsageType{StackExprMediumLevelOperandUsage, ExprMediumLevelOperand},
	OperandUsageType{SourceExprsMediumLevelOperandUsage, ExprListMediumLevelOperand},
	OperandUsageType{ConditionExprMediumLevelOperandUsage, ExprMediumLevelOperand},
	OperandUsageType{TrueTargetMediumLevelOperandUsage, IndexMediumLevelOperand},
	OperandUsageType{FalseTargetMediumLevelOperandUsage, IndexMediumLevelOperand},
	OperandUsageType{TargetMediumLevelOperandUsage, IndexMediumLevelOperand},
	OperandUsageType{OutputVariablesMediumLevelOperandUsage, VariableListMediumLevelOperand},
	OperandUsageType{IntrinsicMediumLevelOperandUsage, IntrinsicMediumLevelOperand},
	OperandUsageType{VectorMediumLevelOperandUsage, IntegerMediumLevelOperand},
	OperandUsageType{DestSSAVariableMediumLevelOperandUsage, SSAVariableMediumLevelOperand},
	OperandUsageType{PartialSSAVariableSourceMediumLevelOperandUsage, SSAVariableMediumLevelOperand},
	OperandUsageType{HighSSAVariableMediumLevelOperandUsage, SSAVariableMediumLevelOperand},
	OperandUsageType{LowSSAVariableMediumLevelOperandUsage, SSAVariableMediumLevelOperand},
	OperandUsageType{SourceSSAVariableMediumLevelOperandUsage, SSAVariableMediumLevelOperand},
	OperandUsageType{OutputExprsSubExprMediumLevelOperandUsage, ExprListMediumLevelOperand},
	OperandUsageType{OutputSSAMemoryVersionMediumLevelOperandUsage, IndexMediumLevelOperand},
	OperandUsageType{SourceMemoryVersionMediumLevelOperandUsage, IndexMediumLevelOperand},
	OperandUsageType{UntypedParameterSSAExprsMediumLevelOperandUsage, ExprListMediumLevelOperand},
	OperandUsageType{ParameterSSAMemoryVersionMediumLevelOperandUsage, IndexMediumLevelOperand},
	OperandUsageType{DestMemoryVersionMediumLevelOperandUsage, IndexMediumLevelOperand},
	OperandUsageType{OutputSSAVariablesMediumLevelOperandUsage, SSAVariableListMediumLevelOperand},
	OperandUsageType{OutputSSAVariablesSubExprMediumLevelOperandUsage, SSAVariableListMediumLevelOperand},
	OperandUsageType{SourceSSAVariablesMediumLevelOperandUsage, SSAVariableListMediumLevelOperand},
	OperandUsageType{SourceMemoryVersionsMediumLevelOperandUsage, IndexListMediumLevelOperand},
};

static_assert(std::is_sorted(s_operandTypeForUsage.begin(), s_operandTypeForUsage.end()),
	"Operand type mapping array is not sorted by usage value");


constexpr inline MediumLevelILOperandType OperandTypeForUsage(MediumLevelILOperandUsage usage)
{
	if (static_cast<size_t>(usage) < s_operandTypeForUsage.size())
		return s_operandTypeForUsage[usage].type;

	throw MediumLevelILInstructionAccessException();
}


static constexpr size_t MaxOperands = 6;
using OperandLocations = detail::ILInstructionOperandLocations<BNMediumLevelILOperation, MediumLevelILOperandLocation, MaxOperands>;

static constexpr std::array s_operandLocations = {
	OperandLocations{MLIL_NOP},
	OperandLocations{MLIL_SET_VAR, {{DestVariableMediumLevelOperandUsage, 0}, {SourceExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_SET_VAR_FIELD, {{DestVariableMediumLevelOperandUsage, 0}, {OffsetMediumLevelOperandUsage, 1}, {SourceExprMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_SET_VAR_SPLIT, {{HighVariableMediumLevelOperandUsage, 0}, {LowVariableMediumLevelOperandUsage, 1}, {SourceExprMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_ASSERT, {{SourceVariableMediumLevelOperandUsage, 0}, {ConstraintMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FORCE_VER, {{DestVariableMediumLevelOperandUsage, 0}, {SourceVariableMediumLevelOperandUsage, 1}, {ForceVersionReasonMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_LOAD, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_LOAD_STRUCT, {{SourceExprMediumLevelOperandUsage, 0}, {OffsetMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_STORE, {{DestExprMediumLevelOperandUsage, 0}, {SourceExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_STORE_STRUCT, {{DestExprMediumLevelOperandUsage, 0}, {OffsetMediumLevelOperandUsage, 1}, {SourceExprMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_VAR, {{SourceVariableMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_VAR_FIELD, {{SourceVariableMediumLevelOperandUsage, 0}, {OffsetMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_VAR_SPLIT, {{HighVariableMediumLevelOperandUsage, 0}, {LowVariableMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_ADDRESS_OF, {{SourceVariableMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_ADDRESS_OF_FIELD, {{SourceVariableMediumLevelOperandUsage, 0}, {OffsetMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_PASS_BY_REF, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_RETURN_BY_REF, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_CONST, {{ConstantMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_CONST_DATA, {{ConstantDataMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_CONST_PTR, {{ConstantMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_EXTERN_PTR, {{ConstantMediumLevelOperandUsage, 0}, {OffsetMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FLOAT_CONST, {{ConstantMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_IMPORT, {{ConstantMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_ADD, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_ADC, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}, {CarryExprMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_SUB, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_SBB, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}, {CarryExprMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_AND, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_OR, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_XOR, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_LSL, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_LSR, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_ASR, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_ROL, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_RLC, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}, {CarryExprMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_ROR, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_RRC, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}, {CarryExprMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_MUL, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_MULU_DP, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_MULS_DP, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_DIVU, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_DIVU_DP, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_DIVS, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_DIVS_DP, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_MODU, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_MODU_DP, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_MODS, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_MODS_DP, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_NEG, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_NOT, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_SX, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_ZX, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_LOW_PART, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_JUMP, {{DestExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_JUMP_TO, {{DestExprMediumLevelOperandUsage, 0}, {TargetsMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_RET_HINT, {{DestExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_CALL, {{OutputExprsMediumLevelOperandUsage, 0}, {DestExprMediumLevelOperandUsage, 2}, {ParameterExprsMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_CALL_UNTYPED, {{OutputExprsMediumLevelOperandUsage, 0}, {DestExprMediumLevelOperandUsage, 2}, {UntypedParameterExprsMediumLevelOperandUsage, 3, 0}, {StackExprMediumLevelOperandUsage, 4}}},
	OperandLocations{MLIL_CALL_PARAM, {{ParameterExprsMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_SEPARATE_PARAM_LIST, {{ParameterExprsMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_SHARED_PARAM_SLOT, {{ParameterExprsMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_VAR_OUTPUT, {{DestVariableMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_VAR_OUTPUT_FIELD, {{DestVariableMediumLevelOperandUsage, 0}, {OffsetMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_STORE_OUTPUT, {{DestExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_RET, {{SourceExprsMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_NORET},
	OperandLocations{MLIL_IF, {{ConditionExprMediumLevelOperandUsage, 0}, {TrueTargetMediumLevelOperandUsage, 1}, {FalseTargetMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_GOTO, {{TargetMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_CMP_E, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_CMP_NE, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_CMP_SLT, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_CMP_ULT, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_CMP_SLE, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_CMP_ULE, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_CMP_SGE, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_CMP_UGE, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_CMP_SGT, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_CMP_UGT, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_TEST_BIT, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_BOOL_TO_INT, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_ADD_OVERFLOW, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_SYSCALL, {{OutputExprsMediumLevelOperandUsage, 0}, {ParameterExprsMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_SYSCALL_UNTYPED, {{OutputExprsMediumLevelOperandUsage, 0}, {UntypedParameterExprsMediumLevelOperandUsage, 2, 0}, {StackExprMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_TAILCALL, {{OutputExprsMediumLevelOperandUsage, 0}, {DestExprMediumLevelOperandUsage, 2}, {ParameterExprsMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_TAILCALL_UNTYPED, {{OutputExprsMediumLevelOperandUsage, 0}, {DestExprMediumLevelOperandUsage, 2}, {UntypedParameterExprsMediumLevelOperandUsage, 3, 0}, {StackExprMediumLevelOperandUsage, 4}}},
	OperandLocations{MLIL_INTRINSIC, {{OutputVariablesMediumLevelOperandUsage, 0}, {IntrinsicMediumLevelOperandUsage, 2}, {ParameterExprsMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_FREE_VAR_SLOT, {{DestVariableMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_BP},
	OperandLocations{MLIL_TRAP, {{VectorMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_UNDEF},
	OperandLocations{MLIL_UNIMPL},
	OperandLocations{MLIL_UNIMPL_MEM, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_FADD, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FSUB, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FMUL, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FDIV, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FSQRT, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_FNEG, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_FABS, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_FLOAT_TO_INT, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_INT_TO_FLOAT, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_FLOAT_CONV, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_ROUND_TO_INT, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_FLOOR, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_CEIL, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_FTRUNC, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_FCMP_E, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FCMP_NE, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FCMP_LT, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FCMP_LE, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FCMP_GE, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FCMP_GT, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FCMP_O, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_FCMP_UO, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_SET_VAR_SSA, {{DestSSAVariableMediumLevelOperandUsage, 0}, {SourceExprMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_SET_VAR_SSA_FIELD, {{DestSSAVariableMediumLevelOperandUsage, 0}, {PartialSSAVariableSourceMediumLevelOperandUsage, 0, std::nullopt, true}, {OffsetMediumLevelOperandUsage, 3}, {SourceExprMediumLevelOperandUsage, 4}}},
	OperandLocations{MLIL_SET_VAR_SPLIT_SSA, {{HighSSAVariableMediumLevelOperandUsage, 0}, {LowSSAVariableMediumLevelOperandUsage, 2}, {SourceExprMediumLevelOperandUsage, 4}}},
	OperandLocations{MLIL_SET_VAR_ALIASED, {{DestSSAVariableMediumLevelOperandUsage, 0}, {PartialSSAVariableSourceMediumLevelOperandUsage, 0, std::nullopt, true}, {SourceExprMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_SET_VAR_ALIASED_FIELD, {{DestSSAVariableMediumLevelOperandUsage, 0}, {PartialSSAVariableSourceMediumLevelOperandUsage, 0, std::nullopt, true}, {OffsetMediumLevelOperandUsage, 3}, {SourceExprMediumLevelOperandUsage, 4}}},
	OperandLocations{MLIL_VAR_SSA, {{SourceSSAVariableMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_VAR_SSA_FIELD, {{SourceSSAVariableMediumLevelOperandUsage, 0}, {OffsetMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_VAR_ALIASED, {{SourceSSAVariableMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_VAR_ALIASED_FIELD, {{SourceSSAVariableMediumLevelOperandUsage, 0}, {OffsetMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_VAR_SPLIT_SSA, {{HighSSAVariableMediumLevelOperandUsage, 0}, {LowSSAVariableMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_ASSERT_SSA, {{SourceSSAVariableMediumLevelOperandUsage, 0}, {ConstraintMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_FORCE_VER_SSA, {{DestSSAVariableMediumLevelOperandUsage, 0}, {SourceSSAVariableMediumLevelOperandUsage, 2}, {ForceVersionReasonMediumLevelOperandUsage, 4}}},
	OperandLocations{MLIL_CALL_SSA, {{OutputExprsSubExprMediumLevelOperandUsage, 0, 1}, {OutputSSAMemoryVersionMediumLevelOperandUsage, 0, 0}, {DestExprMediumLevelOperandUsage, 1}, {ParameterExprsMediumLevelOperandUsage, 2}, {SourceMemoryVersionMediumLevelOperandUsage, 4}}},
	OperandLocations{MLIL_CALL_UNTYPED_SSA, {{OutputExprsSubExprMediumLevelOperandUsage, 0, 1}, {OutputSSAMemoryVersionMediumLevelOperandUsage, 0, 0}, {DestExprMediumLevelOperandUsage, 1}, {UntypedParameterSSAExprsMediumLevelOperandUsage, 2, 1}, {ParameterSSAMemoryVersionMediumLevelOperandUsage, 2, 0}, {StackExprMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_SYSCALL_SSA, {{OutputExprsSubExprMediumLevelOperandUsage, 0, 1}, {OutputSSAMemoryVersionMediumLevelOperandUsage, 0, 0}, {ParameterExprsMediumLevelOperandUsage, 1}, {SourceMemoryVersionMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_SYSCALL_UNTYPED_SSA, {{OutputExprsSubExprMediumLevelOperandUsage, 0, 1}, {OutputSSAMemoryVersionMediumLevelOperandUsage, 0, 0}, {UntypedParameterSSAExprsMediumLevelOperandUsage, 1, 1}, {ParameterSSAMemoryVersionMediumLevelOperandUsage, 1, 0}, {StackExprMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_TAILCALL_SSA, {{OutputExprsSubExprMediumLevelOperandUsage, 0, 1}, {OutputSSAMemoryVersionMediumLevelOperandUsage, 0, 0}, {DestExprMediumLevelOperandUsage, 1}, {ParameterExprsMediumLevelOperandUsage, 2}, {SourceMemoryVersionMediumLevelOperandUsage, 4}}},
	OperandLocations{MLIL_TAILCALL_UNTYPED_SSA, {{OutputExprsSubExprMediumLevelOperandUsage, 0, 1}, {OutputSSAMemoryVersionMediumLevelOperandUsage, 0, 0}, {DestExprMediumLevelOperandUsage, 1}, {UntypedParameterSSAExprsMediumLevelOperandUsage, 2, 1}, {ParameterSSAMemoryVersionMediumLevelOperandUsage, 2, 0}, {StackExprMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_CALL_PARAM_SSA, {{SourceMemoryVersionMediumLevelOperandUsage, 0}, {ParameterExprsMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_CALL_OUTPUT_SSA, {{DestMemoryVersionMediumLevelOperandUsage, 0}, {OutputExprsMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_VAR_OUTPUT_SSA, {{DestSSAVariableMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_VAR_OUTPUT_SSA_FIELD, {{DestSSAVariableMediumLevelOperandUsage, 0}, {PartialSSAVariableSourceMediumLevelOperandUsage, 0, std::nullopt, true}, {OffsetMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_VAR_OUTPUT_ALIASED, {{DestSSAVariableMediumLevelOperandUsage, 0}, {PartialSSAVariableSourceMediumLevelOperandUsage, 0, std::nullopt, true}}},
	OperandLocations{MLIL_VAR_OUTPUT_ALIASED_FIELD, {{DestSSAVariableMediumLevelOperandUsage, 0}, {PartialSSAVariableSourceMediumLevelOperandUsage, 0, std::nullopt, true}, {OffsetMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_MEMORY_INTRINSIC_OUTPUT_SSA, {{DestMemoryVersionMediumLevelOperandUsage, 0}, {OutputSSAVariablesMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_LOAD_SSA, {{SourceExprMediumLevelOperandUsage, 0}, {SourceMemoryVersionMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_LOAD_STRUCT_SSA, {{SourceExprMediumLevelOperandUsage, 0}, {OffsetMediumLevelOperandUsage, 1}, {SourceMemoryVersionMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_STORE_SSA, {{DestExprMediumLevelOperandUsage, 0}, {DestMemoryVersionMediumLevelOperandUsage, 1}, {SourceMemoryVersionMediumLevelOperandUsage, 2}, {SourceExprMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_STORE_STRUCT_SSA, {{DestExprMediumLevelOperandUsage, 0}, {OffsetMediumLevelOperandUsage, 1}, {DestMemoryVersionMediumLevelOperandUsage, 2}, {SourceMemoryVersionMediumLevelOperandUsage, 3}, {SourceExprMediumLevelOperandUsage, 4}}},
	OperandLocations{MLIL_INTRINSIC_SSA, {{OutputSSAVariablesMediumLevelOperandUsage, 0}, {IntrinsicMediumLevelOperandUsage, 2}, {ParameterExprsMediumLevelOperandUsage, 3}}},
	OperandLocations{MLIL_MEMORY_INTRINSIC_SSA, {{OutputSSAVariablesSubExprMediumLevelOperandUsage, 0, 1}, {OutputSSAMemoryVersionMediumLevelOperandUsage, 0, 0}, {IntrinsicMediumLevelOperandUsage, 1}, {ParameterExprsMediumLevelOperandUsage, 2}, {SourceMemoryVersionMediumLevelOperandUsage, 4}}},
	OperandLocations{MLIL_FREE_VAR_SLOT_SSA, {{DestSSAVariableMediumLevelOperandUsage, 0}, {PartialSSAVariableSourceMediumLevelOperandUsage, 0, std::nullopt, true}}},
	OperandLocations{MLIL_VAR_PHI, {{DestSSAVariableMediumLevelOperandUsage, 0}, {SourceSSAVariablesMediumLevelOperandUsage, 2}}},
	OperandLocations{MLIL_MEM_PHI, {{DestMemoryVersionMediumLevelOperandUsage, 0}, {SourceMemoryVersionsMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_BLOCK_TO_EXPAND, {{SourceExprsMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_BSWAP, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_POPCNT, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_CLZ, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_CTZ, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_RBIT, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_CLS, {{SourceExprMediumLevelOperandUsage, 0}}},
	OperandLocations{MLIL_MINS, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_MAXS, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_MINU, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_MAXU, {{LeftExprMediumLevelOperandUsage, 0}, {RightExprMediumLevelOperandUsage, 1}}},
	OperandLocations{MLIL_ABS, {{SourceExprMediumLevelOperandUsage, 0}}},
};


VALIDATE_INSTRUCTION_ORDER(s_operandLocations);
// END GENERATED mlil-operand-tables


std::optional<MediumLevelILOperandLocation> OperandLocationForUsage(
    BNMediumLevelILOperation operation, MediumLevelILOperandUsage usage)
{
	if (operation >= s_operandLocations.size())
		return std::nullopt;
	return s_operandLocations[operation].Find(usage);
}


// Returns the instruction's operand for the first of `usages` it reports.
MediumLevelILOperand OperandForUsages(
    const MediumLevelILInstruction& instr, std::initializer_list<MediumLevelILOperandUsage> usages)
{
	for (MediumLevelILOperandUsage usage : usages)
	{
		if (std::optional<MediumLevelILOperandLocation> location = OperandLocationForUsage(instr.operation, usage))
			return MediumLevelILOperand(instr, *location);
	}
	throw MediumLevelILInstructionAccessException();
}

} // anonymous namespace


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
	offset++;
	return *this;
}


uint64_t MediumLevelILIntegerList::ListIterator::operator*()
{
#ifdef BINARYNINJACORE_LIBRARY
	return function->GetOperand(offset);
#else
	return BNMediumLevelILGetOperand(function->GetObject(), offset);
#endif
}


MediumLevelILIntegerList::MediumLevelILIntegerList(
    MediumLevelILFunction* func, size_t offset, size_t count)
{
	m_start.function = func;
	m_start.offset = offset;
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
	result.offset = m_start.offset + m_start.count;
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
#ifdef BINARYNINJACORE_LIBRARY
	return m_start.function->GetOperand(m_start.offset + i);
#else
	return BNMediumLevelILGetOperand(m_start.function->GetObject(), m_start.offset + i);
#endif
}


MediumLevelILIntegerList::operator vector<uint64_t>() const
{
	vector<uint64_t> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


size_t MediumLevelILIndexList::ListIterator::operator*()
{
	return (size_t)*pos;
}


MediumLevelILIndexList::MediumLevelILIndexList(
    MediumLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count)
{}


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
	result.reserve(size());
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


MediumLevelILIndexMap::MediumLevelILIndexMap(
    MediumLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count & (~1))
{}


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
	for (auto i : *this)
		result[i.first] = i.second;
	return result;
}


const Variable MediumLevelILVariableList::ListIterator::operator*()
{
	return Variable::FromIdentifier(*pos);
}


MediumLevelILVariableList::MediumLevelILVariableList(
    MediumLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count)
{}


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
	result.reserve(size());
	for (auto i : *this)
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


MediumLevelILSSAVariableList::MediumLevelILSSAVariableList(
    MediumLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count & (~1))
{}


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
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const MediumLevelILInstruction MediumLevelILInstructionList::ListIterator::operator*()
{
	return MediumLevelILInstruction(
	    pos.GetFunction(), pos.GetFunction()->GetRawExpr((size_t)*pos), (size_t)*pos, instructionIndex);
}


MediumLevelILInstructionList::MediumLevelILInstructionList(
    MediumLevelILFunction* func, size_t offset, size_t count, size_t instrIndex) :
    m_list(func, offset, count),
    m_instructionIndex(instrIndex)
{}


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
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


MediumLevelILInstructionList::operator vector<ExprId>() const
{
	vector<ExprId> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i.exprIndex);
	return result;
}


MediumLevelILOperand::MediumLevelILOperand(
    const MediumLevelILInstruction& instr, const MediumLevelILOperandLocation& location) :
    m_instr(instr), m_location(location), m_type(OperandTypeForUsage(location.usage))
{
}


MediumLevelILInstruction MediumLevelILOperand::Holder() const
{
	return m_location.field ? m_instr.GetRawOperandAsExpr(m_location.slot) : m_instr;
}


size_t MediumLevelILOperand::Slot() const
{
	return m_location.field.value_or(m_location.slot);
}


uint64_t MediumLevelILOperand::GetInteger() const
{
	if (m_type != IntegerMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return Holder().GetRawOperandAsInteger(Slot());
}


ConstantData MediumLevelILOperand::GetConstantData() const
{
	if (m_type != ConstantDataMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return Holder().GetRawOperandAsConstantData(Slot());
}


size_t MediumLevelILOperand::GetIndex() const
{
	if (m_type != IndexMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return Holder().GetRawOperandAsIndex(Slot());
}


uint32_t MediumLevelILOperand::GetIntrinsic() const
{
	if (m_type != IntrinsicMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return (uint32_t)Holder().GetRawOperandAsInteger(Slot());
}


MediumLevelILInstruction MediumLevelILOperand::GetExpr() const
{
	if (m_type != ExprMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return Holder().GetRawOperandAsExpr(Slot());
}


Variable MediumLevelILOperand::GetVariable() const
{
	if (m_type != VariableMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return Holder().GetRawOperandAsVariable(Slot());
}


SSAVariable MediumLevelILOperand::GetSSAVariable() const
{
	if (m_type != SSAVariableMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	if (m_location.partial)
		return Holder().GetRawOperandAsPartialSSAVariableSource(Slot());
	return Holder().GetRawOperandAsSSAVariable(Slot());
}


MediumLevelILIndexList MediumLevelILOperand::GetIndexList() const
{
	if (m_type != IndexListMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return Holder().GetRawOperandAsIndexList(Slot());
}


MediumLevelILIndexMap MediumLevelILOperand::GetIndexMap() const
{
	if (m_type != IndexMapMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return Holder().GetRawOperandAsIndexMap(Slot());
}


MediumLevelILVariableList MediumLevelILOperand::GetVariableList() const
{
	if (m_type != VariableListMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return Holder().GetRawOperandAsVariableList(Slot());
}


MediumLevelILSSAVariableList MediumLevelILOperand::GetSSAVariableList() const
{
	if (m_type != SSAVariableListMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return Holder().GetRawOperandAsSSAVariableList(Slot());
}


MediumLevelILInstructionList MediumLevelILOperand::GetExprList() const
{
	if (m_type != ExprListMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return Holder().GetRawOperandAsExprList(Slot());
}


PossibleValueSet MediumLevelILOperand::GetConstraint() const
{
	if (m_type != ConstraintMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return Holder().GetRawOperandAsPossibleValueSet(Slot());
}


BNForceVersionReason MediumLevelILOperand::GetForceVersionReason() const
{
	if (m_type != ForceVersionReasonMediumLevelOperand)
		throw MediumLevelILInstructionAccessException();
	return (BNForceVersionReason)Holder().GetRawOperandAsInteger(Slot());
}


const MediumLevelILOperand MediumLevelILOperandList::ListIterator::operator*()
{
	if (index >= owner->m_count)
		throw MediumLevelILInstructionAccessException();
	return MediumLevelILOperand(owner->m_instr, owner->m_locations[index]);
}


MediumLevelILOperandList::MediumLevelILOperandList(
    const MediumLevelILInstruction& instr, const MediumLevelILOperandLocation* locations, uint8_t count) :
    m_instr(instr), m_locations(locations), m_count(count)
{}


MediumLevelILOperandList::const_iterator MediumLevelILOperandList::begin() const
{
	const_iterator result;
	result.owner = this;
	result.index = 0;
	return result;
}


MediumLevelILOperandList::const_iterator MediumLevelILOperandList::end() const
{
	const_iterator result;
	result.owner = this;
	result.index = m_count;
	return result;
}


size_t MediumLevelILOperandList::size() const
{
	return m_count;
}


const MediumLevelILOperand MediumLevelILOperandList::operator[](size_t i) const
{
	if (i >= m_count)
		throw MediumLevelILInstructionAccessException();
	return MediumLevelILOperand(m_instr, m_locations[i]);
}


MediumLevelILOperandList::operator vector<MediumLevelILOperand>() const
{
	vector<MediumLevelILOperand> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


MediumLevelILInstruction::MediumLevelILInstruction()
{
	operation = MLIL_UNDEF;
	attributes = 0;
	sourceOperand = BN_INVALID_OPERAND;
	size = 0;
	address = 0;
	function = nullptr;
	exprIndex = BN_INVALID_EXPR;
	instructionIndex = BN_INVALID_EXPR;
}


MediumLevelILInstruction::MediumLevelILInstruction(
    MediumLevelILFunction* func, const BNMediumLevelILInstruction& instr, size_t expr, size_t instrIdx)
{
	operation = instr.operation;
	attributes = instr.attributes;
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
	attributes = instr.attributes;
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
	if (operation >= s_operandLocations.size())
		throw MediumLevelILInstructionAccessException();

	const auto& info = s_operandLocations[operation];
	return MediumLevelILOperandList(*(const MediumLevelILInstruction*)this, info.locations, info.count);
}


uint64_t MediumLevelILInstructionBase::GetRawOperandAsInteger(size_t operand) const
{
	return operands[operand];
}


ConstantData MediumLevelILInstructionBase::GetRawOperandAsConstantData(size_t operand) const
{
	return ConstantData((BNRegisterValueType)operands[operand], (uint64_t)operands[operand + 1], size, function->GetFunction());
}


size_t MediumLevelILInstructionBase::GetRawOperandAsIndex(size_t operand) const
{
	return (size_t)operands[operand];
}


MediumLevelILInstruction MediumLevelILInstructionBase::GetRawOperandAsExpr(size_t operand) const
{
	return MediumLevelILInstruction(
	    function, function->GetRawExpr(operands[operand]), operands[operand], instructionIndex);
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
	return MediumLevelILIndexList(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


MediumLevelILIndexMap MediumLevelILInstructionBase::GetRawOperandAsIndexMap(size_t operand) const
{
	return MediumLevelILIndexMap(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


MediumLevelILVariableList MediumLevelILInstructionBase::GetRawOperandAsVariableList(size_t operand) const
{
	return MediumLevelILVariableList(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


MediumLevelILSSAVariableList MediumLevelILInstructionBase::GetRawOperandAsSSAVariableList(size_t operand) const
{
	return MediumLevelILSSAVariableList(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


MediumLevelILInstructionList MediumLevelILInstructionBase::GetRawOperandAsExprList(size_t operand) const
{
	return MediumLevelILInstructionList(
	    function, (size_t)operands[operand + 1], (size_t)operands[operand], instructionIndex);
}


PossibleValueSet MediumLevelILInstructionBase::GetRawOperandAsPossibleValueSet(size_t operand) const
{
	return function->GetCachedPossibleValueSet(operands[operand]);
}


void MediumLevelILInstructionBase::UpdateRawOperand(size_t operandIndex, ExprId value)
{
	operands[operandIndex] = value;
	function->UpdateInstructionOperand(exprIndex, operandIndex, value);
}


void MediumLevelILInstructionBase::UpdateRawOperandAsSSAVariableList(
    size_t operandIndex, const vector<SSAVariable>& vars)
{
	UpdateRawOperand(operandIndex, vars.size() * 2);
	UpdateRawOperand(operandIndex + 1, function->AddSSAVariableList(vars));
}


void MediumLevelILInstructionBase::UpdateRawOperandAsExprList(
    size_t operandIndex, const vector<MediumLevelILInstruction>& exprs)
{
	vector<ExprId> exprIndexList;
	exprIndexList.reserve(exprs.size());
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


PossibleValueSet MediumLevelILInstructionBase::GetPossibleValues(const set<BNDataFlowQueryOption>& options) const
{
	return function->GetPossibleExprValues(*(const MediumLevelILInstruction*)this, options);
}


Confidence<Ref<Type>> MediumLevelILInstructionBase::GetType() const
{
	return function->GetExprType(*(const MediumLevelILInstruction*)this);
}


char* MediumLevelILInstructionBase::Dump() const
{
	vector<InstructionTextToken> tokens;
#ifdef BINARYNINJACORE_LIBRARY
	bool success = function->GetExprText(function->GetFunction(), function->GetArchitecture(), *this, tokens, new DisassemblySettings());
#else
	bool success = function->GetExprText(function->GetArchitecture(), exprIndex, tokens);
#endif
	if (success)
	{
		string text;
		if (exprIndex != BN_INVALID_EXPR && (exprIndex & 0xffff000000000000) == 0)
		{
			text += "[expr " + to_string(exprIndex) + "] ";
		}
		if (instructionIndex != BN_INVALID_EXPR && (instructionIndex & 0xffff000000000000) == 0)
		{
			text += "[instr " + to_string(instructionIndex) + "] ";
		}
		Ref<Type> type = GetType().GetValue();
		if (type)
		{
			text += "[type: " + type->GetString() + "] ";
		}
		for (auto& token: tokens)
		{
			text += token.text;
		}
		return strdup(text.c_str());
	}
	else
	{
		return strdup("???");
	}
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


size_t MediumLevelILInstructionBase::GetHighLevelILInstructionIndex() const
{
	return function->GetHighLevelILInstructionIndex(instructionIndex);
}


size_t MediumLevelILInstructionBase::GetHighLevelILExprIndex() const
{
	return function->GetHighLevelILExprIndex(exprIndex);
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


void MediumLevelILInstructionBase::SetAttributes(uint32_t attributes)
{
	function->SetExprAttributes(exprIndex, attributes);
}


void MediumLevelILInstructionBase::SetAttribute(BNILInstructionAttribute attribute, bool state)
{
	uint32_t newAttributes = attributes;
	if (state)
	{
		newAttributes |= attribute;
		switch (attribute)
		{
		case ILAllowDeadStoreElimination:
			newAttributes &= ~ILPreventDeadStoreElimination;
			break;
		case ILPreventDeadStoreElimination:
			newAttributes &= ~ILAllowDeadStoreElimination;
			break;
		default:
			break;
		}
	}
	else
	{
		newAttributes &= ~attribute;
	}
	SetAttributes(newAttributes);
}


void MediumLevelILInstructionBase::ClearAttribute(BNILInstructionAttribute attribute)
{
	SetAttribute(attribute, false);
}


// BEGIN GENERATED mlil-visit: from api/il, do not edit
void MediumLevelILInstruction::VisitExprs(bn::base::function_ref<bool(const MediumLevelILInstruction& expr)> func) const
{
	if (!func(*this))
		return;
	switch (operation)
	{
	case MLIL_SET_VAR:
		GetSourceExpr<MLIL_SET_VAR>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_FIELD:
		GetSourceExpr<MLIL_SET_VAR_FIELD>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_SPLIT:
		GetSourceExpr<MLIL_SET_VAR_SPLIT>().VisitExprs(func);
		break;
	case MLIL_LOAD:
		GetSourceExpr<MLIL_LOAD>().VisitExprs(func);
		break;
	case MLIL_LOAD_STRUCT:
		GetSourceExpr<MLIL_LOAD_STRUCT>().VisitExprs(func);
		break;
	case MLIL_STORE:
		GetDestExpr<MLIL_STORE>().VisitExprs(func);
		GetSourceExpr<MLIL_STORE>().VisitExprs(func);
		break;
	case MLIL_STORE_STRUCT:
		GetDestExpr<MLIL_STORE_STRUCT>().VisitExprs(func);
		GetSourceExpr<MLIL_STORE_STRUCT>().VisitExprs(func);
		break;
	case MLIL_PASS_BY_REF:
		GetSourceExpr<MLIL_PASS_BY_REF>().VisitExprs(func);
		break;
	case MLIL_RETURN_BY_REF:
		GetSourceExpr<MLIL_RETURN_BY_REF>().VisitExprs(func);
		break;
	case MLIL_ADD:
		GetLeftExpr<MLIL_ADD>().VisitExprs(func);
		GetRightExpr<MLIL_ADD>().VisitExprs(func);
		break;
	case MLIL_ADC:
		GetLeftExpr<MLIL_ADC>().VisitExprs(func);
		GetRightExpr<MLIL_ADC>().VisitExprs(func);
		GetCarryExpr<MLIL_ADC>().VisitExprs(func);
		break;
	case MLIL_SUB:
		GetLeftExpr<MLIL_SUB>().VisitExprs(func);
		GetRightExpr<MLIL_SUB>().VisitExprs(func);
		break;
	case MLIL_SBB:
		GetLeftExpr<MLIL_SBB>().VisitExprs(func);
		GetRightExpr<MLIL_SBB>().VisitExprs(func);
		GetCarryExpr<MLIL_SBB>().VisitExprs(func);
		break;
	case MLIL_AND:
		GetLeftExpr<MLIL_AND>().VisitExprs(func);
		GetRightExpr<MLIL_AND>().VisitExprs(func);
		break;
	case MLIL_OR:
		GetLeftExpr<MLIL_OR>().VisitExprs(func);
		GetRightExpr<MLIL_OR>().VisitExprs(func);
		break;
	case MLIL_XOR:
		GetLeftExpr<MLIL_XOR>().VisitExprs(func);
		GetRightExpr<MLIL_XOR>().VisitExprs(func);
		break;
	case MLIL_LSL:
		GetLeftExpr<MLIL_LSL>().VisitExprs(func);
		GetRightExpr<MLIL_LSL>().VisitExprs(func);
		break;
	case MLIL_LSR:
		GetLeftExpr<MLIL_LSR>().VisitExprs(func);
		GetRightExpr<MLIL_LSR>().VisitExprs(func);
		break;
	case MLIL_ASR:
		GetLeftExpr<MLIL_ASR>().VisitExprs(func);
		GetRightExpr<MLIL_ASR>().VisitExprs(func);
		break;
	case MLIL_ROL:
		GetLeftExpr<MLIL_ROL>().VisitExprs(func);
		GetRightExpr<MLIL_ROL>().VisitExprs(func);
		break;
	case MLIL_RLC:
		GetLeftExpr<MLIL_RLC>().VisitExprs(func);
		GetRightExpr<MLIL_RLC>().VisitExprs(func);
		GetCarryExpr<MLIL_RLC>().VisitExprs(func);
		break;
	case MLIL_ROR:
		GetLeftExpr<MLIL_ROR>().VisitExprs(func);
		GetRightExpr<MLIL_ROR>().VisitExprs(func);
		break;
	case MLIL_RRC:
		GetLeftExpr<MLIL_RRC>().VisitExprs(func);
		GetRightExpr<MLIL_RRC>().VisitExprs(func);
		GetCarryExpr<MLIL_RRC>().VisitExprs(func);
		break;
	case MLIL_MUL:
		GetLeftExpr<MLIL_MUL>().VisitExprs(func);
		GetRightExpr<MLIL_MUL>().VisitExprs(func);
		break;
	case MLIL_MULU_DP:
		GetLeftExpr<MLIL_MULU_DP>().VisitExprs(func);
		GetRightExpr<MLIL_MULU_DP>().VisitExprs(func);
		break;
	case MLIL_MULS_DP:
		GetLeftExpr<MLIL_MULS_DP>().VisitExprs(func);
		GetRightExpr<MLIL_MULS_DP>().VisitExprs(func);
		break;
	case MLIL_DIVU:
		GetLeftExpr<MLIL_DIVU>().VisitExprs(func);
		GetRightExpr<MLIL_DIVU>().VisitExprs(func);
		break;
	case MLIL_DIVU_DP:
		GetLeftExpr<MLIL_DIVU_DP>().VisitExprs(func);
		GetRightExpr<MLIL_DIVU_DP>().VisitExprs(func);
		break;
	case MLIL_DIVS:
		GetLeftExpr<MLIL_DIVS>().VisitExprs(func);
		GetRightExpr<MLIL_DIVS>().VisitExprs(func);
		break;
	case MLIL_DIVS_DP:
		GetLeftExpr<MLIL_DIVS_DP>().VisitExprs(func);
		GetRightExpr<MLIL_DIVS_DP>().VisitExprs(func);
		break;
	case MLIL_MODU:
		GetLeftExpr<MLIL_MODU>().VisitExprs(func);
		GetRightExpr<MLIL_MODU>().VisitExprs(func);
		break;
	case MLIL_MODU_DP:
		GetLeftExpr<MLIL_MODU_DP>().VisitExprs(func);
		GetRightExpr<MLIL_MODU_DP>().VisitExprs(func);
		break;
	case MLIL_MODS:
		GetLeftExpr<MLIL_MODS>().VisitExprs(func);
		GetRightExpr<MLIL_MODS>().VisitExprs(func);
		break;
	case MLIL_MODS_DP:
		GetLeftExpr<MLIL_MODS_DP>().VisitExprs(func);
		GetRightExpr<MLIL_MODS_DP>().VisitExprs(func);
		break;
	case MLIL_NEG:
		GetSourceExpr<MLIL_NEG>().VisitExprs(func);
		break;
	case MLIL_NOT:
		GetSourceExpr<MLIL_NOT>().VisitExprs(func);
		break;
	case MLIL_SX:
		GetSourceExpr<MLIL_SX>().VisitExprs(func);
		break;
	case MLIL_ZX:
		GetSourceExpr<MLIL_ZX>().VisitExprs(func);
		break;
	case MLIL_LOW_PART:
		GetSourceExpr<MLIL_LOW_PART>().VisitExprs(func);
		break;
	case MLIL_JUMP:
		GetDestExpr<MLIL_JUMP>().VisitExprs(func);
		break;
	case MLIL_JUMP_TO:
		GetDestExpr<MLIL_JUMP_TO>().VisitExprs(func);
		break;
	case MLIL_RET_HINT:
		GetDestExpr<MLIL_RET_HINT>().VisitExprs(func);
		break;
	case MLIL_CALL:
		GetDestExpr<MLIL_CALL>().VisitExprs(func);
		for (const auto& expr : GetOutputExprs<MLIL_CALL>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_CALL>())
			expr.VisitExprs(func);
		break;
	case MLIL_CALL_UNTYPED:
		GetDestExpr<MLIL_CALL_UNTYPED>().VisitExprs(func);
		for (const auto& expr : GetOutputExprs<MLIL_CALL_UNTYPED>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_CALL_UNTYPED>())
			expr.VisitExprs(func);
		break;
	case MLIL_SEPARATE_PARAM_LIST:
		for (const auto& expr : GetParameterExprs<MLIL_SEPARATE_PARAM_LIST>())
			expr.VisitExprs(func);
		break;
	case MLIL_SHARED_PARAM_SLOT:
		for (const auto& expr : GetParameterExprs<MLIL_SHARED_PARAM_SLOT>())
			expr.VisitExprs(func);
		break;
	case MLIL_STORE_OUTPUT:
		GetDestExpr<MLIL_STORE_OUTPUT>().VisitExprs(func);
		break;
	case MLIL_RET:
		for (const auto& expr : GetSourceExprs<MLIL_RET>())
			expr.VisitExprs(func);
		break;
	case MLIL_IF:
		GetConditionExpr<MLIL_IF>().VisitExprs(func);
		break;
	case MLIL_CMP_E:
		GetLeftExpr<MLIL_CMP_E>().VisitExprs(func);
		GetRightExpr<MLIL_CMP_E>().VisitExprs(func);
		break;
	case MLIL_CMP_NE:
		GetLeftExpr<MLIL_CMP_NE>().VisitExprs(func);
		GetRightExpr<MLIL_CMP_NE>().VisitExprs(func);
		break;
	case MLIL_CMP_SLT:
		GetLeftExpr<MLIL_CMP_SLT>().VisitExprs(func);
		GetRightExpr<MLIL_CMP_SLT>().VisitExprs(func);
		break;
	case MLIL_CMP_ULT:
		GetLeftExpr<MLIL_CMP_ULT>().VisitExprs(func);
		GetRightExpr<MLIL_CMP_ULT>().VisitExprs(func);
		break;
	case MLIL_CMP_SLE:
		GetLeftExpr<MLIL_CMP_SLE>().VisitExprs(func);
		GetRightExpr<MLIL_CMP_SLE>().VisitExprs(func);
		break;
	case MLIL_CMP_ULE:
		GetLeftExpr<MLIL_CMP_ULE>().VisitExprs(func);
		GetRightExpr<MLIL_CMP_ULE>().VisitExprs(func);
		break;
	case MLIL_CMP_SGE:
		GetLeftExpr<MLIL_CMP_SGE>().VisitExprs(func);
		GetRightExpr<MLIL_CMP_SGE>().VisitExprs(func);
		break;
	case MLIL_CMP_UGE:
		GetLeftExpr<MLIL_CMP_UGE>().VisitExprs(func);
		GetRightExpr<MLIL_CMP_UGE>().VisitExprs(func);
		break;
	case MLIL_CMP_SGT:
		GetLeftExpr<MLIL_CMP_SGT>().VisitExprs(func);
		GetRightExpr<MLIL_CMP_SGT>().VisitExprs(func);
		break;
	case MLIL_CMP_UGT:
		GetLeftExpr<MLIL_CMP_UGT>().VisitExprs(func);
		GetRightExpr<MLIL_CMP_UGT>().VisitExprs(func);
		break;
	case MLIL_TEST_BIT:
		GetLeftExpr<MLIL_TEST_BIT>().VisitExprs(func);
		GetRightExpr<MLIL_TEST_BIT>().VisitExprs(func);
		break;
	case MLIL_BOOL_TO_INT:
		GetSourceExpr<MLIL_BOOL_TO_INT>().VisitExprs(func);
		break;
	case MLIL_ADD_OVERFLOW:
		GetLeftExpr<MLIL_ADD_OVERFLOW>().VisitExprs(func);
		GetRightExpr<MLIL_ADD_OVERFLOW>().VisitExprs(func);
		break;
	case MLIL_SYSCALL:
		for (const auto& expr : GetOutputExprs<MLIL_SYSCALL>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_SYSCALL>())
			expr.VisitExprs(func);
		break;
	case MLIL_SYSCALL_UNTYPED:
		for (const auto& expr : GetOutputExprs<MLIL_SYSCALL_UNTYPED>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_SYSCALL_UNTYPED>())
			expr.VisitExprs(func);
		break;
	case MLIL_TAILCALL:
		GetDestExpr<MLIL_TAILCALL>().VisitExprs(func);
		for (const auto& expr : GetOutputExprs<MLIL_TAILCALL>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_TAILCALL>())
			expr.VisitExprs(func);
		break;
	case MLIL_TAILCALL_UNTYPED:
		GetDestExpr<MLIL_TAILCALL_UNTYPED>().VisitExprs(func);
		for (const auto& expr : GetOutputExprs<MLIL_TAILCALL_UNTYPED>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_TAILCALL_UNTYPED>())
			expr.VisitExprs(func);
		break;
	case MLIL_INTRINSIC:
		for (const auto& expr : GetParameterExprs<MLIL_INTRINSIC>())
			expr.VisitExprs(func);
		break;
	case MLIL_UNIMPL_MEM:
		GetSourceExpr<MLIL_UNIMPL_MEM>().VisitExprs(func);
		break;
	case MLIL_FADD:
		GetLeftExpr<MLIL_FADD>().VisitExprs(func);
		GetRightExpr<MLIL_FADD>().VisitExprs(func);
		break;
	case MLIL_FSUB:
		GetLeftExpr<MLIL_FSUB>().VisitExprs(func);
		GetRightExpr<MLIL_FSUB>().VisitExprs(func);
		break;
	case MLIL_FMUL:
		GetLeftExpr<MLIL_FMUL>().VisitExprs(func);
		GetRightExpr<MLIL_FMUL>().VisitExprs(func);
		break;
	case MLIL_FDIV:
		GetLeftExpr<MLIL_FDIV>().VisitExprs(func);
		GetRightExpr<MLIL_FDIV>().VisitExprs(func);
		break;
	case MLIL_FSQRT:
		GetSourceExpr<MLIL_FSQRT>().VisitExprs(func);
		break;
	case MLIL_FNEG:
		GetSourceExpr<MLIL_FNEG>().VisitExprs(func);
		break;
	case MLIL_FABS:
		GetSourceExpr<MLIL_FABS>().VisitExprs(func);
		break;
	case MLIL_FLOAT_TO_INT:
		GetSourceExpr<MLIL_FLOAT_TO_INT>().VisitExprs(func);
		break;
	case MLIL_INT_TO_FLOAT:
		GetSourceExpr<MLIL_INT_TO_FLOAT>().VisitExprs(func);
		break;
	case MLIL_FLOAT_CONV:
		GetSourceExpr<MLIL_FLOAT_CONV>().VisitExprs(func);
		break;
	case MLIL_ROUND_TO_INT:
		GetSourceExpr<MLIL_ROUND_TO_INT>().VisitExprs(func);
		break;
	case MLIL_FLOOR:
		GetSourceExpr<MLIL_FLOOR>().VisitExprs(func);
		break;
	case MLIL_CEIL:
		GetSourceExpr<MLIL_CEIL>().VisitExprs(func);
		break;
	case MLIL_FTRUNC:
		GetSourceExpr<MLIL_FTRUNC>().VisitExprs(func);
		break;
	case MLIL_FCMP_E:
		GetLeftExpr<MLIL_FCMP_E>().VisitExprs(func);
		GetRightExpr<MLIL_FCMP_E>().VisitExprs(func);
		break;
	case MLIL_FCMP_NE:
		GetLeftExpr<MLIL_FCMP_NE>().VisitExprs(func);
		GetRightExpr<MLIL_FCMP_NE>().VisitExprs(func);
		break;
	case MLIL_FCMP_LT:
		GetLeftExpr<MLIL_FCMP_LT>().VisitExprs(func);
		GetRightExpr<MLIL_FCMP_LT>().VisitExprs(func);
		break;
	case MLIL_FCMP_LE:
		GetLeftExpr<MLIL_FCMP_LE>().VisitExprs(func);
		GetRightExpr<MLIL_FCMP_LE>().VisitExprs(func);
		break;
	case MLIL_FCMP_GE:
		GetLeftExpr<MLIL_FCMP_GE>().VisitExprs(func);
		GetRightExpr<MLIL_FCMP_GE>().VisitExprs(func);
		break;
	case MLIL_FCMP_GT:
		GetLeftExpr<MLIL_FCMP_GT>().VisitExprs(func);
		GetRightExpr<MLIL_FCMP_GT>().VisitExprs(func);
		break;
	case MLIL_FCMP_O:
		GetLeftExpr<MLIL_FCMP_O>().VisitExprs(func);
		GetRightExpr<MLIL_FCMP_O>().VisitExprs(func);
		break;
	case MLIL_FCMP_UO:
		GetLeftExpr<MLIL_FCMP_UO>().VisitExprs(func);
		GetRightExpr<MLIL_FCMP_UO>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_SSA:
		GetSourceExpr<MLIL_SET_VAR_SSA>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_SSA_FIELD:
		GetSourceExpr<MLIL_SET_VAR_SSA_FIELD>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_SPLIT_SSA:
		GetSourceExpr<MLIL_SET_VAR_SPLIT_SSA>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_ALIASED:
		GetSourceExpr<MLIL_SET_VAR_ALIASED>().VisitExprs(func);
		break;
	case MLIL_SET_VAR_ALIASED_FIELD:
		GetSourceExpr<MLIL_SET_VAR_ALIASED_FIELD>().VisitExprs(func);
		break;
	case MLIL_CALL_SSA:
		GetDestExpr<MLIL_CALL_SSA>().VisitExprs(func);
		for (const auto& expr : GetOutputExprs<MLIL_CALL_SSA>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_CALL_SSA>())
			expr.VisitExprs(func);
		break;
	case MLIL_CALL_UNTYPED_SSA:
		GetDestExpr<MLIL_CALL_UNTYPED_SSA>().VisitExprs(func);
		for (const auto& expr : GetOutputExprs<MLIL_CALL_UNTYPED_SSA>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_CALL_UNTYPED_SSA>())
			expr.VisitExprs(func);
		break;
	case MLIL_SYSCALL_SSA:
		for (const auto& expr : GetOutputExprs<MLIL_SYSCALL_SSA>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_SYSCALL_SSA>())
			expr.VisitExprs(func);
		break;
	case MLIL_SYSCALL_UNTYPED_SSA:
		for (const auto& expr : GetOutputExprs<MLIL_SYSCALL_UNTYPED_SSA>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_SYSCALL_UNTYPED_SSA>())
			expr.VisitExprs(func);
		break;
	case MLIL_TAILCALL_SSA:
		GetDestExpr<MLIL_TAILCALL_SSA>().VisitExprs(func);
		for (const auto& expr : GetOutputExprs<MLIL_TAILCALL_SSA>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_TAILCALL_SSA>())
			expr.VisitExprs(func);
		break;
	case MLIL_TAILCALL_UNTYPED_SSA:
		GetDestExpr<MLIL_TAILCALL_UNTYPED_SSA>().VisitExprs(func);
		for (const auto& expr : GetOutputExprs<MLIL_TAILCALL_UNTYPED_SSA>())
			expr.VisitExprs(func);
		for (const auto& expr : GetParameterExprs<MLIL_TAILCALL_UNTYPED_SSA>())
			expr.VisitExprs(func);
		break;
	case MLIL_LOAD_SSA:
		GetSourceExpr<MLIL_LOAD_SSA>().VisitExprs(func);
		break;
	case MLIL_LOAD_STRUCT_SSA:
		GetSourceExpr<MLIL_LOAD_STRUCT_SSA>().VisitExprs(func);
		break;
	case MLIL_STORE_SSA:
		GetDestExpr<MLIL_STORE_SSA>().VisitExprs(func);
		GetSourceExpr<MLIL_STORE_SSA>().VisitExprs(func);
		break;
	case MLIL_STORE_STRUCT_SSA:
		GetDestExpr<MLIL_STORE_STRUCT_SSA>().VisitExprs(func);
		GetSourceExpr<MLIL_STORE_STRUCT_SSA>().VisitExprs(func);
		break;
	case MLIL_INTRINSIC_SSA:
		for (const auto& expr : GetParameterExprs<MLIL_INTRINSIC_SSA>())
			expr.VisitExprs(func);
		break;
	case MLIL_MEMORY_INTRINSIC_SSA:
		for (const auto& expr : GetParameterExprs<MLIL_MEMORY_INTRINSIC_SSA>())
			expr.VisitExprs(func);
		break;
	case MLIL_BLOCK_TO_EXPAND:
		for (const auto& expr : GetSourceExprs<MLIL_BLOCK_TO_EXPAND>())
			expr.VisitExprs(func);
		break;
	case MLIL_BSWAP:
		GetSourceExpr<MLIL_BSWAP>().VisitExprs(func);
		break;
	case MLIL_POPCNT:
		GetSourceExpr<MLIL_POPCNT>().VisitExprs(func);
		break;
	case MLIL_CLZ:
		GetSourceExpr<MLIL_CLZ>().VisitExprs(func);
		break;
	case MLIL_CTZ:
		GetSourceExpr<MLIL_CTZ>().VisitExprs(func);
		break;
	case MLIL_RBIT:
		GetSourceExpr<MLIL_RBIT>().VisitExprs(func);
		break;
	case MLIL_CLS:
		GetSourceExpr<MLIL_CLS>().VisitExprs(func);
		break;
	case MLIL_MINS:
		GetLeftExpr<MLIL_MINS>().VisitExprs(func);
		GetRightExpr<MLIL_MINS>().VisitExprs(func);
		break;
	case MLIL_MAXS:
		GetLeftExpr<MLIL_MAXS>().VisitExprs(func);
		GetRightExpr<MLIL_MAXS>().VisitExprs(func);
		break;
	case MLIL_MINU:
		GetLeftExpr<MLIL_MINU>().VisitExprs(func);
		GetRightExpr<MLIL_MINU>().VisitExprs(func);
		break;
	case MLIL_MAXU:
		GetLeftExpr<MLIL_MAXU>().VisitExprs(func);
		GetRightExpr<MLIL_MAXU>().VisitExprs(func);
		break;
	case MLIL_ABS:
		GetSourceExpr<MLIL_ABS>().VisitExprs(func);
		break;
	default:
		break;
	}
}
// END GENERATED mlil-visit


ExprId MediumLevelILInstruction::CopyTo(MediumLevelILFunction* dest, const ILSourceLocation& sourceLocation) const
{
	return CopyTo(dest, [&](const MediumLevelILInstruction& subExpr) { return subExpr.CopyTo(dest, sourceLocation); }, sourceLocation);
}


// Rebuilds a branch so it targets `dest`'s labels, because its targets are instruction indices in the source
// function.
static ExprId CopyBranchTo(const MediumLevelILInstruction& instr, MediumLevelILFunction* dest,
	bn::base::function_ref<ExprId(const MediumLevelILInstruction& subExpr)> subExprHandler, const ILSourceLocation& loc)
{
	switch (instr.operation)
	{
	case MLIL_JUMP_TO:
	{
		map<uint64_t, BNMediumLevelILLabel*> labels;
		for (auto target : instr.GetTargets<MLIL_JUMP_TO>())
		{
			BNMediumLevelILLabel* label = dest->GetLabelForSourceInstruction(target.second);
			if (!label)
				return dest->Jump(subExprHandler(instr.GetDestExpr<MLIL_JUMP_TO>()), loc);
			labels[target.first] = label;
		}
		return dest->JumpTo(subExprHandler(instr.GetDestExpr<MLIL_JUMP_TO>()), labels, loc);
	}
	case MLIL_GOTO:
	{
		BNMediumLevelILLabel* label = dest->GetLabelForSourceInstruction(instr.GetTarget<MLIL_GOTO>());
		if (!label)
		{
			return dest->Jump(dest->ConstPointer(instr.function->GetArchitecture()->GetAddressSize(),
				instr.function->GetInstruction(instr.GetTarget<MLIL_GOTO>()).address), loc);
		}
		return dest->Goto(*label, loc);
	}
	case MLIL_IF:
	{
		BNMediumLevelILLabel* trueLabel = dest->GetLabelForSourceInstruction(instr.GetTrueTarget<MLIL_IF>());
		BNMediumLevelILLabel* falseLabel = dest->GetLabelForSourceInstruction(instr.GetFalseTarget<MLIL_IF>());
		if (!trueLabel || !falseLabel)
			return dest->Undefined(loc);
		return dest->If(subExprHandler(instr.GetConditionExpr<MLIL_IF>()), *trueLabel, *falseLabel, loc);
	}
	default:
		throw MediumLevelILInstructionAccessException();
	}
}

// BEGIN GENERATED mlil-copy: from api/il, do not edit
static ExprId CopyOperandList(MediumLevelILFunction* dest, const MediumLevelILInstruction& instr, size_t operand)
{
	vector<uint64_t> items = instr.function->GetOperandList(instr.exprIndex, operand);
	return dest->AddIndexList(vector<size_t>(items.begin(), items.end()));
}


ExprId MediumLevelILInstruction::CopyTo(MediumLevelILFunction* dest,
    bn::base::function_ref<ExprId(const MediumLevelILInstruction& subExpr)> subExprHandler,
    const ILSourceLocation& sourceLocation) const
{
	const auto& loc = sourceLocation.valid ? sourceLocation : ILSourceLocation{*this};
	switch (operation)
	{
	case MLIL_JUMP_TO:
	case MLIL_IF:
	case MLIL_GOTO:
		return CopyBranchTo(*this, dest, subExprHandler, loc);
	case MLIL_NOP:
		return dest->AddExprWithLocation(MLIL_NOP, loc, size);
	case MLIL_SET_VAR:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_SET_VAR, loc, size, GetRawOperandAsInteger(0), srcCopy);
	}
	case MLIL_SET_VAR_FIELD:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    MLIL_SET_VAR_FIELD, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1), srcCopy);
	}
	case MLIL_SET_VAR_SPLIT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    MLIL_SET_VAR_SPLIT, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1), srcCopy);
	}
	case MLIL_ASSERT:
		return dest->AddExprWithLocation(MLIL_ASSERT, loc, size, GetRawOperandAsInteger(0),
		    dest->CachePossibleValueSet(GetRawOperandAsPossibleValueSet(1)));
	case MLIL_FORCE_VER:
		return dest->AddExprWithLocation(
		    MLIL_FORCE_VER, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	case MLIL_LOAD:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_LOAD, loc, size, srcCopy);
	}
	case MLIL_LOAD_STRUCT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_LOAD_STRUCT, loc, size, srcCopy, GetRawOperandAsInteger(1));
	}
	case MLIL_STORE:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_STORE, loc, size, destCopy, srcCopy);
	}
	case MLIL_STORE_STRUCT:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(MLIL_STORE_STRUCT, loc, size, destCopy, GetRawOperandAsInteger(1), srcCopy);
	}
	case MLIL_VAR:
		return dest->AddExprWithLocation(MLIL_VAR, loc, size, GetRawOperandAsInteger(0));
	case MLIL_VAR_FIELD:
		return dest->AddExprWithLocation(
		    MLIL_VAR_FIELD, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case MLIL_VAR_SPLIT:
		return dest->AddExprWithLocation(
		    MLIL_VAR_SPLIT, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case MLIL_ADDRESS_OF:
		return dest->AddExprWithLocation(MLIL_ADDRESS_OF, loc, size, GetRawOperandAsInteger(0));
	case MLIL_ADDRESS_OF_FIELD:
		return dest->AddExprWithLocation(
		    MLIL_ADDRESS_OF_FIELD, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case MLIL_PASS_BY_REF:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_PASS_BY_REF, loc, size, srcCopy);
	}
	case MLIL_RETURN_BY_REF:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_RETURN_BY_REF, loc, size, srcCopy);
	}
	case MLIL_CONST:
		return dest->AddExprWithLocation(MLIL_CONST, loc, size, GetRawOperandAsInteger(0));
	case MLIL_CONST_DATA:
		return dest->AddExprWithLocation(
		    MLIL_CONST_DATA, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case MLIL_CONST_PTR:
		return dest->AddExprWithLocation(MLIL_CONST_PTR, loc, size, GetRawOperandAsInteger(0));
	case MLIL_EXTERN_PTR:
		return dest->AddExprWithLocation(
		    MLIL_EXTERN_PTR, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case MLIL_FLOAT_CONST:
		return dest->AddExprWithLocation(MLIL_FLOAT_CONST, loc, size, GetRawOperandAsInteger(0));
	case MLIL_IMPORT:
		return dest->AddExprWithLocation(MLIL_IMPORT, loc, size, GetRawOperandAsInteger(0));
	case MLIL_ADD:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_ADD, loc, size, leftCopy, rightCopy);
	}
	case MLIL_ADC:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(MLIL_ADC, loc, size, leftCopy, rightCopy, carryCopy);
	}
	case MLIL_SUB:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_SUB, loc, size, leftCopy, rightCopy);
	}
	case MLIL_SBB:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(MLIL_SBB, loc, size, leftCopy, rightCopy, carryCopy);
	}
	case MLIL_AND:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_AND, loc, size, leftCopy, rightCopy);
	}
	case MLIL_OR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_OR, loc, size, leftCopy, rightCopy);
	}
	case MLIL_XOR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_XOR, loc, size, leftCopy, rightCopy);
	}
	case MLIL_LSL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_LSL, loc, size, leftCopy, rightCopy);
	}
	case MLIL_LSR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_LSR, loc, size, leftCopy, rightCopy);
	}
	case MLIL_ASR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_ASR, loc, size, leftCopy, rightCopy);
	}
	case MLIL_ROL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_ROL, loc, size, leftCopy, rightCopy);
	}
	case MLIL_RLC:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(MLIL_RLC, loc, size, leftCopy, rightCopy, carryCopy);
	}
	case MLIL_ROR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_ROR, loc, size, leftCopy, rightCopy);
	}
	case MLIL_RRC:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(MLIL_RRC, loc, size, leftCopy, rightCopy, carryCopy);
	}
	case MLIL_MUL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_MUL, loc, size, leftCopy, rightCopy);
	}
	case MLIL_MULU_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_MULU_DP, loc, size, leftCopy, rightCopy);
	}
	case MLIL_MULS_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_MULS_DP, loc, size, leftCopy, rightCopy);
	}
	case MLIL_DIVU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_DIVU, loc, size, leftCopy, rightCopy);
	}
	case MLIL_DIVU_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_DIVU_DP, loc, size, leftCopy, rightCopy);
	}
	case MLIL_DIVS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_DIVS, loc, size, leftCopy, rightCopy);
	}
	case MLIL_DIVS_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_DIVS_DP, loc, size, leftCopy, rightCopy);
	}
	case MLIL_MODU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_MODU, loc, size, leftCopy, rightCopy);
	}
	case MLIL_MODU_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_MODU_DP, loc, size, leftCopy, rightCopy);
	}
	case MLIL_MODS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_MODS, loc, size, leftCopy, rightCopy);
	}
	case MLIL_MODS_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_MODS_DP, loc, size, leftCopy, rightCopy);
	}
	case MLIL_NEG:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_NEG, loc, size, srcCopy);
	}
	case MLIL_NOT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_NOT, loc, size, srcCopy);
	}
	case MLIL_SX:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_SX, loc, size, srcCopy);
	}
	case MLIL_ZX:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_ZX, loc, size, srcCopy);
	}
	case MLIL_LOW_PART:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_LOW_PART, loc, size, srcCopy);
	}
	case MLIL_JUMP:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_JUMP, loc, size, destCopy);
	}
	case MLIL_RET_HINT:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_RET_HINT, loc, size, destCopy);
	}
	case MLIL_CALL:
	{
		vector<ExprId> outputExprsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			outputExprsCopy.push_back(subExprHandler(expr));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(2));
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(3))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(MLIL_CALL, loc, size, outputExprsCopy.size(),
		    dest->AddOperandList(outputExprsCopy), destCopy, paramsCopy.size(), dest->AddOperandList(paramsCopy));
	}
	case MLIL_CALL_UNTYPED:
	{
		vector<ExprId> outputExprsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			outputExprsCopy.push_back(subExprHandler(expr));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(2));
		MediumLevelILInstruction param = GetRawOperandAsExpr(3);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(0))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(
		    MLIL_CALL_PARAM, loc, param.size, paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		ExprId stackCopy = subExprHandler(GetRawOperandAsExpr(4));
		return dest->AddExprWithLocation(MLIL_CALL_UNTYPED, loc, size, outputExprsCopy.size(),
		    dest->AddOperandList(outputExprsCopy), destCopy, paramCopy, stackCopy);
	}
	case MLIL_SEPARATE_PARAM_LIST:
	{
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(
		    MLIL_SEPARATE_PARAM_LIST, loc, size, paramsCopy.size(), dest->AddOperandList(paramsCopy));
	}
	case MLIL_SHARED_PARAM_SLOT:
	{
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(
		    MLIL_SHARED_PARAM_SLOT, loc, size, paramsCopy.size(), dest->AddOperandList(paramsCopy));
	}
	case MLIL_VAR_OUTPUT:
		return dest->AddExprWithLocation(MLIL_VAR_OUTPUT, loc, size, GetRawOperandAsInteger(0));
	case MLIL_VAR_OUTPUT_FIELD:
		return dest->AddExprWithLocation(
		    MLIL_VAR_OUTPUT_FIELD, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case MLIL_STORE_OUTPUT:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_STORE_OUTPUT, loc, size, destCopy);
	}
	case MLIL_RET:
	{
		vector<ExprId> srcCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			srcCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(MLIL_RET, loc, size, srcCopy.size(), dest->AddOperandList(srcCopy));
	}
	case MLIL_NORET:
		return dest->AddExprWithLocation(MLIL_NORET, loc, size);
	case MLIL_CMP_E:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_CMP_E, loc, size, leftCopy, rightCopy);
	}
	case MLIL_CMP_NE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_CMP_NE, loc, size, leftCopy, rightCopy);
	}
	case MLIL_CMP_SLT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_CMP_SLT, loc, size, leftCopy, rightCopy);
	}
	case MLIL_CMP_ULT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_CMP_ULT, loc, size, leftCopy, rightCopy);
	}
	case MLIL_CMP_SLE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_CMP_SLE, loc, size, leftCopy, rightCopy);
	}
	case MLIL_CMP_ULE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_CMP_ULE, loc, size, leftCopy, rightCopy);
	}
	case MLIL_CMP_SGE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_CMP_SGE, loc, size, leftCopy, rightCopy);
	}
	case MLIL_CMP_UGE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_CMP_UGE, loc, size, leftCopy, rightCopy);
	}
	case MLIL_CMP_SGT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_CMP_SGT, loc, size, leftCopy, rightCopy);
	}
	case MLIL_CMP_UGT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_CMP_UGT, loc, size, leftCopy, rightCopy);
	}
	case MLIL_TEST_BIT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_TEST_BIT, loc, size, leftCopy, rightCopy);
	}
	case MLIL_BOOL_TO_INT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_BOOL_TO_INT, loc, size, srcCopy);
	}
	case MLIL_ADD_OVERFLOW:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_ADD_OVERFLOW, loc, size, leftCopy, rightCopy);
	}
	case MLIL_SYSCALL:
	{
		vector<ExprId> outputExprsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			outputExprsCopy.push_back(subExprHandler(expr));
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(2))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(MLIL_SYSCALL, loc, size, outputExprsCopy.size(),
		    dest->AddOperandList(outputExprsCopy), paramsCopy.size(), dest->AddOperandList(paramsCopy));
	}
	case MLIL_SYSCALL_UNTYPED:
	{
		vector<ExprId> outputExprsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			outputExprsCopy.push_back(subExprHandler(expr));
		MediumLevelILInstruction param = GetRawOperandAsExpr(2);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(0))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(
		    MLIL_CALL_PARAM, loc, param.size, paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		ExprId stackCopy = subExprHandler(GetRawOperandAsExpr(3));
		return dest->AddExprWithLocation(MLIL_SYSCALL_UNTYPED, loc, size, outputExprsCopy.size(),
		    dest->AddOperandList(outputExprsCopy), paramCopy, stackCopy);
	}
	case MLIL_TAILCALL:
	{
		vector<ExprId> outputExprsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			outputExprsCopy.push_back(subExprHandler(expr));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(2));
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(3))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(MLIL_TAILCALL, loc, size, outputExprsCopy.size(),
		    dest->AddOperandList(outputExprsCopy), destCopy, paramsCopy.size(), dest->AddOperandList(paramsCopy));
	}
	case MLIL_TAILCALL_UNTYPED:
	{
		vector<ExprId> outputExprsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			outputExprsCopy.push_back(subExprHandler(expr));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(2));
		MediumLevelILInstruction param = GetRawOperandAsExpr(3);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(0))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(
		    MLIL_CALL_PARAM, loc, param.size, paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		ExprId stackCopy = subExprHandler(GetRawOperandAsExpr(4));
		return dest->AddExprWithLocation(MLIL_TAILCALL_UNTYPED, loc, size, outputExprsCopy.size(),
		    dest->AddOperandList(outputExprsCopy), destCopy, paramCopy, stackCopy);
	}
	case MLIL_INTRINSIC:
	{
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(3))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(MLIL_INTRINSIC, loc, size, GetRawOperandAsInteger(0),
		    CopyOperandList(dest, *this, 0), GetRawOperandAsInteger(2), paramsCopy.size(),
		    dest->AddOperandList(paramsCopy));
	}
	case MLIL_FREE_VAR_SLOT:
		return dest->AddExprWithLocation(MLIL_FREE_VAR_SLOT, loc, size, GetRawOperandAsInteger(0));
	case MLIL_BP:
		return dest->AddExprWithLocation(MLIL_BP, loc, size);
	case MLIL_TRAP:
		return dest->AddExprWithLocation(MLIL_TRAP, loc, size, GetRawOperandAsInteger(0));
	case MLIL_UNDEF:
		return dest->AddExprWithLocation(MLIL_UNDEF, loc, size);
	case MLIL_UNIMPL:
		return dest->AddExprWithLocation(MLIL_UNIMPL, loc, size, GetRawOperandAsInteger(0));
	case MLIL_UNIMPL_MEM:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_UNIMPL_MEM, loc, size, srcCopy, GetRawOperandAsInteger(1));
	}
	case MLIL_FADD:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FADD, loc, size, leftCopy, rightCopy);
	}
	case MLIL_FSUB:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FSUB, loc, size, leftCopy, rightCopy);
	}
	case MLIL_FMUL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FMUL, loc, size, leftCopy, rightCopy);
	}
	case MLIL_FDIV:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FDIV, loc, size, leftCopy, rightCopy);
	}
	case MLIL_FSQRT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_FSQRT, loc, size, srcCopy);
	}
	case MLIL_FNEG:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_FNEG, loc, size, srcCopy);
	}
	case MLIL_FABS:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_FABS, loc, size, srcCopy);
	}
	case MLIL_FLOAT_TO_INT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_FLOAT_TO_INT, loc, size, srcCopy);
	}
	case MLIL_INT_TO_FLOAT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_INT_TO_FLOAT, loc, size, srcCopy);
	}
	case MLIL_FLOAT_CONV:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_FLOAT_CONV, loc, size, srcCopy);
	}
	case MLIL_ROUND_TO_INT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_ROUND_TO_INT, loc, size, srcCopy);
	}
	case MLIL_FLOOR:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_FLOOR, loc, size, srcCopy);
	}
	case MLIL_CEIL:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_CEIL, loc, size, srcCopy);
	}
	case MLIL_FTRUNC:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_FTRUNC, loc, size, srcCopy);
	}
	case MLIL_FCMP_E:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FCMP_E, loc, size, leftCopy, rightCopy);
	}
	case MLIL_FCMP_NE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FCMP_NE, loc, size, leftCopy, rightCopy);
	}
	case MLIL_FCMP_LT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FCMP_LT, loc, size, leftCopy, rightCopy);
	}
	case MLIL_FCMP_LE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FCMP_LE, loc, size, leftCopy, rightCopy);
	}
	case MLIL_FCMP_GE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FCMP_GE, loc, size, leftCopy, rightCopy);
	}
	case MLIL_FCMP_GT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FCMP_GT, loc, size, leftCopy, rightCopy);
	}
	case MLIL_FCMP_O:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FCMP_O, loc, size, leftCopy, rightCopy);
	}
	case MLIL_FCMP_UO:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_FCMP_UO, loc, size, leftCopy, rightCopy);
	}
	case MLIL_SET_VAR_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    MLIL_SET_VAR_SSA, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1), srcCopy);
	}
	case MLIL_SET_VAR_SSA_FIELD:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(4));
		return dest->AddExprWithLocation(MLIL_SET_VAR_SSA_FIELD, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), GetRawOperandAsInteger(3), srcCopy);
	}
	case MLIL_SET_VAR_SPLIT_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(4));
		return dest->AddExprWithLocation(MLIL_SET_VAR_SPLIT_SSA, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), GetRawOperandAsInteger(3), srcCopy);
	}
	case MLIL_SET_VAR_ALIASED:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(3));
		return dest->AddExprWithLocation(MLIL_SET_VAR_ALIASED, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), srcCopy);
	}
	case MLIL_SET_VAR_ALIASED_FIELD:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(4));
		return dest->AddExprWithLocation(MLIL_SET_VAR_ALIASED_FIELD, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), GetRawOperandAsInteger(3), srcCopy);
	}
	case MLIL_VAR_SSA:
		return dest->AddExprWithLocation(MLIL_VAR_SSA, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case MLIL_VAR_SSA_FIELD:
		return dest->AddExprWithLocation(MLIL_VAR_SSA_FIELD, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	case MLIL_VAR_ALIASED:
		return dest->AddExprWithLocation(
		    MLIL_VAR_ALIASED, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case MLIL_VAR_ALIASED_FIELD:
		return dest->AddExprWithLocation(MLIL_VAR_ALIASED_FIELD, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	case MLIL_VAR_SPLIT_SSA:
		return dest->AddExprWithLocation(MLIL_VAR_SPLIT_SSA, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), GetRawOperandAsInteger(3));
	case MLIL_ASSERT_SSA:
		return dest->AddExprWithLocation(MLIL_ASSERT_SSA, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), dest->CachePossibleValueSet(GetRawOperandAsPossibleValueSet(2)));
	case MLIL_FORCE_VER_SSA:
		return dest->AddExprWithLocation(MLIL_FORCE_VER_SSA, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), GetRawOperandAsInteger(3), GetRawOperandAsInteger(4));
	case MLIL_CALL_SSA:
	{
		MediumLevelILInstruction outputExpr = GetRawOperandAsExpr(0);
		vector<ExprId> outputExprOutputExprsCopy;
		for (const auto& expr : outputExpr.GetRawOperandAsExprList(1))
			outputExprOutputExprsCopy.push_back(subExprHandler(expr));
		ExprId outputExprCopy =
		    dest->AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, outputExpr.size, outputExpr.GetRawOperandAsInteger(0),
		        outputExprOutputExprsCopy.size(), dest->AddOperandList(outputExprOutputExprsCopy));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(1));
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(2))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(MLIL_CALL_SSA, loc, size, outputExprCopy, destCopy, paramsCopy.size(),
		    dest->AddOperandList(paramsCopy), GetRawOperandAsInteger(4));
	}
	case MLIL_CALL_UNTYPED_SSA:
	{
		MediumLevelILInstruction outputExpr = GetRawOperandAsExpr(0);
		vector<ExprId> outputExprOutputExprsCopy;
		for (const auto& expr : outputExpr.GetRawOperandAsExprList(1))
			outputExprOutputExprsCopy.push_back(subExprHandler(expr));
		ExprId outputExprCopy =
		    dest->AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, outputExpr.size, outputExpr.GetRawOperandAsInteger(0),
		        outputExprOutputExprsCopy.size(), dest->AddOperandList(outputExprOutputExprsCopy));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(1));
		MediumLevelILInstruction param = GetRawOperandAsExpr(2);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(1))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(MLIL_CALL_PARAM_SSA, loc, param.size,
		    param.GetRawOperandAsInteger(0), paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		ExprId stackCopy = subExprHandler(GetRawOperandAsExpr(3));
		return dest->AddExprWithLocation(
		    MLIL_CALL_UNTYPED_SSA, loc, size, outputExprCopy, destCopy, paramCopy, stackCopy);
	}
	case MLIL_SYSCALL_SSA:
	{
		MediumLevelILInstruction outputExpr = GetRawOperandAsExpr(0);
		vector<ExprId> outputExprOutputExprsCopy;
		for (const auto& expr : outputExpr.GetRawOperandAsExprList(1))
			outputExprOutputExprsCopy.push_back(subExprHandler(expr));
		ExprId outputExprCopy =
		    dest->AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, outputExpr.size, outputExpr.GetRawOperandAsInteger(0),
		        outputExprOutputExprsCopy.size(), dest->AddOperandList(outputExprOutputExprsCopy));
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(1))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(MLIL_SYSCALL_SSA, loc, size, outputExprCopy, paramsCopy.size(),
		    dest->AddOperandList(paramsCopy), GetRawOperandAsInteger(3));
	}
	case MLIL_SYSCALL_UNTYPED_SSA:
	{
		MediumLevelILInstruction outputExpr = GetRawOperandAsExpr(0);
		vector<ExprId> outputExprOutputExprsCopy;
		for (const auto& expr : outputExpr.GetRawOperandAsExprList(1))
			outputExprOutputExprsCopy.push_back(subExprHandler(expr));
		ExprId outputExprCopy =
		    dest->AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, outputExpr.size, outputExpr.GetRawOperandAsInteger(0),
		        outputExprOutputExprsCopy.size(), dest->AddOperandList(outputExprOutputExprsCopy));
		MediumLevelILInstruction param = GetRawOperandAsExpr(1);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(1))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(MLIL_CALL_PARAM_SSA, loc, param.size,
		    param.GetRawOperandAsInteger(0), paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		ExprId stackCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(MLIL_SYSCALL_UNTYPED_SSA, loc, size, outputExprCopy, paramCopy, stackCopy);
	}
	case MLIL_TAILCALL_SSA:
	{
		MediumLevelILInstruction outputExpr = GetRawOperandAsExpr(0);
		vector<ExprId> outputExprOutputExprsCopy;
		for (const auto& expr : outputExpr.GetRawOperandAsExprList(1))
			outputExprOutputExprsCopy.push_back(subExprHandler(expr));
		ExprId outputExprCopy =
		    dest->AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, outputExpr.size, outputExpr.GetRawOperandAsInteger(0),
		        outputExprOutputExprsCopy.size(), dest->AddOperandList(outputExprOutputExprsCopy));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(1));
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(2))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(MLIL_TAILCALL_SSA, loc, size, outputExprCopy, destCopy, paramsCopy.size(),
		    dest->AddOperandList(paramsCopy), GetRawOperandAsInteger(4));
	}
	case MLIL_TAILCALL_UNTYPED_SSA:
	{
		MediumLevelILInstruction outputExpr = GetRawOperandAsExpr(0);
		vector<ExprId> outputExprOutputExprsCopy;
		for (const auto& expr : outputExpr.GetRawOperandAsExprList(1))
			outputExprOutputExprsCopy.push_back(subExprHandler(expr));
		ExprId outputExprCopy =
		    dest->AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, outputExpr.size, outputExpr.GetRawOperandAsInteger(0),
		        outputExprOutputExprsCopy.size(), dest->AddOperandList(outputExprOutputExprsCopy));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(1));
		MediumLevelILInstruction param = GetRawOperandAsExpr(2);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(1))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(MLIL_CALL_PARAM_SSA, loc, param.size,
		    param.GetRawOperandAsInteger(0), paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		ExprId stackCopy = subExprHandler(GetRawOperandAsExpr(3));
		return dest->AddExprWithLocation(
		    MLIL_TAILCALL_UNTYPED_SSA, loc, size, outputExprCopy, destCopy, paramCopy, stackCopy);
	}
	case MLIL_VAR_OUTPUT_SSA:
		return dest->AddExprWithLocation(
		    MLIL_VAR_OUTPUT_SSA, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case MLIL_VAR_OUTPUT_SSA_FIELD:
		return dest->AddExprWithLocation(MLIL_VAR_OUTPUT_SSA_FIELD, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), GetRawOperandAsInteger(3));
	case MLIL_VAR_OUTPUT_ALIASED:
		return dest->AddExprWithLocation(MLIL_VAR_OUTPUT_ALIASED, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	case MLIL_VAR_OUTPUT_ALIASED_FIELD:
		return dest->AddExprWithLocation(MLIL_VAR_OUTPUT_ALIASED_FIELD, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), GetRawOperandAsInteger(3));
	case MLIL_LOAD_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_LOAD_SSA, loc, size, srcCopy, GetRawOperandAsInteger(1));
	}
	case MLIL_LOAD_STRUCT_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(
		    MLIL_LOAD_STRUCT_SSA, loc, size, srcCopy, GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	}
	case MLIL_STORE_SSA:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(3));
		return dest->AddExprWithLocation(
		    MLIL_STORE_SSA, loc, size, destCopy, GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), srcCopy);
	}
	case MLIL_STORE_STRUCT_SSA:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(4));
		return dest->AddExprWithLocation(MLIL_STORE_STRUCT_SSA, loc, size, destCopy, GetRawOperandAsInteger(1),
		    GetRawOperandAsInteger(2), GetRawOperandAsInteger(3), srcCopy);
	}
	case MLIL_INTRINSIC_SSA:
	{
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(3))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(MLIL_INTRINSIC_SSA, loc, size, GetRawOperandAsInteger(0),
		    CopyOperandList(dest, *this, 0), GetRawOperandAsInteger(2), paramsCopy.size(),
		    dest->AddOperandList(paramsCopy));
	}
	case MLIL_MEMORY_INTRINSIC_SSA:
	{
		MediumLevelILInstruction outputExpr = GetRawOperandAsExpr(0);
		ExprId outputExprCopy = dest->AddExprWithLocation(MLIL_MEMORY_INTRINSIC_OUTPUT_SSA, loc, outputExpr.size,
		    outputExpr.GetRawOperandAsInteger(0), outputExpr.GetRawOperandAsInteger(1),
		    CopyOperandList(dest, outputExpr, 1));
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(2))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(MLIL_MEMORY_INTRINSIC_SSA, loc, size, outputExprCopy,
		    GetRawOperandAsInteger(1), paramsCopy.size(), dest->AddOperandList(paramsCopy), GetRawOperandAsInteger(4));
	}
	case MLIL_FREE_VAR_SLOT_SSA:
		return dest->AddExprWithLocation(MLIL_FREE_VAR_SLOT_SSA, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	case MLIL_VAR_PHI:
		return dest->AddExprWithLocation(MLIL_VAR_PHI, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1),
		    GetRawOperandAsInteger(2), CopyOperandList(dest, *this, 2));
	case MLIL_MEM_PHI:
		return dest->AddExprWithLocation(MLIL_MEM_PHI, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1),
		    CopyOperandList(dest, *this, 1));
	case MLIL_BLOCK_TO_EXPAND:
	{
		vector<ExprId> srcCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			srcCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(
		    MLIL_BLOCK_TO_EXPAND, loc, size, srcCopy.size(), dest->AddOperandList(srcCopy));
	}
	case MLIL_BSWAP:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_BSWAP, loc, size, srcCopy);
	}
	case MLIL_POPCNT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_POPCNT, loc, size, srcCopy);
	}
	case MLIL_CLZ:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_CLZ, loc, size, srcCopy);
	}
	case MLIL_CTZ:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_CTZ, loc, size, srcCopy);
	}
	case MLIL_RBIT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_RBIT, loc, size, srcCopy);
	}
	case MLIL_CLS:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_CLS, loc, size, srcCopy);
	}
	case MLIL_MINS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_MINS, loc, size, leftCopy, rightCopy);
	}
	case MLIL_MAXS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_MAXS, loc, size, leftCopy, rightCopy);
	}
	case MLIL_MINU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_MINU, loc, size, leftCopy, rightCopy);
	}
	case MLIL_MAXU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(MLIL_MAXU, loc, size, leftCopy, rightCopy);
	}
	case MLIL_ABS:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(MLIL_ABS, loc, size, srcCopy);
	}
	default:
		throw MediumLevelILInstructionAccessException();
	}
}
// END GENERATED mlil-copy


bool MediumLevelILInstruction::GetOperandIndexForUsage(MediumLevelILOperandUsage usage, size_t& operandIndex) const
{
	std::optional<MediumLevelILOperandLocation> location = OperandLocationForUsage(operation, usage);
	if (!location)
		return false;

	operandIndex = location->partial && !location->field ? location->slot + 2 : location->slot;
	return true;
}


// BEGIN GENERATED mlil-instruction-getters: from api/il, do not edit
MediumLevelILInstruction MediumLevelILInstruction::GetCarryExpr() const
{
	return OperandForUsages(*this, {CarryExprMediumLevelOperandUsage}).GetExpr();
}


MediumLevelILInstruction MediumLevelILInstruction::GetConditionExpr() const
{
	return OperandForUsages(*this, {ConditionExprMediumLevelOperandUsage}).GetExpr();
}


int64_t MediumLevelILInstruction::GetConstant() const
{
	return OperandForUsages(*this, {ConstantMediumLevelOperandUsage}).GetInteger();
}


ConstantData MediumLevelILInstruction::GetConstantData() const
{
	return OperandForUsages(*this, {ConstantDataMediumLevelOperandUsage}).GetConstantData();
}


PossibleValueSet MediumLevelILInstruction::GetConstraint() const
{
	return OperandForUsages(*this, {ConstraintMediumLevelOperandUsage}).GetConstraint();
}


MediumLevelILInstruction MediumLevelILInstruction::GetDestExpr() const
{
	return OperandForUsages(*this, {DestExprMediumLevelOperandUsage}).GetExpr();
}


size_t MediumLevelILInstruction::GetDestMemoryVersion() const
{
	return OperandForUsages(
	    *this, {OutputSSAMemoryVersionMediumLevelOperandUsage, DestMemoryVersionMediumLevelOperandUsage})
	    .GetIndex();
}


SSAVariable MediumLevelILInstruction::GetDestSSAVariable() const
{
	return OperandForUsages(*this, {DestSSAVariableMediumLevelOperandUsage}).GetSSAVariable();
}


Variable MediumLevelILInstruction::GetDestVariable() const
{
	return OperandForUsages(*this, {DestVariableMediumLevelOperandUsage}).GetVariable();
}


size_t MediumLevelILInstruction::GetFalseTarget() const
{
	return OperandForUsages(*this, {FalseTargetMediumLevelOperandUsage}).GetIndex();
}


BNForceVersionReason MediumLevelILInstruction::GetForceVersionReason() const
{
	return OperandForUsages(*this, {ForceVersionReasonMediumLevelOperandUsage}).GetForceVersionReason();
}


SSAVariable MediumLevelILInstruction::GetHighSSAVariable() const
{
	return OperandForUsages(*this, {HighSSAVariableMediumLevelOperandUsage}).GetSSAVariable();
}


Variable MediumLevelILInstruction::GetHighVariable() const
{
	return OperandForUsages(*this, {HighVariableMediumLevelOperandUsage}).GetVariable();
}


uint32_t MediumLevelILInstruction::GetIntrinsic() const
{
	return OperandForUsages(*this, {IntrinsicMediumLevelOperandUsage}).GetIntrinsic();
}


MediumLevelILInstruction MediumLevelILInstruction::GetLeftExpr() const
{
	return OperandForUsages(*this, {LeftExprMediumLevelOperandUsage}).GetExpr();
}


SSAVariable MediumLevelILInstruction::GetLowSSAVariable() const
{
	return OperandForUsages(*this, {LowSSAVariableMediumLevelOperandUsage}).GetSSAVariable();
}


Variable MediumLevelILInstruction::GetLowVariable() const
{
	return OperandForUsages(*this, {LowVariableMediumLevelOperandUsage}).GetVariable();
}


uint64_t MediumLevelILInstruction::GetOffset() const
{
	return OperandForUsages(*this, {OffsetMediumLevelOperandUsage}).GetInteger();
}


MediumLevelILInstructionList MediumLevelILInstruction::GetOutputExprs() const
{
	return OperandForUsages(*this, {OutputExprsMediumLevelOperandUsage, OutputExprsSubExprMediumLevelOperandUsage})
	    .GetExprList();
}


vector<SSAVariable> MediumLevelILInstruction::GetOutputSSAVariables() const
{
	switch (operation)
	{
	case MLIL_CALL_SSA:
		return GetOutputSSAVariables<MLIL_CALL_SSA>();
	case MLIL_CALL_UNTYPED_SSA:
		return GetOutputSSAVariables<MLIL_CALL_UNTYPED_SSA>();
	case MLIL_SYSCALL_SSA:
		return GetOutputSSAVariables<MLIL_SYSCALL_SSA>();
	case MLIL_SYSCALL_UNTYPED_SSA:
		return GetOutputSSAVariables<MLIL_SYSCALL_UNTYPED_SSA>();
	case MLIL_TAILCALL_SSA:
		return GetOutputSSAVariables<MLIL_TAILCALL_SSA>();
	case MLIL_TAILCALL_UNTYPED_SSA:
		return GetOutputSSAVariables<MLIL_TAILCALL_UNTYPED_SSA>();
	default:
		return OperandForUsages(
		    *this, {OutputSSAVariablesMediumLevelOperandUsage, OutputSSAVariablesSubExprMediumLevelOperandUsage})
		    .GetSSAVariableList();
	}
}


vector<Variable> MediumLevelILInstruction::GetOutputVariables() const
{
	switch (operation)
	{
	case MLIL_CALL:
		return GetOutputVariables<MLIL_CALL>();
	case MLIL_CALL_UNTYPED:
		return GetOutputVariables<MLIL_CALL_UNTYPED>();
	case MLIL_SYSCALL:
		return GetOutputVariables<MLIL_SYSCALL>();
	case MLIL_SYSCALL_UNTYPED:
		return GetOutputVariables<MLIL_SYSCALL_UNTYPED>();
	case MLIL_TAILCALL:
		return GetOutputVariables<MLIL_TAILCALL>();
	case MLIL_TAILCALL_UNTYPED:
		return GetOutputVariables<MLIL_TAILCALL_UNTYPED>();
	default:
		return OperandForUsages(*this, {OutputVariablesMediumLevelOperandUsage}).GetVariableList();
	}
}


MediumLevelILInstructionList MediumLevelILInstruction::GetParameterExprs() const
{
	return OperandForUsages(*this, {ParameterExprsMediumLevelOperandUsage, UntypedParameterExprsMediumLevelOperandUsage,
	                                   UntypedParameterSSAExprsMediumLevelOperandUsage})
	    .GetExprList();
}


MediumLevelILInstruction MediumLevelILInstruction::GetRightExpr() const
{
	return OperandForUsages(*this, {RightExprMediumLevelOperandUsage}).GetExpr();
}


MediumLevelILInstruction MediumLevelILInstruction::GetSourceExpr() const
{
	return OperandForUsages(*this, {SourceExprMediumLevelOperandUsage}).GetExpr();
}


MediumLevelILInstructionList MediumLevelILInstruction::GetSourceExprs() const
{
	return OperandForUsages(*this, {SourceExprsMediumLevelOperandUsage}).GetExprList();
}


size_t MediumLevelILInstruction::GetSourceMemoryVersion() const
{
	return OperandForUsages(
	    *this, {SourceMemoryVersionMediumLevelOperandUsage, ParameterSSAMemoryVersionMediumLevelOperandUsage})
	    .GetIndex();
}


MediumLevelILIndexList MediumLevelILInstruction::GetSourceMemoryVersions() const
{
	return OperandForUsages(*this, {SourceMemoryVersionsMediumLevelOperandUsage}).GetIndexList();
}


SSAVariable MediumLevelILInstruction::GetSourceSSAVariable() const
{
	return OperandForUsages(
	    *this, {PartialSSAVariableSourceMediumLevelOperandUsage, SourceSSAVariableMediumLevelOperandUsage})
	    .GetSSAVariable();
}


MediumLevelILSSAVariableList MediumLevelILInstruction::GetSourceSSAVariables() const
{
	return OperandForUsages(*this, {SourceSSAVariablesMediumLevelOperandUsage}).GetSSAVariableList();
}


Variable MediumLevelILInstruction::GetSourceVariable() const
{
	return OperandForUsages(*this, {SourceVariableMediumLevelOperandUsage}).GetVariable();
}


MediumLevelILInstruction MediumLevelILInstruction::GetStackExpr() const
{
	return OperandForUsages(*this, {StackExprMediumLevelOperandUsage}).GetExpr();
}


size_t MediumLevelILInstruction::GetTarget() const
{
	return OperandForUsages(*this, {TargetMediumLevelOperandUsage}).GetIndex();
}


MediumLevelILIndexMap MediumLevelILInstruction::GetTargets() const
{
	return OperandForUsages(*this, {TargetsMediumLevelOperandUsage}).GetIndexMap();
}


size_t MediumLevelILInstruction::GetTrueTarget() const
{
	return OperandForUsages(*this, {TrueTargetMediumLevelOperandUsage}).GetIndex();
}


int64_t MediumLevelILInstruction::GetVector() const
{
	return OperandForUsages(*this, {VectorMediumLevelOperandUsage}).GetInteger();
}


bool MediumLevelILInstruction::IsUnknown() const
{
	switch (operation)
	{
	case MLIL_UNIMPL:
		return IsUnknown<MLIL_UNIMPL>();
	case MLIL_UNIMPL_MEM:
		return IsUnknown<MLIL_UNIMPL_MEM>();
	default:
		throw MediumLevelILInstructionAccessException();
	}
}
// END GENERATED mlil-instruction-getters


vector<Variable> MediumLevelILCallInstruction::GetOutputVariables() const
{
	vector<Variable> result;
	for (auto i : GetOutputExprs())
	{
		if (i.operation == MLIL_VAR_OUTPUT)
			result.push_back(i.GetDestVariable<MLIL_VAR_OUTPUT>());
		else if (i.operation == MLIL_VAR_OUTPUT_FIELD)
			result.push_back(i.GetDestVariable<MLIL_VAR_OUTPUT_FIELD>());
		else if (i.operation == MLIL_RETURN_BY_REF && i.GetSourceExpr<MLIL_RETURN_BY_REF>().operation == MLIL_VAR_OUTPUT)
			result.push_back(i.GetSourceExpr<MLIL_RETURN_BY_REF>().GetDestVariable<MLIL_VAR_OUTPUT>());
		else if (i.operation == MLIL_RETURN_BY_REF && i.GetSourceExpr<MLIL_RETURN_BY_REF>().operation == MLIL_VAR_OUTPUT_FIELD)
			result.push_back(i.GetSourceExpr<MLIL_RETURN_BY_REF>().GetDestVariable<MLIL_VAR_OUTPUT_FIELD>());
	}
	return result;
}


vector<SSAVariable> MediumLevelILCallSSAInstruction::GetOutputSSAVariables() const
{
	vector<SSAVariable> result;
	for (auto i : GetOutputExprs())
	{
		if (i.operation == MLIL_RETURN_BY_REF)
			i = i.GetSourceExpr<MLIL_RETURN_BY_REF>();
		switch (i.operation)
		{
		case MLIL_VAR_OUTPUT_SSA:
			result.push_back(i.GetDestSSAVariable<MLIL_VAR_OUTPUT_SSA>());
			break;
		case MLIL_VAR_OUTPUT_SSA_FIELD:
			result.push_back(i.GetDestSSAVariable<MLIL_VAR_OUTPUT_SSA_FIELD>());
			break;
		case MLIL_VAR_OUTPUT_ALIASED:
			result.push_back(i.GetDestSSAVariable<MLIL_VAR_OUTPUT_ALIASED>());
			break;
		case MLIL_VAR_OUTPUT_ALIASED_FIELD:
			result.push_back(i.GetDestSSAVariable<MLIL_VAR_OUTPUT_ALIASED_FIELD>());
			break;
		default:
			break;
		}
	}
	return result;
}


// BEGIN GENERATED mlil-builders: from api/il, do not edit
ExprId MediumLevelILFunction::Nop(const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_NOP, loc, 0);
}


ExprId MediumLevelILFunction::SetVar(size_t size, const Variable& dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR, loc, size, dest.ToIdentifier(), src);
}


ExprId MediumLevelILFunction::SetVarField(
    size_t size, const Variable& dest, uint64_t offset, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_FIELD, loc, size, dest.ToIdentifier(), offset, src);
}


ExprId MediumLevelILFunction::SetVarSplit(
    size_t size, const Variable& high, const Variable& low, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_SPLIT, loc, size, high.ToIdentifier(), low.ToIdentifier(), src);
}


ExprId MediumLevelILFunction::Assert(
    size_t size, const Variable& src, const PossibleValueSet& constraint, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ASSERT, loc, size, src.ToIdentifier(), CachePossibleValueSet(constraint));
}


ExprId MediumLevelILFunction::ForceVer(
    size_t size, const Variable& dest, const Variable& src, BNForceVersionReason reason, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FORCE_VER, loc, size, dest.ToIdentifier(), src.ToIdentifier(), reason);
}


ExprId MediumLevelILFunction::Load(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LOAD, loc, size, src);
}


ExprId MediumLevelILFunction::LoadStruct(size_t size, ExprId src, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LOAD_STRUCT, loc, size, src, offset);
}


ExprId MediumLevelILFunction::Store(size_t size, ExprId dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_STORE, loc, size, dest, src);
}


ExprId MediumLevelILFunction::StoreStruct(
    size_t size, ExprId dest, uint64_t offset, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_STORE_STRUCT, loc, size, dest, offset, src);
}


ExprId MediumLevelILFunction::Var(size_t size, const Variable& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR, loc, size, src.ToIdentifier());
}


ExprId MediumLevelILFunction::VarField(size_t size, const Variable& src, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_FIELD, loc, size, src.ToIdentifier(), offset);
}


ExprId MediumLevelILFunction::VarSplit(
    size_t size, const Variable& high, const Variable& low, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_SPLIT, loc, size, high.ToIdentifier(), low.ToIdentifier());
}


ExprId MediumLevelILFunction::AddressOf(const Variable& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ADDRESS_OF, loc, 0, src.ToIdentifier());
}


ExprId MediumLevelILFunction::AddressOfField(const Variable& src, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ADDRESS_OF_FIELD, loc, 0, src.ToIdentifier(), offset);
}


ExprId MediumLevelILFunction::PassByRef(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_PASS_BY_REF, loc, size, src);
}


ExprId MediumLevelILFunction::ReturnByRef(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_RETURN_BY_REF, loc, size, src);
}


ExprId MediumLevelILFunction::Const(size_t size, uint64_t constant, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CONST, loc, size, constant);
}


ExprId MediumLevelILFunction::ConstData(size_t size, const ConstantData& constantData, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CONST_DATA, loc, size, constantData.state, constantData.value);
}


ExprId MediumLevelILFunction::ConstPointer(size_t size, uint64_t constant, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CONST_PTR, loc, size, constant);
}


ExprId MediumLevelILFunction::ExternPointer(
    size_t size, uint64_t constant, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_EXTERN_PTR, loc, size, constant, offset);
}


ExprId MediumLevelILFunction::FloatConstRaw(size_t size, uint64_t constant, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FLOAT_CONST, loc, size, constant);
}


ExprId MediumLevelILFunction::ImportedAddress(size_t size, uint64_t constant, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_IMPORT, loc, size, constant);
}


ExprId MediumLevelILFunction::Add(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ADD, loc, size, left, right);
}


ExprId MediumLevelILFunction::AddWithCarry(
    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ADC, loc, size, left, right, carry);
}


ExprId MediumLevelILFunction::Sub(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SUB, loc, size, left, right);
}


ExprId MediumLevelILFunction::SubWithBorrow(
    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc)
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


ExprId MediumLevelILFunction::ShiftLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LSL, loc, size, left, right);
}


ExprId MediumLevelILFunction::LogicalShiftRight(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LSR, loc, size, left, right);
}


ExprId MediumLevelILFunction::ArithShiftRight(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ASR, loc, size, left, right);
}


ExprId MediumLevelILFunction::RotateLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ROL, loc, size, left, right);
}


ExprId MediumLevelILFunction::RotateLeftCarry(
    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_RLC, loc, size, left, right, carry);
}


ExprId MediumLevelILFunction::RotateRight(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ROR, loc, size, left, right);
}


ExprId MediumLevelILFunction::RotateRightCarry(
    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_RRC, loc, size, left, right, carry);
}


ExprId MediumLevelILFunction::Mult(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MUL, loc, size, left, right);
}


ExprId MediumLevelILFunction::MultDoublePrecUnsigned(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MULU_DP, loc, size, left, right);
}


ExprId MediumLevelILFunction::MultDoublePrecSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MULS_DP, loc, size, left, right);
}


ExprId MediumLevelILFunction::DivUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_DIVU, loc, size, left, right);
}


ExprId MediumLevelILFunction::DivDoublePrecUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_DIVU_DP, loc, size, left, right);
}


ExprId MediumLevelILFunction::DivSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_DIVS, loc, size, left, right);
}


ExprId MediumLevelILFunction::DivDoublePrecSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_DIVS_DP, loc, size, left, right);
}


ExprId MediumLevelILFunction::ModUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MODU, loc, size, left, right);
}


ExprId MediumLevelILFunction::ModDoublePrecUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MODU_DP, loc, size, left, right);
}


ExprId MediumLevelILFunction::ModSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MODS, loc, size, left, right);
}


ExprId MediumLevelILFunction::ModDoublePrecSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MODS_DP, loc, size, left, right);
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


ExprId MediumLevelILFunction::JumpTo(
    ExprId dest, const map<uint64_t, BNMediumLevelILLabel*>& targets, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_JUMP_TO, loc, 0, dest, targets.size() * 2, AddLabelMap(targets));
}


ExprId MediumLevelILFunction::ReturnHint(ExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_RET_HINT, loc, 0, dest);
}


ExprId MediumLevelILFunction::Call(
    const vector<ExprId>& outputExprs, ExprId dest, const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CALL, loc, 0, outputExprs.size(), AddOperandList(outputExprs), dest, params.size(),
	    AddOperandList(params));
}


ExprId MediumLevelILFunction::CallUntyped(const vector<ExprId>& outputExprs, ExprId dest, const vector<ExprId>& params,
    ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CALL_UNTYPED, loc, 0, outputExprs.size(), AddOperandList(outputExprs), dest,
	    AddExprWithLocation(MLIL_CALL_PARAM, loc, 0, params.size(), AddOperandList(params)), stack);
}


ExprId MediumLevelILFunction::SeparateParamList(const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SEPARATE_PARAM_LIST, loc, 0, params.size(), AddOperandList(params));
}


ExprId MediumLevelILFunction::SharedParamSlot(const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SHARED_PARAM_SLOT, loc, 0, params.size(), AddOperandList(params));
}


ExprId MediumLevelILFunction::VarOutput(size_t size, const Variable& dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_OUTPUT, loc, size, dest.ToIdentifier());
}


ExprId MediumLevelILFunction::VarOutputField(
    size_t size, const Variable& dest, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_OUTPUT_FIELD, loc, size, dest.ToIdentifier(), offset);
}


ExprId MediumLevelILFunction::StoreOutput(size_t size, ExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_STORE_OUTPUT, loc, size, dest);
}


ExprId MediumLevelILFunction::Return(const vector<ExprId>& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_RET, loc, 0, src.size(), AddOperandList(src));
}


ExprId MediumLevelILFunction::NoReturn(const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_NORET, loc, 0);
}


ExprId MediumLevelILFunction::CompareEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_E, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareNotEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_NE, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareSignedLessThan(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_SLT, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareUnsignedLessThan(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_ULT, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareSignedLessEqual(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_SLE, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareUnsignedLessEqual(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_ULE, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareSignedGreaterEqual(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_SGE, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareUnsignedGreaterEqual(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_UGE, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareSignedGreaterThan(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_SGT, loc, size, left, right);
}


ExprId MediumLevelILFunction::CompareUnsignedGreaterThan(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CMP_UGT, loc, size, left, right);
}


ExprId MediumLevelILFunction::TestBit(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TEST_BIT, loc, size, left, right);
}


ExprId MediumLevelILFunction::BoolToInt(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_BOOL_TO_INT, loc, size, src);
}


ExprId MediumLevelILFunction::AddOverflow(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ADD_OVERFLOW, loc, size, left, right);
}


ExprId MediumLevelILFunction::Syscall(
    const vector<ExprId>& outputExprs, const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    MLIL_SYSCALL, loc, 0, outputExprs.size(), AddOperandList(outputExprs), params.size(), AddOperandList(params));
}


ExprId MediumLevelILFunction::SyscallUntyped(
    const vector<ExprId>& outputExprs, const vector<ExprId>& params, ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SYSCALL_UNTYPED, loc, 0, outputExprs.size(), AddOperandList(outputExprs),
	    AddExprWithLocation(MLIL_CALL_PARAM, loc, 0, params.size(), AddOperandList(params)), stack);
}


ExprId MediumLevelILFunction::TailCall(
    const vector<ExprId>& outputExprs, ExprId dest, const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TAILCALL, loc, 0, outputExprs.size(), AddOperandList(outputExprs), dest,
	    params.size(), AddOperandList(params));
}


ExprId MediumLevelILFunction::TailCallUntyped(const vector<ExprId>& outputExprs, ExprId dest,
    const vector<ExprId>& params, ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TAILCALL_UNTYPED, loc, 0, outputExprs.size(), AddOperandList(outputExprs), dest,
	    AddExprWithLocation(MLIL_CALL_PARAM, loc, 0, params.size(), AddOperandList(params)), stack);
}


ExprId MediumLevelILFunction::Intrinsic(
    const vector<Variable>& output, uint32_t intrinsic, const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_INTRINSIC, loc, 0, output.size(), AddVariableList(output), intrinsic, params.size(),
	    AddOperandList(params));
}


ExprId MediumLevelILFunction::FreeVarSlot(const Variable& dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FREE_VAR_SLOT, loc, 0, dest.ToIdentifier());
}


ExprId MediumLevelILFunction::Breakpoint(const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_BP, loc, 0);
}


ExprId MediumLevelILFunction::Trap(int64_t vector, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TRAP, loc, 0, vector);
}


ExprId MediumLevelILFunction::Undefined(const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_UNDEF, loc, 0);
}


ExprId MediumLevelILFunction::Unimplemented(const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_UNIMPL, loc, 0, 0);
}


ExprId MediumLevelILFunction::Unknown(const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_UNIMPL, loc, 0, 1);
}


ExprId MediumLevelILFunction::UnimplementedMemoryRef(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_UNIMPL_MEM, loc, size, src, 0);
}


ExprId MediumLevelILFunction::UnknownMemoryRef(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_UNIMPL_MEM, loc, size, src, 1);
}


ExprId MediumLevelILFunction::FloatAdd(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FADD, loc, size, left, right);
}


ExprId MediumLevelILFunction::FloatSub(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FSUB, loc, size, left, right);
}


ExprId MediumLevelILFunction::FloatMult(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FMUL, loc, size, left, right);
}


ExprId MediumLevelILFunction::FloatDiv(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FDIV, loc, size, left, right);
}


ExprId MediumLevelILFunction::FloatSqrt(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FSQRT, loc, size, src);
}


ExprId MediumLevelILFunction::FloatNeg(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FNEG, loc, size, src);
}


ExprId MediumLevelILFunction::FloatAbs(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FABS, loc, size, src);
}


ExprId MediumLevelILFunction::FloatToInt(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FLOAT_TO_INT, loc, size, src);
}


ExprId MediumLevelILFunction::IntToFloat(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_INT_TO_FLOAT, loc, size, src);
}


ExprId MediumLevelILFunction::FloatConvert(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FLOAT_CONV, loc, size, src);
}


ExprId MediumLevelILFunction::RoundToInt(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ROUND_TO_INT, loc, size, src);
}


ExprId MediumLevelILFunction::Floor(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FLOOR, loc, size, src);
}


ExprId MediumLevelILFunction::Ceil(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CEIL, loc, size, src);
}


ExprId MediumLevelILFunction::FloatTrunc(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FTRUNC, loc, size, src);
}


ExprId MediumLevelILFunction::FloatCompareEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_E, loc, size, left, right);
}


ExprId MediumLevelILFunction::FloatCompareNotEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_NE, loc, size, left, right);
}


ExprId MediumLevelILFunction::FloatCompareLessThan(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_LT, loc, size, left, right);
}


ExprId MediumLevelILFunction::FloatCompareLessEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_LE, loc, size, left, right);
}


ExprId MediumLevelILFunction::FloatCompareGreaterEqual(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_GE, loc, size, left, right);
}


ExprId MediumLevelILFunction::FloatCompareGreaterThan(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_GT, loc, size, left, right);
}


ExprId MediumLevelILFunction::FloatCompareOrdered(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_O, loc, size, left, right);
}


ExprId MediumLevelILFunction::FloatCompareUnordered(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FCMP_UO, loc, size, left, right);
}


ExprId MediumLevelILFunction::SetVarSSA(size_t size, const SSAVariable& dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_SSA, loc, size, dest.var.ToIdentifier(), dest.version, src);
}


ExprId MediumLevelILFunction::SetVarSSAField(size_t size, const Variable& var, size_t destVersion, size_t prevVersion,
    uint64_t offset, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    MLIL_SET_VAR_SSA_FIELD, loc, size, var.ToIdentifier(), destVersion, prevVersion, offset, src);
}


ExprId MediumLevelILFunction::SetVarSSASplit(
    size_t size, const SSAVariable& high, const SSAVariable& low, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_SPLIT_SSA, loc, size, high.var.ToIdentifier(), high.version,
	    low.var.ToIdentifier(), low.version, src);
}


ExprId MediumLevelILFunction::SetVarAliased(
    size_t size, const Variable& var, size_t destMemory, size_t prevMemory, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SET_VAR_ALIASED, loc, size, var.ToIdentifier(), destMemory, prevMemory, src);
}


ExprId MediumLevelILFunction::SetVarAliasedField(size_t size, const Variable& var, size_t destMemory, size_t prevMemory,
    uint64_t offset, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    MLIL_SET_VAR_ALIASED_FIELD, loc, size, var.ToIdentifier(), destMemory, prevMemory, offset, src);
}


ExprId MediumLevelILFunction::VarSSA(size_t size, const SSAVariable& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_SSA, loc, size, src.var.ToIdentifier(), src.version);
}


ExprId MediumLevelILFunction::VarSSAField(
    size_t size, const SSAVariable& src, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_SSA_FIELD, loc, size, src.var.ToIdentifier(), src.version, offset);
}


ExprId MediumLevelILFunction::VarAliased(
    size_t size, const Variable& var, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_ALIASED, loc, size, var.ToIdentifier(), srcMemory);
}


ExprId MediumLevelILFunction::VarAliasedField(
    size_t size, const Variable& var, size_t srcMemory, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_ALIASED_FIELD, loc, size, var.ToIdentifier(), srcMemory, offset);
}


ExprId MediumLevelILFunction::VarSplitSSA(
    size_t size, const SSAVariable& high, const SSAVariable& low, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    MLIL_VAR_SPLIT_SSA, loc, size, high.var.ToIdentifier(), high.version, low.var.ToIdentifier(), low.version);
}


ExprId MediumLevelILFunction::AssertSSA(
    size_t size, const SSAVariable& src, const PossibleValueSet& constraint, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    MLIL_ASSERT_SSA, loc, size, src.var.ToIdentifier(), src.version, CachePossibleValueSet(constraint));
}


ExprId MediumLevelILFunction::ForceVerSSA(size_t size, const SSAVariable& dest, const SSAVariable& src,
    BNForceVersionReason reason, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FORCE_VER_SSA, loc, size, dest.var.ToIdentifier(), dest.version,
	    src.var.ToIdentifier(), src.version, reason);
}


ExprId MediumLevelILFunction::CallSSA(const vector<ExprId>& outputExprs, ExprId dest, const vector<ExprId>& params,
    size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CALL_SSA, loc, 0,
	    AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, destMemory, outputExprs.size(), AddOperandList(outputExprs)),
	    dest, params.size(), AddOperandList(params), srcMemory);
}


ExprId MediumLevelILFunction::CallUntypedSSA(const vector<ExprId>& outputExprs, ExprId dest,
    const vector<ExprId>& params, size_t destMemory, size_t srcMemory, ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CALL_UNTYPED_SSA, loc, 0,
	    AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, destMemory, outputExprs.size(), AddOperandList(outputExprs)),
	    dest, AddExprWithLocation(MLIL_CALL_PARAM_SSA, loc, 0, srcMemory, params.size(), AddOperandList(params)),
	    stack);
}


ExprId MediumLevelILFunction::SyscallSSA(const vector<ExprId>& outputExprs, const vector<ExprId>& params,
    size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SYSCALL_SSA, loc, 0,
	    AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, destMemory, outputExprs.size(), AddOperandList(outputExprs)),
	    params.size(), AddOperandList(params), srcMemory);
}


ExprId MediumLevelILFunction::SyscallUntypedSSA(const vector<ExprId>& outputExprs, const vector<ExprId>& params,
    size_t destMemory, size_t srcMemory, ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_SYSCALL_UNTYPED_SSA, loc, 0,
	    AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, destMemory, outputExprs.size(), AddOperandList(outputExprs)),
	    AddExprWithLocation(MLIL_CALL_PARAM_SSA, loc, 0, srcMemory, params.size(), AddOperandList(params)), stack);
}


ExprId MediumLevelILFunction::TailCallSSA(const vector<ExprId>& outputExprs, ExprId dest, const vector<ExprId>& params,
    size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TAILCALL_SSA, loc, 0,
	    AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, destMemory, outputExprs.size(), AddOperandList(outputExprs)),
	    dest, params.size(), AddOperandList(params), srcMemory);
}


ExprId MediumLevelILFunction::TailCallUntypedSSA(const vector<ExprId>& outputExprs, ExprId dest,
    const vector<ExprId>& params, size_t destMemory, size_t srcMemory, ExprId stack, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_TAILCALL_UNTYPED_SSA, loc, 0,
	    AddExprWithLocation(MLIL_CALL_OUTPUT_SSA, loc, 0, destMemory, outputExprs.size(), AddOperandList(outputExprs)),
	    dest, AddExprWithLocation(MLIL_CALL_PARAM_SSA, loc, 0, srcMemory, params.size(), AddOperandList(params)),
	    stack);
}


ExprId MediumLevelILFunction::VarOutputSSA(size_t size, const SSAVariable& dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_OUTPUT_SSA, loc, size, dest.var.ToIdentifier(), dest.version);
}


ExprId MediumLevelILFunction::VarOutputSSAField(size_t size, const Variable& var, size_t destVersion,
    size_t prevVersion, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    MLIL_VAR_OUTPUT_SSA_FIELD, loc, size, var.ToIdentifier(), destVersion, prevVersion, offset);
}


ExprId MediumLevelILFunction::VarOutputAliased(
    size_t size, const Variable& var, size_t destMemory, size_t prevMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_VAR_OUTPUT_ALIASED, loc, size, var.ToIdentifier(), destMemory, prevMemory);
}


ExprId MediumLevelILFunction::VarOutputAliasedField(size_t size, const Variable& var, size_t destMemory,
    size_t prevMemory, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    MLIL_VAR_OUTPUT_ALIASED_FIELD, loc, size, var.ToIdentifier(), destMemory, prevMemory, offset);
}


ExprId MediumLevelILFunction::LoadSSA(size_t size, ExprId src, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LOAD_SSA, loc, size, src, srcMemory);
}


ExprId MediumLevelILFunction::LoadStructSSA(
    size_t size, ExprId src, uint64_t offset, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_LOAD_STRUCT_SSA, loc, size, src, offset, srcMemory);
}


ExprId MediumLevelILFunction::StoreSSA(
    size_t size, ExprId dest, size_t destMemory, size_t srcMemory, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_STORE_SSA, loc, size, dest, destMemory, srcMemory, src);
}


ExprId MediumLevelILFunction::StoreStructSSA(size_t size, ExprId dest, uint64_t offset, size_t destMemory,
    size_t srcMemory, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_STORE_STRUCT_SSA, loc, size, dest, offset, destMemory, srcMemory, src);
}


ExprId MediumLevelILFunction::IntrinsicSSA(
    const vector<SSAVariable>& output, uint32_t intrinsic, const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_INTRINSIC_SSA, loc, 0, output.size() * 2, AddSSAVariableList(output), intrinsic,
	    params.size(), AddOperandList(params));
}


ExprId MediumLevelILFunction::MemoryIntrinsicSSA(const vector<SSAVariable>& output, uint32_t intrinsic,
    const vector<ExprId>& params, size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MEMORY_INTRINSIC_SSA, loc, 0,
	    AddExprWithLocation(
	        MLIL_MEMORY_INTRINSIC_OUTPUT_SSA, loc, 0, destMemory, output.size() * 2, AddSSAVariableList(output)),
	    intrinsic, params.size(), AddOperandList(params), srcMemory);
}


ExprId MediumLevelILFunction::FreeVarSlotSSA(
    const Variable& var, size_t destVersion, size_t prevVersion, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_FREE_VAR_SLOT_SSA, loc, 0, var.ToIdentifier(), destVersion, prevVersion);
}


ExprId MediumLevelILFunction::VarPhi(
    const SSAVariable& dest, const vector<SSAVariable>& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    MLIL_VAR_PHI, loc, 0, dest.var.ToIdentifier(), dest.version, src.size() * 2, AddSSAVariableList(src));
}


ExprId MediumLevelILFunction::MemoryPhi(size_t destMemory, const vector<size_t>& srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MEM_PHI, loc, 0, destMemory, srcMemory.size(), AddIndexList(srcMemory));
}


ExprId MediumLevelILFunction::BlockToExpand(const vector<ExprId>& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_BLOCK_TO_EXPAND, loc, 0, src.size(), AddOperandList(src));
}


ExprId MediumLevelILFunction::ByteSwap(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_BSWAP, loc, size, src);
}


ExprId MediumLevelILFunction::PopulationCount(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_POPCNT, loc, size, src);
}


ExprId MediumLevelILFunction::CountLeadingZeros(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CLZ, loc, size, src);
}


ExprId MediumLevelILFunction::CountTrailingZeros(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CTZ, loc, size, src);
}


ExprId MediumLevelILFunction::ReverseBits(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_RBIT, loc, size, src);
}


ExprId MediumLevelILFunction::CountLeadingSigns(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_CLS, loc, size, src);
}


ExprId MediumLevelILFunction::MinSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MINS, loc, size, left, right);
}


ExprId MediumLevelILFunction::MaxSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MAXS, loc, size, left, right);
}


ExprId MediumLevelILFunction::MinUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MINU, loc, size, left, right);
}


ExprId MediumLevelILFunction::MaxUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_MAXU, loc, size, left, right);
}


ExprId MediumLevelILFunction::AbsoluteValue(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(MLIL_ABS, loc, size, src);
}
// END GENERATED mlil-builders


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


fmt::format_context::iterator fmt::formatter<MediumLevelILInstruction>::format(const MediumLevelILInstruction& obj, format_context& ctx) const
{
	if (!obj.function)
		return fmt::format_to(ctx.out(), "<uninit>");

	vector<InstructionTextToken> tokens;
#ifdef BINARYNINJACORE_LIBRARY
	bool success = obj.function->GetExprText(obj.function->GetFunction(), obj.function->GetArchitecture(), obj, tokens, new DisassemblySettings());
#else
	bool success = obj.function->GetExprText(obj.function->GetArchitecture(), obj.exprIndex, tokens);
#endif
	if (success)
	{
		string text;
		if (presentation == '?')
		{
			fmt::format_to(ctx.out(), "{} ", obj.operation);
			fmt::format_to(ctx.out(), "@ {:#x} ", obj.address);
			if (obj.exprIndex != BN_INVALID_EXPR && (obj.exprIndex & 0xffff000000000000) == 0)
			{
				fmt::format_to(ctx.out(), "[expr {}] ", obj.exprIndex);
			}
			if (obj.instructionIndex != BN_INVALID_EXPR && (obj.instructionIndex & 0xffff000000000000) == 0)
			{
				fmt::format_to(ctx.out(), "[instr {}] ", obj.instructionIndex);
			}
			Ref<Type> type = obj.GetType().GetValue();
			if (type)
			{
				fmt::format_to(ctx.out(), "[type: {}] ", type->GetString());
			}
		}

		for (auto& token: tokens)
		{
			fmt::format_to(ctx.out(), "{}", token.text);
		}
	}
	else
	{
		fmt::format_to(ctx.out(), "???");
	}
	return ctx.out();
}
