// Copyright (c) 2019-2026 Vector 35 Inc
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
	#include "highlevelilfunction.h"
	#include "highlevelilssafunction.h"
	#include "mediumlevelilfunction.h"
	#include "mediumlevelilssafunction.h"
using namespace BinaryNinjaCore;
#else
	#include "binaryninjaapi.h"
	#include "highlevelilinstruction.h"
	#include "mediumlevelilinstruction.h"
using namespace BinaryNinja;
#endif

#ifndef BINARYNINJACORE_LIBRARY
using namespace std;
#endif

namespace {

struct OperandUsageType
{
	HighLevelILOperandUsage usage;
	HighLevelILOperandType type;

	constexpr auto operator<=>(const OperandUsageType& other) const
	{
		return usage <=> other.usage;
	}
};

// BEGIN GENERATED hlil-operand-tables: from api/il, do not edit
static constexpr std::array s_operandTypeForUsage = {
	OperandUsageType{BlockExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{ConditionExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{TrueExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{FalseExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{LoopExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{InitExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{UpdateExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{DefaultExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{CasesHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{ValueExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{DestExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{SourceExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{TargetHighLevelOperandUsage, IndexHighLevelOperand},
	OperandUsageType{VariableHighLevelOperandUsage, VariableHighLevelOperand},
	OperandUsageType{DestVariableHighLevelOperandUsage, VariableHighLevelOperand},
	OperandUsageType{SourceExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{DestExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{ConstraintHighLevelOperandUsage, ConstraintHighLevelOperand},
	OperandUsageType{OffsetHighLevelOperandUsage, IntegerHighLevelOperand},
	OperandUsageType{MemberIndexHighLevelOperandUsage, IndexHighLevelOperand},
	OperandUsageType{IndexExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{HighExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{LowExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{ConstantHighLevelOperandUsage, IntegerHighLevelOperand},
	OperandUsageType{ConstantDataHighLevelOperandUsage, ConstantDataHighLevelOperand},
	OperandUsageType{LeftExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{RightExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{CarryExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{ParameterExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{IntrinsicHighLevelOperandUsage, IntrinsicHighLevelOperand},
	OperandUsageType{VectorHighLevelOperandUsage, IntegerHighLevelOperand},
	OperandUsageType{FieldExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{ConditionPhiExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{DestSSAVariableHighLevelOperandUsage, SSAVariableHighLevelOperand},
	OperandUsageType{DestMemoryVersionHighLevelOperandUsage, IndexHighLevelOperand},
	OperandUsageType{SourceMemoryVersionHighLevelOperandUsage, IndexHighLevelOperand},
	OperandUsageType{SSAVariableHighLevelOperandUsage, SSAVariableHighLevelOperand},
	OperandUsageType{PartialSSAVariableSourceHighLevelOperandUsage, SSAVariableHighLevelOperand},
	OperandUsageType{SourceSSAVariablesHighLevelOperandUsage, SSAVariableListHighLevelOperand},
	OperandUsageType{SourceMemoryVersionsHighLevelOperandUsage, IndexListHighLevelOperand},
};

static_assert(std::is_sorted(s_operandTypeForUsage.begin(), s_operandTypeForUsage.end()),
	"Operand type mapping array is not sorted by usage value");


constexpr inline HighLevelILOperandType OperandTypeForUsage(HighLevelILOperandUsage usage)
{
	if (static_cast<size_t>(usage) < s_operandTypeForUsage.size())
		return s_operandTypeForUsage[usage].type;

	throw HighLevelILInstructionAccessException();
}


static constexpr size_t MaxOperands = 5;
using OperandLocations = detail::ILInstructionOperandLocations<BNHighLevelILOperation, HighLevelILOperandLocation, MaxOperands>;

static constexpr std::array s_operandLocations = {
	OperandLocations{HLIL_NOP},
	OperandLocations{HLIL_BLOCK, {{BlockExprsHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_IF, {{ConditionExprHighLevelOperandUsage, 0}, {TrueExprHighLevelOperandUsage, 1}, {FalseExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_WHILE, {{ConditionExprHighLevelOperandUsage, 0}, {LoopExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_DO_WHILE, {{LoopExprHighLevelOperandUsage, 0}, {ConditionExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FOR, {{InitExprHighLevelOperandUsage, 0}, {ConditionExprHighLevelOperandUsage, 1}, {UpdateExprHighLevelOperandUsage, 2}, {LoopExprHighLevelOperandUsage, 3}}},
	OperandLocations{HLIL_SWITCH, {{ConditionExprHighLevelOperandUsage, 0}, {DefaultExprHighLevelOperandUsage, 1}, {CasesHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_CASE, {{ValueExprsHighLevelOperandUsage, 0}, {TrueExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_BREAK},
	OperandLocations{HLIL_CONTINUE},
	OperandLocations{HLIL_JUMP, {{DestExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_RET, {{SourceExprsHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_NORET},
	OperandLocations{HLIL_GOTO, {{TargetHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_LABEL, {{TargetHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_VAR_DECLARE, {{VariableHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_VAR_INIT, {{DestVariableHighLevelOperandUsage, 0}, {SourceExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_ASSIGN, {{DestExprHighLevelOperandUsage, 0}, {SourceExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_ASSIGN_UNPACK, {{DestExprsHighLevelOperandUsage, 0}, {SourceExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_FORCE_VER, {{DestVariableHighLevelOperandUsage, 0}, {VariableHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_ASSERT, {{VariableHighLevelOperandUsage, 0}, {ConstraintHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_VAR, {{VariableHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_STRUCT_FIELD, {{SourceExprHighLevelOperandUsage, 0}, {OffsetHighLevelOperandUsage, 1}, {MemberIndexHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_ARRAY_INDEX, {{SourceExprHighLevelOperandUsage, 0}, {IndexExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_SPLIT, {{HighExprHighLevelOperandUsage, 0}, {LowExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_DEREF, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_DEREF_FIELD, {{SourceExprHighLevelOperandUsage, 0}, {OffsetHighLevelOperandUsage, 1}, {MemberIndexHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_ADDRESS_OF, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_PASS_BY_REF, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_RETURN_BY_REF, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_CONST, {{ConstantHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_CONST_DATA, {{ConstantDataHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_CONST_PTR, {{ConstantHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_EXTERN_PTR, {{ConstantHighLevelOperandUsage, 0}, {OffsetHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FLOAT_CONST, {{ConstantHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_IMPORT, {{ConstantHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_ADD, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_ADC, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}, {CarryExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_SUB, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_SBB, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}, {CarryExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_AND, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_OR, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_XOR, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_LSL, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_LSR, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_ASR, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_ROL, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_RLC, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}, {CarryExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_ROR, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_RRC, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}, {CarryExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_MUL, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_MULU_DP, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_MULS_DP, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_DIVU, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_DIVU_DP, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_DIVS, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_DIVS_DP, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_MODU, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_MODU_DP, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_MODS, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_MODS_DP, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_NEG, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_NOT, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_SX, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_ZX, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_LOW_PART, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_CALL, {{DestExprHighLevelOperandUsage, 0}, {ParameterExprsHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_CMP_E, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_CMP_NE, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_CMP_SLT, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_CMP_ULT, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_CMP_SLE, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_CMP_ULE, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_CMP_SGE, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_CMP_UGE, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_CMP_SGT, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_CMP_UGT, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_TEST_BIT, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_BOOL_TO_INT, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_ADD_OVERFLOW, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_SYSCALL, {{ParameterExprsHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_TAILCALL, {{DestExprHighLevelOperandUsage, 0}, {ParameterExprsHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_INTRINSIC, {{IntrinsicHighLevelOperandUsage, 0}, {ParameterExprsHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_BP},
	OperandLocations{HLIL_TRAP, {{VectorHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_UNDEF},
	OperandLocations{HLIL_UNIMPL},
	OperandLocations{HLIL_UNIMPL_MEM, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_STRUCT_INIT, {{FieldExprsHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_STRUCT_INIT_FIELD, {{OffsetHighLevelOperandUsage, 0}, {MemberIndexHighLevelOperandUsage, 1}, {SourceExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_FADD, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FSUB, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FMUL, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FDIV, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FSQRT, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_FNEG, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_FABS, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_FLOAT_TO_INT, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_INT_TO_FLOAT, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_FLOAT_CONV, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_ROUND_TO_INT, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_FLOOR, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_CEIL, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_FTRUNC, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_FCMP_E, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FCMP_NE, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FCMP_LT, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FCMP_LE, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FCMP_GE, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FCMP_GT, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FCMP_O, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_FCMP_UO, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_UNREACHABLE},
	OperandLocations{HLIL_WHILE_SSA, {{ConditionPhiExprHighLevelOperandUsage, 0}, {ConditionExprHighLevelOperandUsage, 1}, {LoopExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_DO_WHILE_SSA, {{LoopExprHighLevelOperandUsage, 0}, {ConditionPhiExprHighLevelOperandUsage, 1}, {ConditionExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_FOR_SSA, {{InitExprHighLevelOperandUsage, 0}, {ConditionPhiExprHighLevelOperandUsage, 1}, {ConditionExprHighLevelOperandUsage, 2}, {UpdateExprHighLevelOperandUsage, 3}, {LoopExprHighLevelOperandUsage, 4}}},
	OperandLocations{HLIL_VAR_INIT_SSA, {{DestSSAVariableHighLevelOperandUsage, 0}, {SourceExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_ASSIGN_MEM_SSA, {{DestExprHighLevelOperandUsage, 0}, {DestMemoryVersionHighLevelOperandUsage, 1}, {SourceExprHighLevelOperandUsage, 2}, {SourceMemoryVersionHighLevelOperandUsage, 3}}},
	OperandLocations{HLIL_ASSIGN_UNPACK_MEM_SSA, {{DestExprsHighLevelOperandUsage, 0}, {DestMemoryVersionHighLevelOperandUsage, 2}, {SourceExprHighLevelOperandUsage, 3}, {SourceMemoryVersionHighLevelOperandUsage, 4}}},
	OperandLocations{HLIL_FORCE_VER_SSA, {{DestSSAVariableHighLevelOperandUsage, 0}, {SSAVariableHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_ASSERT_SSA, {{SSAVariableHighLevelOperandUsage, 0}, {ConstraintHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_VAR_SSA, {{SSAVariableHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_VAR_SSA_PARTIAL, {{DestSSAVariableHighLevelOperandUsage, 0}, {PartialSSAVariableSourceHighLevelOperandUsage, 0, true}}},
	OperandLocations{HLIL_ARRAY_INDEX_SSA, {{SourceExprHighLevelOperandUsage, 0}, {SourceMemoryVersionHighLevelOperandUsage, 1}, {IndexExprHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_DEREF_SSA, {{SourceExprHighLevelOperandUsage, 0}, {SourceMemoryVersionHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_DEREF_FIELD_SSA, {{SourceExprHighLevelOperandUsage, 0}, {SourceMemoryVersionHighLevelOperandUsage, 1}, {OffsetHighLevelOperandUsage, 2}, {MemberIndexHighLevelOperandUsage, 3}}},
	OperandLocations{HLIL_CALL_SSA, {{DestExprHighLevelOperandUsage, 0}, {ParameterExprsHighLevelOperandUsage, 1}, {DestMemoryVersionHighLevelOperandUsage, 3}, {SourceMemoryVersionHighLevelOperandUsage, 4}}},
	OperandLocations{HLIL_SYSCALL_SSA, {{ParameterExprsHighLevelOperandUsage, 0}, {DestMemoryVersionHighLevelOperandUsage, 2}, {SourceMemoryVersionHighLevelOperandUsage, 3}}},
	OperandLocations{HLIL_INTRINSIC_SSA, {{IntrinsicHighLevelOperandUsage, 0}, {ParameterExprsHighLevelOperandUsage, 1}, {DestMemoryVersionHighLevelOperandUsage, 3}, {SourceMemoryVersionHighLevelOperandUsage, 4}}},
	OperandLocations{HLIL_VAR_PHI, {{DestSSAVariableHighLevelOperandUsage, 0}, {SourceSSAVariablesHighLevelOperandUsage, 2}}},
	OperandLocations{HLIL_MEM_PHI, {{DestMemoryVersionHighLevelOperandUsage, 0}, {SourceMemoryVersionsHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_BSWAP, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_POPCNT, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_CLZ, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_CTZ, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_RBIT, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_CLS, {{SourceExprHighLevelOperandUsage, 0}}},
	OperandLocations{HLIL_MINS, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_MAXS, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_MINU, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_MAXU, {{LeftExprHighLevelOperandUsage, 0}, {RightExprHighLevelOperandUsage, 1}}},
	OperandLocations{HLIL_ABS, {{SourceExprHighLevelOperandUsage, 0}}},
};


VALIDATE_INSTRUCTION_ORDER(s_operandLocations);
// END GENERATED hlil-operand-tables


std::optional<HighLevelILOperandLocation> OperandLocationForUsage(
    BNHighLevelILOperation operation, HighLevelILOperandUsage usage)
{
	if (operation >= s_operandLocations.size())
		return std::nullopt;
	return s_operandLocations[operation].Find(usage);
}


// Returns the instruction's operand for the first of `usages` it reports.
HighLevelILOperand OperandForUsages(
    const HighLevelILInstruction& instr, std::initializer_list<HighLevelILOperandUsage> usages)
{
	for (HighLevelILOperandUsage usage : usages)
	{
		if (std::optional<HighLevelILOperandLocation> location = OperandLocationForUsage(instr.operation, usage))
			return HighLevelILOperand(instr, *location);
	}
	throw HighLevelILInstructionAccessException();
}

} // unnamed namespace


bool HighLevelILIntegerList::ListIterator::operator==(const ListIterator& a) const
{
	return count == a.count;
}


bool HighLevelILIntegerList::ListIterator::operator!=(const ListIterator& a) const
{
	return count != a.count;
}


bool HighLevelILIntegerList::ListIterator::operator<(const ListIterator& a) const
{
	return count > a.count;
}


HighLevelILIntegerList::ListIterator& HighLevelILIntegerList::ListIterator::operator++()
{
	count--;
	offset++;
	return *this;
}


uint64_t HighLevelILIntegerList::ListIterator::operator*()
{
#ifdef BINARYNINJACORE_LIBRARY
	return function->GetOperand(offset);
#else
	return BNHighLevelILGetOperand(function->GetObject(), offset);
#endif
}


HighLevelILIntegerList::HighLevelILIntegerList(
    HighLevelILFunction* func, size_t offset, size_t count)
{
	m_start.function = func;
	m_start.offset = offset;
	m_start.count = count;
}


HighLevelILIntegerList::const_iterator HighLevelILIntegerList::begin() const
{
	return m_start;
}


HighLevelILIntegerList::const_iterator HighLevelILIntegerList::end() const
{
	const_iterator result;
	result.function = m_start.function;
	result.offset = m_start.offset + m_start.count;
	result.count = 0;
	return result;
}


size_t HighLevelILIntegerList::size() const
{
	return m_start.count;
}


uint64_t HighLevelILIntegerList::operator[](size_t i) const
{
	if (i >= size())
		throw HighLevelILInstructionAccessException();
#ifdef BINARYNINJACORE_LIBRARY
	return m_start.function->GetOperand(m_start.offset + i);
#else
	return BNHighLevelILGetOperand(m_start.function->GetObject(), m_start.offset + i);
#endif
}


HighLevelILIntegerList::operator vector<uint64_t>() const
{
	vector<uint64_t> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


size_t HighLevelILIndexList::ListIterator::operator*()
{
	return (size_t)*pos;
}


HighLevelILIndexList::HighLevelILIndexList(
    HighLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count)
{}


HighLevelILIndexList::const_iterator HighLevelILIndexList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


HighLevelILIndexList::const_iterator HighLevelILIndexList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t HighLevelILIndexList::size() const
{
	return m_list.size();
}


size_t HighLevelILIndexList::operator[](size_t i) const
{
	if (i >= size())
		throw HighLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


HighLevelILIndexList::operator vector<size_t>() const
{
	vector<size_t> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const HighLevelILInstruction HighLevelILInstructionList::ListIterator::operator*()
{
	if (ast)
	{
		return HighLevelILInstruction(
		    pos.GetFunction(), pos.GetFunction()->GetRawExpr((size_t)*pos), (size_t)*pos, true, instructionIndex);
	}
	return HighLevelILInstruction(
	    pos.GetFunction(), pos.GetFunction()->GetRawNonASTExpr((size_t)*pos), (size_t)*pos, false, instructionIndex);
}


HighLevelILInstructionList::HighLevelILInstructionList(HighLevelILFunction* func, size_t offset,
    size_t count, bool asFullAst, size_t instructionIndex) :
    m_list(func, offset, count),
    m_ast(asFullAst), m_instructionIndex(instructionIndex)
{}


HighLevelILInstructionList::const_iterator HighLevelILInstructionList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	result.ast = m_ast;
	result.instructionIndex = m_instructionIndex;
	return result;
}


HighLevelILInstructionList::const_iterator HighLevelILInstructionList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	result.ast = m_ast;
	result.instructionIndex = m_instructionIndex;
	return result;
}


size_t HighLevelILInstructionList::size() const
{
	return m_list.size();
}


const HighLevelILInstruction HighLevelILInstructionList::operator[](size_t i) const
{
	if (i >= size())
		throw HighLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


HighLevelILInstructionList::operator vector<HighLevelILInstruction>() const
{
	vector<HighLevelILInstruction> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


HighLevelILInstructionList::operator vector<ExprId>() const
{
	vector<ExprId> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i.exprIndex);
	return result;
}


const SSAVariable HighLevelILSSAVariableList::ListIterator::operator*()
{
	HighLevelILIntegerList::const_iterator cur = pos;
	Variable var = Variable::FromIdentifier(*cur);
	++cur;
	size_t version = (size_t)*cur;
	return SSAVariable(var, version);
}


HighLevelILSSAVariableList::HighLevelILSSAVariableList(
    HighLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count & (~1))
{}


HighLevelILSSAVariableList::const_iterator HighLevelILSSAVariableList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


HighLevelILSSAVariableList::const_iterator HighLevelILSSAVariableList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t HighLevelILSSAVariableList::size() const
{
	return m_list.size() / 2;
}


const SSAVariable HighLevelILSSAVariableList::operator[](size_t i) const
{
	if (i >= size())
		throw HighLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


HighLevelILSSAVariableList::operator vector<SSAVariable>() const
{
	vector<SSAVariable> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


HighLevelILOperand::HighLevelILOperand(
    const HighLevelILInstruction& instr, const HighLevelILOperandLocation& location) :
    m_instr(instr), m_location(location), m_type(OperandTypeForUsage(location.usage))
{
}


uint64_t HighLevelILOperand::GetInteger() const
{
	if (m_type != IntegerHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsInteger(m_location.slot);
}


ConstantData HighLevelILOperand::GetConstantData() const
{
	if (m_type != ConstantDataHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsConstantData(m_location.slot);
}


size_t HighLevelILOperand::GetIndex() const
{
	if (m_type != IndexHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsIndex(m_location.slot);
}


uint32_t HighLevelILOperand::GetIntrinsic() const
{
	if (m_type != IntrinsicHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return (uint32_t)m_instr.GetRawOperandAsInteger(m_location.slot);
}


HighLevelILInstruction HighLevelILOperand::GetExpr() const
{
	if (m_type != ExprHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsExpr(m_location.slot);
}


Variable HighLevelILOperand::GetVariable() const
{
	if (m_type != VariableHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsVariable(m_location.slot);
}


SSAVariable HighLevelILOperand::GetSSAVariable() const
{
	if (m_type != SSAVariableHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	if (m_location.partial)
		return m_instr.GetRawOperandAsPartialSSAVariableSource(m_location.slot);
	return m_instr.GetRawOperandAsSSAVariable(m_location.slot);
}


HighLevelILInstructionList HighLevelILOperand::GetExprList() const
{
	if (m_type != ExprListHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsExprList(m_location.slot);
}


HighLevelILSSAVariableList HighLevelILOperand::GetSSAVariableList() const
{
	if (m_type != SSAVariableListHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsSSAVariableList(m_location.slot);
}


HighLevelILIndexList HighLevelILOperand::GetIndexList() const
{
	if (m_type != IndexListHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsIndexList(m_location.slot);
}


PossibleValueSet HighLevelILOperand::GetConstraint() const
{
	if (m_type != ConstraintHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsPossibleValueSet(m_location.slot);
}


const HighLevelILOperand HighLevelILOperandList::ListIterator::operator*()
{
	if (index >= owner->m_count)
		throw HighLevelILInstructionAccessException();
	return HighLevelILOperand(owner->m_instr, owner->m_locations[index]);
}


HighLevelILOperandList::HighLevelILOperandList(
    const HighLevelILInstruction& instr, const HighLevelILOperandLocation* locations, uint8_t count) :
    m_instr(instr), m_locations(locations), m_count(count)
{}


HighLevelILOperandList::const_iterator HighLevelILOperandList::begin() const
{
	const_iterator result;
	result.owner = this;
	result.index = 0;
	return result;
}


HighLevelILOperandList::const_iterator HighLevelILOperandList::end() const
{
	const_iterator result;
	result.owner = this;
	result.index = m_count;
	return result;
}


size_t HighLevelILOperandList::size() const
{
	return m_count;
}


const HighLevelILOperand HighLevelILOperandList::operator[](size_t i) const
{
	if (i >= m_count)
		throw HighLevelILInstructionAccessException();
	return HighLevelILOperand(m_instr, m_locations[i]);
}


HighLevelILOperandList::operator vector<HighLevelILOperand>() const
{
	vector<HighLevelILOperand> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


HighLevelILInstruction::HighLevelILInstruction()
{
	operation = HLIL_UNDEF;
	attributes = 0;
	sourceOperand = BN_INVALID_OPERAND;
	size = 0;
	address = 0;
	function = nullptr;
	exprIndex = BN_INVALID_EXPR;
	parent = BN_INVALID_EXPR;
}


HighLevelILInstruction::HighLevelILInstruction(
    HighLevelILFunction* func, const BNHighLevelILInstruction& instr, size_t expr, bool asFullAst, size_t instrIdx)
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
	parent = instr.parent;
	function = func;
	exprIndex = expr;
	instructionIndex = instrIdx;
	ast = asFullAst;
}


HighLevelILInstruction::HighLevelILInstruction(const HighLevelILInstructionBase& instr)
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
	ast = instr.ast;
	parent = instr.parent;
}


HighLevelILOperandList HighLevelILInstructionBase::GetOperands() const
{
	if (operation >= s_operandLocations.size())
		throw HighLevelILInstructionAccessException();

	const auto& info = s_operandLocations[operation];
	return HighLevelILOperandList(*(const HighLevelILInstruction*)this, info.locations, info.count);
}


uint64_t HighLevelILInstructionBase::GetRawOperandAsInteger(size_t operand) const
{
	return operands[operand];
}


ConstantData HighLevelILInstructionBase::GetRawOperandAsConstantData(size_t operand) const
{
	return ConstantData((BNRegisterValueType)operands[operand], (uint64_t)operands[operand + 1], size, function->GetFunction());
}


size_t HighLevelILInstructionBase::GetRawOperandAsIndex(size_t operand) const
{
	return (size_t)operands[operand];
}


HighLevelILInstruction HighLevelILInstructionBase::GetRawOperandAsExpr(size_t operand) const
{
	if (ast)
	{
		return HighLevelILInstruction(
		    function, function->GetRawExpr(operands[operand]), operands[operand], true, instructionIndex);
	}
	return HighLevelILInstruction(
	    function, function->GetRawNonASTExpr(operands[operand]), operands[operand], false, instructionIndex);
}


Variable HighLevelILInstructionBase::GetRawOperandAsVariable(size_t operand) const
{
	return Variable::FromIdentifier(operands[operand]);
}


SSAVariable HighLevelILInstructionBase::GetRawOperandAsSSAVariable(size_t operand) const
{
	return SSAVariable(Variable::FromIdentifier(operands[operand]), (size_t)operands[operand + 1]);
}


SSAVariable HighLevelILInstructionBase::GetRawOperandAsPartialSSAVariableSource(size_t operand) const
{
	return SSAVariable(Variable::FromIdentifier(operands[operand]), (size_t)operands[operand + 2]);
}


HighLevelILInstructionList HighLevelILInstructionBase::GetRawOperandAsExprList(size_t operand) const
{
	return HighLevelILInstructionList(
	    function, (size_t)operands[operand + 1], (size_t)operands[operand], ast, instructionIndex);
}


HighLevelILSSAVariableList HighLevelILInstructionBase::GetRawOperandAsSSAVariableList(size_t operand) const
{
	return HighLevelILSSAVariableList(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


HighLevelILIndexList HighLevelILInstructionBase::GetRawOperandAsIndexList(size_t operand) const
{
	return HighLevelILIndexList(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


PossibleValueSet HighLevelILInstructionBase::GetRawOperandAsPossibleValueSet(size_t operand) const
{
	return function->GetCachedPossibleValueSet(operands[operand]);
}


void HighLevelILInstructionBase::UpdateRawOperand(size_t operandIndex, ExprId value)
{
	operands[operandIndex] = value;
	function->UpdateInstructionOperand(exprIndex, operandIndex, value);
}


void HighLevelILInstructionBase::UpdateRawOperandAsInteger(size_t operandIndex, uint64_t value)
{
	operands[operandIndex] = value;
	function->UpdateInstructionOperand(exprIndex, operandIndex, value);
}


void HighLevelILInstructionBase::UpdateRawOperandAsExprList(
    size_t operandIndex, const vector<HighLevelILInstruction>& exprs)
{
	vector<ExprId> exprIndexList;
	exprIndexList.reserve(exprs.size());
	for (auto& i : exprs)
		exprIndexList.push_back((ExprId)i.exprIndex);
	UpdateRawOperand(operandIndex, exprIndexList.size());
	UpdateRawOperand(operandIndex + 1, function->AddOperandList(exprIndexList));
}


void HighLevelILInstructionBase::UpdateRawOperandAsExprList(size_t operandIndex, const vector<ExprId>& exprs)
{
	UpdateRawOperand(operandIndex, exprs.size());
	UpdateRawOperand(operandIndex + 1, function->AddOperandList(exprs));
}


void HighLevelILInstructionBase::UpdateRawOperandAsSSAVariableList(size_t operandIndex, const vector<SSAVariable>& vars)
{
	UpdateRawOperand(operandIndex, vars.size() * 2);
	UpdateRawOperand(operandIndex + 1, function->AddSSAVariableList(vars));
}


RegisterValue HighLevelILInstructionBase::GetValue() const
{
	if (!HasMediumLevelIL())
		return RegisterValue();
	return GetMediumLevelILSSAForm().GetValue();
}


PossibleValueSet HighLevelILInstructionBase::GetPossibleValues(const set<BNDataFlowQueryOption>& options) const
{
	if (!HasMediumLevelIL())
		return PossibleValueSet();
	return GetMediumLevelILSSAForm().GetPossibleValues(options);
}


Confidence<Ref<Type>> HighLevelILInstructionBase::GetType() const
{
	return function->GetExprType(exprIndex);
}


size_t HighLevelILInstructionBase::GetSSAExprIndex() const
{
	return function->GetSSAExprIndex(exprIndex);
}


size_t HighLevelILInstructionBase::GetNonSSAExprIndex() const
{
	return function->GetNonSSAExprIndex(exprIndex);
}


HighLevelILInstruction HighLevelILInstructionBase::GetSSAForm() const
{
	Ref<HighLevelILFunction> ssa = function->GetSSAForm().GetPtr();
	if (!ssa)
		return *this;
	size_t expr = GetSSAExprIndex();
	return ssa->GetExpr(expr);
}


HighLevelILInstruction HighLevelILInstructionBase::GetNonSSAForm() const
{
	Ref<HighLevelILFunction> nonSsa = function->GetNonSSAForm();
	if (!nonSsa)
		return *this;
	size_t expr = GetNonSSAExprIndex();
	return nonSsa->GetExpr(expr);
}


size_t HighLevelILInstructionBase::GetMediumLevelILExprIndex() const
{
	return function->GetMediumLevelILExprIndex(exprIndex);
}


bool HighLevelILInstructionBase::HasMediumLevelIL() const
{
	Ref<MediumLevelILFunction> func = function->GetMediumLevelIL();
	if (!func)
		return false;
	Ref<MediumLevelILFunction> ssa = func->GetSSAForm().GetPtr();
	if (!ssa)
		return false;
	return GetMediumLevelILExprIndex() < ssa->GetExprCount();
}


MediumLevelILInstruction HighLevelILInstructionBase::GetMediumLevelIL() const
{
	return GetMediumLevelILSSAForm().GetNonSSAForm();
}


MediumLevelILInstruction HighLevelILInstructionBase::GetMediumLevelILSSAForm() const
{
	Ref<MediumLevelILFunction> func = function->GetMediumLevelIL();
	if (!func)
		throw MediumLevelILInstructionAccessException();
	Ref<MediumLevelILFunction> ssa = func->GetSSAForm().GetPtr();
	if (!ssa)
		throw MediumLevelILInstructionAccessException();
	size_t expr = GetMediumLevelILExprIndex();
	if (expr >= ssa->GetExprCount())
		throw MediumLevelILInstructionAccessException();
	return ssa->GetExpr(expr);
}


char* HighLevelILInstructionBase::Dump() const
{
	if (!function)
		return strdup("<uninit>");

	vector<InstructionTextToken> tokens;
	vector<DisassemblyTextLine> lines = function->GetExprText(*this, new DisassemblySettings());
	if (!lines.empty())
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

		for (auto& line: lines)
		{
			for (auto& token: line.tokens)
			{
				text += token.text;
			}
			text += " ; ";
		}
		return strdup(text.c_str());
	}
	else
	{
		return strdup("???");
	}
}


void HighLevelILInstructionBase::Replace(ExprId expr)
{
	function->ReplaceExpr(exprIndex, expr);
}


void HighLevelILInstructionBase::SetAttributes(uint32_t attributes)
{
	function->SetExprAttributes(exprIndex, attributes);
}


void HighLevelILInstructionBase::SetAttribute(BNILInstructionAttribute attribute, bool state)
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


void HighLevelILInstructionBase::ClearAttribute(BNILInstructionAttribute attribute)
{
	SetAttribute(attribute, false);
}


std::optional<DerivedString> HighLevelILInstructionBase::GetDerivedStringReference() const
{
	return function->GetDerivedStringReferenceForExpr(exprIndex);
}


void HighLevelILInstructionBase::SetDerivedStringReference(const DerivedString& str)
{
	function->SetDerivedStringReferenceForExpr(exprIndex, str);
}


void HighLevelILInstructionBase::RemoveDerivedStringReference()
{
	function->RemoveDerivedStringReferenceForExpr(exprIndex);
}


size_t HighLevelILInstructionBase::GetInstructionIndex() const
{
	return function->GetInstructionForExpr(exprIndex);
}


HighLevelILInstruction HighLevelILInstructionBase::GetInstruction() const
{
	return function->GetInstruction(GetInstructionIndex());
}


HighLevelILInstruction HighLevelILInstructionBase::AsAST() const
{
	return function->GetExpr(exprIndex, true);
}


HighLevelILInstruction HighLevelILInstructionBase::AsNonAST() const
{
	return function->GetExpr(exprIndex, false);
}


bool HighLevelILInstructionBase::HasParent() const
{
	return parent != BN_INVALID_EXPR;
}


HighLevelILInstruction HighLevelILInstructionBase::GetParent() const
{
	return function->GetExpr(parent, true);
}


// BEGIN GENERATED hlil-visit: from api/il, do not edit
void HighLevelILInstruction::CollectSubExprs(stack<size_t>& toProcess) const
{
	vector<HighLevelILInstruction> exprs;
	switch (operation)
	{
	case HLIL_BLOCK:
		exprs = GetBlockExprs<HLIL_BLOCK>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_IF:
		if (ast)
		{
			toProcess.push(GetFalseExpr<HLIL_IF>().exprIndex);
			toProcess.push(GetTrueExpr<HLIL_IF>().exprIndex);
		}
		toProcess.push(GetConditionExpr<HLIL_IF>().exprIndex);
		break;
	case HLIL_WHILE:
		if (ast)
			toProcess.push(GetLoopExpr<HLIL_WHILE>().exprIndex);
		toProcess.push(GetConditionExpr<HLIL_WHILE>().exprIndex);
		break;
	case HLIL_DO_WHILE:
		toProcess.push(GetConditionExpr<HLIL_DO_WHILE>().exprIndex);
		if (ast)
			toProcess.push(GetLoopExpr<HLIL_DO_WHILE>().exprIndex);
		break;
	case HLIL_FOR:
		if (ast)
			toProcess.push(GetLoopExpr<HLIL_FOR>().exprIndex);
		toProcess.push(GetUpdateExpr<HLIL_FOR>().exprIndex);
		toProcess.push(GetConditionExpr<HLIL_FOR>().exprIndex);
		toProcess.push(GetInitExpr<HLIL_FOR>().exprIndex);
		break;
	case HLIL_SWITCH:
		if (ast)
		{
			exprs = GetCases<HLIL_SWITCH>();
			for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
				toProcess.push(i->exprIndex);
			toProcess.push(GetDefaultExpr<HLIL_SWITCH>().exprIndex);
		}
		toProcess.push(GetConditionExpr<HLIL_SWITCH>().exprIndex);
		break;
	case HLIL_CASE:
		if (ast)
			toProcess.push(GetTrueExpr<HLIL_CASE>().exprIndex);
		exprs = GetValueExprs<HLIL_CASE>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_JUMP:
		toProcess.push(GetDestExpr<HLIL_JUMP>().exprIndex);
		break;
	case HLIL_RET:
		exprs = GetSourceExprs<HLIL_RET>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_VAR_INIT:
		toProcess.push(GetSourceExpr<HLIL_VAR_INIT>().exprIndex);
		break;
	case HLIL_ASSIGN:
		toProcess.push(GetDestExpr<HLIL_ASSIGN>().exprIndex);
		toProcess.push(GetSourceExpr<HLIL_ASSIGN>().exprIndex);
		break;
	case HLIL_ASSIGN_UNPACK:
		exprs = GetDestExprs<HLIL_ASSIGN_UNPACK>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		toProcess.push(GetSourceExpr<HLIL_ASSIGN_UNPACK>().exprIndex);
		break;
	case HLIL_STRUCT_FIELD:
		toProcess.push(GetSourceExpr<HLIL_STRUCT_FIELD>().exprIndex);
		break;
	case HLIL_ARRAY_INDEX:
		toProcess.push(GetSourceExpr<HLIL_ARRAY_INDEX>().exprIndex);
		toProcess.push(GetIndexExpr<HLIL_ARRAY_INDEX>().exprIndex);
		break;
	case HLIL_SPLIT:
		toProcess.push(GetLowExpr<HLIL_SPLIT>().exprIndex);
		toProcess.push(GetHighExpr<HLIL_SPLIT>().exprIndex);
		break;
	case HLIL_DEREF:
		toProcess.push(GetSourceExpr<HLIL_DEREF>().exprIndex);
		break;
	case HLIL_DEREF_FIELD:
		toProcess.push(GetSourceExpr<HLIL_DEREF_FIELD>().exprIndex);
		break;
	case HLIL_ADDRESS_OF:
		toProcess.push(GetSourceExpr<HLIL_ADDRESS_OF>().exprIndex);
		break;
	case HLIL_PASS_BY_REF:
		toProcess.push(GetSourceExpr<HLIL_PASS_BY_REF>().exprIndex);
		break;
	case HLIL_RETURN_BY_REF:
		toProcess.push(GetSourceExpr<HLIL_RETURN_BY_REF>().exprIndex);
		break;
	case HLIL_ADD:
		toProcess.push(GetRightExpr<HLIL_ADD>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_ADD>().exprIndex);
		break;
	case HLIL_ADC:
		toProcess.push(GetCarryExpr<HLIL_ADC>().exprIndex);
		toProcess.push(GetRightExpr<HLIL_ADC>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_ADC>().exprIndex);
		break;
	case HLIL_SUB:
		toProcess.push(GetRightExpr<HLIL_SUB>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_SUB>().exprIndex);
		break;
	case HLIL_SBB:
		toProcess.push(GetCarryExpr<HLIL_SBB>().exprIndex);
		toProcess.push(GetRightExpr<HLIL_SBB>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_SBB>().exprIndex);
		break;
	case HLIL_AND:
		toProcess.push(GetRightExpr<HLIL_AND>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_AND>().exprIndex);
		break;
	case HLIL_OR:
		toProcess.push(GetRightExpr<HLIL_OR>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_OR>().exprIndex);
		break;
	case HLIL_XOR:
		toProcess.push(GetRightExpr<HLIL_XOR>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_XOR>().exprIndex);
		break;
	case HLIL_LSL:
		toProcess.push(GetRightExpr<HLIL_LSL>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_LSL>().exprIndex);
		break;
	case HLIL_LSR:
		toProcess.push(GetRightExpr<HLIL_LSR>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_LSR>().exprIndex);
		break;
	case HLIL_ASR:
		toProcess.push(GetRightExpr<HLIL_ASR>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_ASR>().exprIndex);
		break;
	case HLIL_ROL:
		toProcess.push(GetRightExpr<HLIL_ROL>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_ROL>().exprIndex);
		break;
	case HLIL_RLC:
		toProcess.push(GetCarryExpr<HLIL_RLC>().exprIndex);
		toProcess.push(GetRightExpr<HLIL_RLC>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_RLC>().exprIndex);
		break;
	case HLIL_ROR:
		toProcess.push(GetRightExpr<HLIL_ROR>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_ROR>().exprIndex);
		break;
	case HLIL_RRC:
		toProcess.push(GetCarryExpr<HLIL_RRC>().exprIndex);
		toProcess.push(GetRightExpr<HLIL_RRC>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_RRC>().exprIndex);
		break;
	case HLIL_MUL:
		toProcess.push(GetRightExpr<HLIL_MUL>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_MUL>().exprIndex);
		break;
	case HLIL_MULU_DP:
		toProcess.push(GetRightExpr<HLIL_MULU_DP>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_MULU_DP>().exprIndex);
		break;
	case HLIL_MULS_DP:
		toProcess.push(GetRightExpr<HLIL_MULS_DP>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_MULS_DP>().exprIndex);
		break;
	case HLIL_DIVU:
		toProcess.push(GetRightExpr<HLIL_DIVU>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_DIVU>().exprIndex);
		break;
	case HLIL_DIVU_DP:
		toProcess.push(GetRightExpr<HLIL_DIVU_DP>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_DIVU_DP>().exprIndex);
		break;
	case HLIL_DIVS:
		toProcess.push(GetRightExpr<HLIL_DIVS>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_DIVS>().exprIndex);
		break;
	case HLIL_DIVS_DP:
		toProcess.push(GetRightExpr<HLIL_DIVS_DP>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_DIVS_DP>().exprIndex);
		break;
	case HLIL_MODU:
		toProcess.push(GetRightExpr<HLIL_MODU>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_MODU>().exprIndex);
		break;
	case HLIL_MODU_DP:
		toProcess.push(GetRightExpr<HLIL_MODU_DP>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_MODU_DP>().exprIndex);
		break;
	case HLIL_MODS:
		toProcess.push(GetRightExpr<HLIL_MODS>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_MODS>().exprIndex);
		break;
	case HLIL_MODS_DP:
		toProcess.push(GetRightExpr<HLIL_MODS_DP>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_MODS_DP>().exprIndex);
		break;
	case HLIL_NEG:
		toProcess.push(GetSourceExpr<HLIL_NEG>().exprIndex);
		break;
	case HLIL_NOT:
		toProcess.push(GetSourceExpr<HLIL_NOT>().exprIndex);
		break;
	case HLIL_SX:
		toProcess.push(GetSourceExpr<HLIL_SX>().exprIndex);
		break;
	case HLIL_ZX:
		toProcess.push(GetSourceExpr<HLIL_ZX>().exprIndex);
		break;
	case HLIL_LOW_PART:
		toProcess.push(GetSourceExpr<HLIL_LOW_PART>().exprIndex);
		break;
	case HLIL_CALL:
		toProcess.push(GetDestExpr<HLIL_CALL>().exprIndex);
		exprs = GetParameterExprs<HLIL_CALL>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_CMP_E:
		toProcess.push(GetRightExpr<HLIL_CMP_E>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_CMP_E>().exprIndex);
		break;
	case HLIL_CMP_NE:
		toProcess.push(GetRightExpr<HLIL_CMP_NE>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_CMP_NE>().exprIndex);
		break;
	case HLIL_CMP_SLT:
		toProcess.push(GetRightExpr<HLIL_CMP_SLT>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_CMP_SLT>().exprIndex);
		break;
	case HLIL_CMP_ULT:
		toProcess.push(GetRightExpr<HLIL_CMP_ULT>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_CMP_ULT>().exprIndex);
		break;
	case HLIL_CMP_SLE:
		toProcess.push(GetRightExpr<HLIL_CMP_SLE>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_CMP_SLE>().exprIndex);
		break;
	case HLIL_CMP_ULE:
		toProcess.push(GetRightExpr<HLIL_CMP_ULE>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_CMP_ULE>().exprIndex);
		break;
	case HLIL_CMP_SGE:
		toProcess.push(GetRightExpr<HLIL_CMP_SGE>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_CMP_SGE>().exprIndex);
		break;
	case HLIL_CMP_UGE:
		toProcess.push(GetRightExpr<HLIL_CMP_UGE>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_CMP_UGE>().exprIndex);
		break;
	case HLIL_CMP_SGT:
		toProcess.push(GetRightExpr<HLIL_CMP_SGT>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_CMP_SGT>().exprIndex);
		break;
	case HLIL_CMP_UGT:
		toProcess.push(GetRightExpr<HLIL_CMP_UGT>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_CMP_UGT>().exprIndex);
		break;
	case HLIL_TEST_BIT:
		toProcess.push(GetRightExpr<HLIL_TEST_BIT>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_TEST_BIT>().exprIndex);
		break;
	case HLIL_BOOL_TO_INT:
		toProcess.push(GetSourceExpr<HLIL_BOOL_TO_INT>().exprIndex);
		break;
	case HLIL_ADD_OVERFLOW:
		toProcess.push(GetRightExpr<HLIL_ADD_OVERFLOW>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_ADD_OVERFLOW>().exprIndex);
		break;
	case HLIL_SYSCALL:
		exprs = GetParameterExprs<HLIL_SYSCALL>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_TAILCALL:
		toProcess.push(GetDestExpr<HLIL_TAILCALL>().exprIndex);
		exprs = GetParameterExprs<HLIL_TAILCALL>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_INTRINSIC:
		exprs = GetParameterExprs<HLIL_INTRINSIC>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_UNIMPL_MEM:
		toProcess.push(GetSourceExpr<HLIL_UNIMPL_MEM>().exprIndex);
		break;
	case HLIL_STRUCT_INIT:
		exprs = GetFieldExprs<HLIL_STRUCT_INIT>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_STRUCT_INIT_FIELD:
		toProcess.push(GetSourceExpr<HLIL_STRUCT_INIT_FIELD>().exprIndex);
		break;
	case HLIL_FADD:
		toProcess.push(GetRightExpr<HLIL_FADD>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FADD>().exprIndex);
		break;
	case HLIL_FSUB:
		toProcess.push(GetRightExpr<HLIL_FSUB>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FSUB>().exprIndex);
		break;
	case HLIL_FMUL:
		toProcess.push(GetRightExpr<HLIL_FMUL>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FMUL>().exprIndex);
		break;
	case HLIL_FDIV:
		toProcess.push(GetRightExpr<HLIL_FDIV>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FDIV>().exprIndex);
		break;
	case HLIL_FSQRT:
		toProcess.push(GetSourceExpr<HLIL_FSQRT>().exprIndex);
		break;
	case HLIL_FNEG:
		toProcess.push(GetSourceExpr<HLIL_FNEG>().exprIndex);
		break;
	case HLIL_FABS:
		toProcess.push(GetSourceExpr<HLIL_FABS>().exprIndex);
		break;
	case HLIL_FLOAT_TO_INT:
		toProcess.push(GetSourceExpr<HLIL_FLOAT_TO_INT>().exprIndex);
		break;
	case HLIL_INT_TO_FLOAT:
		toProcess.push(GetSourceExpr<HLIL_INT_TO_FLOAT>().exprIndex);
		break;
	case HLIL_FLOAT_CONV:
		toProcess.push(GetSourceExpr<HLIL_FLOAT_CONV>().exprIndex);
		break;
	case HLIL_ROUND_TO_INT:
		toProcess.push(GetSourceExpr<HLIL_ROUND_TO_INT>().exprIndex);
		break;
	case HLIL_FLOOR:
		toProcess.push(GetSourceExpr<HLIL_FLOOR>().exprIndex);
		break;
	case HLIL_CEIL:
		toProcess.push(GetSourceExpr<HLIL_CEIL>().exprIndex);
		break;
	case HLIL_FTRUNC:
		toProcess.push(GetSourceExpr<HLIL_FTRUNC>().exprIndex);
		break;
	case HLIL_FCMP_E:
		toProcess.push(GetRightExpr<HLIL_FCMP_E>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FCMP_E>().exprIndex);
		break;
	case HLIL_FCMP_NE:
		toProcess.push(GetRightExpr<HLIL_FCMP_NE>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FCMP_NE>().exprIndex);
		break;
	case HLIL_FCMP_LT:
		toProcess.push(GetRightExpr<HLIL_FCMP_LT>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FCMP_LT>().exprIndex);
		break;
	case HLIL_FCMP_LE:
		toProcess.push(GetRightExpr<HLIL_FCMP_LE>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FCMP_LE>().exprIndex);
		break;
	case HLIL_FCMP_GE:
		toProcess.push(GetRightExpr<HLIL_FCMP_GE>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FCMP_GE>().exprIndex);
		break;
	case HLIL_FCMP_GT:
		toProcess.push(GetRightExpr<HLIL_FCMP_GT>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FCMP_GT>().exprIndex);
		break;
	case HLIL_FCMP_O:
		toProcess.push(GetRightExpr<HLIL_FCMP_O>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FCMP_O>().exprIndex);
		break;
	case HLIL_FCMP_UO:
		toProcess.push(GetRightExpr<HLIL_FCMP_UO>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_FCMP_UO>().exprIndex);
		break;
	case HLIL_WHILE_SSA:
		if (ast)
			toProcess.push(GetLoopExpr<HLIL_WHILE_SSA>().exprIndex);
		toProcess.push(GetConditionExpr<HLIL_WHILE_SSA>().exprIndex);
		toProcess.push(GetConditionPhiExpr<HLIL_WHILE_SSA>().exprIndex);
		break;
	case HLIL_DO_WHILE_SSA:
		toProcess.push(GetConditionExpr<HLIL_DO_WHILE_SSA>().exprIndex);
		toProcess.push(GetConditionPhiExpr<HLIL_DO_WHILE_SSA>().exprIndex);
		if (ast)
			toProcess.push(GetLoopExpr<HLIL_DO_WHILE_SSA>().exprIndex);
		break;
	case HLIL_FOR_SSA:
		if (ast)
			toProcess.push(GetLoopExpr<HLIL_FOR_SSA>().exprIndex);
		toProcess.push(GetUpdateExpr<HLIL_FOR_SSA>().exprIndex);
		toProcess.push(GetConditionExpr<HLIL_FOR_SSA>().exprIndex);
		toProcess.push(GetConditionPhiExpr<HLIL_FOR_SSA>().exprIndex);
		toProcess.push(GetInitExpr<HLIL_FOR_SSA>().exprIndex);
		break;
	case HLIL_VAR_INIT_SSA:
		toProcess.push(GetSourceExpr<HLIL_VAR_INIT_SSA>().exprIndex);
		break;
	case HLIL_ASSIGN_MEM_SSA:
		toProcess.push(GetDestExpr<HLIL_ASSIGN_MEM_SSA>().exprIndex);
		toProcess.push(GetSourceExpr<HLIL_ASSIGN_MEM_SSA>().exprIndex);
		break;
	case HLIL_ASSIGN_UNPACK_MEM_SSA:
		exprs = GetDestExprs<HLIL_ASSIGN_UNPACK_MEM_SSA>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		toProcess.push(GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>().exprIndex);
		break;
	case HLIL_ARRAY_INDEX_SSA:
		toProcess.push(GetSourceExpr<HLIL_ARRAY_INDEX_SSA>().exprIndex);
		toProcess.push(GetIndexExpr<HLIL_ARRAY_INDEX_SSA>().exprIndex);
		break;
	case HLIL_DEREF_SSA:
		toProcess.push(GetSourceExpr<HLIL_DEREF_SSA>().exprIndex);
		break;
	case HLIL_DEREF_FIELD_SSA:
		toProcess.push(GetSourceExpr<HLIL_DEREF_FIELD_SSA>().exprIndex);
		break;
	case HLIL_CALL_SSA:
		toProcess.push(GetDestExpr<HLIL_CALL_SSA>().exprIndex);
		exprs = GetParameterExprs<HLIL_CALL_SSA>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_SYSCALL_SSA:
		exprs = GetParameterExprs<HLIL_SYSCALL_SSA>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_INTRINSIC_SSA:
		exprs = GetParameterExprs<HLIL_INTRINSIC_SSA>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_BSWAP:
		toProcess.push(GetSourceExpr<HLIL_BSWAP>().exprIndex);
		break;
	case HLIL_POPCNT:
		toProcess.push(GetSourceExpr<HLIL_POPCNT>().exprIndex);
		break;
	case HLIL_CLZ:
		toProcess.push(GetSourceExpr<HLIL_CLZ>().exprIndex);
		break;
	case HLIL_CTZ:
		toProcess.push(GetSourceExpr<HLIL_CTZ>().exprIndex);
		break;
	case HLIL_RBIT:
		toProcess.push(GetSourceExpr<HLIL_RBIT>().exprIndex);
		break;
	case HLIL_CLS:
		toProcess.push(GetSourceExpr<HLIL_CLS>().exprIndex);
		break;
	case HLIL_MINS:
		toProcess.push(GetRightExpr<HLIL_MINS>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_MINS>().exprIndex);
		break;
	case HLIL_MAXS:
		toProcess.push(GetRightExpr<HLIL_MAXS>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_MAXS>().exprIndex);
		break;
	case HLIL_MINU:
		toProcess.push(GetRightExpr<HLIL_MINU>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_MINU>().exprIndex);
		break;
	case HLIL_MAXU:
		toProcess.push(GetRightExpr<HLIL_MAXU>().exprIndex);
		toProcess.push(GetLeftExpr<HLIL_MAXU>().exprIndex);
		break;
	case HLIL_ABS:
		toProcess.push(GetSourceExpr<HLIL_ABS>().exprIndex);
		break;
	default:
		break;
	}
}
// END GENERATED hlil-visit


void HighLevelILInstruction::VisitExprs(bn::base::function_ref<bool(const HighLevelILInstruction& expr)> func) const
{
	stack<size_t> toProcess;
	toProcess.push(exprIndex);
	while (!toProcess.empty())
	{
		HighLevelILInstruction cur = function->GetExpr(toProcess.top(), ast);
		toProcess.pop();
		if (!func(cur))
			continue;
		cur.CollectSubExprs(toProcess);
	}
}


void HighLevelILInstruction::VisitExprs(bn::base::function_ref<bool(const HighLevelILInstruction& expr)> preFunc,
	bn::base::function_ref<void(const HighLevelILInstruction& expr)> postFunc) const
{
	stack<std::pair<HighLevelILInstruction, stack<size_t>>> toProcess;
	HighLevelILInstruction cur = *this;
	if (!preFunc(cur))
		return;

	stack<size_t> subExprs;
	cur.CollectSubExprs(subExprs);

	while (true)
	{
		if (subExprs.size() == 0)
		{
			postFunc(cur);

			if (toProcess.empty())
				break;
			cur = toProcess.top().first;
			subExprs = toProcess.top().second;
			toProcess.pop();
		}
		else
		{
			HighLevelILInstruction next = function->GetExpr(subExprs.top());
			subExprs.pop();

			if (preFunc(next))
			{
				toProcess.push(std::pair<HighLevelILInstruction, stack<size_t>>(cur, subExprs));
				cur = next;
				subExprs = stack<size_t>();
				cur.CollectSubExprs(subExprs);
			}
		}
	}
}


ExprId HighLevelILInstruction::CopyTo(HighLevelILFunction* dest, const ILSourceLocation& sourceLocation) const
{
	return CopyTo(dest, [&](const HighLevelILInstruction& subExpr) { return subExpr.CopyTo(dest, sourceLocation); }, sourceLocation);
}


// BEGIN GENERATED hlil-copy: from api/il, do not edit
static ExprId CopyOperandList(HighLevelILFunction* dest, const HighLevelILInstruction& instr, size_t operand)
{
	vector<uint64_t> items = instr.function->GetOperandList(instr.exprIndex, operand);
	return dest->AddIndexList(vector<size_t>(items.begin(), items.end()));
}


ExprId HighLevelILInstruction::CopyTo(HighLevelILFunction* dest,
    bn::base::function_ref<ExprId(const HighLevelILInstruction& subExpr)> subExprHandler,
    const ILSourceLocation& sourceLocation) const
{
	const auto& loc = sourceLocation.valid ? sourceLocation : ILSourceLocation{*this};
	switch (operation)
	{
	case HLIL_NOP:
		return dest->AddExprWithLocation(HLIL_NOP, loc, size);
	case HLIL_BLOCK:
	{
		vector<ExprId> bodyCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			bodyCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(HLIL_BLOCK, loc, size, bodyCopy.size(), dest->AddOperandList(bodyCopy));
	}
	case HLIL_IF:
	{
		ExprId conditionCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId trueCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId falseCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(HLIL_IF, loc, size, conditionCopy, trueCopy, falseCopy);
	}
	case HLIL_WHILE:
	{
		ExprId conditionCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId bodyCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_WHILE, loc, size, conditionCopy, bodyCopy);
	}
	case HLIL_DO_WHILE:
	{
		ExprId bodyCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId conditionCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_DO_WHILE, loc, size, bodyCopy, conditionCopy);
	}
	case HLIL_FOR:
	{
		ExprId initCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId conditionCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId updateCopy = subExprHandler(GetRawOperandAsExpr(2));
		ExprId bodyCopy = subExprHandler(GetRawOperandAsExpr(3));
		return dest->AddExprWithLocation(HLIL_FOR, loc, size, initCopy, conditionCopy, updateCopy, bodyCopy);
	}
	case HLIL_SWITCH:
	{
		ExprId conditionCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId defaultCopy = subExprHandler(GetRawOperandAsExpr(1));
		vector<ExprId> casesCopy;
		for (const auto& expr : GetRawOperandAsExprList(2))
			casesCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(
		    HLIL_SWITCH, loc, size, conditionCopy, defaultCopy, casesCopy.size(), dest->AddOperandList(casesCopy));
	}
	case HLIL_CASE:
	{
		vector<ExprId> valuesCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			valuesCopy.push_back(subExprHandler(expr));
		ExprId bodyCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    HLIL_CASE, loc, size, valuesCopy.size(), dest->AddOperandList(valuesCopy), bodyCopy);
	}
	case HLIL_BREAK:
		return dest->AddExprWithLocation(HLIL_BREAK, loc, size);
	case HLIL_CONTINUE:
		return dest->AddExprWithLocation(HLIL_CONTINUE, loc, size);
	case HLIL_JUMP:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_JUMP, loc, size, destCopy);
	}
	case HLIL_RET:
	{
		vector<ExprId> srcCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			srcCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(HLIL_RET, loc, size, srcCopy.size(), dest->AddOperandList(srcCopy));
	}
	case HLIL_NORET:
		return dest->AddExprWithLocation(HLIL_NORET, loc, size);
	case HLIL_GOTO:
		return dest->AddExprWithLocation(HLIL_GOTO, loc, size, GetRawOperandAsInteger(0));
	case HLIL_LABEL:
		return dest->AddExprWithLocation(HLIL_LABEL, loc, size, GetRawOperandAsInteger(0));
	case HLIL_VAR_DECLARE:
		return dest->AddExprWithLocation(HLIL_VAR_DECLARE, loc, size, GetRawOperandAsInteger(0));
	case HLIL_VAR_INIT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_VAR_INIT, loc, size, GetRawOperandAsInteger(0), srcCopy);
	}
	case HLIL_ASSIGN:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_ASSIGN, loc, size, destCopy, srcCopy);
	}
	case HLIL_ASSIGN_UNPACK:
	{
		vector<ExprId> destCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			destCopy.push_back(subExprHandler(expr));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    HLIL_ASSIGN_UNPACK, loc, size, destCopy.size(), dest->AddOperandList(destCopy), srcCopy);
	}
	case HLIL_FORCE_VER:
		return dest->AddExprWithLocation(
		    HLIL_FORCE_VER, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case HLIL_ASSERT:
		return dest->AddExprWithLocation(HLIL_ASSERT, loc, size, GetRawOperandAsInteger(0),
		    dest->CachePossibleValueSet(GetRawOperandAsPossibleValueSet(1)));
	case HLIL_VAR:
		return dest->AddExprWithLocation(HLIL_VAR, loc, size, GetRawOperandAsInteger(0));
	case HLIL_STRUCT_FIELD:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(
		    HLIL_STRUCT_FIELD, loc, size, srcCopy, GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	}
	case HLIL_ARRAY_INDEX:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId indexCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_ARRAY_INDEX, loc, size, srcCopy, indexCopy);
	}
	case HLIL_SPLIT:
	{
		ExprId highCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId lowCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_SPLIT, loc, size, highCopy, lowCopy);
	}
	case HLIL_DEREF:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_DEREF, loc, size, srcCopy);
	}
	case HLIL_DEREF_FIELD:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(
		    HLIL_DEREF_FIELD, loc, size, srcCopy, GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	}
	case HLIL_ADDRESS_OF:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_ADDRESS_OF, loc, size, srcCopy);
	}
	case HLIL_PASS_BY_REF:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_PASS_BY_REF, loc, size, srcCopy);
	}
	case HLIL_RETURN_BY_REF:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_RETURN_BY_REF, loc, size, srcCopy);
	}
	case HLIL_CONST:
		return dest->AddExprWithLocation(HLIL_CONST, loc, size, GetRawOperandAsInteger(0));
	case HLIL_CONST_DATA:
		return dest->AddExprWithLocation(
		    HLIL_CONST_DATA, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case HLIL_CONST_PTR:
		return dest->AddExprWithLocation(HLIL_CONST_PTR, loc, size, GetRawOperandAsInteger(0));
	case HLIL_EXTERN_PTR:
		return dest->AddExprWithLocation(
		    HLIL_EXTERN_PTR, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case HLIL_FLOAT_CONST:
		return dest->AddExprWithLocation(HLIL_FLOAT_CONST, loc, size, GetRawOperandAsInteger(0));
	case HLIL_IMPORT:
		return dest->AddExprWithLocation(HLIL_IMPORT, loc, size, GetRawOperandAsInteger(0));
	case HLIL_ADD:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_ADD, loc, size, leftCopy, rightCopy);
	}
	case HLIL_ADC:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(HLIL_ADC, loc, size, leftCopy, rightCopy, carryCopy);
	}
	case HLIL_SUB:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_SUB, loc, size, leftCopy, rightCopy);
	}
	case HLIL_SBB:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(HLIL_SBB, loc, size, leftCopy, rightCopy, carryCopy);
	}
	case HLIL_AND:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_AND, loc, size, leftCopy, rightCopy);
	}
	case HLIL_OR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_OR, loc, size, leftCopy, rightCopy);
	}
	case HLIL_XOR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_XOR, loc, size, leftCopy, rightCopy);
	}
	case HLIL_LSL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_LSL, loc, size, leftCopy, rightCopy);
	}
	case HLIL_LSR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_LSR, loc, size, leftCopy, rightCopy);
	}
	case HLIL_ASR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_ASR, loc, size, leftCopy, rightCopy);
	}
	case HLIL_ROL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_ROL, loc, size, leftCopy, rightCopy);
	}
	case HLIL_RLC:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(HLIL_RLC, loc, size, leftCopy, rightCopy, carryCopy);
	}
	case HLIL_ROR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_ROR, loc, size, leftCopy, rightCopy);
	}
	case HLIL_RRC:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(HLIL_RRC, loc, size, leftCopy, rightCopy, carryCopy);
	}
	case HLIL_MUL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_MUL, loc, size, leftCopy, rightCopy);
	}
	case HLIL_MULU_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_MULU_DP, loc, size, leftCopy, rightCopy);
	}
	case HLIL_MULS_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_MULS_DP, loc, size, leftCopy, rightCopy);
	}
	case HLIL_DIVU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_DIVU, loc, size, leftCopy, rightCopy);
	}
	case HLIL_DIVU_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_DIVU_DP, loc, size, leftCopy, rightCopy);
	}
	case HLIL_DIVS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_DIVS, loc, size, leftCopy, rightCopy);
	}
	case HLIL_DIVS_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_DIVS_DP, loc, size, leftCopy, rightCopy);
	}
	case HLIL_MODU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_MODU, loc, size, leftCopy, rightCopy);
	}
	case HLIL_MODU_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_MODU_DP, loc, size, leftCopy, rightCopy);
	}
	case HLIL_MODS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_MODS, loc, size, leftCopy, rightCopy);
	}
	case HLIL_MODS_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_MODS_DP, loc, size, leftCopy, rightCopy);
	}
	case HLIL_NEG:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_NEG, loc, size, srcCopy);
	}
	case HLIL_NOT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_NOT, loc, size, srcCopy);
	}
	case HLIL_SX:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_SX, loc, size, srcCopy);
	}
	case HLIL_ZX:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_ZX, loc, size, srcCopy);
	}
	case HLIL_LOW_PART:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_LOW_PART, loc, size, srcCopy);
	}
	case HLIL_CALL:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(1))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(
		    HLIL_CALL, loc, size, destCopy, paramsCopy.size(), dest->AddOperandList(paramsCopy));
	}
	case HLIL_CMP_E:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_CMP_E, loc, size, leftCopy, rightCopy);
	}
	case HLIL_CMP_NE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_CMP_NE, loc, size, leftCopy, rightCopy);
	}
	case HLIL_CMP_SLT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_CMP_SLT, loc, size, leftCopy, rightCopy);
	}
	case HLIL_CMP_ULT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_CMP_ULT, loc, size, leftCopy, rightCopy);
	}
	case HLIL_CMP_SLE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_CMP_SLE, loc, size, leftCopy, rightCopy);
	}
	case HLIL_CMP_ULE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_CMP_ULE, loc, size, leftCopy, rightCopy);
	}
	case HLIL_CMP_SGE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_CMP_SGE, loc, size, leftCopy, rightCopy);
	}
	case HLIL_CMP_UGE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_CMP_UGE, loc, size, leftCopy, rightCopy);
	}
	case HLIL_CMP_SGT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_CMP_SGT, loc, size, leftCopy, rightCopy);
	}
	case HLIL_CMP_UGT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_CMP_UGT, loc, size, leftCopy, rightCopy);
	}
	case HLIL_TEST_BIT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_TEST_BIT, loc, size, leftCopy, rightCopy);
	}
	case HLIL_BOOL_TO_INT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_BOOL_TO_INT, loc, size, srcCopy);
	}
	case HLIL_ADD_OVERFLOW:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_ADD_OVERFLOW, loc, size, leftCopy, rightCopy);
	}
	case HLIL_SYSCALL:
	{
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(HLIL_SYSCALL, loc, size, paramsCopy.size(), dest->AddOperandList(paramsCopy));
	}
	case HLIL_TAILCALL:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(1))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(
		    HLIL_TAILCALL, loc, size, destCopy, paramsCopy.size(), dest->AddOperandList(paramsCopy));
	}
	case HLIL_INTRINSIC:
	{
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(1))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(
		    HLIL_INTRINSIC, loc, size, GetRawOperandAsInteger(0), paramsCopy.size(), dest->AddOperandList(paramsCopy));
	}
	case HLIL_BP:
		return dest->AddExprWithLocation(HLIL_BP, loc, size);
	case HLIL_TRAP:
		return dest->AddExprWithLocation(HLIL_TRAP, loc, size, GetRawOperandAsInteger(0));
	case HLIL_UNDEF:
		return dest->AddExprWithLocation(HLIL_UNDEF, loc, size);
	case HLIL_UNIMPL:
		return dest->AddExprWithLocation(HLIL_UNIMPL, loc, size, GetRawOperandAsInteger(0));
	case HLIL_UNIMPL_MEM:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_UNIMPL_MEM, loc, size, srcCopy, GetRawOperandAsInteger(1));
	}
	case HLIL_STRUCT_INIT:
	{
		vector<ExprId> fieldsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			fieldsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(
		    HLIL_STRUCT_INIT, loc, size, fieldsCopy.size(), dest->AddOperandList(fieldsCopy));
	}
	case HLIL_STRUCT_INIT_FIELD:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    HLIL_STRUCT_INIT_FIELD, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1), srcCopy);
	}
	case HLIL_FADD:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FADD, loc, size, leftCopy, rightCopy);
	}
	case HLIL_FSUB:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FSUB, loc, size, leftCopy, rightCopy);
	}
	case HLIL_FMUL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FMUL, loc, size, leftCopy, rightCopy);
	}
	case HLIL_FDIV:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FDIV, loc, size, leftCopy, rightCopy);
	}
	case HLIL_FSQRT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_FSQRT, loc, size, srcCopy);
	}
	case HLIL_FNEG:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_FNEG, loc, size, srcCopy);
	}
	case HLIL_FABS:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_FABS, loc, size, srcCopy);
	}
	case HLIL_FLOAT_TO_INT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_FLOAT_TO_INT, loc, size, srcCopy);
	}
	case HLIL_INT_TO_FLOAT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_INT_TO_FLOAT, loc, size, srcCopy);
	}
	case HLIL_FLOAT_CONV:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_FLOAT_CONV, loc, size, srcCopy);
	}
	case HLIL_ROUND_TO_INT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_ROUND_TO_INT, loc, size, srcCopy);
	}
	case HLIL_FLOOR:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_FLOOR, loc, size, srcCopy);
	}
	case HLIL_CEIL:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_CEIL, loc, size, srcCopy);
	}
	case HLIL_FTRUNC:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_FTRUNC, loc, size, srcCopy);
	}
	case HLIL_FCMP_E:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FCMP_E, loc, size, leftCopy, rightCopy);
	}
	case HLIL_FCMP_NE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FCMP_NE, loc, size, leftCopy, rightCopy);
	}
	case HLIL_FCMP_LT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FCMP_LT, loc, size, leftCopy, rightCopy);
	}
	case HLIL_FCMP_LE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FCMP_LE, loc, size, leftCopy, rightCopy);
	}
	case HLIL_FCMP_GE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FCMP_GE, loc, size, leftCopy, rightCopy);
	}
	case HLIL_FCMP_GT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FCMP_GT, loc, size, leftCopy, rightCopy);
	}
	case HLIL_FCMP_O:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FCMP_O, loc, size, leftCopy, rightCopy);
	}
	case HLIL_FCMP_UO:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_FCMP_UO, loc, size, leftCopy, rightCopy);
	}
	case HLIL_UNREACHABLE:
		return dest->AddExprWithLocation(HLIL_UNREACHABLE, loc, size);
	case HLIL_WHILE_SSA:
	{
		ExprId conditionPhiCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId conditionCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId bodyCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(HLIL_WHILE_SSA, loc, size, conditionPhiCopy, conditionCopy, bodyCopy);
	}
	case HLIL_DO_WHILE_SSA:
	{
		ExprId bodyCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId conditionPhiCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId conditionCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(HLIL_DO_WHILE_SSA, loc, size, bodyCopy, conditionPhiCopy, conditionCopy);
	}
	case HLIL_FOR_SSA:
	{
		ExprId initCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId conditionPhiCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId conditionCopy = subExprHandler(GetRawOperandAsExpr(2));
		ExprId updateCopy = subExprHandler(GetRawOperandAsExpr(3));
		ExprId bodyCopy = subExprHandler(GetRawOperandAsExpr(4));
		return dest->AddExprWithLocation(
		    HLIL_FOR_SSA, loc, size, initCopy, conditionPhiCopy, conditionCopy, updateCopy, bodyCopy);
	}
	case HLIL_VAR_INIT_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    HLIL_VAR_INIT_SSA, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1), srcCopy);
	}
	case HLIL_ASSIGN_MEM_SSA:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    HLIL_ASSIGN_MEM_SSA, loc, size, destCopy, GetRawOperandAsInteger(1), srcCopy, GetRawOperandAsInteger(3));
	}
	case HLIL_ASSIGN_UNPACK_MEM_SSA:
	{
		vector<ExprId> destCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			destCopy.push_back(subExprHandler(expr));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(3));
		return dest->AddExprWithLocation(HLIL_ASSIGN_UNPACK_MEM_SSA, loc, size, destCopy.size(),
		    dest->AddOperandList(destCopy), GetRawOperandAsInteger(2), srcCopy, GetRawOperandAsInteger(4));
	}
	case HLIL_FORCE_VER_SSA:
		return dest->AddExprWithLocation(HLIL_FORCE_VER_SSA, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), GetRawOperandAsInteger(3));
	case HLIL_ASSERT_SSA:
		return dest->AddExprWithLocation(HLIL_ASSERT_SSA, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), dest->CachePossibleValueSet(GetRawOperandAsPossibleValueSet(2)));
	case HLIL_VAR_SSA:
		return dest->AddExprWithLocation(HLIL_VAR_SSA, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case HLIL_VAR_SSA_PARTIAL:
		return dest->AddExprWithLocation(HLIL_VAR_SSA_PARTIAL, loc, size, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	case HLIL_ARRAY_INDEX_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId indexCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    HLIL_ARRAY_INDEX_SSA, loc, size, srcCopy, GetRawOperandAsInteger(1), indexCopy);
	}
	case HLIL_DEREF_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_DEREF_SSA, loc, size, srcCopy, GetRawOperandAsInteger(1));
	}
	case HLIL_DEREF_FIELD_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_DEREF_FIELD_SSA, loc, size, srcCopy, GetRawOperandAsInteger(1),
		    GetRawOperandAsInteger(2), GetRawOperandAsInteger(3));
	}
	case HLIL_CALL_SSA:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(1))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(HLIL_CALL_SSA, loc, size, destCopy, paramsCopy.size(),
		    dest->AddOperandList(paramsCopy), GetRawOperandAsInteger(3), GetRawOperandAsInteger(4));
	}
	case HLIL_SYSCALL_SSA:
	{
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(HLIL_SYSCALL_SSA, loc, size, paramsCopy.size(),
		    dest->AddOperandList(paramsCopy), GetRawOperandAsInteger(2), GetRawOperandAsInteger(3));
	}
	case HLIL_INTRINSIC_SSA:
	{
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(1))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(HLIL_INTRINSIC_SSA, loc, size, GetRawOperandAsInteger(0), paramsCopy.size(),
		    dest->AddOperandList(paramsCopy), GetRawOperandAsInteger(3), GetRawOperandAsInteger(4));
	}
	case HLIL_VAR_PHI:
		return dest->AddExprWithLocation(HLIL_VAR_PHI, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1),
		    GetRawOperandAsInteger(2), CopyOperandList(dest, *this, 2));
	case HLIL_MEM_PHI:
		return dest->AddExprWithLocation(HLIL_MEM_PHI, loc, size, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1),
		    CopyOperandList(dest, *this, 1));
	case HLIL_BSWAP:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_BSWAP, loc, size, srcCopy);
	}
	case HLIL_POPCNT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_POPCNT, loc, size, srcCopy);
	}
	case HLIL_CLZ:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_CLZ, loc, size, srcCopy);
	}
	case HLIL_CTZ:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_CTZ, loc, size, srcCopy);
	}
	case HLIL_RBIT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_RBIT, loc, size, srcCopy);
	}
	case HLIL_CLS:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_CLS, loc, size, srcCopy);
	}
	case HLIL_MINS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_MINS, loc, size, leftCopy, rightCopy);
	}
	case HLIL_MAXS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_MAXS, loc, size, leftCopy, rightCopy);
	}
	case HLIL_MINU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_MINU, loc, size, leftCopy, rightCopy);
	}
	case HLIL_MAXU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(HLIL_MAXU, loc, size, leftCopy, rightCopy);
	}
	case HLIL_ABS:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(HLIL_ABS, loc, size, srcCopy);
	}
	default:
		throw HighLevelILInstructionAccessException();
	}
}
// END GENERATED hlil-copy


static int CompareExprs(const HighLevelILInstruction& a, const HighLevelILInstruction& b);


template <typename T>
static int CompareValues(const T& a, const T& b)
{
	if (a < b)
		return -1;
	if (b < a)
		return 1;
	return 0;
}


static int CompareValues(const HighLevelILInstruction& a, const HighLevelILInstruction& b)
{
	return CompareExprs(a, b);
}


template <typename List>
static int CompareLists(const List& a, const List& b)
{
	if (int result = CompareValues(a.size(), b.size()))
		return result;
	for (auto i = a.begin(), j = b.begin(); i != a.end(); ++i, ++j)
	{
		if (int result = CompareValues(*i, *j))
			return result;
	}
	return 0;
}


// BEGIN GENERATED hlil-compare: from api/il, do not edit
static int CompareExprs(const HighLevelILInstruction& a, const HighLevelILInstruction& b)
{
	if (int result = CompareValues(a.operation, b.operation))
		return result;
	switch (a.operation)
	{
	case HLIL_BLOCK:
		return CompareLists(a.GetBlockExprs<HLIL_BLOCK>(), b.GetBlockExprs<HLIL_BLOCK>());
	case HLIL_IF:
		if (int result = CompareValues(a.GetConditionExpr<HLIL_IF>(), b.GetConditionExpr<HLIL_IF>()))
			return result;
		if (int result = CompareValues(a.GetTrueExpr<HLIL_IF>(), b.GetTrueExpr<HLIL_IF>()))
			return result;
		return CompareValues(a.GetFalseExpr<HLIL_IF>(), b.GetFalseExpr<HLIL_IF>());
	case HLIL_WHILE:
		if (int result = CompareValues(a.GetConditionExpr<HLIL_WHILE>(), b.GetConditionExpr<HLIL_WHILE>()))
			return result;
		return CompareValues(a.GetLoopExpr<HLIL_WHILE>(), b.GetLoopExpr<HLIL_WHILE>());
	case HLIL_DO_WHILE:
		if (int result = CompareValues(a.GetLoopExpr<HLIL_DO_WHILE>(), b.GetLoopExpr<HLIL_DO_WHILE>()))
			return result;
		return CompareValues(a.GetConditionExpr<HLIL_DO_WHILE>(), b.GetConditionExpr<HLIL_DO_WHILE>());
	case HLIL_FOR:
		if (int result = CompareValues(a.GetInitExpr<HLIL_FOR>(), b.GetInitExpr<HLIL_FOR>()))
			return result;
		if (int result = CompareValues(a.GetConditionExpr<HLIL_FOR>(), b.GetConditionExpr<HLIL_FOR>()))
			return result;
		if (int result = CompareValues(a.GetUpdateExpr<HLIL_FOR>(), b.GetUpdateExpr<HLIL_FOR>()))
			return result;
		return CompareValues(a.GetLoopExpr<HLIL_FOR>(), b.GetLoopExpr<HLIL_FOR>());
	case HLIL_SWITCH:
		if (int result = CompareValues(a.GetConditionExpr<HLIL_SWITCH>(), b.GetConditionExpr<HLIL_SWITCH>()))
			return result;
		if (int result = CompareValues(a.GetDefaultExpr<HLIL_SWITCH>(), b.GetDefaultExpr<HLIL_SWITCH>()))
			return result;
		return CompareLists(a.GetCases<HLIL_SWITCH>(), b.GetCases<HLIL_SWITCH>());
	case HLIL_CASE:
		if (int result = CompareLists(a.GetValueExprs<HLIL_CASE>(), b.GetValueExprs<HLIL_CASE>()))
			return result;
		return CompareValues(a.GetTrueExpr<HLIL_CASE>(), b.GetTrueExpr<HLIL_CASE>());
	case HLIL_JUMP:
		return CompareValues(a.GetDestExpr<HLIL_JUMP>(), b.GetDestExpr<HLIL_JUMP>());
	case HLIL_RET:
		return CompareLists(a.GetSourceExprs<HLIL_RET>(), b.GetSourceExprs<HLIL_RET>());
	case HLIL_GOTO:
		return CompareValues(a.GetTarget<HLIL_GOTO>(), b.GetTarget<HLIL_GOTO>());
	case HLIL_LABEL:
		return CompareValues(a.GetTarget<HLIL_LABEL>(), b.GetTarget<HLIL_LABEL>());
	case HLIL_VAR_DECLARE:
		return CompareValues(a.GetVariable<HLIL_VAR_DECLARE>(), b.GetVariable<HLIL_VAR_DECLARE>());
	case HLIL_VAR_INIT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetDestVariable<HLIL_VAR_INIT>(), b.GetDestVariable<HLIL_VAR_INIT>()))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_VAR_INIT>(), b.GetSourceExpr<HLIL_VAR_INIT>());
	case HLIL_ASSIGN:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetDestExpr<HLIL_ASSIGN>(), b.GetDestExpr<HLIL_ASSIGN>()))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_ASSIGN>(), b.GetSourceExpr<HLIL_ASSIGN>());
	case HLIL_ASSIGN_UNPACK:
		if (int result = CompareLists(a.GetDestExprs<HLIL_ASSIGN_UNPACK>(), b.GetDestExprs<HLIL_ASSIGN_UNPACK>()))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_ASSIGN_UNPACK>(), b.GetSourceExpr<HLIL_ASSIGN_UNPACK>());
	case HLIL_FORCE_VER:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetDestVariable<HLIL_FORCE_VER>(), b.GetDestVariable<HLIL_FORCE_VER>()))
			return result;
		return CompareValues(a.GetVariable<HLIL_FORCE_VER>(), b.GetVariable<HLIL_FORCE_VER>());
	case HLIL_ASSERT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetVariable<HLIL_ASSERT>(), b.GetVariable<HLIL_ASSERT>()))
			return result;
		return CompareValues(a.GetRawOperandAsInteger(1), b.GetRawOperandAsInteger(1));
	case HLIL_VAR:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetVariable<HLIL_VAR>(), b.GetVariable<HLIL_VAR>());
	case HLIL_STRUCT_FIELD:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetSourceExpr<HLIL_STRUCT_FIELD>(), b.GetSourceExpr<HLIL_STRUCT_FIELD>()))
			return result;
		if (int result = CompareValues(a.GetOffset<HLIL_STRUCT_FIELD>(), b.GetOffset<HLIL_STRUCT_FIELD>()))
			return result;
		return CompareValues(a.GetMemberIndex<HLIL_STRUCT_FIELD>(), b.GetMemberIndex<HLIL_STRUCT_FIELD>());
	case HLIL_ARRAY_INDEX:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetSourceExpr<HLIL_ARRAY_INDEX>(), b.GetSourceExpr<HLIL_ARRAY_INDEX>()))
			return result;
		return CompareValues(a.GetIndexExpr<HLIL_ARRAY_INDEX>(), b.GetIndexExpr<HLIL_ARRAY_INDEX>());
	case HLIL_SPLIT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetHighExpr<HLIL_SPLIT>(), b.GetHighExpr<HLIL_SPLIT>()))
			return result;
		return CompareValues(a.GetLowExpr<HLIL_SPLIT>(), b.GetLowExpr<HLIL_SPLIT>());
	case HLIL_DEREF:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_DEREF>(), b.GetSourceExpr<HLIL_DEREF>());
	case HLIL_DEREF_FIELD:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetSourceExpr<HLIL_DEREF_FIELD>(), b.GetSourceExpr<HLIL_DEREF_FIELD>()))
			return result;
		if (int result = CompareValues(a.GetOffset<HLIL_DEREF_FIELD>(), b.GetOffset<HLIL_DEREF_FIELD>()))
			return result;
		return CompareValues(a.GetMemberIndex<HLIL_DEREF_FIELD>(), b.GetMemberIndex<HLIL_DEREF_FIELD>());
	case HLIL_ADDRESS_OF:
		return CompareValues(a.GetSourceExpr<HLIL_ADDRESS_OF>(), b.GetSourceExpr<HLIL_ADDRESS_OF>());
	case HLIL_PASS_BY_REF:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_PASS_BY_REF>(), b.GetSourceExpr<HLIL_PASS_BY_REF>());
	case HLIL_RETURN_BY_REF:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_RETURN_BY_REF>(), b.GetSourceExpr<HLIL_RETURN_BY_REF>());
	case HLIL_CONST:
		return CompareValues(a.GetConstant<HLIL_CONST>(), b.GetConstant<HLIL_CONST>());
	case HLIL_CONST_DATA:
		if (int result = CompareValues(a.GetRawOperandAsInteger(0), b.GetRawOperandAsInteger(0)))
			return result;
		return CompareValues(a.GetRawOperandAsInteger(1), b.GetRawOperandAsInteger(1));
	case HLIL_CONST_PTR:
		return CompareValues(a.GetConstant<HLIL_CONST_PTR>(), b.GetConstant<HLIL_CONST_PTR>());
	case HLIL_EXTERN_PTR:
		if (int result = CompareValues(a.GetConstant<HLIL_EXTERN_PTR>(), b.GetConstant<HLIL_EXTERN_PTR>()))
			return result;
		return CompareValues(a.GetOffset<HLIL_EXTERN_PTR>(), b.GetOffset<HLIL_EXTERN_PTR>());
	case HLIL_FLOAT_CONST:
		return CompareValues(a.GetConstant<HLIL_FLOAT_CONST>(), b.GetConstant<HLIL_FLOAT_CONST>());
	case HLIL_IMPORT:
		return CompareValues(a.GetConstant<HLIL_IMPORT>(), b.GetConstant<HLIL_IMPORT>());
	case HLIL_ADD:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_ADD>(), b.GetLeftExpr<HLIL_ADD>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_ADD>(), b.GetRightExpr<HLIL_ADD>());
	case HLIL_ADC:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_ADC>(), b.GetLeftExpr<HLIL_ADC>()))
			return result;
		if (int result = CompareValues(a.GetRightExpr<HLIL_ADC>(), b.GetRightExpr<HLIL_ADC>()))
			return result;
		return CompareValues(a.GetCarryExpr<HLIL_ADC>(), b.GetCarryExpr<HLIL_ADC>());
	case HLIL_SUB:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_SUB>(), b.GetLeftExpr<HLIL_SUB>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_SUB>(), b.GetRightExpr<HLIL_SUB>());
	case HLIL_SBB:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_SBB>(), b.GetLeftExpr<HLIL_SBB>()))
			return result;
		if (int result = CompareValues(a.GetRightExpr<HLIL_SBB>(), b.GetRightExpr<HLIL_SBB>()))
			return result;
		return CompareValues(a.GetCarryExpr<HLIL_SBB>(), b.GetCarryExpr<HLIL_SBB>());
	case HLIL_AND:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_AND>(), b.GetLeftExpr<HLIL_AND>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_AND>(), b.GetRightExpr<HLIL_AND>());
	case HLIL_OR:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_OR>(), b.GetLeftExpr<HLIL_OR>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_OR>(), b.GetRightExpr<HLIL_OR>());
	case HLIL_XOR:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_XOR>(), b.GetLeftExpr<HLIL_XOR>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_XOR>(), b.GetRightExpr<HLIL_XOR>());
	case HLIL_LSL:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_LSL>(), b.GetLeftExpr<HLIL_LSL>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_LSL>(), b.GetRightExpr<HLIL_LSL>());
	case HLIL_LSR:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_LSR>(), b.GetLeftExpr<HLIL_LSR>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_LSR>(), b.GetRightExpr<HLIL_LSR>());
	case HLIL_ASR:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_ASR>(), b.GetLeftExpr<HLIL_ASR>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_ASR>(), b.GetRightExpr<HLIL_ASR>());
	case HLIL_ROL:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_ROL>(), b.GetLeftExpr<HLIL_ROL>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_ROL>(), b.GetRightExpr<HLIL_ROL>());
	case HLIL_RLC:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_RLC>(), b.GetLeftExpr<HLIL_RLC>()))
			return result;
		if (int result = CompareValues(a.GetRightExpr<HLIL_RLC>(), b.GetRightExpr<HLIL_RLC>()))
			return result;
		return CompareValues(a.GetCarryExpr<HLIL_RLC>(), b.GetCarryExpr<HLIL_RLC>());
	case HLIL_ROR:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_ROR>(), b.GetLeftExpr<HLIL_ROR>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_ROR>(), b.GetRightExpr<HLIL_ROR>());
	case HLIL_RRC:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_RRC>(), b.GetLeftExpr<HLIL_RRC>()))
			return result;
		if (int result = CompareValues(a.GetRightExpr<HLIL_RRC>(), b.GetRightExpr<HLIL_RRC>()))
			return result;
		return CompareValues(a.GetCarryExpr<HLIL_RRC>(), b.GetCarryExpr<HLIL_RRC>());
	case HLIL_MUL:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_MUL>(), b.GetLeftExpr<HLIL_MUL>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_MUL>(), b.GetRightExpr<HLIL_MUL>());
	case HLIL_MULU_DP:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_MULU_DP>(), b.GetLeftExpr<HLIL_MULU_DP>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_MULU_DP>(), b.GetRightExpr<HLIL_MULU_DP>());
	case HLIL_MULS_DP:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_MULS_DP>(), b.GetLeftExpr<HLIL_MULS_DP>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_MULS_DP>(), b.GetRightExpr<HLIL_MULS_DP>());
	case HLIL_DIVU:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_DIVU>(), b.GetLeftExpr<HLIL_DIVU>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_DIVU>(), b.GetRightExpr<HLIL_DIVU>());
	case HLIL_DIVU_DP:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_DIVU_DP>(), b.GetLeftExpr<HLIL_DIVU_DP>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_DIVU_DP>(), b.GetRightExpr<HLIL_DIVU_DP>());
	case HLIL_DIVS:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_DIVS>(), b.GetLeftExpr<HLIL_DIVS>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_DIVS>(), b.GetRightExpr<HLIL_DIVS>());
	case HLIL_DIVS_DP:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_DIVS_DP>(), b.GetLeftExpr<HLIL_DIVS_DP>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_DIVS_DP>(), b.GetRightExpr<HLIL_DIVS_DP>());
	case HLIL_MODU:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_MODU>(), b.GetLeftExpr<HLIL_MODU>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_MODU>(), b.GetRightExpr<HLIL_MODU>());
	case HLIL_MODU_DP:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_MODU_DP>(), b.GetLeftExpr<HLIL_MODU_DP>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_MODU_DP>(), b.GetRightExpr<HLIL_MODU_DP>());
	case HLIL_MODS:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_MODS>(), b.GetLeftExpr<HLIL_MODS>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_MODS>(), b.GetRightExpr<HLIL_MODS>());
	case HLIL_MODS_DP:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_MODS_DP>(), b.GetLeftExpr<HLIL_MODS_DP>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_MODS_DP>(), b.GetRightExpr<HLIL_MODS_DP>());
	case HLIL_NEG:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_NEG>(), b.GetSourceExpr<HLIL_NEG>());
	case HLIL_NOT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_NOT>(), b.GetSourceExpr<HLIL_NOT>());
	case HLIL_SX:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_SX>(), b.GetSourceExpr<HLIL_SX>());
	case HLIL_ZX:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_ZX>(), b.GetSourceExpr<HLIL_ZX>());
	case HLIL_LOW_PART:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_LOW_PART>(), b.GetSourceExpr<HLIL_LOW_PART>());
	case HLIL_CALL:
		if (int result = CompareValues(a.GetDestExpr<HLIL_CALL>(), b.GetDestExpr<HLIL_CALL>()))
			return result;
		return CompareLists(a.GetParameterExprs<HLIL_CALL>(), b.GetParameterExprs<HLIL_CALL>());
	case HLIL_CMP_E:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_CMP_E>(), b.GetLeftExpr<HLIL_CMP_E>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_CMP_E>(), b.GetRightExpr<HLIL_CMP_E>());
	case HLIL_CMP_NE:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_CMP_NE>(), b.GetLeftExpr<HLIL_CMP_NE>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_CMP_NE>(), b.GetRightExpr<HLIL_CMP_NE>());
	case HLIL_CMP_SLT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_CMP_SLT>(), b.GetLeftExpr<HLIL_CMP_SLT>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_CMP_SLT>(), b.GetRightExpr<HLIL_CMP_SLT>());
	case HLIL_CMP_ULT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_CMP_ULT>(), b.GetLeftExpr<HLIL_CMP_ULT>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_CMP_ULT>(), b.GetRightExpr<HLIL_CMP_ULT>());
	case HLIL_CMP_SLE:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_CMP_SLE>(), b.GetLeftExpr<HLIL_CMP_SLE>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_CMP_SLE>(), b.GetRightExpr<HLIL_CMP_SLE>());
	case HLIL_CMP_ULE:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_CMP_ULE>(), b.GetLeftExpr<HLIL_CMP_ULE>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_CMP_ULE>(), b.GetRightExpr<HLIL_CMP_ULE>());
	case HLIL_CMP_SGE:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_CMP_SGE>(), b.GetLeftExpr<HLIL_CMP_SGE>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_CMP_SGE>(), b.GetRightExpr<HLIL_CMP_SGE>());
	case HLIL_CMP_UGE:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_CMP_UGE>(), b.GetLeftExpr<HLIL_CMP_UGE>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_CMP_UGE>(), b.GetRightExpr<HLIL_CMP_UGE>());
	case HLIL_CMP_SGT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_CMP_SGT>(), b.GetLeftExpr<HLIL_CMP_SGT>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_CMP_SGT>(), b.GetRightExpr<HLIL_CMP_SGT>());
	case HLIL_CMP_UGT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_CMP_UGT>(), b.GetLeftExpr<HLIL_CMP_UGT>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_CMP_UGT>(), b.GetRightExpr<HLIL_CMP_UGT>());
	case HLIL_TEST_BIT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_TEST_BIT>(), b.GetLeftExpr<HLIL_TEST_BIT>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_TEST_BIT>(), b.GetRightExpr<HLIL_TEST_BIT>());
	case HLIL_BOOL_TO_INT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_BOOL_TO_INT>(), b.GetSourceExpr<HLIL_BOOL_TO_INT>());
	case HLIL_ADD_OVERFLOW:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_ADD_OVERFLOW>(), b.GetLeftExpr<HLIL_ADD_OVERFLOW>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_ADD_OVERFLOW>(), b.GetRightExpr<HLIL_ADD_OVERFLOW>());
	case HLIL_SYSCALL:
		return CompareLists(a.GetParameterExprs<HLIL_SYSCALL>(), b.GetParameterExprs<HLIL_SYSCALL>());
	case HLIL_TAILCALL:
		if (int result = CompareValues(a.GetDestExpr<HLIL_TAILCALL>(), b.GetDestExpr<HLIL_TAILCALL>()))
			return result;
		return CompareLists(a.GetParameterExprs<HLIL_TAILCALL>(), b.GetParameterExprs<HLIL_TAILCALL>());
	case HLIL_INTRINSIC:
		if (int result = CompareValues(a.GetIntrinsic<HLIL_INTRINSIC>(), b.GetIntrinsic<HLIL_INTRINSIC>()))
			return result;
		return CompareLists(a.GetParameterExprs<HLIL_INTRINSIC>(), b.GetParameterExprs<HLIL_INTRINSIC>());
	case HLIL_TRAP:
		return CompareValues(a.GetVector<HLIL_TRAP>(), b.GetVector<HLIL_TRAP>());
	case HLIL_UNIMPL:
		return CompareValues(a.IsUnknown<HLIL_UNIMPL>(), b.IsUnknown<HLIL_UNIMPL>());
	case HLIL_UNIMPL_MEM:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetSourceExpr<HLIL_UNIMPL_MEM>(), b.GetSourceExpr<HLIL_UNIMPL_MEM>()))
			return result;
		return CompareValues(a.IsUnknown<HLIL_UNIMPL_MEM>(), b.IsUnknown<HLIL_UNIMPL_MEM>());
	case HLIL_STRUCT_INIT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareLists(a.GetFieldExprs<HLIL_STRUCT_INIT>(), b.GetFieldExprs<HLIL_STRUCT_INIT>());
	case HLIL_STRUCT_INIT_FIELD:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetOffset<HLIL_STRUCT_INIT_FIELD>(), b.GetOffset<HLIL_STRUCT_INIT_FIELD>()))
			return result;
		if (int result =
		        CompareValues(a.GetMemberIndex<HLIL_STRUCT_INIT_FIELD>(), b.GetMemberIndex<HLIL_STRUCT_INIT_FIELD>()))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_STRUCT_INIT_FIELD>(), b.GetSourceExpr<HLIL_STRUCT_INIT_FIELD>());
	case HLIL_FADD:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FADD>(), b.GetLeftExpr<HLIL_FADD>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FADD>(), b.GetRightExpr<HLIL_FADD>());
	case HLIL_FSUB:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FSUB>(), b.GetLeftExpr<HLIL_FSUB>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FSUB>(), b.GetRightExpr<HLIL_FSUB>());
	case HLIL_FMUL:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FMUL>(), b.GetLeftExpr<HLIL_FMUL>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FMUL>(), b.GetRightExpr<HLIL_FMUL>());
	case HLIL_FDIV:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FDIV>(), b.GetLeftExpr<HLIL_FDIV>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FDIV>(), b.GetRightExpr<HLIL_FDIV>());
	case HLIL_FSQRT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_FSQRT>(), b.GetSourceExpr<HLIL_FSQRT>());
	case HLIL_FNEG:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_FNEG>(), b.GetSourceExpr<HLIL_FNEG>());
	case HLIL_FABS:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_FABS>(), b.GetSourceExpr<HLIL_FABS>());
	case HLIL_FLOAT_TO_INT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_FLOAT_TO_INT>(), b.GetSourceExpr<HLIL_FLOAT_TO_INT>());
	case HLIL_INT_TO_FLOAT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_INT_TO_FLOAT>(), b.GetSourceExpr<HLIL_INT_TO_FLOAT>());
	case HLIL_FLOAT_CONV:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_FLOAT_CONV>(), b.GetSourceExpr<HLIL_FLOAT_CONV>());
	case HLIL_ROUND_TO_INT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_ROUND_TO_INT>(), b.GetSourceExpr<HLIL_ROUND_TO_INT>());
	case HLIL_FLOOR:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_FLOOR>(), b.GetSourceExpr<HLIL_FLOOR>());
	case HLIL_CEIL:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_CEIL>(), b.GetSourceExpr<HLIL_CEIL>());
	case HLIL_FTRUNC:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_FTRUNC>(), b.GetSourceExpr<HLIL_FTRUNC>());
	case HLIL_FCMP_E:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FCMP_E>(), b.GetLeftExpr<HLIL_FCMP_E>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FCMP_E>(), b.GetRightExpr<HLIL_FCMP_E>());
	case HLIL_FCMP_NE:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FCMP_NE>(), b.GetLeftExpr<HLIL_FCMP_NE>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FCMP_NE>(), b.GetRightExpr<HLIL_FCMP_NE>());
	case HLIL_FCMP_LT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FCMP_LT>(), b.GetLeftExpr<HLIL_FCMP_LT>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FCMP_LT>(), b.GetRightExpr<HLIL_FCMP_LT>());
	case HLIL_FCMP_LE:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FCMP_LE>(), b.GetLeftExpr<HLIL_FCMP_LE>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FCMP_LE>(), b.GetRightExpr<HLIL_FCMP_LE>());
	case HLIL_FCMP_GE:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FCMP_GE>(), b.GetLeftExpr<HLIL_FCMP_GE>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FCMP_GE>(), b.GetRightExpr<HLIL_FCMP_GE>());
	case HLIL_FCMP_GT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FCMP_GT>(), b.GetLeftExpr<HLIL_FCMP_GT>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FCMP_GT>(), b.GetRightExpr<HLIL_FCMP_GT>());
	case HLIL_FCMP_O:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FCMP_O>(), b.GetLeftExpr<HLIL_FCMP_O>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FCMP_O>(), b.GetRightExpr<HLIL_FCMP_O>());
	case HLIL_FCMP_UO:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_FCMP_UO>(), b.GetLeftExpr<HLIL_FCMP_UO>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_FCMP_UO>(), b.GetRightExpr<HLIL_FCMP_UO>());
	case HLIL_WHILE_SSA:
		if (int result =
		        CompareValues(a.GetConditionPhiExpr<HLIL_WHILE_SSA>(), b.GetConditionPhiExpr<HLIL_WHILE_SSA>()))
			return result;
		if (int result = CompareValues(a.GetConditionExpr<HLIL_WHILE_SSA>(), b.GetConditionExpr<HLIL_WHILE_SSA>()))
			return result;
		return CompareValues(a.GetLoopExpr<HLIL_WHILE_SSA>(), b.GetLoopExpr<HLIL_WHILE_SSA>());
	case HLIL_DO_WHILE_SSA:
		if (int result = CompareValues(a.GetLoopExpr<HLIL_DO_WHILE_SSA>(), b.GetLoopExpr<HLIL_DO_WHILE_SSA>()))
			return result;
		if (int result =
		        CompareValues(a.GetConditionPhiExpr<HLIL_DO_WHILE_SSA>(), b.GetConditionPhiExpr<HLIL_DO_WHILE_SSA>()))
			return result;
		return CompareValues(a.GetConditionExpr<HLIL_DO_WHILE_SSA>(), b.GetConditionExpr<HLIL_DO_WHILE_SSA>());
	case HLIL_FOR_SSA:
		if (int result = CompareValues(a.GetInitExpr<HLIL_FOR_SSA>(), b.GetInitExpr<HLIL_FOR_SSA>()))
			return result;
		if (int result = CompareValues(a.GetConditionPhiExpr<HLIL_FOR_SSA>(), b.GetConditionPhiExpr<HLIL_FOR_SSA>()))
			return result;
		if (int result = CompareValues(a.GetConditionExpr<HLIL_FOR_SSA>(), b.GetConditionExpr<HLIL_FOR_SSA>()))
			return result;
		if (int result = CompareValues(a.GetUpdateExpr<HLIL_FOR_SSA>(), b.GetUpdateExpr<HLIL_FOR_SSA>()))
			return result;
		return CompareValues(a.GetLoopExpr<HLIL_FOR_SSA>(), b.GetLoopExpr<HLIL_FOR_SSA>());
	case HLIL_VAR_INIT_SSA:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result =
		        CompareValues(a.GetDestSSAVariable<HLIL_VAR_INIT_SSA>(), b.GetDestSSAVariable<HLIL_VAR_INIT_SSA>()))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_VAR_INIT_SSA>(), b.GetSourceExpr<HLIL_VAR_INIT_SSA>());
	case HLIL_ASSIGN_MEM_SSA:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetDestExpr<HLIL_ASSIGN_MEM_SSA>(), b.GetDestExpr<HLIL_ASSIGN_MEM_SSA>()))
			return result;
		if (int result = CompareValues(
		        a.GetDestMemoryVersion<HLIL_ASSIGN_MEM_SSA>(), b.GetDestMemoryVersion<HLIL_ASSIGN_MEM_SSA>()))
			return result;
		if (int result = CompareValues(a.GetSourceExpr<HLIL_ASSIGN_MEM_SSA>(), b.GetSourceExpr<HLIL_ASSIGN_MEM_SSA>()))
			return result;
		return CompareValues(
		    a.GetSourceMemoryVersion<HLIL_ASSIGN_MEM_SSA>(), b.GetSourceMemoryVersion<HLIL_ASSIGN_MEM_SSA>());
	case HLIL_ASSIGN_UNPACK_MEM_SSA:
		if (int result = CompareLists(
		        a.GetDestExprs<HLIL_ASSIGN_UNPACK_MEM_SSA>(), b.GetDestExprs<HLIL_ASSIGN_UNPACK_MEM_SSA>()))
			return result;
		if (int result = CompareValues(a.GetDestMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>(),
		        b.GetDestMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>()))
			return result;
		if (int result = CompareValues(
		        a.GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>(), b.GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>()))
			return result;
		return CompareValues(a.GetSourceMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>(),
		    b.GetSourceMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>());
	case HLIL_FORCE_VER_SSA:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result =
		        CompareValues(a.GetDestSSAVariable<HLIL_FORCE_VER_SSA>(), b.GetDestSSAVariable<HLIL_FORCE_VER_SSA>()))
			return result;
		return CompareValues(a.GetSSAVariable<HLIL_FORCE_VER_SSA>(), b.GetSSAVariable<HLIL_FORCE_VER_SSA>());
	case HLIL_ASSERT_SSA:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetSSAVariable<HLIL_ASSERT_SSA>(), b.GetSSAVariable<HLIL_ASSERT_SSA>()))
			return result;
		return CompareValues(a.GetRawOperandAsInteger(2), b.GetRawOperandAsInteger(2));
	case HLIL_VAR_SSA:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSSAVariable<HLIL_VAR_SSA>(), b.GetSSAVariable<HLIL_VAR_SSA>());
	case HLIL_VAR_SSA_PARTIAL:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(
		        a.GetDestSSAVariable<HLIL_VAR_SSA_PARTIAL>(), b.GetDestSSAVariable<HLIL_VAR_SSA_PARTIAL>()))
			return result;
		return CompareValues(
		    a.GetSourceSSAVariable<HLIL_VAR_SSA_PARTIAL>(), b.GetSourceSSAVariable<HLIL_VAR_SSA_PARTIAL>());
	case HLIL_ARRAY_INDEX_SSA:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result =
		        CompareValues(a.GetSourceExpr<HLIL_ARRAY_INDEX_SSA>(), b.GetSourceExpr<HLIL_ARRAY_INDEX_SSA>()))
			return result;
		if (int result = CompareValues(
		        a.GetSourceMemoryVersion<HLIL_ARRAY_INDEX_SSA>(), b.GetSourceMemoryVersion<HLIL_ARRAY_INDEX_SSA>()))
			return result;
		return CompareValues(a.GetIndexExpr<HLIL_ARRAY_INDEX_SSA>(), b.GetIndexExpr<HLIL_ARRAY_INDEX_SSA>());
	case HLIL_DEREF_SSA:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetSourceExpr<HLIL_DEREF_SSA>(), b.GetSourceExpr<HLIL_DEREF_SSA>()))
			return result;
		return CompareValues(a.GetSourceMemoryVersion<HLIL_DEREF_SSA>(), b.GetSourceMemoryVersion<HLIL_DEREF_SSA>());
	case HLIL_DEREF_FIELD_SSA:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result =
		        CompareValues(a.GetSourceExpr<HLIL_DEREF_FIELD_SSA>(), b.GetSourceExpr<HLIL_DEREF_FIELD_SSA>()))
			return result;
		if (int result = CompareValues(
		        a.GetSourceMemoryVersion<HLIL_DEREF_FIELD_SSA>(), b.GetSourceMemoryVersion<HLIL_DEREF_FIELD_SSA>()))
			return result;
		if (int result = CompareValues(a.GetOffset<HLIL_DEREF_FIELD_SSA>(), b.GetOffset<HLIL_DEREF_FIELD_SSA>()))
			return result;
		return CompareValues(a.GetMemberIndex<HLIL_DEREF_FIELD_SSA>(), b.GetMemberIndex<HLIL_DEREF_FIELD_SSA>());
	case HLIL_CALL_SSA:
		if (int result = CompareValues(a.GetDestExpr<HLIL_CALL_SSA>(), b.GetDestExpr<HLIL_CALL_SSA>()))
			return result;
		if (int result = CompareLists(a.GetParameterExprs<HLIL_CALL_SSA>(), b.GetParameterExprs<HLIL_CALL_SSA>()))
			return result;
		if (int result =
		        CompareValues(a.GetDestMemoryVersion<HLIL_CALL_SSA>(), b.GetDestMemoryVersion<HLIL_CALL_SSA>()))
			return result;
		return CompareValues(a.GetSourceMemoryVersion<HLIL_CALL_SSA>(), b.GetSourceMemoryVersion<HLIL_CALL_SSA>());
	case HLIL_SYSCALL_SSA:
		if (int result = CompareLists(a.GetParameterExprs<HLIL_SYSCALL_SSA>(), b.GetParameterExprs<HLIL_SYSCALL_SSA>()))
			return result;
		if (int result =
		        CompareValues(a.GetDestMemoryVersion<HLIL_SYSCALL_SSA>(), b.GetDestMemoryVersion<HLIL_SYSCALL_SSA>()))
			return result;
		return CompareValues(
		    a.GetSourceMemoryVersion<HLIL_SYSCALL_SSA>(), b.GetSourceMemoryVersion<HLIL_SYSCALL_SSA>());
	case HLIL_INTRINSIC_SSA:
		if (int result = CompareValues(a.GetIntrinsic<HLIL_INTRINSIC_SSA>(), b.GetIntrinsic<HLIL_INTRINSIC_SSA>()))
			return result;
		if (int result =
		        CompareLists(a.GetParameterExprs<HLIL_INTRINSIC_SSA>(), b.GetParameterExprs<HLIL_INTRINSIC_SSA>()))
			return result;
		if (int result = CompareValues(
		        a.GetDestMemoryVersion<HLIL_INTRINSIC_SSA>(), b.GetDestMemoryVersion<HLIL_INTRINSIC_SSA>()))
			return result;
		return CompareValues(
		    a.GetSourceMemoryVersion<HLIL_INTRINSIC_SSA>(), b.GetSourceMemoryVersion<HLIL_INTRINSIC_SSA>());
	case HLIL_VAR_PHI:
		if (int result = CompareValues(a.GetDestSSAVariable<HLIL_VAR_PHI>(), b.GetDestSSAVariable<HLIL_VAR_PHI>()))
			return result;
		return CompareLists(a.GetSourceSSAVariables<HLIL_VAR_PHI>(), b.GetSourceSSAVariables<HLIL_VAR_PHI>());
	case HLIL_MEM_PHI:
		if (int result = CompareValues(a.GetDestMemoryVersion<HLIL_MEM_PHI>(), b.GetDestMemoryVersion<HLIL_MEM_PHI>()))
			return result;
		return CompareLists(a.GetSourceMemoryVersions<HLIL_MEM_PHI>(), b.GetSourceMemoryVersions<HLIL_MEM_PHI>());
	case HLIL_BSWAP:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_BSWAP>(), b.GetSourceExpr<HLIL_BSWAP>());
	case HLIL_POPCNT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_POPCNT>(), b.GetSourceExpr<HLIL_POPCNT>());
	case HLIL_CLZ:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_CLZ>(), b.GetSourceExpr<HLIL_CLZ>());
	case HLIL_CTZ:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_CTZ>(), b.GetSourceExpr<HLIL_CTZ>());
	case HLIL_RBIT:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_RBIT>(), b.GetSourceExpr<HLIL_RBIT>());
	case HLIL_CLS:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_CLS>(), b.GetSourceExpr<HLIL_CLS>());
	case HLIL_MINS:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_MINS>(), b.GetLeftExpr<HLIL_MINS>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_MINS>(), b.GetRightExpr<HLIL_MINS>());
	case HLIL_MAXS:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_MAXS>(), b.GetLeftExpr<HLIL_MAXS>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_MAXS>(), b.GetRightExpr<HLIL_MAXS>());
	case HLIL_MINU:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_MINU>(), b.GetLeftExpr<HLIL_MINU>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_MINU>(), b.GetRightExpr<HLIL_MINU>());
	case HLIL_MAXU:
		if (int result = CompareValues(a.size, b.size))
			return result;
		if (int result = CompareValues(a.GetLeftExpr<HLIL_MAXU>(), b.GetLeftExpr<HLIL_MAXU>()))
			return result;
		return CompareValues(a.GetRightExpr<HLIL_MAXU>(), b.GetRightExpr<HLIL_MAXU>());
	case HLIL_ABS:
		if (int result = CompareValues(a.size, b.size))
			return result;
		return CompareValues(a.GetSourceExpr<HLIL_ABS>(), b.GetSourceExpr<HLIL_ABS>());
	default:
		return 0;
	}
}
// END GENERATED hlil-compare


bool HighLevelILInstruction::operator<(const HighLevelILInstruction& other) const
{
	return CompareExprs(*this, other) < 0;
}


bool HighLevelILInstruction::operator==(const HighLevelILInstruction& other) const
{
	return CompareExprs(*this, other) == 0;
}


bool HighLevelILInstruction::operator!=(const HighLevelILInstruction& other) const
{
	return !(*this == other);
}


bool HighLevelILInstruction::GetOperandIndexForUsage(HighLevelILOperandUsage usage, size_t& operandIndex) const
{
	std::optional<HighLevelILOperandLocation> location = OperandLocationForUsage(operation, usage);
	if (!location)
		return false;

	operandIndex = location->partial ? location->slot + 2 : location->slot;
	return true;
}


// BEGIN GENERATED hlil-instruction-getters: from api/il, do not edit
HighLevelILInstructionList HighLevelILInstruction::GetBlockExprs() const
{
	return OperandForUsages(*this, {BlockExprsHighLevelOperandUsage}).GetExprList();
}


HighLevelILInstruction HighLevelILInstruction::GetCarryExpr() const
{
	return OperandForUsages(*this, {CarryExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstructionList HighLevelILInstruction::GetCases() const
{
	return OperandForUsages(*this, {CasesHighLevelOperandUsage}).GetExprList();
}


HighLevelILInstruction HighLevelILInstruction::GetConditionExpr() const
{
	return OperandForUsages(*this, {ConditionExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstruction HighLevelILInstruction::GetConditionPhiExpr() const
{
	return OperandForUsages(*this, {ConditionPhiExprHighLevelOperandUsage}).GetExpr();
}


int64_t HighLevelILInstruction::GetConstant() const
{
	return OperandForUsages(*this, {ConstantHighLevelOperandUsage}).GetInteger();
}


ConstantData HighLevelILInstruction::GetConstantData() const
{
	return OperandForUsages(*this, {ConstantDataHighLevelOperandUsage}).GetConstantData();
}


PossibleValueSet HighLevelILInstruction::GetConstraint() const
{
	return OperandForUsages(*this, {ConstraintHighLevelOperandUsage}).GetConstraint();
}


HighLevelILInstruction HighLevelILInstruction::GetDefaultExpr() const
{
	return OperandForUsages(*this, {DefaultExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstruction HighLevelILInstruction::GetDestExpr() const
{
	return OperandForUsages(*this, {DestExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstructionList HighLevelILInstruction::GetDestExprs() const
{
	return OperandForUsages(*this, {DestExprsHighLevelOperandUsage}).GetExprList();
}


size_t HighLevelILInstruction::GetDestMemoryVersion() const
{
	return OperandForUsages(*this, {DestMemoryVersionHighLevelOperandUsage}).GetIndex();
}


SSAVariable HighLevelILInstruction::GetDestSSAVariable() const
{
	return OperandForUsages(*this, {DestSSAVariableHighLevelOperandUsage}).GetSSAVariable();
}


Variable HighLevelILInstruction::GetDestVariable() const
{
	return OperandForUsages(*this, {DestVariableHighLevelOperandUsage}).GetVariable();
}


HighLevelILInstruction HighLevelILInstruction::GetFalseExpr() const
{
	return OperandForUsages(*this, {FalseExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstructionList HighLevelILInstruction::GetFieldExprs() const
{
	return OperandForUsages(*this, {FieldExprsHighLevelOperandUsage}).GetExprList();
}


HighLevelILInstruction HighLevelILInstruction::GetHighExpr() const
{
	return OperandForUsages(*this, {HighExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstruction HighLevelILInstruction::GetIndexExpr() const
{
	return OperandForUsages(*this, {IndexExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstruction HighLevelILInstruction::GetInitExpr() const
{
	return OperandForUsages(*this, {InitExprHighLevelOperandUsage}).GetExpr();
}


uint32_t HighLevelILInstruction::GetIntrinsic() const
{
	return OperandForUsages(*this, {IntrinsicHighLevelOperandUsage}).GetIntrinsic();
}


HighLevelILInstruction HighLevelILInstruction::GetLeftExpr() const
{
	return OperandForUsages(*this, {LeftExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstruction HighLevelILInstruction::GetLoopExpr() const
{
	return OperandForUsages(*this, {LoopExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstruction HighLevelILInstruction::GetLowExpr() const
{
	return OperandForUsages(*this, {LowExprHighLevelOperandUsage}).GetExpr();
}


size_t HighLevelILInstruction::GetMemberIndex() const
{
	return OperandForUsages(*this, {MemberIndexHighLevelOperandUsage}).GetIndex();
}


uint64_t HighLevelILInstruction::GetOffset() const
{
	return OperandForUsages(*this, {OffsetHighLevelOperandUsage}).GetInteger();
}


HighLevelILInstructionList HighLevelILInstruction::GetParameterExprs() const
{
	return OperandForUsages(*this, {ParameterExprsHighLevelOperandUsage}).GetExprList();
}


HighLevelILInstruction HighLevelILInstruction::GetRightExpr() const
{
	return OperandForUsages(*this, {RightExprHighLevelOperandUsage}).GetExpr();
}


SSAVariable HighLevelILInstruction::GetSSAVariable() const
{
	return OperandForUsages(*this, {SSAVariableHighLevelOperandUsage}).GetSSAVariable();
}


HighLevelILInstruction HighLevelILInstruction::GetSourceExpr() const
{
	return OperandForUsages(*this, {SourceExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstructionList HighLevelILInstruction::GetSourceExprs() const
{
	return OperandForUsages(*this, {SourceExprsHighLevelOperandUsage}).GetExprList();
}


size_t HighLevelILInstruction::GetSourceMemoryVersion() const
{
	return OperandForUsages(*this, {SourceMemoryVersionHighLevelOperandUsage}).GetIndex();
}


HighLevelILIndexList HighLevelILInstruction::GetSourceMemoryVersions() const
{
	return OperandForUsages(*this, {SourceMemoryVersionsHighLevelOperandUsage}).GetIndexList();
}


SSAVariable HighLevelILInstruction::GetSourceSSAVariable() const
{
	return OperandForUsages(*this, {PartialSSAVariableSourceHighLevelOperandUsage}).GetSSAVariable();
}


HighLevelILSSAVariableList HighLevelILInstruction::GetSourceSSAVariables() const
{
	return OperandForUsages(*this, {SourceSSAVariablesHighLevelOperandUsage}).GetSSAVariableList();
}


uint64_t HighLevelILInstruction::GetTarget() const
{
	return OperandForUsages(*this, {TargetHighLevelOperandUsage}).GetIndex();
}


HighLevelILInstruction HighLevelILInstruction::GetTrueExpr() const
{
	return OperandForUsages(*this, {TrueExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstruction HighLevelILInstruction::GetUpdateExpr() const
{
	return OperandForUsages(*this, {UpdateExprHighLevelOperandUsage}).GetExpr();
}


HighLevelILInstructionList HighLevelILInstruction::GetValueExprs() const
{
	return OperandForUsages(*this, {ValueExprsHighLevelOperandUsage}).GetExprList();
}


Variable HighLevelILInstruction::GetVariable() const
{
	return OperandForUsages(*this, {VariableHighLevelOperandUsage}).GetVariable();
}


int64_t HighLevelILInstruction::GetVector() const
{
	return OperandForUsages(*this, {VectorHighLevelOperandUsage}).GetInteger();
}


bool HighLevelILInstruction::IsUnknown() const
{
	switch (operation)
	{
	case HLIL_UNIMPL:
		return IsUnknown<HLIL_UNIMPL>();
	case HLIL_UNIMPL_MEM:
		return IsUnknown<HLIL_UNIMPL_MEM>();
	default:
		throw HighLevelILInstructionAccessException();
	}
}
// END GENERATED hlil-instruction-getters


bool HighLevelILInstruction::CanCollapse(int operation)
{
	switch (operation)
	{
		case HLIL_IF:
		case HLIL_WHILE:
		case HLIL_WHILE_SSA:
		case HLIL_DO_WHILE:
		case HLIL_DO_WHILE_SSA:
		case HLIL_FOR:
		case HLIL_FOR_SSA:
		case HLIL_SWITCH:
		case HLIL_CASE:
			return true;
		default:
			return false;
	}
}


// BEGIN GENERATED hlil-builders: from api/il, do not edit
ExprId HighLevelILFunction::Nop(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_NOP, loc, 0);
}


ExprId HighLevelILFunction::Block(const vector<ExprId>& body, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_BLOCK, loc, 0, body.size(), AddOperandList(body));
}


ExprId HighLevelILFunction::If(ExprId condition, ExprId trueExpr, ExprId falseExpr, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_IF, loc, 0, condition, trueExpr, falseExpr);
}


ExprId HighLevelILFunction::While(ExprId condition, ExprId body, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_WHILE, loc, 0, condition, body);
}


ExprId HighLevelILFunction::DoWhile(ExprId body, ExprId condition, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DO_WHILE, loc, 0, body, condition);
}


ExprId HighLevelILFunction::For(ExprId init, ExprId condition, ExprId update, ExprId body, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FOR, loc, 0, init, condition, update, body);
}


ExprId HighLevelILFunction::Switch(
    ExprId condition, ExprId defaultExpr, const vector<ExprId>& cases, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SWITCH, loc, 0, condition, defaultExpr, cases.size(), AddOperandList(cases));
}


ExprId HighLevelILFunction::Case(const vector<ExprId>& values, ExprId body, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CASE, loc, 0, values.size(), AddOperandList(values), body);
}


ExprId HighLevelILFunction::Break(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_BREAK, loc, 0);
}


ExprId HighLevelILFunction::Continue(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CONTINUE, loc, 0);
}


ExprId HighLevelILFunction::Jump(ExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_JUMP, loc, 0, dest);
}


ExprId HighLevelILFunction::Return(const vector<ExprId>& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_RET, loc, 0, src.size(), AddOperandList(src));
}


ExprId HighLevelILFunction::NoReturn(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_NORET, loc, 0);
}


ExprId HighLevelILFunction::Goto(uint64_t target, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_GOTO, loc, 0, target);
}


ExprId HighLevelILFunction::Label(uint64_t target, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_LABEL, loc, 0, target);
}


ExprId HighLevelILFunction::VarDeclare(const Variable& var, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR_DECLARE, loc, 0, var.ToIdentifier());
}


ExprId HighLevelILFunction::VarInit(size_t size, const Variable& dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR_INIT, loc, size, dest.ToIdentifier(), src);
}


ExprId HighLevelILFunction::Assign(size_t size, ExprId dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASSIGN, loc, size, dest, src);
}


ExprId HighLevelILFunction::AssignUnpack(const vector<ExprId>& dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASSIGN_UNPACK, loc, 0, dest.size(), AddOperandList(dest), src);
}


ExprId HighLevelILFunction::ForceVer(
    size_t size, const Variable& dest, const Variable& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FORCE_VER, loc, size, dest.ToIdentifier(), src.ToIdentifier());
}


ExprId HighLevelILFunction::Assert(
    size_t size, const Variable& src, const PossibleValueSet& constraint, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASSERT, loc, size, src.ToIdentifier(), CachePossibleValueSet(constraint));
}


ExprId HighLevelILFunction::Var(size_t size, const Variable& var, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR, loc, size, var.ToIdentifier());
}


ExprId HighLevelILFunction::StructField(
    size_t size, ExprId src, uint64_t offset, size_t memberIndex, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_STRUCT_FIELD, loc, size, src, offset, memberIndex);
}


ExprId HighLevelILFunction::ArrayIndex(size_t size, ExprId src, ExprId index, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ARRAY_INDEX, loc, size, src, index);
}


ExprId HighLevelILFunction::Split(size_t size, ExprId high, ExprId low, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SPLIT, loc, size, high, low);
}


ExprId HighLevelILFunction::Deref(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DEREF, loc, size, src);
}


ExprId HighLevelILFunction::DerefField(
    size_t size, ExprId src, uint64_t offset, size_t memberIndex, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DEREF_FIELD, loc, size, src, offset, memberIndex);
}


ExprId HighLevelILFunction::AddressOf(ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ADDRESS_OF, loc, 0, src);
}


ExprId HighLevelILFunction::PassByRef(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_PASS_BY_REF, loc, size, src);
}


ExprId HighLevelILFunction::ReturnByRef(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_RETURN_BY_REF, loc, size, src);
}


ExprId HighLevelILFunction::Const(size_t size, uint64_t constant, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CONST, loc, size, constant);
}


ExprId HighLevelILFunction::ConstData(size_t size, const ConstantData& constantData, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CONST_DATA, loc, size, constantData.state, constantData.value);
}


ExprId HighLevelILFunction::ConstPointer(size_t size, uint64_t constant, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CONST_PTR, loc, size, constant);
}


ExprId HighLevelILFunction::ExternPointer(size_t size, uint64_t constant, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_EXTERN_PTR, loc, size, constant, offset);
}


ExprId HighLevelILFunction::FloatConstRaw(size_t size, uint64_t constant, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FLOAT_CONST, loc, size, constant);
}


ExprId HighLevelILFunction::ImportedAddress(size_t size, uint64_t constant, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_IMPORT, loc, size, constant);
}


ExprId HighLevelILFunction::Add(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ADD, loc, size, left, right);
}


ExprId HighLevelILFunction::AddWithCarry(
    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ADC, loc, size, left, right, carry);
}


ExprId HighLevelILFunction::Sub(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SUB, loc, size, left, right);
}


ExprId HighLevelILFunction::SubWithBorrow(
    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SBB, loc, size, left, right, carry);
}


ExprId HighLevelILFunction::And(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_AND, loc, size, left, right);
}


ExprId HighLevelILFunction::Or(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_OR, loc, size, left, right);
}


ExprId HighLevelILFunction::Xor(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_XOR, loc, size, left, right);
}


ExprId HighLevelILFunction::ShiftLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_LSL, loc, size, left, right);
}


ExprId HighLevelILFunction::LogicalShiftRight(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_LSR, loc, size, left, right);
}


ExprId HighLevelILFunction::ArithShiftRight(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASR, loc, size, left, right);
}


ExprId HighLevelILFunction::RotateLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ROL, loc, size, left, right);
}


ExprId HighLevelILFunction::RotateLeftCarry(
    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_RLC, loc, size, left, right, carry);
}


ExprId HighLevelILFunction::RotateRight(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ROR, loc, size, left, right);
}


ExprId HighLevelILFunction::RotateRightCarry(
    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_RRC, loc, size, left, right, carry);
}


ExprId HighLevelILFunction::Mult(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MUL, loc, size, left, right);
}


ExprId HighLevelILFunction::MultDoublePrecUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MULU_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::MultDoublePrecSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MULS_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::DivUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVU, loc, size, left, right);
}


ExprId HighLevelILFunction::DivDoublePrecUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVU_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::DivSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVS, loc, size, left, right);
}


ExprId HighLevelILFunction::DivDoublePrecSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVS_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::ModUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MODU, loc, size, left, right);
}


ExprId HighLevelILFunction::ModDoublePrecUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MODU_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::ModSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MODS, loc, size, left, right);
}


ExprId HighLevelILFunction::ModDoublePrecSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MODS_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::Neg(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_NEG, loc, size, src);
}


ExprId HighLevelILFunction::Not(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_NOT, loc, size, src);
}


ExprId HighLevelILFunction::SignExtend(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SX, loc, size, src);
}


ExprId HighLevelILFunction::ZeroExtend(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ZX, loc, size, src);
}


ExprId HighLevelILFunction::LowPart(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_LOW_PART, loc, size, src);
}


ExprId HighLevelILFunction::Call(ExprId dest, const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CALL, loc, 0, dest, params.size(), AddOperandList(params));
}


ExprId HighLevelILFunction::CompareEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_E, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareNotEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_NE, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareSignedLessThan(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_SLT, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareUnsignedLessThan(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_ULT, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareSignedLessEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_SLE, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareUnsignedLessEqual(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_ULE, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareSignedGreaterEqual(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_SGE, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareUnsignedGreaterEqual(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_UGE, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareSignedGreaterThan(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_SGT, loc, size, left, right);
}


ExprId HighLevelILFunction::CompareUnsignedGreaterThan(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CMP_UGT, loc, size, left, right);
}


ExprId HighLevelILFunction::TestBit(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_TEST_BIT, loc, size, left, right);
}


ExprId HighLevelILFunction::BoolToInt(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_BOOL_TO_INT, loc, size, src);
}


ExprId HighLevelILFunction::AddOverflow(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ADD_OVERFLOW, loc, size, left, right);
}


ExprId HighLevelILFunction::Syscall(const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SYSCALL, loc, 0, params.size(), AddOperandList(params));
}


ExprId HighLevelILFunction::TailCall(ExprId dest, const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_TAILCALL, loc, 0, dest, params.size(), AddOperandList(params));
}


ExprId HighLevelILFunction::Intrinsic(uint32_t intrinsic, const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_INTRINSIC, loc, 0, intrinsic, params.size(), AddOperandList(params));
}


ExprId HighLevelILFunction::Breakpoint(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_BP, loc, 0);
}


ExprId HighLevelILFunction::Trap(int64_t vector, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_TRAP, loc, 0, vector);
}


ExprId HighLevelILFunction::Undefined(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNDEF, loc, 0);
}


ExprId HighLevelILFunction::Unimplemented(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNIMPL, loc, 0, 0);
}


ExprId HighLevelILFunction::Unknown(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNIMPL, loc, 0, 1);
}


ExprId HighLevelILFunction::UnimplementedMemoryRef(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNIMPL_MEM, loc, size, src, 0);
}


ExprId HighLevelILFunction::UnknownMemoryRef(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNIMPL_MEM, loc, size, src, 1);
}


ExprId HighLevelILFunction::StructInit(size_t size, const vector<ExprId>& fields, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_STRUCT_INIT, loc, size, fields.size(), AddOperandList(fields));
}


ExprId HighLevelILFunction::StructInitField(
    size_t size, uint64_t offset, size_t memberIndex, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_STRUCT_INIT_FIELD, loc, size, offset, memberIndex, src);
}


ExprId HighLevelILFunction::FloatAdd(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FADD, loc, size, left, right);
}


ExprId HighLevelILFunction::FloatSub(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FSUB, loc, size, left, right);
}


ExprId HighLevelILFunction::FloatMult(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FMUL, loc, size, left, right);
}


ExprId HighLevelILFunction::FloatDiv(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FDIV, loc, size, left, right);
}


ExprId HighLevelILFunction::FloatSqrt(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FSQRT, loc, size, src);
}


ExprId HighLevelILFunction::FloatNeg(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FNEG, loc, size, src);
}


ExprId HighLevelILFunction::FloatAbs(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FABS, loc, size, src);
}


ExprId HighLevelILFunction::FloatToInt(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FLOAT_TO_INT, loc, size, src);
}


ExprId HighLevelILFunction::IntToFloat(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_INT_TO_FLOAT, loc, size, src);
}


ExprId HighLevelILFunction::FloatConvert(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FLOAT_CONV, loc, size, src);
}


ExprId HighLevelILFunction::RoundToInt(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ROUND_TO_INT, loc, size, src);
}


ExprId HighLevelILFunction::Floor(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FLOOR, loc, size, src);
}


ExprId HighLevelILFunction::Ceil(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CEIL, loc, size, src);
}


ExprId HighLevelILFunction::FloatTrunc(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FTRUNC, loc, size, src);
}


ExprId HighLevelILFunction::FloatCompareEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_E, loc, size, left, right);
}


ExprId HighLevelILFunction::FloatCompareNotEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_NE, loc, size, left, right);
}


ExprId HighLevelILFunction::FloatCompareLessThan(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_LT, loc, size, left, right);
}


ExprId HighLevelILFunction::FloatCompareLessEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_LE, loc, size, left, right);
}


ExprId HighLevelILFunction::FloatCompareGreaterEqual(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_GE, loc, size, left, right);
}


ExprId HighLevelILFunction::FloatCompareGreaterThan(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_GT, loc, size, left, right);
}


ExprId HighLevelILFunction::FloatCompareOrdered(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_O, loc, size, left, right);
}


ExprId HighLevelILFunction::FloatCompareUnordered(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_UO, loc, size, left, right);
}


ExprId HighLevelILFunction::Unreachable(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNREACHABLE, loc, 0);
}


ExprId HighLevelILFunction::WhileSSA(ExprId conditionPhi, ExprId condition, ExprId body, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_WHILE_SSA, loc, 0, conditionPhi, condition, body);
}


ExprId HighLevelILFunction::DoWhileSSA(ExprId body, ExprId conditionPhi, ExprId condition, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DO_WHILE_SSA, loc, 0, body, conditionPhi, condition);
}


ExprId HighLevelILFunction::ForSSA(
    ExprId init, ExprId conditionPhi, ExprId condition, ExprId update, ExprId body, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FOR_SSA, loc, 0, init, conditionPhi, condition, update, body);
}


ExprId HighLevelILFunction::VarInitSSA(size_t size, const SSAVariable& dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR_INIT_SSA, loc, size, dest.var.ToIdentifier(), dest.version, src);
}


ExprId HighLevelILFunction::AssignMemSSA(
    size_t size, ExprId dest, size_t destMemory, ExprId src, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASSIGN_MEM_SSA, loc, size, dest, destMemory, src, srcMemory);
}


ExprId HighLevelILFunction::AssignUnpackMemSSA(
    const vector<ExprId>& dest, size_t destMemory, ExprId src, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    HLIL_ASSIGN_UNPACK_MEM_SSA, loc, 0, dest.size(), AddOperandList(dest), destMemory, src, srcMemory);
}


ExprId HighLevelILFunction::ForceVerSSA(
    size_t size, const SSAVariable& dest, const SSAVariable& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    HLIL_FORCE_VER_SSA, loc, size, dest.var.ToIdentifier(), dest.version, src.var.ToIdentifier(), src.version);
}


ExprId HighLevelILFunction::AssertSSA(
    size_t size, const SSAVariable& src, const PossibleValueSet& constraint, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    HLIL_ASSERT_SSA, loc, size, src.var.ToIdentifier(), src.version, CachePossibleValueSet(constraint));
}


ExprId HighLevelILFunction::VarSSA(size_t size, const SSAVariable& var, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR_SSA, loc, size, var.var.ToIdentifier(), var.version);
}


ExprId HighLevelILFunction::VarSSAPartial(
    size_t size, const Variable& var, size_t destVersion, size_t prevVersion, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR_SSA_PARTIAL, loc, size, var.ToIdentifier(), destVersion, prevVersion);
}


ExprId HighLevelILFunction::ArrayIndexSSA(
    size_t size, ExprId src, size_t srcMemory, ExprId index, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ARRAY_INDEX_SSA, loc, size, src, srcMemory, index);
}


ExprId HighLevelILFunction::DerefSSA(size_t size, ExprId src, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DEREF_SSA, loc, size, src, srcMemory);
}


ExprId HighLevelILFunction::DerefFieldSSA(
    size_t size, ExprId src, size_t srcMemory, uint64_t offset, size_t memberIndex, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DEREF_FIELD_SSA, loc, size, src, srcMemory, offset, memberIndex);
}


ExprId HighLevelILFunction::CallSSA(
    ExprId dest, const vector<ExprId>& params, size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    HLIL_CALL_SSA, loc, 0, dest, params.size(), AddOperandList(params), destMemory, srcMemory);
}


ExprId HighLevelILFunction::SyscallSSA(
    const vector<ExprId>& params, size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SYSCALL_SSA, loc, 0, params.size(), AddOperandList(params), destMemory, srcMemory);
}


ExprId HighLevelILFunction::IntrinsicSSA(
    uint32_t intrinsic, const vector<ExprId>& params, size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    HLIL_INTRINSIC_SSA, loc, 0, intrinsic, params.size(), AddOperandList(params), destMemory, srcMemory);
}


ExprId HighLevelILFunction::VarPhi(const SSAVariable& dest, const vector<SSAVariable>& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    HLIL_VAR_PHI, loc, 0, dest.var.ToIdentifier(), dest.version, src.size() * 2, AddSSAVariableList(src));
}


ExprId HighLevelILFunction::MemPhi(size_t destMemory, const vector<size_t>& srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MEM_PHI, loc, 0, destMemory, srcMemory.size(), AddIndexList(srcMemory));
}


ExprId HighLevelILFunction::ByteSwap(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_BSWAP, loc, size, src);
}


ExprId HighLevelILFunction::PopulationCount(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_POPCNT, loc, size, src);
}


ExprId HighLevelILFunction::CountLeadingZeros(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CLZ, loc, size, src);
}


ExprId HighLevelILFunction::CountTrailingZeros(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CTZ, loc, size, src);
}


ExprId HighLevelILFunction::ReverseBits(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_RBIT, loc, size, src);
}


ExprId HighLevelILFunction::CountLeadingSigns(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CLS, loc, size, src);
}


ExprId HighLevelILFunction::MinSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MINS, loc, size, left, right);
}


ExprId HighLevelILFunction::MaxSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MAXS, loc, size, left, right);
}


ExprId HighLevelILFunction::MinUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MINU, loc, size, left, right);
}


ExprId HighLevelILFunction::MaxUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MAXU, loc, size, left, right);
}


ExprId HighLevelILFunction::AbsoluteValue(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ABS, loc, size, src);
}
// END GENERATED hlil-builders


ExprId HighLevelILFunction::FloatConstSingle(float val, const ILSourceLocation& loc)
{
	union
	{
		float f;
		uint32_t i;
	} bits;
	bits.f = val;
	return AddExprWithLocation(HLIL_FLOAT_CONST, loc, 4, bits.i);
}


ExprId HighLevelILFunction::FloatConstDouble(double val, const ILSourceLocation& loc)
{
	union
	{
		double f;
		uint64_t i;
	} bits;
	bits.f = val;
	return AddExprWithLocation(HLIL_FLOAT_CONST, loc, 8, bits.i);
}


fmt::format_context::iterator fmt::formatter<HighLevelILInstruction>::format(const HighLevelILInstruction& obj, format_context& ctx) const
{
	if (!obj.function)
		return fmt::format_to(ctx.out(), "<uninit>");

	vector<InstructionTextToken> tokens;
	Ref<DisassemblySettings> settings = new DisassemblySettings();
	vector<DisassemblyTextLine> lines = obj.function->GetExprText(obj, settings);
	if (!lines.empty())
	{
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

		bool first = true;
		for (auto& line: lines)
		{
			if (!first)
			{
				fmt::format_to(ctx.out(), " ; ");
			}
			first = false;

			for (auto& token: line.tokens)
			{
				fmt::format_to(ctx.out(), "{}", token.text);
			}
		}
	}
	else
	{
		fmt::format_to(ctx.out(), "???");
	}
	return ctx.out();
}
