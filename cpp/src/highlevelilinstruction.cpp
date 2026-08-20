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

static constexpr std::array s_operandTypeForUsage = {
	OperandUsageType{SourceExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{VariableHighLevelOperandUsage, VariableHighLevelOperand},
	OperandUsageType{DestVariableHighLevelOperandUsage, VariableHighLevelOperand},
	OperandUsageType{SSAVariableHighLevelOperandUsage, SSAVariableHighLevelOperand},
	OperandUsageType{DestSSAVariableHighLevelOperandUsage, SSAVariableHighLevelOperand},
	OperandUsageType{PartialSSAVariableSourceHighLevelOperandUsage, SSAVariableHighLevelOperand},
	OperandUsageType{DestExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{LeftExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{RightExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{CarryExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{IndexExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{ConditionExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{ConditionPhiExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{TrueExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{FalseExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{LoopExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{InitExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{UpdateExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{DefaultExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{HighExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{LowExprHighLevelOperandUsage, ExprHighLevelOperand},
	OperandUsageType{OffsetHighLevelOperandUsage, IntegerHighLevelOperand},
	OperandUsageType{MemberIndexHighLevelOperandUsage, IndexHighLevelOperand},
	OperandUsageType{ConstantHighLevelOperandUsage, IntegerHighLevelOperand},
	OperandUsageType{ConstantDataHighLevelOperandUsage, ConstantDataHighLevelOperand},
	OperandUsageType{VectorHighLevelOperandUsage, IntegerHighLevelOperand},
	OperandUsageType{IntrinsicHighLevelOperandUsage, IntrinsicHighLevelOperand},
	OperandUsageType{TargetHighLevelOperandUsage, IndexHighLevelOperand},
	OperandUsageType{ParameterExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{SourceExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{DestExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{BlockExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{CasesHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{ValueExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{FieldExprsHighLevelOperandUsage, ExprListHighLevelOperand},
	OperandUsageType{SourceSSAVariablesHighLevelOperandUsage, SSAVariableListHighLevelOperand},
	OperandUsageType{SourceMemoryVersionHighLevelOperandUsage, IndexHighLevelOperand},
	OperandUsageType{SourceMemoryVersionsHighLevelOperandUsage, IndexListHighLevelOperand},
	OperandUsageType{DestMemoryVersionHighLevelOperandUsage, IndexHighLevelOperand}
};

static_assert(std::is_sorted(s_operandTypeForUsage.begin(), s_operandTypeForUsage.end()),
			  "Operand type mapping array is not sorted by usage value");

constexpr inline HighLevelILOperandType OperandTypeForUsage(HighLevelILOperandUsage usage)
{
	if (static_cast<size_t>(usage) < s_operandTypeForUsage.size())
		return s_operandTypeForUsage[usage].type;

	throw HighLevelILInstructionAccessException();
}

struct HighLevelILOperationTraits
{
	using ILOperation = BNHighLevelILOperation;
	using OperandUsage = HighLevelILOperandUsage;
	static constexpr size_t MaxOperands = 5;

	static constexpr uint8_t GetOperandIndexAdvance(OperandUsage usage, size_t /* operandIndex */)
	{
		if (usage == PartialSSAVariableSourceHighLevelOperandUsage)
		{
			// SSA variables are usually two slots, but this one has previously defined
			// variables and thus only takes one slot
			return 1;
		}
		switch (OperandTypeForUsage(usage))
		{
		case SSAVariableHighLevelOperand:
		case SSAVariableListHighLevelOperand:
		case ExprListHighLevelOperand:
		case IndexListHighLevelOperand:
			return 2;
		default:
			return 1;
		}
	}
};

using OperandUsage = detail::ILInstructionOperandUsage<HighLevelILOperationTraits>;
static_assert(sizeof(OperandUsage) == 12);


static constexpr std::array s_instructionOperandUsage = {
	OperandUsage{HLIL_NOP},
	OperandUsage{HLIL_BLOCK, {BlockExprsHighLevelOperandUsage}},
	OperandUsage{HLIL_IF, {ConditionExprHighLevelOperandUsage, TrueExprHighLevelOperandUsage, FalseExprHighLevelOperandUsage}},
	OperandUsage{HLIL_WHILE, {ConditionExprHighLevelOperandUsage, LoopExprHighLevelOperandUsage}},
	OperandUsage{HLIL_DO_WHILE, {LoopExprHighLevelOperandUsage, ConditionExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FOR, {InitExprHighLevelOperandUsage, ConditionExprHighLevelOperandUsage, UpdateExprHighLevelOperandUsage, LoopExprHighLevelOperandUsage}},
	OperandUsage{HLIL_SWITCH, {ConditionExprHighLevelOperandUsage, DefaultExprHighLevelOperandUsage, CasesHighLevelOperandUsage}},
	OperandUsage{HLIL_CASE, {ValueExprsHighLevelOperandUsage, TrueExprHighLevelOperandUsage}},
	OperandUsage{HLIL_BREAK},
	OperandUsage{HLIL_CONTINUE},
	OperandUsage{HLIL_JUMP, {DestExprHighLevelOperandUsage}},
	OperandUsage{HLIL_RET, {SourceExprsHighLevelOperandUsage}},
	OperandUsage{HLIL_NORET},
	OperandUsage{HLIL_GOTO, {TargetHighLevelOperandUsage}},
	OperandUsage{HLIL_LABEL, {TargetHighLevelOperandUsage}},
	OperandUsage{HLIL_VAR_DECLARE, {VariableHighLevelOperandUsage}},
	OperandUsage{HLIL_VAR_INIT, {DestVariableHighLevelOperandUsage, SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_ASSIGN, {DestExprHighLevelOperandUsage, SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_ASSIGN_UNPACK, {DestExprsHighLevelOperandUsage, SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FORCE_VER, {DestVariableHighLevelOperandUsage, VariableHighLevelOperandUsage}},
	OperandUsage{HLIL_ASSERT, {VariableHighLevelOperandUsage, ConstantHighLevelOperandUsage}},
	OperandUsage{HLIL_VAR, {VariableHighLevelOperandUsage}},
	OperandUsage{HLIL_STRUCT_FIELD, {SourceExprHighLevelOperandUsage, OffsetHighLevelOperandUsage, MemberIndexHighLevelOperandUsage}},
	OperandUsage{HLIL_ARRAY_INDEX, {SourceExprHighLevelOperandUsage, IndexExprHighLevelOperandUsage}},
	OperandUsage{HLIL_SPLIT, {HighExprHighLevelOperandUsage, LowExprHighLevelOperandUsage}},
	OperandUsage{HLIL_DEREF, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_DEREF_FIELD, {SourceExprHighLevelOperandUsage, OffsetHighLevelOperandUsage, MemberIndexHighLevelOperandUsage}},
	OperandUsage{HLIL_ADDRESS_OF, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_PASS_BY_REF, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_RETURN_BY_REF, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CONST, {ConstantHighLevelOperandUsage}},
	OperandUsage{HLIL_CONST_DATA, {ConstantDataHighLevelOperandUsage}},
	OperandUsage{HLIL_CONST_PTR, {ConstantHighLevelOperandUsage}},
	OperandUsage{HLIL_EXTERN_PTR, {ConstantHighLevelOperandUsage, OffsetHighLevelOperandUsage}},
	OperandUsage{HLIL_FLOAT_CONST, {ConstantHighLevelOperandUsage}},
	OperandUsage{HLIL_IMPORT, {ConstantHighLevelOperandUsage}},
	OperandUsage{HLIL_ADD, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_ADC, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage, CarryExprHighLevelOperandUsage}},
	OperandUsage{HLIL_SUB, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_SBB, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage, CarryExprHighLevelOperandUsage}},
	OperandUsage{HLIL_AND, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_OR, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_XOR, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_LSL, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_LSR, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_ASR, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_ROL, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_RLC, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage, CarryExprHighLevelOperandUsage}},
	OperandUsage{HLIL_ROR, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_RRC, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage, CarryExprHighLevelOperandUsage}},
	OperandUsage{HLIL_MUL, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_MULU_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_MULS_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_DIVU, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_DIVU_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_DIVS, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_DIVS_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_MODU, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_MODU_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_MODS, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_MODS_DP, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_NEG, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_NOT, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_SX, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_ZX, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_LOW_PART, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CALL, {DestExprHighLevelOperandUsage, ParameterExprsHighLevelOperandUsage}},
	OperandUsage{HLIL_CMP_E, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CMP_NE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CMP_SLT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CMP_ULT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CMP_SLE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CMP_ULE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CMP_SGE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CMP_UGE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CMP_SGT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CMP_UGT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_TEST_BIT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_BOOL_TO_INT, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_ADD_OVERFLOW, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_SYSCALL, {ParameterExprsHighLevelOperandUsage}},
	OperandUsage{HLIL_TAILCALL, {DestExprHighLevelOperandUsage, ParameterExprsHighLevelOperandUsage}},
	OperandUsage{HLIL_INTRINSIC, {IntrinsicHighLevelOperandUsage, ParameterExprsHighLevelOperandUsage}},
	OperandUsage{HLIL_BP},
	OperandUsage{HLIL_TRAP, {VectorHighLevelOperandUsage}},
	OperandUsage{HLIL_UNDEF},
	OperandUsage{HLIL_UNIMPL},
	OperandUsage{HLIL_UNIMPL_MEM, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_STRUCT_INIT, {FieldExprsHighLevelOperandUsage}},
	OperandUsage{HLIL_STRUCT_INIT_FIELD, {OffsetHighLevelOperandUsage, MemberIndexHighLevelOperandUsage, SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FADD, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FSUB, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FMUL, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FDIV, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FSQRT, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FNEG, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FABS, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FLOAT_TO_INT, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_INT_TO_FLOAT, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FLOAT_CONV, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_ROUND_TO_INT, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FLOOR, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CEIL, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FTRUNC, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FCMP_E, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FCMP_NE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FCMP_LT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FCMP_LE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FCMP_GE, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FCMP_GT, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FCMP_O, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FCMP_UO, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_UNREACHABLE},
	// SSA operations
	OperandUsage{HLIL_WHILE_SSA, {ConditionPhiExprHighLevelOperandUsage, ConditionExprHighLevelOperandUsage, LoopExprHighLevelOperandUsage}},
	OperandUsage{HLIL_DO_WHILE_SSA, {LoopExprHighLevelOperandUsage, ConditionPhiExprHighLevelOperandUsage, ConditionExprHighLevelOperandUsage}},
	OperandUsage{HLIL_FOR_SSA, {InitExprHighLevelOperandUsage, ConditionPhiExprHighLevelOperandUsage, ConditionExprHighLevelOperandUsage, UpdateExprHighLevelOperandUsage, LoopExprHighLevelOperandUsage}},
	OperandUsage{HLIL_VAR_INIT_SSA, {DestSSAVariableHighLevelOperandUsage, SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_ASSIGN_MEM_SSA, {DestExprHighLevelOperandUsage, DestMemoryVersionHighLevelOperandUsage, SourceExprHighLevelOperandUsage, SourceMemoryVersionHighLevelOperandUsage}},
	OperandUsage{HLIL_ASSIGN_UNPACK_MEM_SSA, {DestExprsHighLevelOperandUsage, DestMemoryVersionHighLevelOperandUsage, SourceExprHighLevelOperandUsage, SourceMemoryVersionHighLevelOperandUsage}},
	OperandUsage{HLIL_FORCE_VER_SSA, {DestSSAVariableHighLevelOperandUsage, SSAVariableHighLevelOperandUsage}},
	OperandUsage{HLIL_ASSERT_SSA, {SSAVariableHighLevelOperandUsage, ConstantHighLevelOperandUsage}},
	OperandUsage{HLIL_VAR_SSA, {SSAVariableHighLevelOperandUsage}},
	OperandUsage{HLIL_VAR_SSA_PARTIAL, {SSAVariableHighLevelOperandUsage, PartialSSAVariableSourceHighLevelOperandUsage}},
	OperandUsage{HLIL_ARRAY_INDEX_SSA, {SourceExprHighLevelOperandUsage, SourceMemoryVersionHighLevelOperandUsage, IndexExprHighLevelOperandUsage}},
	OperandUsage{HLIL_DEREF_SSA, {SourceExprHighLevelOperandUsage, SourceMemoryVersionHighLevelOperandUsage}},
	OperandUsage{HLIL_DEREF_FIELD_SSA, {SourceExprHighLevelOperandUsage, SourceMemoryVersionHighLevelOperandUsage, OffsetHighLevelOperandUsage, MemberIndexHighLevelOperandUsage}},
	OperandUsage{HLIL_CALL_SSA, {DestExprHighLevelOperandUsage, ParameterExprsHighLevelOperandUsage, DestMemoryVersionHighLevelOperandUsage, SourceMemoryVersionHighLevelOperandUsage}},
	OperandUsage{HLIL_SYSCALL_SSA, {ParameterExprsHighLevelOperandUsage, DestMemoryVersionHighLevelOperandUsage, SourceMemoryVersionHighLevelOperandUsage}},
	OperandUsage{HLIL_INTRINSIC_SSA, {IntrinsicHighLevelOperandUsage, ParameterExprsHighLevelOperandUsage, DestMemoryVersionHighLevelOperandUsage, SourceMemoryVersionHighLevelOperandUsage}},
	OperandUsage{HLIL_VAR_PHI, {DestSSAVariableHighLevelOperandUsage, SourceSSAVariablesHighLevelOperandUsage}},
	OperandUsage{HLIL_MEM_PHI, {DestMemoryVersionHighLevelOperandUsage, SourceMemoryVersionsHighLevelOperandUsage}},
	OperandUsage{HLIL_BSWAP, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_POPCNT, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CLZ, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CTZ, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_RBIT, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_CLS, {SourceExprHighLevelOperandUsage}},
	OperandUsage{HLIL_MINS, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_MAXS, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_MINU, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_MAXU, {LeftExprHighLevelOperandUsage, RightExprHighLevelOperandUsage}},
	OperandUsage{HLIL_ABS, {SourceExprHighLevelOperandUsage}},
};


VALIDATE_INSTRUCTION_ORDER(s_instructionOperandUsage);


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
    const HighLevelILInstruction& instr, HighLevelILOperandUsage usage, size_t operandIndex) :
	m_instr(instr),
	m_usage(usage),
	m_type(OperandTypeForUsage(m_usage)),
	m_operandIndex(operandIndex)
{
}


uint64_t HighLevelILOperand::GetInteger() const
{
	if (m_type != IntegerHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsInteger(m_operandIndex);
}


ConstantData HighLevelILOperand::GetConstantData() const
{
	if (m_type != ConstantDataHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsConstantData(m_operandIndex);
}


size_t HighLevelILOperand::GetIndex() const
{
	if (m_type != IndexHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsIndex(m_operandIndex);
}


uint32_t HighLevelILOperand::GetIntrinsic() const
{
	if (m_type != IntrinsicHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return (uint32_t)m_instr.GetRawOperandAsInteger(m_operandIndex);
}


HighLevelILInstruction HighLevelILOperand::GetExpr() const
{
	if (m_type != ExprHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsExpr(m_operandIndex);
}


Variable HighLevelILOperand::GetVariable() const
{
	if (m_type != VariableHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsVariable(m_operandIndex);
}


SSAVariable HighLevelILOperand::GetSSAVariable() const
{
	if (m_type != SSAVariableHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsSSAVariable(m_operandIndex);
}


HighLevelILInstructionList HighLevelILOperand::GetExprList() const
{
	if (m_type != ExprListHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsExprList(m_operandIndex);
}


HighLevelILSSAVariableList HighLevelILOperand::GetSSAVariableList() const
{
	if (m_type != SSAVariableListHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsSSAVariableList(m_operandIndex);
}


HighLevelILIndexList HighLevelILOperand::GetIndexList() const
{
	if (m_type != IndexListHighLevelOperand)
		throw HighLevelILInstructionAccessException();
	return m_instr.GetRawOperandAsIndexList(m_operandIndex);
}


const HighLevelILOperand HighLevelILOperandList::ListIterator::operator*()
{
	if (index >= owner->m_count)
		throw HighLevelILInstructionAccessException();
	HighLevelILOperandUsage usage = owner->m_usages[index];
	return HighLevelILOperand(owner->m_instr, usage, owner->m_indices[index]);
}


HighLevelILOperandList::HighLevelILOperandList(const HighLevelILInstruction& instr,
    const HighLevelILOperandUsage* usages,
    const uint8_t* indices,
    uint8_t count) :
    m_instr(instr),
    m_usages(usages), m_indices(indices), m_count(count)
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
	HighLevelILOperandUsage usage = m_usages[i];
	return HighLevelILOperand(m_instr, usage, m_indices[i]);
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
	if (operation >= s_instructionOperandUsage.size())
		throw HighLevelILInstructionAccessException();

	const auto& info = s_instructionOperandUsage[operation];
	return HighLevelILOperandList(*(const HighLevelILInstruction*)this, info.usages, info.indices, info.count);
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
	case HLIL_WHILE_SSA:
		if (ast)
			toProcess.push(GetLoopExpr<HLIL_WHILE_SSA>().exprIndex);
		toProcess.push(GetConditionExpr<HLIL_WHILE_SSA>().exprIndex);
		toProcess.push(GetConditionPhiExpr<HLIL_WHILE_SSA>().exprIndex);
		break;
	case HLIL_DO_WHILE:
		toProcess.push(GetConditionExpr<HLIL_DO_WHILE>().exprIndex);
		if (ast)
			toProcess.push(GetLoopExpr<HLIL_DO_WHILE>().exprIndex);
		break;
	case HLIL_DO_WHILE_SSA:
		toProcess.push(GetConditionExpr<HLIL_DO_WHILE_SSA>().exprIndex);
		toProcess.push(GetConditionPhiExpr<HLIL_DO_WHILE_SSA>().exprIndex);
		if (ast)
			toProcess.push(GetLoopExpr<HLIL_DO_WHILE_SSA>().exprIndex);
		break;
	case HLIL_FOR:
		if (ast)
			toProcess.push(GetLoopExpr<HLIL_FOR>().exprIndex);
		toProcess.push(GetUpdateExpr<HLIL_FOR>().exprIndex);
		toProcess.push(GetConditionExpr<HLIL_FOR>().exprIndex);
		toProcess.push(GetInitExpr<HLIL_FOR>().exprIndex);
		break;
	case HLIL_FOR_SSA:
		if (ast)
			toProcess.push(GetLoopExpr<HLIL_FOR_SSA>().exprIndex);
		toProcess.push(GetUpdateExpr<HLIL_FOR_SSA>().exprIndex);
		toProcess.push(GetConditionExpr<HLIL_FOR_SSA>().exprIndex);
		toProcess.push(GetConditionPhiExpr<HLIL_FOR_SSA>().exprIndex);
		toProcess.push(GetInitExpr<HLIL_FOR_SSA>().exprIndex);
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
	case HLIL_VAR_INIT:
		toProcess.push(GetSourceExpr<HLIL_VAR_INIT>().exprIndex);
		break;
	case HLIL_VAR_INIT_SSA:
		toProcess.push(GetSourceExpr<HLIL_VAR_INIT_SSA>().exprIndex);
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
	case HLIL_STRUCT_FIELD:
		toProcess.push(GetSourceExpr<HLIL_STRUCT_FIELD>().exprIndex);
		break;
	case HLIL_ARRAY_INDEX:
		toProcess.push(GetSourceExpr<HLIL_ARRAY_INDEX>().exprIndex);
		toProcess.push(GetIndexExpr<HLIL_ARRAY_INDEX>().exprIndex);
		break;
	case HLIL_ARRAY_INDEX_SSA:
		toProcess.push(GetSourceExpr<HLIL_ARRAY_INDEX_SSA>().exprIndex);
		toProcess.push(GetIndexExpr<HLIL_ARRAY_INDEX_SSA>().exprIndex);
		break;
	case HLIL_SPLIT:
		toProcess.push(GetLowExpr<HLIL_SPLIT>().exprIndex);
		toProcess.push(GetHighExpr<HLIL_SPLIT>().exprIndex);
		break;
	case HLIL_DEREF_FIELD:
		toProcess.push(GetSourceExpr<HLIL_DEREF_FIELD>().exprIndex);
		break;
	case HLIL_DEREF_SSA:
		toProcess.push(GetSourceExpr<HLIL_DEREF_SSA>().exprIndex);
		break;
	case HLIL_DEREF_FIELD_SSA:
		toProcess.push(GetSourceExpr<HLIL_DEREF_FIELD_SSA>().exprIndex);
		break;
	case HLIL_STRUCT_INIT:
		exprs = GetFieldExprs<HLIL_STRUCT_INIT>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_STRUCT_INIT_FIELD:
		toProcess.push(GetSourceExpr<HLIL_STRUCT_INIT_FIELD>().exprIndex);
		break;
	case HLIL_CALL:
		toProcess.push(GetDestExpr<HLIL_CALL>().exprIndex);
		exprs = GetParameterExprs<HLIL_CALL>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
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
	case HLIL_RET:
		exprs = GetSourceExprs<HLIL_RET>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_DEREF:
	case HLIL_ADDRESS_OF:
	case HLIL_NEG:
	case HLIL_NOT:
	case HLIL_BSWAP:
	case HLIL_POPCNT:
	case HLIL_CLZ:
	case HLIL_CTZ:
	case HLIL_RBIT:
	case HLIL_CLS:
	case HLIL_ABS:
	case HLIL_SX:
	case HLIL_ZX:
	case HLIL_LOW_PART:
	case HLIL_BOOL_TO_INT:
	case HLIL_JUMP:
	case HLIL_UNIMPL_MEM:
	case HLIL_FSQRT:
	case HLIL_FNEG:
	case HLIL_FABS:
	case HLIL_FLOAT_TO_INT:
	case HLIL_INT_TO_FLOAT:
	case HLIL_FLOAT_CONV:
	case HLIL_ROUND_TO_INT:
	case HLIL_FLOOR:
	case HLIL_CEIL:
	case HLIL_FTRUNC:
	case HLIL_PASS_BY_REF:
	case HLIL_RETURN_BY_REF:
		toProcess.push(AsOneOperand().GetSourceExpr().exprIndex);
		break;
	case HLIL_ADD:
	case HLIL_SUB:
	case HLIL_AND:
	case HLIL_OR:
	case HLIL_XOR:
	case HLIL_MINS:
	case HLIL_MAXS:
	case HLIL_MINU:
	case HLIL_MAXU:
	case HLIL_LSL:
	case HLIL_LSR:
	case HLIL_ASR:
	case HLIL_ROL:
	case HLIL_ROR:
	case HLIL_MUL:
	case HLIL_MULU_DP:
	case HLIL_MULS_DP:
	case HLIL_DIVU:
	case HLIL_DIVS:
	case HLIL_MODU:
	case HLIL_MODS:
	case HLIL_DIVU_DP:
	case HLIL_DIVS_DP:
	case HLIL_MODU_DP:
	case HLIL_MODS_DP:
	case HLIL_CMP_E:
	case HLIL_CMP_NE:
	case HLIL_CMP_SLT:
	case HLIL_CMP_ULT:
	case HLIL_CMP_SLE:
	case HLIL_CMP_ULE:
	case HLIL_CMP_SGE:
	case HLIL_CMP_UGE:
	case HLIL_CMP_SGT:
	case HLIL_CMP_UGT:
	case HLIL_TEST_BIT:
	case HLIL_ADD_OVERFLOW:
	case HLIL_FADD:
	case HLIL_FSUB:
	case HLIL_FMUL:
	case HLIL_FDIV:
	case HLIL_FCMP_E:
	case HLIL_FCMP_NE:
	case HLIL_FCMP_LT:
	case HLIL_FCMP_LE:
	case HLIL_FCMP_GE:
	case HLIL_FCMP_GT:
	case HLIL_FCMP_O:
	case HLIL_FCMP_UO:
		toProcess.push(AsTwoOperand().GetRightExpr().exprIndex);
		toProcess.push(AsTwoOperand().GetLeftExpr().exprIndex);
		break;
	case HLIL_ADC:
	case HLIL_SBB:
	case HLIL_RLC:
	case HLIL_RRC:
		toProcess.push(AsTwoOperandWithCarry().GetCarryExpr().exprIndex);
		toProcess.push(AsTwoOperandWithCarry().GetRightExpr().exprIndex);
		toProcess.push(AsTwoOperandWithCarry().GetLeftExpr().exprIndex);
		break;
	case HLIL_INTRINSIC:
		exprs = GetParameterExprs<HLIL_INTRINSIC>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	case HLIL_INTRINSIC_SSA:
		exprs = GetParameterExprs<HLIL_INTRINSIC_SSA>();
		for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)
			toProcess.push(i->exprIndex);
		break;
	default:
		break;
	}
}


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


ExprId HighLevelILInstruction::CopyTo(
    HighLevelILFunction* dest, bn::base::function_ref<ExprId(const HighLevelILInstruction& subExpr)> subExprHandler, const ILSourceLocation& sourceLocation) const
{
	vector<ExprId> output, params;

	const auto& loc = sourceLocation.valid ? sourceLocation : ILSourceLocation{*this};

	switch (operation)
	{
	case HLIL_NOP:
		return dest->Nop(loc);
	case HLIL_BLOCK:
		for (auto i : GetBlockExprs<HLIL_BLOCK>())
			params.push_back(subExprHandler(i));
		return dest->Block(params, loc);
	case HLIL_IF:
		return dest->If(subExprHandler(GetConditionExpr<HLIL_IF>()), subExprHandler(GetTrueExpr<HLIL_IF>()),
		    subExprHandler(GetFalseExpr<HLIL_IF>()), loc);
	case HLIL_WHILE:
		return dest->While(
		    subExprHandler(GetConditionExpr<HLIL_WHILE>()), subExprHandler(GetLoopExpr<HLIL_WHILE>()), loc);
	case HLIL_WHILE_SSA:
		return dest->WhileSSA(subExprHandler(GetConditionPhiExpr<HLIL_WHILE_SSA>()),
		    subExprHandler(GetConditionExpr<HLIL_WHILE_SSA>()), subExprHandler(GetLoopExpr<HLIL_WHILE_SSA>()), loc);
	case HLIL_DO_WHILE:
		return dest->DoWhile(
		    subExprHandler(GetLoopExpr<HLIL_DO_WHILE>()), subExprHandler(GetConditionExpr<HLIL_DO_WHILE>()), loc);
	case HLIL_DO_WHILE_SSA:
		return dest->DoWhileSSA(subExprHandler(GetLoopExpr<HLIL_DO_WHILE_SSA>()),
		    subExprHandler(GetConditionPhiExpr<HLIL_DO_WHILE_SSA>()),
		    subExprHandler(GetConditionExpr<HLIL_DO_WHILE_SSA>()), loc);
	case HLIL_FOR:
		return dest->For(subExprHandler(GetInitExpr<HLIL_FOR>()), subExprHandler(GetConditionExpr<HLIL_FOR>()),
		    subExprHandler(GetUpdateExpr<HLIL_FOR>()), subExprHandler(GetLoopExpr<HLIL_FOR>()), loc);
	case HLIL_FOR_SSA:
		return dest->ForSSA(subExprHandler(GetInitExpr<HLIL_FOR_SSA>()),
		    subExprHandler(GetConditionPhiExpr<HLIL_FOR_SSA>()), subExprHandler(GetConditionExpr<HLIL_FOR_SSA>()),
		    subExprHandler(GetUpdateExpr<HLIL_FOR_SSA>()), subExprHandler(GetLoopExpr<HLIL_FOR_SSA>()), loc);
	case HLIL_SWITCH:
		for (auto i : GetCases<HLIL_SWITCH>())
			params.push_back(subExprHandler(i));
		return dest->Switch(subExprHandler(GetConditionExpr<HLIL_SWITCH>()),
		    subExprHandler(GetDefaultExpr<HLIL_SWITCH>()), params, loc);
	case HLIL_CASE:
		for (auto i : GetValueExprs<HLIL_CASE>())
			params.push_back(subExprHandler(i));
		return dest->Case(params, subExprHandler(GetTrueExpr<HLIL_CASE>()), loc);
	case HLIL_BREAK:
		return dest->Break(loc);
	case HLIL_CONTINUE:
		return dest->Continue(loc);
	case HLIL_GOTO:
		return dest->Goto(GetTarget<HLIL_GOTO>(), loc);
	case HLIL_LABEL:
		return dest->Label(GetTarget<HLIL_LABEL>(), loc);
	case HLIL_VAR_DECLARE:
		return dest->VarDeclare(GetVariable<HLIL_VAR_DECLARE>(), loc);
	case HLIL_VAR_INIT:
		return dest->VarInit(
		    size, GetDestVariable<HLIL_VAR_INIT>(), subExprHandler(GetSourceExpr<HLIL_VAR_INIT>()), loc);
	case HLIL_VAR_INIT_SSA:
		return dest->VarInitSSA(
		    size, GetDestSSAVariable<HLIL_VAR_INIT_SSA>(), subExprHandler(GetSourceExpr<HLIL_VAR_INIT_SSA>()), loc);
	case HLIL_ASSIGN:
		return dest->Assign(
		    size, subExprHandler(GetDestExpr<HLIL_ASSIGN>()), subExprHandler(GetSourceExpr<HLIL_ASSIGN>()), loc);
	case HLIL_ASSIGN_UNPACK:
		for (auto i : GetDestExprs<HLIL_ASSIGN_UNPACK>())
			output.push_back(subExprHandler(i));
		return dest->AssignUnpack(output, subExprHandler(GetSourceExpr<HLIL_ASSIGN_UNPACK>()), loc);
	case HLIL_ASSIGN_MEM_SSA:
		return dest->AssignMemSSA(size, subExprHandler(GetDestExpr<HLIL_ASSIGN_MEM_SSA>()),
		    GetDestMemoryVersion<HLIL_ASSIGN_MEM_SSA>(), subExprHandler(GetSourceExpr<HLIL_ASSIGN_MEM_SSA>()),
		    GetSourceMemoryVersion<HLIL_ASSIGN_MEM_SSA>(), loc);
	case HLIL_ASSIGN_UNPACK_MEM_SSA:
		for (auto i : GetDestExprs<HLIL_ASSIGN_UNPACK_MEM_SSA>())
			output.push_back(subExprHandler(i));
		return dest->AssignUnpackMemSSA(output, GetDestMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>(),
		    subExprHandler(GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>()),
		    GetSourceMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>(), loc);
	case HLIL_FORCE_VER:
		return dest->ForceVer(size, GetDestVariable<HLIL_FORCE_VER>(), GetVariable<HLIL_FORCE_VER>(), loc);
	case HLIL_FORCE_VER_SSA:
		return dest->ForceVerSSA(size, GetDestSSAVariable<HLIL_FORCE_VER_SSA>(), GetSSAVariable<HLIL_FORCE_VER_SSA>(), loc);
	case HLIL_ASSERT:
		return dest->Assert(size, GetVariable<HLIL_ASSERT>(), GetConstraint<HLIL_ASSERT>(), loc);
	case HLIL_ASSERT_SSA:
		return dest->AssertSSA(size, GetSSAVariable<HLIL_ASSERT_SSA>(), GetConstraint<HLIL_ASSERT_SSA>(), loc);
	case HLIL_VAR:
		return dest->Var(size, GetVariable<HLIL_VAR>(), loc);
	case HLIL_VAR_SSA:
		return dest->VarSSA(size, GetSSAVariable<HLIL_VAR_SSA>(), loc);
	case HLIL_VAR_SSA_PARTIAL:
		return dest->VarSSAPartial(size, GetDestSSAVariable<HLIL_VAR_SSA_PARTIAL>().var,
			GetDestSSAVariable<HLIL_VAR_SSA_PARTIAL>().version,
			GetSourceSSAVariable<HLIL_VAR_SSA_PARTIAL>().version, loc);
	case HLIL_VAR_PHI:
		return dest->VarPhi(GetDestSSAVariable<HLIL_VAR_PHI>(), GetSourceSSAVariables<HLIL_VAR_PHI>(), loc);
	case HLIL_MEM_PHI:
		return dest->MemPhi(GetDestMemoryVersion<HLIL_MEM_PHI>(), GetSourceMemoryVersions<HLIL_MEM_PHI>(), loc);
	case HLIL_STRUCT_FIELD:
		return dest->StructField(size, subExprHandler(GetSourceExpr<HLIL_STRUCT_FIELD>()),
		    GetOffset<HLIL_STRUCT_FIELD>(), GetMemberIndex<HLIL_STRUCT_FIELD>(), loc);
	case HLIL_ARRAY_INDEX:
		return dest->ArrayIndex(size, subExprHandler(GetSourceExpr<HLIL_ARRAY_INDEX>()),
		    subExprHandler(GetIndexExpr<HLIL_ARRAY_INDEX>()), loc);
	case HLIL_ARRAY_INDEX_SSA:
		return dest->ArrayIndexSSA(size, subExprHandler(GetSourceExpr<HLIL_ARRAY_INDEX_SSA>()),
		    GetSourceMemoryVersion<HLIL_ARRAY_INDEX_SSA>(), subExprHandler(GetIndexExpr<HLIL_ARRAY_INDEX_SSA>()),
		    loc);
	case HLIL_STRUCT_INIT:
		for (auto i : GetFieldExprs<HLIL_STRUCT_INIT>())
			params.push_back(subExprHandler(i));
		return dest->StructInit(size, params, loc);
	case HLIL_STRUCT_INIT_FIELD:
		return dest->StructInitField(size, GetOffset<HLIL_STRUCT_INIT_FIELD>(),
			GetMemberIndex<HLIL_STRUCT_INIT_FIELD>(), subExprHandler(GetSourceExpr<HLIL_STRUCT_INIT_FIELD>()), loc);
	case HLIL_SPLIT:
		return dest->Split(
		    size, subExprHandler(GetHighExpr<HLIL_SPLIT>()), subExprHandler(GetLowExpr<HLIL_SPLIT>()), loc);
	case HLIL_DEREF:
		return dest->Deref(size, subExprHandler(GetSourceExpr<HLIL_DEREF>()), loc);
	case HLIL_DEREF_FIELD:
		return dest->DerefField(size, subExprHandler(GetSourceExpr<HLIL_DEREF_FIELD>()), GetOffset<HLIL_DEREF_FIELD>(),
		    GetMemberIndex<HLIL_DEREF_FIELD>(), loc);
	case HLIL_DEREF_SSA:
		return dest->DerefSSA(
		    size, subExprHandler(GetSourceExpr<HLIL_DEREF_SSA>()), GetSourceMemoryVersion<HLIL_DEREF_SSA>(), loc);
	case HLIL_DEREF_FIELD_SSA:
		return dest->DerefFieldSSA(size, subExprHandler(GetSourceExpr<HLIL_DEREF_FIELD_SSA>()),
		    GetSourceMemoryVersion<HLIL_DEREF_FIELD_SSA>(), GetOffset<HLIL_DEREF_FIELD_SSA>(),
		    GetMemberIndex<HLIL_DEREF_FIELD_SSA>(), loc);
	case HLIL_ADDRESS_OF:
		return dest->AddressOf(subExprHandler(GetSourceExpr<HLIL_ADDRESS_OF>()), loc);
	case HLIL_CALL:
		for (auto i : GetParameterExprs<HLIL_CALL>())
			params.push_back(subExprHandler(i));
		return dest->Call(subExprHandler(GetDestExpr<HLIL_CALL>()), params, loc);
	case HLIL_SYSCALL:
		for (auto i : GetParameterExprs<HLIL_SYSCALL>())
			params.push_back(subExprHandler(i));
		return dest->Syscall(params, loc);
	case HLIL_TAILCALL:
		for (auto i : GetParameterExprs<HLIL_TAILCALL>())
			params.push_back(subExprHandler(i));
		return dest->TailCall(subExprHandler(GetDestExpr<HLIL_TAILCALL>()), params, loc);
	case HLIL_CALL_SSA:
		for (auto i : GetParameterExprs<HLIL_CALL_SSA>())
			params.push_back(subExprHandler(i));
		return dest->CallSSA(subExprHandler(GetDestExpr<HLIL_CALL_SSA>()), params,
		    GetDestMemoryVersion<HLIL_CALL_SSA>(), GetSourceMemoryVersion<HLIL_CALL_SSA>(), loc);
	case HLIL_SYSCALL_SSA:
		for (auto i : GetParameterExprs<HLIL_SYSCALL_SSA>())
			params.push_back(subExprHandler(i));
		return dest->SyscallSSA(
		    params, GetDestMemoryVersion<HLIL_SYSCALL_SSA>(), GetSourceMemoryVersion<HLIL_SYSCALL_SSA>(), loc);
	case HLIL_RET:
		for (auto i : GetSourceExprs<HLIL_RET>())
			params.push_back(subExprHandler(i));
		return dest->Return(params, loc);
	case HLIL_NORET:
		return dest->NoReturn(loc);
	case HLIL_UNREACHABLE:
		return dest->Unreachable(loc);
	case HLIL_NEG:
	case HLIL_NOT:
	case HLIL_BSWAP:
	case HLIL_POPCNT:
	case HLIL_CLZ:
	case HLIL_CTZ:
	case HLIL_RBIT:
	case HLIL_CLS:
	case HLIL_ABS:
	case HLIL_SX:
	case HLIL_ZX:
	case HLIL_LOW_PART:
	case HLIL_BOOL_TO_INT:
	case HLIL_JUMP:
	case HLIL_FSQRT:
	case HLIL_FNEG:
	case HLIL_FABS:
	case HLIL_FLOAT_TO_INT:
	case HLIL_INT_TO_FLOAT:
	case HLIL_FLOAT_CONV:
	case HLIL_ROUND_TO_INT:
	case HLIL_FLOOR:
	case HLIL_CEIL:
	case HLIL_FTRUNC:
	case HLIL_PASS_BY_REF:
	case HLIL_RETURN_BY_REF:
		return dest->AddExprWithLocation(operation, loc, size, subExprHandler(AsOneOperand().GetSourceExpr()));
	case HLIL_UNIMPL_MEM:
		return dest->AddExprWithLocation(operation, loc, size, subExprHandler(AsOneOperand().GetSourceExpr()), GetRawOperandAsInteger(1));
	case HLIL_ADD:
	case HLIL_SUB:
	case HLIL_AND:
	case HLIL_OR:
	case HLIL_XOR:
	case HLIL_MINS:
	case HLIL_MAXS:
	case HLIL_MINU:
	case HLIL_MAXU:
	case HLIL_LSL:
	case HLIL_LSR:
	case HLIL_ASR:
	case HLIL_ROL:
	case HLIL_ROR:
	case HLIL_MUL:
	case HLIL_MULU_DP:
	case HLIL_MULS_DP:
	case HLIL_DIVU:
	case HLIL_DIVS:
	case HLIL_MODU:
	case HLIL_MODS:
	case HLIL_DIVU_DP:
	case HLIL_DIVS_DP:
	case HLIL_MODU_DP:
	case HLIL_MODS_DP:
	case HLIL_CMP_E:
	case HLIL_CMP_NE:
	case HLIL_CMP_SLT:
	case HLIL_CMP_ULT:
	case HLIL_CMP_SLE:
	case HLIL_CMP_ULE:
	case HLIL_CMP_SGE:
	case HLIL_CMP_UGE:
	case HLIL_CMP_SGT:
	case HLIL_CMP_UGT:
	case HLIL_TEST_BIT:
	case HLIL_ADD_OVERFLOW:
	case HLIL_FADD:
	case HLIL_FSUB:
	case HLIL_FMUL:
	case HLIL_FDIV:
	case HLIL_FCMP_E:
	case HLIL_FCMP_NE:
	case HLIL_FCMP_LT:
	case HLIL_FCMP_LE:
	case HLIL_FCMP_GE:
	case HLIL_FCMP_GT:
	case HLIL_FCMP_O:
	case HLIL_FCMP_UO:
		return dest->AddExprWithLocation(operation, loc, size, subExprHandler(AsTwoOperand().GetLeftExpr()),
		    subExprHandler(AsTwoOperand().GetRightExpr()));
	case HLIL_ADC:
	case HLIL_SBB:
	case HLIL_RLC:
	case HLIL_RRC:
		return dest->AddExprWithLocation(operation, loc, size, subExprHandler(AsTwoOperandWithCarry().GetLeftExpr()),
		    subExprHandler(AsTwoOperandWithCarry().GetRightExpr()),
		    subExprHandler(AsTwoOperandWithCarry().GetCarryExpr()));
	case HLIL_CONST:
		return dest->Const(size, GetConstant<HLIL_CONST>(), loc);
	case HLIL_CONST_PTR:
		return dest->ConstPointer(size, GetConstant<HLIL_CONST_PTR>(), loc);
	case HLIL_EXTERN_PTR:
		return dest->ExternPointer(size, GetConstant<HLIL_EXTERN_PTR>(), GetOffset<HLIL_EXTERN_PTR>(), loc);
	case HLIL_FLOAT_CONST:
		return dest->FloatConstRaw(size, GetConstant<HLIL_FLOAT_CONST>(), loc);
	case HLIL_IMPORT:
		return dest->ImportedAddress(size, GetConstant<HLIL_IMPORT>(), loc);
	case HLIL_CONST_DATA:
		return dest->ConstData(size, GetConstantData<HLIL_CONST_DATA>(), loc);
	case HLIL_BP:
		return dest->Breakpoint(loc);
	case HLIL_TRAP:
		return dest->Trap(GetVector<HLIL_TRAP>(), loc);
	case HLIL_INTRINSIC:
		for (auto i : GetParameterExprs<HLIL_INTRINSIC>())
			params.push_back(subExprHandler(i));
		return dest->Intrinsic(GetIntrinsic<HLIL_INTRINSIC>(), params, loc);
	case HLIL_INTRINSIC_SSA:
		for (auto i : GetParameterExprs<HLIL_INTRINSIC_SSA>())
			params.push_back(subExprHandler(i));
		return dest->IntrinsicSSA(GetIntrinsic<HLIL_INTRINSIC_SSA>(), params,
		    GetDestMemoryVersion<HLIL_INTRINSIC_SSA>(), GetSourceMemoryVersion<HLIL_INTRINSIC_SSA>(), loc);
	case HLIL_UNDEF:
		return dest->Undefined(loc);
	case HLIL_UNIMPL:
		return As<HLIL_UNIMPL>().IsUnknown() ? dest->Unknown(loc) : dest->Unimplemented(loc);
	default:
		throw HighLevelILInstructionAccessException();
	}
}


static bool CompareExprList(const HighLevelILInstructionList& a, const HighLevelILInstructionList& b)
{
	if (a.size() < b.size())
		return true;
	if (a.size() > b.size())
		return false;
	auto i = a.begin();
	auto j = b.begin();
	for (; i != a.end(); ++i, ++j)
	{
		if (*i < *j)
			return true;
		if (*j < *i)
			return false;
	}
	return false;
}


bool HighLevelILInstruction::operator<(const HighLevelILInstruction& other) const
{
	if (operation < other.operation)
		return true;
	if (operation > other.operation)
		return false;

	switch (operation)
	{
	case HLIL_BLOCK:
		return CompareExprList(GetBlockExprs<HLIL_BLOCK>(), other.GetBlockExprs<HLIL_BLOCK>());
	case HLIL_IF:
		if (GetConditionExpr<HLIL_IF>() < other.GetConditionExpr<HLIL_IF>())
			return true;
		if (other.GetConditionExpr<HLIL_IF>() < GetConditionExpr<HLIL_IF>())
			return false;
		if (GetTrueExpr<HLIL_IF>() < other.GetTrueExpr<HLIL_IF>())
			return true;
		if (other.GetTrueExpr<HLIL_IF>() < GetTrueExpr<HLIL_IF>())
			return false;
		return GetFalseExpr<HLIL_IF>() < other.GetFalseExpr<HLIL_IF>();
	case HLIL_WHILE:
		if (GetConditionExpr<HLIL_WHILE>() < other.GetConditionExpr<HLIL_WHILE>())
			return true;
		if (other.GetConditionExpr<HLIL_WHILE>() < GetConditionExpr<HLIL_WHILE>())
			return false;
		return GetLoopExpr<HLIL_WHILE>() < other.GetLoopExpr<HLIL_WHILE>();
	case HLIL_WHILE_SSA:
		if (GetConditionPhiExpr<HLIL_WHILE_SSA>() < other.GetConditionPhiExpr<HLIL_WHILE_SSA>())
			return true;
		if (other.GetConditionPhiExpr<HLIL_WHILE_SSA>() < GetConditionPhiExpr<HLIL_WHILE_SSA>())
			return false;
		if (GetConditionExpr<HLIL_WHILE>() < other.GetConditionExpr<HLIL_WHILE>())
			return true;
		if (other.GetConditionExpr<HLIL_WHILE>() < GetConditionExpr<HLIL_WHILE>())
			return false;
		return GetLoopExpr<HLIL_WHILE>() < other.GetLoopExpr<HLIL_WHILE>();
	case HLIL_DO_WHILE:
		if (GetLoopExpr<HLIL_DO_WHILE>() < other.GetLoopExpr<HLIL_DO_WHILE>())
			return true;
		if (other.GetLoopExpr<HLIL_DO_WHILE>() < GetLoopExpr<HLIL_DO_WHILE>())
			return false;
		return GetConditionExpr<HLIL_DO_WHILE>() < other.GetConditionExpr<HLIL_DO_WHILE>();
	case HLIL_DO_WHILE_SSA:
		if (GetLoopExpr<HLIL_DO_WHILE_SSA>() < other.GetLoopExpr<HLIL_DO_WHILE_SSA>())
			return true;
		if (other.GetLoopExpr<HLIL_DO_WHILE_SSA>() < GetLoopExpr<HLIL_DO_WHILE_SSA>())
			return false;
		if (GetConditionPhiExpr<HLIL_DO_WHILE_SSA>() < other.GetConditionPhiExpr<HLIL_DO_WHILE_SSA>())
			return true;
		if (other.GetConditionPhiExpr<HLIL_DO_WHILE_SSA>() < GetConditionPhiExpr<HLIL_DO_WHILE_SSA>())
			return false;
		return GetConditionExpr<HLIL_DO_WHILE_SSA>() < other.GetConditionExpr<HLIL_DO_WHILE_SSA>();
	case HLIL_FOR:
		if (GetInitExpr<HLIL_FOR>() < other.GetInitExpr<HLIL_FOR>())
			return true;
		if (other.GetInitExpr<HLIL_FOR>() < GetInitExpr<HLIL_FOR>())
			return false;
		if (GetConditionExpr<HLIL_FOR>() < other.GetConditionExpr<HLIL_FOR>())
			return true;
		if (other.GetConditionExpr<HLIL_FOR>() < GetConditionExpr<HLIL_FOR>())
			return false;
		if (GetUpdateExpr<HLIL_FOR>() < other.GetUpdateExpr<HLIL_FOR>())
			return true;
		if (other.GetUpdateExpr<HLIL_FOR>() < GetUpdateExpr<HLIL_FOR>())
			return false;
		return GetLoopExpr<HLIL_FOR>() < other.GetLoopExpr<HLIL_FOR>();
	case HLIL_FOR_SSA:
		if (GetInitExpr<HLIL_FOR_SSA>() < other.GetInitExpr<HLIL_FOR_SSA>())
			return true;
		if (other.GetInitExpr<HLIL_FOR_SSA>() < GetInitExpr<HLIL_FOR_SSA>())
			return false;
		if (GetConditionPhiExpr<HLIL_FOR_SSA>() < other.GetConditionPhiExpr<HLIL_FOR_SSA>())
			return true;
		if (other.GetConditionPhiExpr<HLIL_FOR_SSA>() < GetConditionPhiExpr<HLIL_FOR_SSA>())
			return false;
		if (GetConditionExpr<HLIL_FOR_SSA>() < other.GetConditionExpr<HLIL_FOR_SSA>())
			return true;
		if (other.GetConditionExpr<HLIL_FOR_SSA>() < GetConditionExpr<HLIL_FOR_SSA>())
			return false;
		if (GetUpdateExpr<HLIL_FOR_SSA>() < other.GetUpdateExpr<HLIL_FOR_SSA>())
			return true;
		if (other.GetUpdateExpr<HLIL_FOR_SSA>() < GetUpdateExpr<HLIL_FOR_SSA>())
			return false;
		return GetLoopExpr<HLIL_FOR_SSA>() < other.GetLoopExpr<HLIL_FOR_SSA>();
	case HLIL_SWITCH:
		if (GetConditionExpr<HLIL_SWITCH>() < other.GetConditionExpr<HLIL_SWITCH>())
			return true;
		if (other.GetConditionExpr<HLIL_SWITCH>() < GetConditionExpr<HLIL_SWITCH>())
			return false;
		if (GetDefaultExpr<HLIL_SWITCH>() < other.GetDefaultExpr<HLIL_SWITCH>())
			return true;
		if (other.GetDefaultExpr<HLIL_SWITCH>() < GetDefaultExpr<HLIL_SWITCH>())
			return false;
		return CompareExprList(GetCases<HLIL_SWITCH>(), other.GetCases<HLIL_SWITCH>());
	case HLIL_CASE:
		if (GetTrueExpr<HLIL_CASE>() < other.GetTrueExpr<HLIL_CASE>())
			return true;
		if (other.GetTrueExpr<HLIL_CASE>() < GetTrueExpr<HLIL_CASE>())
			return false;
		return CompareExprList(GetValueExprs<HLIL_CASE>(), other.GetValueExprs<HLIL_CASE>());
	case HLIL_JUMP:
		return GetDestExpr<HLIL_JUMP>() < other.GetDestExpr<HLIL_JUMP>();
	case HLIL_RET:
		return CompareExprList(GetSourceExprs<HLIL_RET>(), other.GetSourceExprs<HLIL_RET>());
	case HLIL_GOTO:
		return GetTarget<HLIL_GOTO>() < other.GetTarget<HLIL_GOTO>();
	case HLIL_LABEL:
		return GetTarget<HLIL_LABEL>() < other.GetTarget<HLIL_LABEL>();
	case HLIL_VAR_DECLARE:
		return GetVariable<HLIL_VAR_DECLARE>() < other.GetVariable<HLIL_VAR_DECLARE>();
	case HLIL_VAR_INIT:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetDestVariable<HLIL_VAR_INIT>() < other.GetDestVariable<HLIL_VAR_INIT>())
			return true;
		if (other.GetDestVariable<HLIL_VAR_INIT>() < GetDestVariable<HLIL_VAR_INIT>())
			return false;
		return GetSourceExpr<HLIL_VAR_INIT>() < other.GetSourceExpr<HLIL_VAR_INIT>();
	case HLIL_VAR_INIT_SSA:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetDestSSAVariable<HLIL_VAR_INIT_SSA>() < other.GetDestSSAVariable<HLIL_VAR_INIT_SSA>())
			return true;
		if (other.GetDestSSAVariable<HLIL_VAR_INIT_SSA>() < GetDestSSAVariable<HLIL_VAR_INIT_SSA>())
			return false;
		return GetSourceExpr<HLIL_VAR_INIT_SSA>() < other.GetSourceExpr<HLIL_VAR_INIT_SSA>();
	case HLIL_ASSIGN:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetDestExpr<HLIL_ASSIGN>() < other.GetDestExpr<HLIL_ASSIGN>())
			return true;
		if (other.GetDestExpr<HLIL_ASSIGN>() < GetDestExpr<HLIL_ASSIGN>())
			return false;
		return GetSourceExpr<HLIL_ASSIGN>() < other.GetSourceExpr<HLIL_ASSIGN>();
	case HLIL_ASSIGN_UNPACK:
		if (GetSourceExpr<HLIL_ASSIGN_UNPACK>() < other.GetSourceExpr<HLIL_ASSIGN_UNPACK>())
			return true;
		if (other.GetSourceExpr<HLIL_ASSIGN_UNPACK>() < GetSourceExpr<HLIL_ASSIGN_UNPACK>())
			return false;
		return CompareExprList(GetDestExprs<HLIL_ASSIGN_UNPACK>(), other.GetDestExprs<HLIL_ASSIGN_UNPACK>());
	case HLIL_ASSIGN_MEM_SSA:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetDestExpr<HLIL_ASSIGN_MEM_SSA>() < other.GetDestExpr<HLIL_ASSIGN_MEM_SSA>())
			return true;
		if (other.GetDestExpr<HLIL_ASSIGN_MEM_SSA>() < GetDestExpr<HLIL_ASSIGN_MEM_SSA>())
			return false;
		if (GetDestMemoryVersion<HLIL_ASSIGN_MEM_SSA>() < other.GetDestMemoryVersion<HLIL_ASSIGN_MEM_SSA>())
			return true;
		if (other.GetDestMemoryVersion<HLIL_ASSIGN_MEM_SSA>() < GetDestMemoryVersion<HLIL_ASSIGN_MEM_SSA>())
			return false;
		if (GetSourceExpr<HLIL_ASSIGN_MEM_SSA>() < other.GetSourceExpr<HLIL_ASSIGN_MEM_SSA>())
			return true;
		if (other.GetSourceExpr<HLIL_ASSIGN_MEM_SSA>() < GetSourceExpr<HLIL_ASSIGN_MEM_SSA>())
			return false;
		return GetSourceMemoryVersion<HLIL_ASSIGN_MEM_SSA>() < other.GetSourceMemoryVersion<HLIL_ASSIGN_MEM_SSA>();
	case HLIL_ASSIGN_UNPACK_MEM_SSA:
		if (GetDestMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>()
		    < other.GetDestMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>())
			return true;
		if (other.GetDestMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>()
		    < GetDestMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>())
			return false;
		if (GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>() < other.GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>())
			return true;
		if (other.GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>() < GetSourceExpr<HLIL_ASSIGN_UNPACK_MEM_SSA>())
			return false;
		if (GetSourceMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>()
		    < other.GetSourceMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>())
			return true;
		if (other.GetSourceMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>()
		    < GetSourceMemoryVersion<HLIL_ASSIGN_UNPACK_MEM_SSA>())
			return false;
		return CompareExprList(
		    GetDestExprs<HLIL_ASSIGN_UNPACK_MEM_SSA>(), other.GetDestExprs<HLIL_ASSIGN_UNPACK_MEM_SSA>());
	case HLIL_VAR:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		return GetVariable<HLIL_VAR>() < other.GetVariable<HLIL_VAR>();
	case HLIL_VAR_SSA:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		return GetSSAVariable<HLIL_VAR_SSA>() < other.GetSSAVariable<HLIL_VAR_SSA>();
	case HLIL_VAR_SSA_PARTIAL:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetDestSSAVariable<HLIL_VAR_SSA_PARTIAL>() < other.GetDestSSAVariable<HLIL_VAR_SSA_PARTIAL>())
			return true;
		if (other.GetDestSSAVariable<HLIL_VAR_SSA_PARTIAL>() < GetDestSSAVariable<HLIL_VAR_SSA_PARTIAL>())
			return false;
		return GetSourceSSAVariable<HLIL_VAR_SSA_PARTIAL>() < other.GetSourceSSAVariable<HLIL_VAR_SSA_PARTIAL>();
	case HLIL_STRUCT_FIELD:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetSourceExpr<HLIL_STRUCT_FIELD>() < other.GetSourceExpr<HLIL_STRUCT_FIELD>())
			return true;
		if (other.GetSourceExpr<HLIL_STRUCT_FIELD>() < GetSourceExpr<HLIL_STRUCT_FIELD>())
			return false;
		if (GetOffset<HLIL_STRUCT_FIELD>() < other.GetOffset<HLIL_STRUCT_FIELD>())
			return true;
		if (other.GetOffset<HLIL_STRUCT_FIELD>() < GetOffset<HLIL_STRUCT_FIELD>())
			return false;
		return GetMemberIndex<HLIL_STRUCT_FIELD>() < other.GetMemberIndex<HLIL_STRUCT_FIELD>();
	case HLIL_ARRAY_INDEX:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetSourceExpr<HLIL_ARRAY_INDEX>() < other.GetSourceExpr<HLIL_ARRAY_INDEX>())
			return true;
		if (other.GetSourceExpr<HLIL_ARRAY_INDEX>() < GetSourceExpr<HLIL_ARRAY_INDEX>())
			return false;
		return GetIndexExpr<HLIL_ARRAY_INDEX>() < other.GetIndexExpr<HLIL_ARRAY_INDEX>();
	case HLIL_ARRAY_INDEX_SSA:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetSourceExpr<HLIL_ARRAY_INDEX_SSA>() < other.GetSourceExpr<HLIL_ARRAY_INDEX_SSA>())
			return true;
		if (other.GetSourceExpr<HLIL_ARRAY_INDEX_SSA>() < GetSourceExpr<HLIL_ARRAY_INDEX_SSA>())
			return false;
		if (GetIndexExpr<HLIL_ARRAY_INDEX_SSA>() < other.GetIndexExpr<HLIL_ARRAY_INDEX_SSA>())
			return true;
		if (other.GetIndexExpr<HLIL_ARRAY_INDEX_SSA>() < GetIndexExpr<HLIL_ARRAY_INDEX_SSA>())
			return false;
		return GetSourceMemoryVersion<HLIL_ARRAY_INDEX_SSA>() < other.GetSourceMemoryVersion<HLIL_ARRAY_INDEX_SSA>();
	case HLIL_STRUCT_INIT:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		return CompareExprList(GetFieldExprs<HLIL_STRUCT_INIT>(), other.GetFieldExprs<HLIL_STRUCT_INIT>());
	case HLIL_STRUCT_INIT_FIELD:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetOffset<HLIL_STRUCT_INIT_FIELD>() < other.GetOffset<HLIL_STRUCT_INIT_FIELD>())
			return true;
		if (other.GetOffset<HLIL_STRUCT_INIT_FIELD>() < GetOffset<HLIL_STRUCT_INIT_FIELD>())
			return false;
		if (GetMemberIndex<HLIL_STRUCT_INIT_FIELD>() < other.GetMemberIndex<HLIL_STRUCT_INIT_FIELD>())
			return true;
		if (other.GetMemberIndex<HLIL_STRUCT_INIT_FIELD>() < GetMemberIndex<HLIL_STRUCT_INIT_FIELD>())
			return false;
		return GetSourceExpr<HLIL_STRUCT_INIT_FIELD>() < other.GetSourceExpr<HLIL_STRUCT_INIT_FIELD>();
	case HLIL_SPLIT:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetHighExpr<HLIL_SPLIT>() < other.GetHighExpr<HLIL_SPLIT>())
			return true;
		if (other.GetHighExpr<HLIL_SPLIT>() < GetHighExpr<HLIL_SPLIT>())
			return false;
		return GetLowExpr<HLIL_SPLIT>() < other.GetLowExpr<HLIL_SPLIT>();
	case HLIL_DEREF_FIELD:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetSourceExpr<HLIL_DEREF_FIELD>() < other.GetSourceExpr<HLIL_DEREF_FIELD>())
			return true;
		if (other.GetSourceExpr<HLIL_DEREF_FIELD>() < GetSourceExpr<HLIL_DEREF_FIELD>())
			return false;
		if (GetOffset<HLIL_DEREF_FIELD>() < other.GetOffset<HLIL_DEREF_FIELD>())
			return true;
		if (other.GetOffset<HLIL_DEREF_FIELD>() < GetOffset<HLIL_DEREF_FIELD>())
			return false;
		return GetMemberIndex<HLIL_DEREF_FIELD>() < other.GetMemberIndex<HLIL_DEREF_FIELD>();
	case HLIL_DEREF_SSA:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetSourceExpr<HLIL_DEREF_SSA>() < other.GetSourceExpr<HLIL_DEREF_SSA>())
			return true;
		if (other.GetSourceExpr<HLIL_DEREF_SSA>() < GetSourceExpr<HLIL_DEREF_SSA>())
			return false;
		return GetSourceMemoryVersion<HLIL_DEREF_SSA>() < other.GetSourceMemoryVersion<HLIL_DEREF_SSA>();
	case HLIL_DEREF_FIELD_SSA:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (GetSourceExpr<HLIL_DEREF_FIELD_SSA>() < other.GetSourceExpr<HLIL_DEREF_FIELD_SSA>())
			return true;
		if (other.GetSourceExpr<HLIL_DEREF_FIELD_SSA>() < GetSourceExpr<HLIL_DEREF_FIELD_SSA>())
			return false;
		if (GetOffset<HLIL_DEREF_FIELD_SSA>() < other.GetOffset<HLIL_DEREF_FIELD_SSA>())
			return true;
		if (other.GetOffset<HLIL_DEREF_FIELD_SSA>() < GetOffset<HLIL_DEREF_FIELD_SSA>())
			return false;
		if (GetMemberIndex<HLIL_DEREF_FIELD_SSA>() < other.GetMemberIndex<HLIL_DEREF_FIELD_SSA>())
			return true;
		if (other.GetMemberIndex<HLIL_DEREF_FIELD_SSA>() < GetMemberIndex<HLIL_DEREF_FIELD_SSA>())
			return false;
		return GetSourceMemoryVersion<HLIL_DEREF_FIELD_SSA>() < other.GetSourceMemoryVersion<HLIL_DEREF_FIELD_SSA>();
	case HLIL_ADDRESS_OF:
		return GetSourceExpr<HLIL_ADDRESS_OF>() < other.GetSourceExpr<HLIL_ADDRESS_OF>();
	case HLIL_EXTERN_PTR:
		if (GetConstant<HLIL_EXTERN_PTR>() < other.GetConstant<HLIL_EXTERN_PTR>())
			return true;
		if (other.GetConstant<HLIL_EXTERN_PTR>() < GetConstant<HLIL_EXTERN_PTR>())
			return false;
		return GetOffset<HLIL_EXTERN_PTR>() < other.GetOffset<HLIL_EXTERN_PTR>();
	case HLIL_CALL:
		if (GetDestExpr<HLIL_CALL>() < other.GetDestExpr<HLIL_CALL>())
			return true;
		if (other.GetDestExpr<HLIL_CALL>() < GetDestExpr<HLIL_CALL>())
			return false;
		return CompareExprList(GetParameterExprs<HLIL_CALL>(), other.GetParameterExprs<HLIL_CALL>());
	case HLIL_SYSCALL:
		return CompareExprList(GetParameterExprs<HLIL_SYSCALL>(), other.GetParameterExprs<HLIL_SYSCALL>());
	case HLIL_TAILCALL:
		if (GetDestExpr<HLIL_TAILCALL>() < other.GetDestExpr<HLIL_TAILCALL>())
			return true;
		if (other.GetDestExpr<HLIL_TAILCALL>() < GetDestExpr<HLIL_TAILCALL>())
			return false;
		return CompareExprList(GetParameterExprs<HLIL_TAILCALL>(), other.GetParameterExprs<HLIL_TAILCALL>());
	case HLIL_INTRINSIC:
		if (GetIntrinsic<HLIL_INTRINSIC>() < other.GetIntrinsic<HLIL_INTRINSIC>())
			return true;
		if (other.GetIntrinsic<HLIL_INTRINSIC>() < GetIntrinsic<HLIL_INTRINSIC>())
			return false;
		return CompareExprList(GetParameterExprs<HLIL_INTRINSIC>(), other.GetParameterExprs<HLIL_INTRINSIC>());
	case HLIL_CALL_SSA:
		if (GetDestExpr<HLIL_CALL_SSA>() < other.GetDestExpr<HLIL_CALL_SSA>())
			return true;
		if (other.GetDestExpr<HLIL_CALL_SSA>() < GetDestExpr<HLIL_CALL_SSA>())
			return false;
		if (GetDestMemoryVersion<HLIL_CALL_SSA>() < other.GetDestMemoryVersion<HLIL_CALL_SSA>())
			return true;
		if (other.GetDestMemoryVersion<HLIL_CALL_SSA>() < GetDestMemoryVersion<HLIL_CALL_SSA>())
			return false;
		if (GetSourceMemoryVersion<HLIL_CALL_SSA>() < other.GetSourceMemoryVersion<HLIL_CALL_SSA>())
			return true;
		if (other.GetSourceMemoryVersion<HLIL_CALL_SSA>() < GetSourceMemoryVersion<HLIL_CALL_SSA>())
			return false;
		return CompareExprList(GetParameterExprs<HLIL_CALL_SSA>(), other.GetParameterExprs<HLIL_CALL_SSA>());
	case HLIL_SYSCALL_SSA:
		if (GetDestMemoryVersion<HLIL_SYSCALL_SSA>() < other.GetDestMemoryVersion<HLIL_SYSCALL_SSA>())
			return true;
		if (other.GetDestMemoryVersion<HLIL_SYSCALL_SSA>() < GetDestMemoryVersion<HLIL_SYSCALL_SSA>())
			return false;
		if (GetSourceMemoryVersion<HLIL_SYSCALL_SSA>() < other.GetSourceMemoryVersion<HLIL_SYSCALL_SSA>())
			return true;
		if (other.GetSourceMemoryVersion<HLIL_SYSCALL_SSA>() < GetSourceMemoryVersion<HLIL_SYSCALL_SSA>())
			return false;
		return CompareExprList(GetParameterExprs<HLIL_SYSCALL_SSA>(), other.GetParameterExprs<HLIL_SYSCALL_SSA>());
	case HLIL_INTRINSIC_SSA:
		if (GetIntrinsic<HLIL_INTRINSIC_SSA>() < other.GetIntrinsic<HLIL_INTRINSIC_SSA>())
			return true;
		if (other.GetIntrinsic<HLIL_INTRINSIC_SSA>() < GetIntrinsic<HLIL_INTRINSIC_SSA>())
			return false;
		if (GetDestMemoryVersion<HLIL_INTRINSIC_SSA>() < other.GetDestMemoryVersion<HLIL_INTRINSIC_SSA>())
			return true;
		if (other.GetDestMemoryVersion<HLIL_INTRINSIC_SSA>() < GetDestMemoryVersion<HLIL_INTRINSIC_SSA>())
			return false;
		if (GetSourceMemoryVersion<HLIL_INTRINSIC_SSA>() < other.GetSourceMemoryVersion<HLIL_INTRINSIC_SSA>())
			return true;
		if (other.GetSourceMemoryVersion<HLIL_INTRINSIC_SSA>() < GetSourceMemoryVersion<HLIL_INTRINSIC_SSA>())
			return false;
		return CompareExprList(GetParameterExprs<HLIL_INTRINSIC_SSA>(), other.GetParameterExprs<HLIL_INTRINSIC_SSA>());
	case HLIL_TRAP:
		return GetVector<HLIL_TRAP>() < other.GetVector<HLIL_TRAP>();
	case HLIL_ADD:
	case HLIL_SUB:
	case HLIL_AND:
	case HLIL_OR:
	case HLIL_XOR:
	case HLIL_MINS:
	case HLIL_MAXS:
	case HLIL_MINU:
	case HLIL_MAXU:
	case HLIL_LSL:
	case HLIL_LSR:
	case HLIL_ASR:
	case HLIL_ROL:
	case HLIL_ROR:
	case HLIL_MUL:
	case HLIL_MULU_DP:
	case HLIL_MULS_DP:
	case HLIL_DIVU:
	case HLIL_DIVS:
	case HLIL_MODU:
	case HLIL_MODS:
	case HLIL_DIVU_DP:
	case HLIL_DIVS_DP:
	case HLIL_MODU_DP:
	case HLIL_MODS_DP:
	case HLIL_CMP_E:
	case HLIL_CMP_NE:
	case HLIL_CMP_SLT:
	case HLIL_CMP_ULT:
	case HLIL_CMP_SLE:
	case HLIL_CMP_ULE:
	case HLIL_CMP_SGE:
	case HLIL_CMP_UGE:
	case HLIL_CMP_SGT:
	case HLIL_CMP_UGT:
	case HLIL_TEST_BIT:
	case HLIL_ADD_OVERFLOW:
	case HLIL_FADD:
	case HLIL_FSUB:
	case HLIL_FMUL:
	case HLIL_FDIV:
	case HLIL_FCMP_E:
	case HLIL_FCMP_NE:
	case HLIL_FCMP_LT:
	case HLIL_FCMP_LE:
	case HLIL_FCMP_GE:
	case HLIL_FCMP_GT:
	case HLIL_FCMP_O:
	case HLIL_FCMP_UO:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (AsTwoOperand().GetLeftExpr() < other.AsTwoOperand().GetLeftExpr())
			return true;
		if (other.AsTwoOperand().GetLeftExpr() < AsTwoOperand().GetLeftExpr())
			return false;
		return AsTwoOperand().GetRightExpr() < other.AsTwoOperand().GetRightExpr();
	case HLIL_ADC:
	case HLIL_SBB:
	case HLIL_RLC:
	case HLIL_RRC:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		if (AsTwoOperandWithCarry().GetLeftExpr() < other.AsTwoOperandWithCarry().GetLeftExpr())
			return true;
		if (other.AsTwoOperandWithCarry().GetLeftExpr() < AsTwoOperandWithCarry().GetLeftExpr())
			return false;
		if (AsTwoOperandWithCarry().GetRightExpr() < other.AsTwoOperandWithCarry().GetRightExpr())
			return true;
		if (other.AsTwoOperandWithCarry().GetRightExpr() < AsTwoOperandWithCarry().GetRightExpr())
			return false;
		return AsTwoOperandWithCarry().GetCarryExpr() < other.AsTwoOperandWithCarry().GetCarryExpr();
	case HLIL_CONST:
	case HLIL_CONST_DATA:
	case HLIL_CONST_PTR:
	case HLIL_FLOAT_CONST:
	case HLIL_IMPORT:
		return AsConstant().GetConstant() < other.AsConstant().GetConstant();
	case HLIL_DEREF:
	case HLIL_NEG:
	case HLIL_NOT:
	case HLIL_BSWAP:
	case HLIL_POPCNT:
	case HLIL_CLZ:
	case HLIL_CTZ:
	case HLIL_RBIT:
	case HLIL_CLS:
	case HLIL_ABS:
	case HLIL_SX:
	case HLIL_ZX:
	case HLIL_LOW_PART:
	case HLIL_BOOL_TO_INT:
	case HLIL_UNIMPL_MEM:
	case HLIL_FSQRT:
	case HLIL_FNEG:
	case HLIL_FABS:
	case HLIL_FLOAT_TO_INT:
	case HLIL_INT_TO_FLOAT:
	case HLIL_FLOAT_CONV:
	case HLIL_ROUND_TO_INT:
	case HLIL_FLOOR:
	case HLIL_CEIL:
	case HLIL_FTRUNC:
	case HLIL_PASS_BY_REF:
	case HLIL_RETURN_BY_REF:
		if (size < other.size)
			return true;
		if (size > other.size)
			return false;
		return AsOneOperand().GetSourceExpr() < other.AsOneOperand().GetSourceExpr();
	case HLIL_VAR_PHI:
	{
		if (GetDestSSAVariable<HLIL_VAR_PHI>() < other.GetDestSSAVariable<HLIL_VAR_PHI>())
			return true;
		if (other.GetDestSSAVariable<HLIL_VAR_PHI>() < GetDestSSAVariable<HLIL_VAR_PHI>())
			return false;
		HighLevelILSSAVariableList list = GetSourceSSAVariables<HLIL_VAR_PHI>();
		HighLevelILSSAVariableList otherList = other.GetSourceSSAVariables<HLIL_VAR_PHI>();
		if (list.size() < otherList.size())
			return true;
		if (list.size() > otherList.size())
			return false;
		auto i = list.begin();
		auto j = otherList.begin();
		for (; i != list.end(); ++i, ++j)
		{
			if (*i < *j)
				return true;
			if (*j < *i)
				return false;
		}
		return false;
	}
	case HLIL_MEM_PHI:
	{
		if (GetDestMemoryVersion<HLIL_MEM_PHI>() < other.GetDestMemoryVersion<HLIL_MEM_PHI>())
			return true;
		if (other.GetDestMemoryVersion<HLIL_MEM_PHI>() < GetDestMemoryVersion<HLIL_MEM_PHI>())
			return false;
		HighLevelILIndexList list = GetSourceMemoryVersions<HLIL_MEM_PHI>();
		HighLevelILIndexList otherList = other.GetSourceMemoryVersions<HLIL_MEM_PHI>();
		if (list.size() < otherList.size())
			return true;
		if (list.size() > otherList.size())
			return false;
		auto i = list.begin();
		auto j = otherList.begin();
		for (; i != list.end(); ++i, ++j)
		{
			if (*i < *j)
				return true;
			if (*j < *i)
				return false;
		}
		return false;
	}
	default:
		return false;
	}
}


bool HighLevelILInstruction::operator==(const HighLevelILInstruction& other) const
{
	return !((*this < other) || (other < *this));
}


bool HighLevelILInstruction::operator!=(const HighLevelILInstruction& other) const
{
	return !(*this == other);
}


bool HighLevelILInstruction::GetOperandIndexForUsage(HighLevelILOperandUsage usage, size_t& operandIndex) const
{
	if (operation >= s_instructionOperandUsage.size())
		return false;

	const auto& info = s_instructionOperandUsage[operation];
	for (uint8_t i = 0; i < info.count; ++i)
	{
		if (info.usages[i] == usage)
		{
			operandIndex = info.indices[i];
			return true;
		}
	}

	return false;
}


HighLevelILInstruction HighLevelILInstruction::GetSourceExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


Variable HighLevelILInstruction::GetVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(VariableHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsVariable(operandIndex);
	throw HighLevelILInstructionAccessException();
}


Variable HighLevelILInstruction::GetDestVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(DestVariableHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsVariable(operandIndex);
	throw HighLevelILInstructionAccessException();
}


SSAVariable HighLevelILInstruction::GetSSAVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SSAVariableHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAVariable(operandIndex);
	throw HighLevelILInstructionAccessException();
}


SSAVariable HighLevelILInstruction::GetDestSSAVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(DestSSAVariableHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAVariable(operandIndex);
	throw HighLevelILInstructionAccessException();
}


SSAVariable HighLevelILInstruction::GetSourceSSAVariable() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(PartialSSAVariableSourceHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsPartialSSAVariableSource(operandIndex - 2);
	throw MediumLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetDestExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(DestExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetLeftExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(LeftExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetRightExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(RightExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetCarryExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(CarryExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetIndexExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(IndexExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetConditionExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ConditionExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetConditionPhiExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ConditionPhiExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetTrueExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(TrueExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetFalseExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(FalseExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetLoopExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(LoopExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetInitExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(InitExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetUpdateExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(UpdateExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetDefaultExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(DefaultExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetHighExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(HighExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstruction HighLevelILInstruction::GetLowExpr() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(LowExprHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExpr(operandIndex);
	throw HighLevelILInstructionAccessException();
}


uint64_t HighLevelILInstruction::GetOffset() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(OffsetHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
	throw HighLevelILInstructionAccessException();
}


size_t HighLevelILInstruction::GetMemberIndex() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(MemberIndexHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
	throw HighLevelILInstructionAccessException();
}


int64_t HighLevelILInstruction::GetConstant() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ConstantHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
	throw HighLevelILInstructionAccessException();
}


ConstantData HighLevelILInstruction::GetConstantData() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ConstantDataHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsConstantData(operandIndex);
	throw HighLevelILInstructionAccessException();
}


int64_t HighLevelILInstruction::GetVector() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(VectorHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
	throw HighLevelILInstructionAccessException();
}


uint32_t HighLevelILInstruction::GetIntrinsic() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(IntrinsicHighLevelOperandUsage, operandIndex))
		return (uint32_t)GetRawOperandAsInteger(operandIndex);
	throw HighLevelILInstructionAccessException();
}


uint64_t HighLevelILInstruction::GetTarget() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(TargetHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsInteger(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstructionList HighLevelILInstruction::GetParameterExprs() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ParameterExprsHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExprList(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstructionList HighLevelILInstruction::GetSourceExprs() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceExprsHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExprList(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstructionList HighLevelILInstruction::GetDestExprs() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(DestExprsHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExprList(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstructionList HighLevelILInstruction::GetBlockExprs() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(BlockExprsHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExprList(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstructionList HighLevelILInstruction::GetCases() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(CasesHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExprList(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstructionList HighLevelILInstruction::GetValueExprs() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(ValueExprsHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExprList(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILInstructionList HighLevelILInstruction::GetFieldExprs() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(FieldExprsHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsExprList(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILSSAVariableList HighLevelILInstruction::GetSourceSSAVariables() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceSSAVariablesHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsSSAVariableList(operandIndex);
	throw HighLevelILInstructionAccessException();
}


size_t HighLevelILInstruction::GetSourceMemoryVersion() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceMemoryVersionHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
	throw HighLevelILInstructionAccessException();
}


HighLevelILIndexList HighLevelILInstruction::GetSourceMemoryVersions() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(SourceMemoryVersionsHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndexList(operandIndex);
	throw HighLevelILInstructionAccessException();
}


size_t HighLevelILInstruction::GetDestMemoryVersion() const
{
	size_t operandIndex;
	if (GetOperandIndexForUsage(DestMemoryVersionHighLevelOperandUsage, operandIndex))
		return GetRawOperandAsIndex(operandIndex);
	throw HighLevelILInstructionAccessException();
}


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

ExprId HighLevelILFunction::Nop(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_NOP, loc, 0);
}


ExprId HighLevelILFunction::Block(const vector<ExprId>& exprs, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_BLOCK, loc, 0, exprs.size(), AddOperandList(exprs));
}


ExprId HighLevelILFunction::If(ExprId condition, ExprId trueExpr, ExprId falseExpr, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_IF, loc, 0, condition, trueExpr, falseExpr);
}


ExprId HighLevelILFunction::While(ExprId condition, ExprId loopExpr, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_WHILE, loc, 0, condition, loopExpr);
}


ExprId HighLevelILFunction::WhileSSA(
    ExprId conditionPhi, ExprId condition, ExprId loopExpr, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_WHILE_SSA, loc, 0, conditionPhi, condition, loopExpr);
}


ExprId HighLevelILFunction::DoWhile(ExprId loopExpr, ExprId condition, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DO_WHILE, loc, 0, loopExpr, condition);
}


ExprId HighLevelILFunction::DoWhileSSA(
    ExprId loopExpr, ExprId conditionPhi, ExprId condition, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DO_WHILE_SSA, loc, 0, loopExpr, conditionPhi, condition);
}


ExprId HighLevelILFunction::For(
    ExprId initExpr, ExprId condition, ExprId updateExpr, ExprId loopExpr, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FOR, loc, 0, initExpr, condition, updateExpr, loopExpr);
}


ExprId HighLevelILFunction::ForSSA(ExprId initExpr, ExprId conditionPhi, ExprId condition, ExprId updateExpr,
    ExprId loopExpr, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FOR_SSA, loc, 0, initExpr, conditionPhi, condition, updateExpr, loopExpr);
}


ExprId HighLevelILFunction::Switch(
    ExprId condition, ExprId defaultExpr, const vector<ExprId>& cases, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SWITCH, loc, 0, condition, defaultExpr, cases.size(), AddOperandList(cases));
}


ExprId HighLevelILFunction::Case(const vector<ExprId>& values, ExprId expr, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CASE, loc, 0, values.size(), AddOperandList(values), expr);
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


ExprId HighLevelILFunction::Return(const vector<ExprId>& sources, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_RET, loc, 0, sources.size(), AddOperandList(sources));
}


ExprId HighLevelILFunction::NoReturn(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_NORET, loc, 0);
}


ExprId HighLevelILFunction::Unreachable(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNREACHABLE, loc, 0);
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


ExprId HighLevelILFunction::VarInitSSA(size_t size, const SSAVariable& dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR_INIT_SSA, loc, size, dest.var.ToIdentifier(), dest.version, src);
}


ExprId HighLevelILFunction::Assign(size_t size, ExprId dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASSIGN, loc, size, dest, src);
}


ExprId HighLevelILFunction::AssignUnpack(const vector<ExprId>& output, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASSIGN_UNPACK, loc, 0, output.size(), AddOperandList(output), src);
}


ExprId HighLevelILFunction::AssignMemSSA(
    size_t size, ExprId dest, size_t destMemVersion, ExprId src, size_t srcMemVersion, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASSIGN_MEM_SSA, loc, size, dest, destMemVersion, src, srcMemVersion);
}


ExprId HighLevelILFunction::AssignUnpackMemSSA(
    const vector<ExprId>& output, size_t destMemVersion, ExprId src, size_t srcMemVersion, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    HLIL_ASSIGN_UNPACK_MEM_SSA, loc, 0, output.size(), AddOperandList(output), destMemVersion, src, srcMemVersion);
}


ExprId HighLevelILFunction::ForceVer(size_t size, const Variable& dest, const Variable& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FORCE_VER, loc, size, dest.ToIdentifier(), src.ToIdentifier());
}


ExprId HighLevelILFunction::ForceVerSSA(size_t size, const SSAVariable& dest, const SSAVariable& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FORCE_VER_SSA, loc, size, dest.var.ToIdentifier(), dest.version, src.var.ToIdentifier(), src.version);
}


ExprId HighLevelILFunction::Assert(size_t size, const Variable& src, const PossibleValueSet& pvs, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASSERT, loc, size, src.ToIdentifier(), CachePossibleValueSet(pvs));
}


ExprId HighLevelILFunction::AssertSSA(size_t size, const SSAVariable& src, const PossibleValueSet& pvs, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ASSERT_SSA, loc, size, src.var.ToIdentifier(), src.version, CachePossibleValueSet(pvs));
}


ExprId HighLevelILFunction::Var(size_t size, const Variable& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR, loc, size, src.ToIdentifier());
}


ExprId HighLevelILFunction::VarSSA(size_t size, const SSAVariable& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR_SSA, loc, size, src.var.ToIdentifier(), src.version);
}


ExprId HighLevelILFunction::VarSSAPartial(size_t size, const Variable& dest, size_t newVersion, size_t prevVersion,
	const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_VAR_SSA_PARTIAL, loc, size, dest.ToIdentifier(), newVersion, prevVersion);
}


ExprId HighLevelILFunction::VarPhi(
    const SSAVariable& dest, const vector<SSAVariable>& sources, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    HLIL_VAR_PHI, loc, 0, dest.var.ToIdentifier(), dest.version, sources.size() * 2, AddSSAVariableList(sources));
}


ExprId HighLevelILFunction::MemPhi(size_t dest, const vector<size_t>& sources, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MEM_PHI, loc, 0, dest, sources.size(), AddIndexList(sources));
}


ExprId HighLevelILFunction::StructField(
    size_t size, ExprId src, uint64_t offset, size_t memberIndex, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_STRUCT_FIELD, loc, size, src, offset, memberIndex);
}


ExprId HighLevelILFunction::Split(size_t size, ExprId high, ExprId low, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SPLIT, loc, size, high, low);
}


ExprId HighLevelILFunction::ArrayIndex(size_t size, ExprId src, ExprId idx, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ARRAY_INDEX, loc, size, src, idx);
}


ExprId HighLevelILFunction::ArrayIndexSSA(
    size_t size, ExprId src, size_t srcMemVersion, ExprId idx, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ARRAY_INDEX_SSA, loc, size, src, srcMemVersion, idx);
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


ExprId HighLevelILFunction::Deref(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DEREF, loc, size, src);
}


ExprId HighLevelILFunction::DerefField(
    size_t size, ExprId src, uint64_t offset, size_t memberIndex, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DEREF_FIELD, loc, size, src, offset, memberIndex);
}


ExprId HighLevelILFunction::DerefSSA(size_t size, ExprId src, size_t srcMemVersion, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DEREF_SSA, loc, size, src, srcMemVersion);
}


ExprId HighLevelILFunction::DerefFieldSSA(
    size_t size, ExprId src, size_t srcMemVersion, uint64_t offset, size_t memberIndex, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DEREF_FIELD_SSA, loc, size, src, srcMemVersion, offset, memberIndex);
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


ExprId HighLevelILFunction::Const(size_t size, uint64_t val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CONST, loc, size, val);
}


ExprId HighLevelILFunction::ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CONST_PTR, loc, size, val);
}


ExprId HighLevelILFunction::ExternPointer(size_t size, uint64_t val, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_EXTERN_PTR, loc, size, val, offset);
}


ExprId HighLevelILFunction::FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FLOAT_CONST, loc, size, val);
}


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


ExprId HighLevelILFunction::ImportedAddress(size_t size, uint64_t val, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_IMPORT, loc, size, val);
}


ExprId HighLevelILFunction::ConstData(size_t size, const ConstantData& data, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CONST_DATA, loc, size, data.state, data.value);
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


ExprId HighLevelILFunction::MultDoublePrecSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MULS_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::MultDoublePrecUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MULU_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::DivSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVS, loc, size, left, right);
}


ExprId HighLevelILFunction::DivUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVU, loc, size, left, right);
}


ExprId HighLevelILFunction::DivDoublePrecSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVS_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::DivDoublePrecUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_DIVU_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::ModSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MODS, loc, size, left, right);
}


ExprId HighLevelILFunction::ModUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MODU, loc, size, left, right);
}


ExprId HighLevelILFunction::ModDoublePrecSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MODS_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::ModDoublePrecUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_MODU_DP, loc, size, left, right);
}


ExprId HighLevelILFunction::Neg(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_NEG, loc, size, src);
}


ExprId HighLevelILFunction::Not(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_NOT, loc, size, src);
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


ExprId HighLevelILFunction::Syscall(const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_SYSCALL, loc, 0, params.size(), AddOperandList(params));
}


ExprId HighLevelILFunction::TailCall(ExprId dest, const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_TAILCALL, loc, 0, dest, params.size(), AddOperandList(params));
}


ExprId HighLevelILFunction::CallSSA(
    ExprId dest, const vector<ExprId>& params, size_t destMemVersion, size_t srcMemVersion, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    HLIL_CALL_SSA, loc, 0, dest, params.size(), AddOperandList(params), destMemVersion, srcMemVersion);
}


ExprId HighLevelILFunction::SyscallSSA(
    const vector<ExprId>& params, size_t destMemVersion, size_t srcMemVersion, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    HLIL_SYSCALL_SSA, loc, 0, params.size(), AddOperandList(params), destMemVersion, srcMemVersion);
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


ExprId HighLevelILFunction::Breakpoint(const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_BP, loc, 0);
}


ExprId HighLevelILFunction::Trap(int64_t vector, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_TRAP, loc, 0, vector);
}


ExprId HighLevelILFunction::Intrinsic(uint32_t intrinsic, const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_INTRINSIC, loc, 0, intrinsic, params.size(), AddOperandList(params));
}


ExprId HighLevelILFunction::IntrinsicSSA(uint32_t intrinsic, const vector<ExprId>& params, size_t destMemVersion,
    size_t srcMemVersion, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    HLIL_INTRINSIC_SSA, loc, 0, intrinsic, params.size(), AddOperandList(params), destMemVersion, srcMemVersion);
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


ExprId HighLevelILFunction::UnimplementedMemoryRef(size_t size, ExprId target, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNIMPL_MEM, loc, size, target, 0);
}


ExprId HighLevelILFunction::UnknownMemoryRef(size_t size, ExprId target, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_UNIMPL_MEM, loc, size, target, 1);
}


ExprId HighLevelILFunction::FloatAdd(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FADD, loc, size, a, b);
}


ExprId HighLevelILFunction::FloatSub(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FSUB, loc, size, a, b);
}


ExprId HighLevelILFunction::FloatMult(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FMUL, loc, size, a, b);
}


ExprId HighLevelILFunction::FloatDiv(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FDIV, loc, size, a, b);
}


ExprId HighLevelILFunction::FloatSqrt(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FSQRT, loc, size, a);
}


ExprId HighLevelILFunction::FloatNeg(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FNEG, loc, size, a);
}


ExprId HighLevelILFunction::FloatAbs(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FABS, loc, size, a);
}


ExprId HighLevelILFunction::FloatToInt(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FLOAT_TO_INT, loc, size, a);
}


ExprId HighLevelILFunction::IntToFloat(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_INT_TO_FLOAT, loc, size, a);
}


ExprId HighLevelILFunction::FloatConvert(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FLOAT_CONV, loc, size, a);
}


ExprId HighLevelILFunction::RoundToInt(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_ROUND_TO_INT, loc, size, a);
}


ExprId HighLevelILFunction::Floor(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FLOOR, loc, size, a);
}


ExprId HighLevelILFunction::Ceil(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_CEIL, loc, size, a);
}


ExprId HighLevelILFunction::FloatTrunc(size_t size, ExprId a, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FTRUNC, loc, size, a);
}


ExprId HighLevelILFunction::FloatCompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_E, loc, size, a, b);
}


ExprId HighLevelILFunction::FloatCompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_NE, loc, size, a, b);
}


ExprId HighLevelILFunction::FloatCompareLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_LT, loc, size, a, b);
}


ExprId HighLevelILFunction::FloatCompareLessEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_LE, loc, size, a, b);
}


ExprId HighLevelILFunction::FloatCompareGreaterEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_GE, loc, size, a, b);
}


ExprId HighLevelILFunction::FloatCompareGreaterThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_GT, loc, size, a, b);
}


ExprId HighLevelILFunction::FloatCompareOrdered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_O, loc, size, a, b);
}


ExprId HighLevelILFunction::FloatCompareUnordered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc)
{
	return AddExprWithLocation(HLIL_FCMP_UO, loc, size, a, b);
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
