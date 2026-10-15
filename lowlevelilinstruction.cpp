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
#include <cstring>
#include <array>
#include <initializer_list>

#include "sharedilinstruction.h"

#ifdef BINARYNINJACORE_LIBRARY
	#include "lowlevelilfunction.h"
	#include "lowlevelilssafunction.h"
	#include "mediumlevelilfunction.h"
using namespace BinaryNinjaCore;
#else
	#include "binaryninjaapi.h"
	#include "lowlevelilinstruction.h"
	#include "mediumlevelilinstruction.h"
using namespace BinaryNinja;
#endif

#ifndef BINARYNINJACORE_LIBRARY
using namespace std;
#endif


namespace {

struct OperandUsageType
{
	LowLevelILOperandUsage usage;
	LowLevelILOperandType type;

	constexpr auto operator<=>(const OperandUsageType& other) const
	{
		return usage <=> other.usage;
	}
};

// BEGIN GENERATED llil-operand-tables: from api/il, do not edit
static constexpr std::array s_operandTypeForUsage = {
	OperandUsageType{DestRegisterLowLevelOperandUsage, RegisterLowLevelOperand},
	OperandUsageType{SourceExprLowLevelOperandUsage, ExprLowLevelOperand},
	OperandUsageType{HighRegisterLowLevelOperandUsage, RegisterLowLevelOperand},
	OperandUsageType{LowRegisterLowLevelOperandUsage, RegisterLowLevelOperand},
	OperandUsageType{DestFlagLowLevelOperandUsage, FlagLowLevelOperand},
	OperandUsageType{DestRegisterStackLowLevelOperandUsage, RegisterStackLowLevelOperand},
	OperandUsageType{DestExprLowLevelOperandUsage, ExprLowLevelOperand},
	OperandUsageType{SourceRegisterLowLevelOperandUsage, RegisterLowLevelOperand},
	OperandUsageType{ConstraintLowLevelOperandUsage, ConstraintLowLevelOperand},
	OperandUsageType{SourceRegisterStackLowLevelOperandUsage, RegisterStackLowLevelOperand},
	OperandUsageType{ConstantLowLevelOperandUsage, IntegerLowLevelOperand},
	OperandUsageType{OffsetLowLevelOperandUsage, IntegerLowLevelOperand},
	OperandUsageType{SourceFlagLowLevelOperandUsage, FlagLowLevelOperand},
	OperandUsageType{BitIndexLowLevelOperandUsage, IndexLowLevelOperand},
	OperandUsageType{LeftExprLowLevelOperandUsage, ExprLowLevelOperand},
	OperandUsageType{RightExprLowLevelOperandUsage, ExprLowLevelOperand},
	OperandUsageType{CarryExprLowLevelOperandUsage, ExprLowLevelOperand},
	OperandUsageType{TargetsLowLevelOperandUsage, IndexMapLowLevelOperand},
	OperandUsageType{StackAdjustmentLowLevelOperandUsage, IntegerLowLevelOperand},
	OperandUsageType{RegisterStackAdjustmentsLowLevelOperandUsage, RegisterStackAdjustmentsLowLevelOperand},
	OperandUsageType{ConditionExprLowLevelOperandUsage, ExprLowLevelOperand},
	OperandUsageType{TrueTargetLowLevelOperandUsage, IndexLowLevelOperand},
	OperandUsageType{FalseTargetLowLevelOperandUsage, IndexLowLevelOperand},
	OperandUsageType{TargetLowLevelOperandUsage, IndexLowLevelOperand},
	OperandUsageType{FlagConditionLowLevelOperandUsage, FlagConditionLowLevelOperand},
	OperandUsageType{SemanticFlagClassLowLevelOperandUsage, SemanticFlagClassLowLevelOperand},
	OperandUsageType{SemanticFlagGroupLowLevelOperandUsage, SemanticFlagGroupLowLevelOperand},
	OperandUsageType{VectorLowLevelOperandUsage, IntegerLowLevelOperand},
	OperandUsageType{OutputRegisterOrFlagListLowLevelOperandUsage, RegisterOrFlagListLowLevelOperand},
	OperandUsageType{IntrinsicLowLevelOperandUsage, IntrinsicLowLevelOperand},
	OperandUsageType{ParameterExprsLowLevelOperandUsage, ExprListLowLevelOperand},
	OperandUsageType{DestSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
	OperandUsageType{PartialRegisterLowLevelOperandUsage, RegisterLowLevelOperand},
	OperandUsageType{HighSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
	OperandUsageType{LowSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
	OperandUsageType{DestSSARegisterStackLowLevelOperandUsage, SSARegisterStackLowLevelOperand},
	OperandUsageType{PartialSSARegisterStackSourceLowLevelOperandUsage, SSARegisterStackLowLevelOperand},
	OperandUsageType{TopSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
	OperandUsageType{SourceSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
	OperandUsageType{SourceSSARegisterStackLowLevelOperandUsage, SSARegisterStackLowLevelOperand},
	OperandUsageType{DestSSAFlagLowLevelOperandUsage, SSAFlagLowLevelOperand},
	OperandUsageType{SourceSSAFlagLowLevelOperandUsage, SSAFlagLowLevelOperand},
	OperandUsageType{OutputSSARegistersLowLevelOperandUsage, SSARegisterListLowLevelOperand},
	OperandUsageType{OutputMemoryVersionLowLevelOperandUsage, IndexLowLevelOperand},
	OperandUsageType{StackSSARegisterLowLevelOperandUsage, SSARegisterLowLevelOperand},
	OperandUsageType{StackMemoryVersionLowLevelOperandUsage, IndexLowLevelOperand},
	OperandUsageType{SourceMemoryVersionLowLevelOperandUsage, IndexLowLevelOperand},
	OperandUsageType{DestMemoryVersionLowLevelOperandUsage, IndexLowLevelOperand},
	OperandUsageType{OutputSSARegisterOrFlagListLowLevelOperandUsage, SSARegisterOrFlagListLowLevelOperand},
	OperandUsageType{OutputMemoryIntrinsicLowLevelOperandUsage, SSARegisterOrFlagListLowLevelOperand},
	OperandUsageType{SourceSSARegistersLowLevelOperandUsage, SSARegisterListLowLevelOperand},
	OperandUsageType{SourceSSARegisterStacksLowLevelOperandUsage, SSARegisterStackListLowLevelOperand},
	OperandUsageType{SourceSSAFlagsLowLevelOperandUsage, SSAFlagListLowLevelOperand},
	OperandUsageType{SourceMemoryVersionsLowLevelOperandUsage, IndexListLowLevelOperand},
};

static_assert(std::is_sorted(s_operandTypeForUsage.begin(), s_operandTypeForUsage.end()),
	"Operand type mapping array is not sorted by usage value");


constexpr inline LowLevelILOperandType OperandTypeForUsage(LowLevelILOperandUsage usage)
{
	if (static_cast<size_t>(usage) < s_operandTypeForUsage.size())
		return s_operandTypeForUsage[usage].type;

	throw LowLevelILInstructionAccessException();
}


static constexpr size_t MaxOperands = 6;
using OperandLocations = detail::ILInstructionOperandLocations<BNLowLevelILOperation, LowLevelILOperandLocation, MaxOperands>;

static constexpr std::array s_operandLocations = {
	OperandLocations{LLIL_NOP},
	OperandLocations{LLIL_SET_REG, {{DestRegisterLowLevelOperandUsage, 0}, {SourceExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_SET_REG_SPLIT, {{HighRegisterLowLevelOperandUsage, 0}, {LowRegisterLowLevelOperandUsage, 1}, {SourceExprLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_SET_FLAG, {{DestFlagLowLevelOperandUsage, 0}, {SourceExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_SET_REG_STACK_REL, {{DestRegisterStackLowLevelOperandUsage, 0}, {DestExprLowLevelOperandUsage, 1}, {SourceExprLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_REG_STACK_PUSH, {{DestRegisterStackLowLevelOperandUsage, 0}, {SourceExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_ASSERT, {{SourceRegisterLowLevelOperandUsage, 0}, {ConstraintLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FORCE_VER, {{DestRegisterLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_LOAD, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_STORE, {{DestExprLowLevelOperandUsage, 0}, {SourceExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_PUSH, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_POP},
	OperandLocations{LLIL_REG, {{SourceRegisterLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_REG_SPLIT, {{HighRegisterLowLevelOperandUsage, 0}, {LowRegisterLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_REG_STACK_REL, {{SourceRegisterStackLowLevelOperandUsage, 0}, {SourceExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_REG_STACK_POP, {{SourceRegisterStackLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_REG_STACK_FREE_REG, {{DestRegisterLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_REG_STACK_FREE_REL, {{DestRegisterStackLowLevelOperandUsage, 0}, {DestExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_CONST, {{ConstantLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_CONST_PTR, {{ConstantLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_EXTERN_PTR, {{ConstantLowLevelOperandUsage, 0}, {OffsetLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FLOAT_CONST, {{ConstantLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FLAG, {{SourceFlagLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FLAG_BIT, {{SourceFlagLowLevelOperandUsage, 0}, {BitIndexLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_ADD, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_ADC, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}, {CarryExprLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_SUB, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_SBB, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}, {CarryExprLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_AND, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_OR, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_XOR, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_LSL, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_LSR, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_ASR, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_ROL, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_RLC, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}, {CarryExprLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_ROR, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_RRC, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}, {CarryExprLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_MUL, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_MULU_DP, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_MULS_DP, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_DIVU, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_DIVU_DP, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_DIVS, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_DIVS_DP, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_MODU, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_MODU_DP, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_MODS, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_MODS_DP, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_NEG, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_NOT, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_SX, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_ZX, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_LOW_PART, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_JUMP, {{DestExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_JUMP_TO, {{DestExprLowLevelOperandUsage, 0}, {TargetsLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_CALL, {{DestExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_CALL_STACK_ADJUST, {{DestExprLowLevelOperandUsage, 0}, {StackAdjustmentLowLevelOperandUsage, 1}, {RegisterStackAdjustmentsLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_TAILCALL, {{DestExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_RET, {{DestExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_NORET},
	OperandLocations{LLIL_IF, {{ConditionExprLowLevelOperandUsage, 0}, {TrueTargetLowLevelOperandUsage, 1}, {FalseTargetLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_GOTO, {{TargetLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FLAG_COND, {{FlagConditionLowLevelOperandUsage, 0}, {SemanticFlagClassLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FLAG_GROUP, {{SemanticFlagGroupLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_CMP_E, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_CMP_NE, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_CMP_SLT, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_CMP_ULT, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_CMP_SLE, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_CMP_ULE, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_CMP_SGE, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_CMP_UGE, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_CMP_SGT, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_CMP_UGT, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_TEST_BIT, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_BOOL_TO_INT, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_ADD_OVERFLOW, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_SYSCALL},
	OperandLocations{LLIL_BP},
	OperandLocations{LLIL_TRAP, {{VectorLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_INTRINSIC, {{OutputRegisterOrFlagListLowLevelOperandUsage, 0}, {IntrinsicLowLevelOperandUsage, 2}, {ParameterExprsLowLevelOperandUsage, 3, 0}}},
	OperandLocations{LLIL_UNDEF},
	OperandLocations{LLIL_UNIMPL},
	OperandLocations{LLIL_UNIMPL_MEM, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FADD, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FSUB, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FMUL, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FDIV, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FSQRT, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FNEG, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FABS, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FLOAT_TO_INT, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_INT_TO_FLOAT, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FLOAT_CONV, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_ROUND_TO_INT, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FLOOR, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_CEIL, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FTRUNC, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FCMP_E, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FCMP_NE, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FCMP_LT, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FCMP_LE, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FCMP_GE, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FCMP_GT, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FCMP_O, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_FCMP_UO, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_SET_REG_SSA, {{DestSSARegisterLowLevelOperandUsage, 0}, {SourceExprLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_SET_REG_SSA_PARTIAL, {{DestSSARegisterLowLevelOperandUsage, 0}, {PartialRegisterLowLevelOperandUsage, 2}, {SourceExprLowLevelOperandUsage, 3}}},
	OperandLocations{LLIL_SET_REG_SPLIT_SSA, {{HighSSARegisterLowLevelOperandUsage, 0, 0}, {LowSSARegisterLowLevelOperandUsage, 1, 0}, {SourceExprLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_SET_REG_STACK_REL_SSA, {{DestSSARegisterStackLowLevelOperandUsage, 0, 0}, {PartialSSARegisterStackSourceLowLevelOperandUsage, 0, 0, true}, {DestExprLowLevelOperandUsage, 1}, {TopSSARegisterLowLevelOperandUsage, 2, 0}, {SourceExprLowLevelOperandUsage, 3}}},
	OperandLocations{LLIL_SET_REG_STACK_ABS_SSA, {{DestSSARegisterStackLowLevelOperandUsage, 0, 0}, {PartialSSARegisterStackSourceLowLevelOperandUsage, 0, 0, true}, {DestRegisterLowLevelOperandUsage, 1}, {SourceExprLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_REG_SPLIT_DEST_SSA, {{DestSSARegisterLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_REG_STACK_DEST_SSA, {{DestSSARegisterStackLowLevelOperandUsage, 0}, {PartialSSARegisterStackSourceLowLevelOperandUsage, 0, std::nullopt, true}}},
	OperandLocations{LLIL_REG_SSA, {{SourceSSARegisterLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_REG_SSA_PARTIAL, {{SourceSSARegisterLowLevelOperandUsage, 0}, {PartialRegisterLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_REG_SPLIT_SSA, {{HighSSARegisterLowLevelOperandUsage, 0}, {LowSSARegisterLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_REG_STACK_REL_SSA, {{SourceSSARegisterStackLowLevelOperandUsage, 0}, {SourceExprLowLevelOperandUsage, 2}, {TopSSARegisterLowLevelOperandUsage, 3, 0}}},
	OperandLocations{LLIL_REG_STACK_ABS_SSA, {{SourceSSARegisterStackLowLevelOperandUsage, 0}, {SourceRegisterLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_REG_STACK_FREE_REL_SSA, {{DestSSARegisterStackLowLevelOperandUsage, 0, 0}, {PartialSSARegisterStackSourceLowLevelOperandUsage, 0, 0, true}, {DestExprLowLevelOperandUsage, 1}, {TopSSARegisterLowLevelOperandUsage, 2, 0}}},
	OperandLocations{LLIL_REG_STACK_FREE_ABS_SSA, {{DestSSARegisterStackLowLevelOperandUsage, 0, 0}, {PartialSSARegisterStackSourceLowLevelOperandUsage, 0, 0, true}, {DestRegisterLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_SET_FLAG_SSA, {{DestSSAFlagLowLevelOperandUsage, 0}, {SourceExprLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_ASSERT_SSA, {{SourceSSARegisterLowLevelOperandUsage, 0}, {ConstraintLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_FORCE_VER_SSA, {{DestSSARegisterLowLevelOperandUsage, 0}, {SourceSSARegisterLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_FLAG_SSA, {{SourceSSAFlagLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_FLAG_BIT_SSA, {{SourceSSAFlagLowLevelOperandUsage, 0}, {BitIndexLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_CALL_SSA, {{OutputSSARegistersLowLevelOperandUsage, 0, 1}, {OutputMemoryVersionLowLevelOperandUsage, 0, 0}, {DestExprLowLevelOperandUsage, 1}, {StackSSARegisterLowLevelOperandUsage, 2, 0}, {StackMemoryVersionLowLevelOperandUsage, 2, 2}, {ParameterExprsLowLevelOperandUsage, 3, 0}}},
	OperandLocations{LLIL_SYSCALL_SSA, {{OutputSSARegistersLowLevelOperandUsage, 0, 1}, {OutputMemoryVersionLowLevelOperandUsage, 0, 0}, {StackSSARegisterLowLevelOperandUsage, 1, 0}, {StackMemoryVersionLowLevelOperandUsage, 1, 2}, {ParameterExprsLowLevelOperandUsage, 2, 0}}},
	OperandLocations{LLIL_TAILCALL_SSA, {{OutputSSARegistersLowLevelOperandUsage, 0, 1}, {OutputMemoryVersionLowLevelOperandUsage, 0, 0}, {DestExprLowLevelOperandUsage, 1}, {StackSSARegisterLowLevelOperandUsage, 2, 0}, {StackMemoryVersionLowLevelOperandUsage, 2, 2}, {ParameterExprsLowLevelOperandUsage, 3, 0}}},
	OperandLocations{LLIL_CALL_PARAM, {{ParameterExprsLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_CALL_STACK_SSA, {{StackSSARegisterLowLevelOperandUsage, 0}, {SourceMemoryVersionLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_CALL_OUTPUT_SSA, {{DestMemoryVersionLowLevelOperandUsage, 0}, {OutputSSARegistersLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_SEPARATE_PARAM_LIST_SSA, {{ParameterExprsLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_SHARED_PARAM_SLOT_SSA, {{ParameterExprsLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_MEMORY_INTRINSIC_OUTPUT_SSA, {{DestMemoryVersionLowLevelOperandUsage, 0}, {OutputSSARegisterOrFlagListLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_LOAD_SSA, {{SourceExprLowLevelOperandUsage, 0}, {SourceMemoryVersionLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_STORE_SSA, {{DestExprLowLevelOperandUsage, 0}, {DestMemoryVersionLowLevelOperandUsage, 1}, {SourceMemoryVersionLowLevelOperandUsage, 2}, {SourceExprLowLevelOperandUsage, 3}}},
	OperandLocations{LLIL_INTRINSIC_SSA, {{OutputSSARegisterOrFlagListLowLevelOperandUsage, 0}, {IntrinsicLowLevelOperandUsage, 2}, {ParameterExprsLowLevelOperandUsage, 3, 0}}},
	OperandLocations{LLIL_MEMORY_INTRINSIC_SSA, {{OutputMemoryIntrinsicLowLevelOperandUsage, 0, 1}, {OutputMemoryVersionLowLevelOperandUsage, 0, 0}, {IntrinsicLowLevelOperandUsage, 1}, {ParameterExprsLowLevelOperandUsage, 2, 0}, {SourceMemoryVersionLowLevelOperandUsage, 3}}},
	OperandLocations{LLIL_REG_PHI, {{DestSSARegisterLowLevelOperandUsage, 0}, {SourceSSARegistersLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_REG_STACK_PHI, {{DestSSARegisterStackLowLevelOperandUsage, 0}, {SourceSSARegisterStacksLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_FLAG_PHI, {{DestSSAFlagLowLevelOperandUsage, 0}, {SourceSSAFlagsLowLevelOperandUsage, 2}}},
	OperandLocations{LLIL_MEM_PHI, {{DestMemoryVersionLowLevelOperandUsage, 0}, {SourceMemoryVersionsLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_BSWAP, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_POPCNT, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_CLZ, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_CTZ, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_RBIT, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_CLS, {{SourceExprLowLevelOperandUsage, 0}}},
	OperandLocations{LLIL_MINS, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_MAXS, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_MINU, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_MAXU, {{LeftExprLowLevelOperandUsage, 0}, {RightExprLowLevelOperandUsage, 1}}},
	OperandLocations{LLIL_ABS, {{SourceExprLowLevelOperandUsage, 0}}},
};


VALIDATE_INSTRUCTION_ORDER(s_operandLocations);
// END GENERATED llil-operand-tables


std::optional<LowLevelILOperandLocation> OperandLocationForUsage(
    BNLowLevelILOperation operation, LowLevelILOperandUsage usage)
{
	if (operation >= s_operandLocations.size())
		return std::nullopt;
	return s_operandLocations[operation].Find(usage);
}


// Returns the instruction's operand for the first of `usages` it reports.
LowLevelILOperand OperandForUsages(
    const LowLevelILInstruction& instr, std::initializer_list<LowLevelILOperandUsage> usages)
{
	for (LowLevelILOperandUsage usage : usages)
	{
		if (std::optional<LowLevelILOperandLocation> location = OperandLocationForUsage(instr.operation, usage))
			return LowLevelILOperand(instr, *location);
	}
	throw LowLevelILInstructionAccessException();
}


} // unnamed namespace


RegisterOrFlag::RegisterOrFlag() : isFlag(false), index(BN_INVALID_REGISTER) {}


RegisterOrFlag::RegisterOrFlag(bool flag, uint32_t i) : isFlag(flag), index(i) {}


RegisterOrFlag::RegisterOrFlag(const RegisterOrFlag& v) : isFlag(v.isFlag), index(v.index) {}


uint32_t RegisterOrFlag::GetRegister() const
{
	if (isFlag)
		throw LowLevelILInstructionAccessException();
	return index;
}


uint32_t RegisterOrFlag::GetFlag() const
{
	if (!isFlag)
		throw LowLevelILInstructionAccessException();
	return index;
}


RegisterOrFlag& RegisterOrFlag::operator=(const RegisterOrFlag& v)
{
	isFlag = v.isFlag;
	index = v.index;
	return *this;
}


bool RegisterOrFlag::operator==(const RegisterOrFlag& v) const
{
	if (isFlag != v.isFlag)
		return false;
	return index == v.index;
}


bool RegisterOrFlag::operator!=(const RegisterOrFlag& v) const
{
	return !((*this) == v);
}


bool RegisterOrFlag::operator<(const RegisterOrFlag& v) const
{
	return ToIdentifier() < v.ToIdentifier();
}


uint64_t RegisterOrFlag::ToIdentifier() const
{
	return ((uint64_t)index) | (isFlag ? (1LL << 32) : 0);
}


RegisterOrFlag RegisterOrFlag::FromIdentifier(uint64_t id)
{
	return RegisterOrFlag((id & (1LL << 32)) != 0, (uint32_t)id);
}


SSARegister::SSARegister() : reg(BN_INVALID_REGISTER), version(0) {}


SSARegister::SSARegister(const uint32_t r, size_t i) : reg(r), version(i) {}


SSARegister::SSARegister(const SSARegister& v) : reg(v.reg), version(v.version) {}


SSARegister& SSARegister::operator=(const SSARegister& v)
{
	reg = v.reg;
	version = v.version;
	return *this;
}


bool SSARegister::operator==(const SSARegister& v) const
{
	if (reg != v.reg)
		return false;
	return version == v.version;
}


bool SSARegister::operator!=(const SSARegister& v) const
{
	return !((*this) == v);
}


bool SSARegister::operator<(const SSARegister& v) const
{
	if (reg < v.reg)
		return true;
	if (v.reg < reg)
		return false;
	return version < v.version;
}


SSARegisterStack::SSARegisterStack() : regStack(BN_INVALID_REGISTER), version(0) {}


SSARegisterStack::SSARegisterStack(const uint32_t r, size_t i) : regStack(r), version(i) {}


SSARegisterStack::SSARegisterStack(const SSARegisterStack& v) : regStack(v.regStack), version(v.version) {}


SSARegisterStack& SSARegisterStack::operator=(const SSARegisterStack& v)
{
	regStack = v.regStack;
	version = v.version;
	return *this;
}


bool SSARegisterStack::operator==(const SSARegisterStack& v) const
{
	if (regStack != v.regStack)
		return false;
	return version == v.version;
}


bool SSARegisterStack::operator!=(const SSARegisterStack& v) const
{
	return !((*this) == v);
}


bool SSARegisterStack::operator<(const SSARegisterStack& v) const
{
	if (regStack < v.regStack)
		return true;
	if (v.regStack < regStack)
		return false;
	return version < v.version;
}


SSAFlag::SSAFlag() : flag(BN_INVALID_REGISTER), version(0) {}


SSAFlag::SSAFlag(const uint32_t f, size_t i) : flag(f), version(i) {}


SSAFlag::SSAFlag(const SSAFlag& v) : flag(v.flag), version(v.version) {}


SSAFlag& SSAFlag::operator=(const SSAFlag& v)
{
	flag = v.flag;
	version = v.version;
	return *this;
}


bool SSAFlag::operator==(const SSAFlag& v) const
{
	if (flag != v.flag)
		return false;
	return version == v.version;
}


bool SSAFlag::operator!=(const SSAFlag& v) const
{
	return !((*this) == v);
}


bool SSAFlag::operator<(const SSAFlag& v) const
{
	if (flag < v.flag)
		return true;
	if (v.flag < flag)
		return false;
	return version < v.version;
}


SSARegisterOrFlag::SSARegisterOrFlag() : version(0) {}


SSARegisterOrFlag::SSARegisterOrFlag(const RegisterOrFlag& rf, size_t i) : regOrFlag(rf), version(i) {}


SSARegisterOrFlag::SSARegisterOrFlag(const SSARegister& v) : regOrFlag(false, v.reg), version(v.version) {}


SSARegisterOrFlag::SSARegisterOrFlag(const SSAFlag& v) : regOrFlag(true, v.flag), version(v.version) {}


SSARegisterOrFlag::SSARegisterOrFlag(const SSARegisterOrFlag& v) : regOrFlag(v.regOrFlag), version(v.version) {}


SSARegisterOrFlag& SSARegisterOrFlag::operator=(const SSARegisterOrFlag& v)
{
	regOrFlag = v.regOrFlag;
	version = v.version;
	return *this;
}


bool SSARegisterOrFlag::operator==(const SSARegisterOrFlag& v) const
{
	if (regOrFlag != v.regOrFlag)
		return false;
	return version == v.version;
}


bool SSARegisterOrFlag::operator!=(const SSARegisterOrFlag& v) const
{
	return !((*this) == v);
}


bool SSARegisterOrFlag::operator<(const SSARegisterOrFlag& v) const
{
	if (regOrFlag < v.regOrFlag)
		return true;
	if (v.regOrFlag < regOrFlag)
		return false;
	return version < v.version;
}


bool LowLevelILIntegerList::ListIterator::operator==(const ListIterator& a) const
{
	return count == a.count;
}


bool LowLevelILIntegerList::ListIterator::operator!=(const ListIterator& a) const
{
	return count != a.count;
}


bool LowLevelILIntegerList::ListIterator::operator<(const ListIterator& a) const
{
	return count > a.count;
}


LowLevelILIntegerList::ListIterator& LowLevelILIntegerList::ListIterator::operator++()
{
	count--;
	offset++;
	return *this;
}


uint64_t LowLevelILIntegerList::ListIterator::operator*()
{
#ifdef BINARYNINJACORE_LIBRARY
	return function->GetOperand(offset);
#else
	return BNLowLevelILGetOperand(function->GetObject(), offset);
#endif
}


LowLevelILIntegerList::LowLevelILIntegerList(
    LowLevelILFunction* func, size_t offset, size_t count)
{
	m_start.function = func;
	m_start.offset = offset;
	m_start.count = count;
}


LowLevelILIntegerList::const_iterator LowLevelILIntegerList::begin() const
{
	return m_start;
}


LowLevelILIntegerList::const_iterator LowLevelILIntegerList::end() const
{
	const_iterator result;
	result.function = m_start.function;
	result.offset = m_start.offset + m_start.count;
	result.count = 0;
	return result;
}


size_t LowLevelILIntegerList::size() const
{
	return m_start.count;
}


uint64_t LowLevelILIntegerList::operator[](size_t i) const
{
	if (i >= size())
		throw LowLevelILInstructionAccessException();
#ifdef BINARYNINJACORE_LIBRARY
	return m_start.function->GetOperand(m_start.offset + i);
#else
	return BNLowLevelILGetOperand(m_start.function->GetObject(), m_start.offset + i);
#endif
}


LowLevelILIntegerList::operator vector<uint64_t>() const
{
	vector<uint64_t> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


size_t LowLevelILIndexList::ListIterator::operator*()
{
	return (size_t)*pos;
}


LowLevelILIndexList::LowLevelILIndexList(LowLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count)
{}


LowLevelILIndexList::const_iterator LowLevelILIndexList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


LowLevelILIndexList::const_iterator LowLevelILIndexList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t LowLevelILIndexList::size() const
{
	return m_list.size();
}


size_t LowLevelILIndexList::operator[](size_t i) const
{
	if (i >= size())
		throw LowLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


LowLevelILIndexList::operator vector<size_t>() const
{
	vector<size_t> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const pair<uint64_t, size_t> LowLevelILIndexMap::ListIterator::operator*()
{
	LowLevelILIntegerList::const_iterator cur = pos;
	uint64_t value = *cur;
	++cur;
	size_t target = (size_t)*cur;
	return pair<uint64_t, size_t>(value, target);
}


LowLevelILIndexMap::LowLevelILIndexMap(LowLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count & (~1))
{}


LowLevelILIndexMap::const_iterator LowLevelILIndexMap::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


LowLevelILIndexMap::const_iterator LowLevelILIndexMap::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t LowLevelILIndexMap::size() const
{
	return m_list.size() / 2;
}


size_t LowLevelILIndexMap::operator[](uint64_t value) const
{
	for (auto iter = begin(); iter != end(); ++iter)
	{
		if ((*iter).first == value)
			return (*iter).second;
	}
	throw LowLevelILInstructionAccessException();
}


LowLevelILIndexMap::operator map<uint64_t, size_t>() const
{
	map<uint64_t, size_t> result;
	for (auto i : *this)
		result[i.first] = i.second;
	return result;
}


const LowLevelILInstruction LowLevelILInstructionList::ListIterator::operator*()
{
	return LowLevelILInstruction(
	    pos.GetFunction(), pos.GetFunction()->GetRawExpr((size_t)*pos), (size_t)*pos, instructionIndex);
}


LowLevelILInstructionList::LowLevelILInstructionList(
    LowLevelILFunction* func, size_t offset, size_t count, size_t instrIndex) :
    m_list(func, offset, count),
    m_instructionIndex(instrIndex)
{}


LowLevelILInstructionList::const_iterator LowLevelILInstructionList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	result.instructionIndex = m_instructionIndex;
	return result;
}


LowLevelILInstructionList::const_iterator LowLevelILInstructionList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	result.instructionIndex = m_instructionIndex;
	return result;
}


size_t LowLevelILInstructionList::size() const
{
	return m_list.size();
}


const LowLevelILInstruction LowLevelILInstructionList::operator[](size_t i) const
{
	if (i >= size())
		throw LowLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


LowLevelILInstructionList::operator vector<LowLevelILInstruction>() const
{
	vector<LowLevelILInstruction> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


LowLevelILInstructionList::operator vector<ExprId>() const
{
	vector<ExprId> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i.exprIndex);
	return result;
}


const RegisterOrFlag LowLevelILRegisterOrFlagList::ListIterator::operator*()
{
	return RegisterOrFlag::FromIdentifier(*pos);
}


LowLevelILRegisterOrFlagList::LowLevelILRegisterOrFlagList(
    LowLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count)
{}


LowLevelILRegisterOrFlagList::const_iterator LowLevelILRegisterOrFlagList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


LowLevelILRegisterOrFlagList::const_iterator LowLevelILRegisterOrFlagList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t LowLevelILRegisterOrFlagList::size() const
{
	return m_list.size();
}


const RegisterOrFlag LowLevelILRegisterOrFlagList::operator[](size_t i) const
{
	if (i >= size())
		throw LowLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


LowLevelILRegisterOrFlagList::operator vector<RegisterOrFlag>() const
{
	vector<RegisterOrFlag> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const SSARegister LowLevelILSSARegisterList::ListIterator::operator*()
{
	LowLevelILIntegerList::const_iterator cur = pos;
	uint32_t reg = (uint32_t)*cur;
	++cur;
	size_t version = (size_t)*cur;
	return SSARegister(reg, version);
}


LowLevelILSSARegisterList::LowLevelILSSARegisterList(
    LowLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count & (~1))
{}


LowLevelILSSARegisterList::const_iterator LowLevelILSSARegisterList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


LowLevelILSSARegisterList::const_iterator LowLevelILSSARegisterList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t LowLevelILSSARegisterList::size() const
{
	return m_list.size() / 2;
}


const SSARegister LowLevelILSSARegisterList::operator[](size_t i) const
{
	if (i >= size())
		throw LowLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


LowLevelILSSARegisterList::operator vector<SSARegister>() const
{
	vector<SSARegister> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const SSARegisterStack LowLevelILSSARegisterStackList::ListIterator::operator*()
{
	LowLevelILIntegerList::const_iterator cur = pos;
	uint32_t regStack = (uint32_t)*cur;
	++cur;
	size_t version = (size_t)*cur;
	return SSARegisterStack(regStack, version);
}


LowLevelILSSARegisterStackList::LowLevelILSSARegisterStackList(
    LowLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count & (~1))
{}


LowLevelILSSARegisterStackList::const_iterator LowLevelILSSARegisterStackList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


LowLevelILSSARegisterStackList::const_iterator LowLevelILSSARegisterStackList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t LowLevelILSSARegisterStackList::size() const
{
	return m_list.size() / 2;
}


const SSARegisterStack LowLevelILSSARegisterStackList::operator[](size_t i) const
{
	if (i >= size())
		throw LowLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


LowLevelILSSARegisterStackList::operator vector<SSARegisterStack>() const
{
	vector<SSARegisterStack> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const SSAFlag LowLevelILSSAFlagList::ListIterator::operator*()
{
	LowLevelILIntegerList::const_iterator cur = pos;
	uint32_t flag = (uint32_t)*cur;
	++cur;
	size_t version = (size_t)*cur;
	return SSAFlag(flag, version);
}


LowLevelILSSAFlagList::LowLevelILSSAFlagList(
    LowLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count & (~1))
{}


LowLevelILSSAFlagList::const_iterator LowLevelILSSAFlagList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


LowLevelILSSAFlagList::const_iterator LowLevelILSSAFlagList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t LowLevelILSSAFlagList::size() const
{
	return m_list.size() / 2;
}


const SSAFlag LowLevelILSSAFlagList::operator[](size_t i) const
{
	if (i >= size())
		throw LowLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


LowLevelILSSAFlagList::operator vector<SSAFlag>() const
{
	vector<SSAFlag> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


const SSARegisterOrFlag LowLevelILSSARegisterOrFlagList::ListIterator::operator*()
{
	LowLevelILIntegerList::const_iterator cur = pos;
	RegisterOrFlag rf = RegisterOrFlag::FromIdentifier(*cur);
	++cur;
	size_t version = (size_t)*cur;
	return SSARegisterOrFlag(rf, version);
}


LowLevelILSSARegisterOrFlagList::LowLevelILSSARegisterOrFlagList(
    LowLevelILFunction* func, size_t offset, size_t count) :
    m_list(func, offset, count & (~1))
{}


LowLevelILSSARegisterOrFlagList::const_iterator LowLevelILSSARegisterOrFlagList::begin() const
{
	const_iterator result;
	result.pos = m_list.begin();
	return result;
}


LowLevelILSSARegisterOrFlagList::const_iterator LowLevelILSSARegisterOrFlagList::end() const
{
	const_iterator result;
	result.pos = m_list.end();
	return result;
}


size_t LowLevelILSSARegisterOrFlagList::size() const
{
	return m_list.size() / 2;
}


const SSARegisterOrFlag LowLevelILSSARegisterOrFlagList::operator[](size_t i) const
{
	if (i >= size())
		throw LowLevelILInstructionAccessException();
	auto iter = begin();
	for (size_t j = 0; j < i; j++)
		++iter;
	return *iter;
}


LowLevelILSSARegisterOrFlagList::operator vector<SSARegisterOrFlag>() const
{
	vector<SSARegisterOrFlag> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


LowLevelILOperand::LowLevelILOperand(const LowLevelILInstruction& instr, const LowLevelILOperandLocation& location) :
    m_instr(instr), m_location(location), m_type(OperandTypeForUsage(location.usage))
{
}


LowLevelILInstruction LowLevelILOperand::Holder() const
{
	return m_location.field ? m_instr.GetRawOperandAsExpr(m_location.slot) : m_instr;
}


size_t LowLevelILOperand::Slot() const
{
	return m_location.field.value_or(m_location.slot);
}


uint64_t LowLevelILOperand::GetInteger() const
{
	if (m_type != IntegerLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsInteger(Slot());
}


size_t LowLevelILOperand::GetIndex() const
{
	if (m_type != IndexLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsIndex(Slot());
}


LowLevelILInstruction LowLevelILOperand::GetExpr() const
{
	if (m_type != ExprLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsExpr(Slot());
}


uint32_t LowLevelILOperand::GetRegister() const
{
	if (m_type != RegisterLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsRegister(Slot());
}


uint32_t LowLevelILOperand::GetRegisterStack() const
{
	if (m_type != RegisterStackLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsRegister(Slot());
}


uint32_t LowLevelILOperand::GetFlag() const
{
	if (m_type != FlagLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsRegister(Slot());
}


BNLowLevelILFlagCondition LowLevelILOperand::GetFlagCondition() const
{
	if (m_type != FlagConditionLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsFlagCondition(Slot());
}


uint32_t LowLevelILOperand::GetSemanticFlagClass() const
{
	if (m_type != SemanticFlagClassLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsRegister(Slot());
}


uint32_t LowLevelILOperand::GetSemanticFlagGroup() const
{
	if (m_type != SemanticFlagGroupLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsRegister(Slot());
}


uint32_t LowLevelILOperand::GetIntrinsic() const
{
	if (m_type != IntrinsicLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsRegister(Slot());
}


SSARegister LowLevelILOperand::GetSSARegister() const
{
	if (m_type != SSARegisterLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsSSARegister(Slot());
}


SSARegisterStack LowLevelILOperand::GetSSARegisterStack() const
{
	if (m_type != SSARegisterStackLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	if (m_location.partial)
		return Holder().GetRawOperandAsPartialSSARegisterStackSource(Slot());
	return Holder().GetRawOperandAsSSARegisterStack(Slot());
}


SSAFlag LowLevelILOperand::GetSSAFlag() const
{
	if (m_type != SSAFlagLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsSSAFlag(Slot());
}


LowLevelILIndexList LowLevelILOperand::GetIndexList() const
{
	if (m_type != IndexListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsIndexList(Slot());
}


LowLevelILIndexMap LowLevelILOperand::GetIndexMap() const
{
	if (m_type != IndexMapLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsIndexMap(Slot());
}


LowLevelILInstructionList LowLevelILOperand::GetExprList() const
{
	if (m_type != ExprListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsExprList(Slot());
}


LowLevelILRegisterOrFlagList LowLevelILOperand::GetRegisterOrFlagList() const
{
	if (m_type != RegisterOrFlagListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsRegisterOrFlagList(Slot());
}


LowLevelILSSARegisterList LowLevelILOperand::GetSSARegisterList() const
{
	if (m_type != SSARegisterListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsSSARegisterList(Slot());
}


LowLevelILSSARegisterStackList LowLevelILOperand::GetSSARegisterStackList() const
{
	if (m_type != SSARegisterStackListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsSSARegisterStackList(Slot());
}


LowLevelILSSAFlagList LowLevelILOperand::GetSSAFlagList() const
{
	if (m_type != SSAFlagListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsSSAFlagList(Slot());
}


LowLevelILSSARegisterOrFlagList LowLevelILOperand::GetSSARegisterOrFlagList() const
{
	if (m_type != SSARegisterOrFlagListLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsSSARegisterOrFlagList(Slot());
}


map<uint32_t, int32_t> LowLevelILOperand::GetRegisterStackAdjustments() const
{
	if (m_type != RegisterStackAdjustmentsLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsRegisterStackAdjustments(Slot());
}


PossibleValueSet LowLevelILOperand::GetConstraint() const
{
	if (m_type != ConstraintLowLevelOperand)
		throw LowLevelILInstructionAccessException();
	return Holder().GetRawOperandAsPossibleValueSet(Slot());
}


const LowLevelILOperand LowLevelILOperandList::ListIterator::operator*()
{
	if (index >= owner->m_count)
		throw LowLevelILInstructionAccessException();
	return LowLevelILOperand(owner->m_instr, owner->m_locations[index]);
}


LowLevelILOperandList::LowLevelILOperandList(
    const LowLevelILInstruction& instr, const LowLevelILOperandLocation* locations, uint8_t count) :
    m_instr(instr), m_locations(locations), m_count(count)
{}


LowLevelILOperandList::const_iterator LowLevelILOperandList::begin() const
{
	const_iterator result;
	result.owner = this;
	result.index = 0;
	return result;
}


LowLevelILOperandList::const_iterator LowLevelILOperandList::end() const
{
	const_iterator result;
	result.owner = this;
	result.index = m_count;
	return result;
}


size_t LowLevelILOperandList::size() const
{
	return m_count;
}


const LowLevelILOperand LowLevelILOperandList::operator[](size_t i) const
{
	if (i >= m_count)
		throw LowLevelILInstructionAccessException();
	return LowLevelILOperand(m_instr, m_locations[i]);
}


LowLevelILOperandList::operator vector<LowLevelILOperand>() const
{
	vector<LowLevelILOperand> result;
	result.reserve(size());
	for (auto i : *this)
		result.push_back(i);
	return result;
}


LowLevelILInstruction::LowLevelILInstruction()
{
	operation = LLIL_UNDEF;
	attributes = 0;
	sourceOperand = BN_INVALID_OPERAND;
	size = 0;
	flags = 0;
	address = 0;
	function = nullptr;
	exprIndex = BN_INVALID_EXPR;
	instructionIndex = BN_INVALID_EXPR;
}


LowLevelILInstruction::LowLevelILInstruction(
    LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t expr, size_t instrIdx)
{
	operation = instr.operation;
	attributes = instr.attributes;
	sourceOperand = instr.sourceOperand;
	size = instr.size;
	flags = instr.flags;
	operands[0] = instr.operands[0];
	operands[1] = instr.operands[1];
	operands[2] = instr.operands[2];
	operands[3] = instr.operands[3];
	address = instr.address;
	function = func;
	exprIndex = expr;
	instructionIndex = instrIdx;
}


LowLevelILInstruction::LowLevelILInstruction(const LowLevelILInstructionBase& instr)
{
	operation = instr.operation;
	attributes = instr.attributes;
	sourceOperand = instr.sourceOperand;
	size = instr.size;
	flags = instr.flags;
	operands[0] = instr.operands[0];
	operands[1] = instr.operands[1];
	operands[2] = instr.operands[2];
	operands[3] = instr.operands[3];
	address = instr.address;
	function = instr.function;
	exprIndex = instr.exprIndex;
	instructionIndex = instr.instructionIndex;
}


LowLevelILOperandList LowLevelILInstructionBase::GetOperands() const
{
	if (operation >= s_operandLocations.size())
		throw LowLevelILInstructionAccessException();

	const auto& info = s_operandLocations[operation];
	return LowLevelILOperandList(*(const LowLevelILInstruction*)this, info.locations, info.count);
}


uint64_t LowLevelILInstructionBase::GetRawOperandAsInteger(size_t operand) const
{
	return operands[operand];
}


size_t LowLevelILInstructionBase::GetRawOperandAsIndex(size_t operand) const
{
	return (size_t)operands[operand];
}


uint32_t LowLevelILInstructionBase::GetRawOperandAsRegister(size_t operand) const
{
	return (uint32_t)operands[operand];
}


BNLowLevelILFlagCondition LowLevelILInstructionBase::GetRawOperandAsFlagCondition(size_t operand) const
{
	return (BNLowLevelILFlagCondition)operands[operand];
}


LowLevelILInstruction LowLevelILInstructionBase::GetRawOperandAsExpr(size_t operand) const
{
	return LowLevelILInstruction(
	    function, function->GetRawExpr(operands[operand]), operands[operand], instructionIndex);
}


SSARegister LowLevelILInstructionBase::GetRawOperandAsSSARegister(size_t operand) const
{
	return SSARegister((uint32_t)operands[operand], (size_t)operands[operand + 1]);
}


SSARegisterStack LowLevelILInstructionBase::GetRawOperandAsSSARegisterStack(size_t operand) const
{
	return SSARegisterStack((uint32_t)operands[operand], (size_t)operands[operand + 1]);
}


SSARegisterStack LowLevelILInstructionBase::GetRawOperandAsPartialSSARegisterStackSource(size_t operand) const
{
	return SSARegisterStack((uint32_t)operands[operand], (size_t)operands[operand + 2]);
}


SSAFlag LowLevelILInstructionBase::GetRawOperandAsSSAFlag(size_t operand) const
{
	return SSAFlag((uint32_t)operands[operand], (size_t)operands[operand + 1]);
}


LowLevelILIndexList LowLevelILInstructionBase::GetRawOperandAsIndexList(size_t operand) const
{
	return LowLevelILIndexList(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


LowLevelILIndexMap LowLevelILInstructionBase::GetRawOperandAsIndexMap(size_t operand) const
{
	return LowLevelILIndexMap(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


LowLevelILInstructionList LowLevelILInstructionBase::GetRawOperandAsExprList(size_t operand) const
{
	return LowLevelILInstructionList(
	    function, (size_t)operands[operand + 1], (size_t)operands[operand], instructionIndex);
}


LowLevelILRegisterOrFlagList LowLevelILInstructionBase::GetRawOperandAsRegisterOrFlagList(size_t operand) const
{
	return LowLevelILRegisterOrFlagList(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


LowLevelILSSARegisterList LowLevelILInstructionBase::GetRawOperandAsSSARegisterList(size_t operand) const
{
	return LowLevelILSSARegisterList(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


LowLevelILSSARegisterStackList LowLevelILInstructionBase::GetRawOperandAsSSARegisterStackList(size_t operand) const
{
	return LowLevelILSSARegisterStackList(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


LowLevelILSSAFlagList LowLevelILInstructionBase::GetRawOperandAsSSAFlagList(size_t operand) const
{
	return LowLevelILSSAFlagList(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


LowLevelILSSARegisterOrFlagList LowLevelILInstructionBase::GetRawOperandAsSSARegisterOrFlagList(size_t operand) const
{
	return LowLevelILSSARegisterOrFlagList(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
}


map<uint32_t, int32_t> LowLevelILInstructionBase::GetRawOperandAsRegisterStackAdjustments(size_t operand) const
{
	LowLevelILIntegerList list(function, (size_t)operands[operand + 1], (size_t)operands[operand]);
	map<uint32_t, int32_t> result;
	for (auto i = list.begin(); i != list.end();)
	{
		uint32_t regStack = (uint32_t)*i;
		++i;
		if (i == list.end())
			break;
		int32_t adjust = (int32_t)*i;
		++i;
		result[regStack] = adjust;
	}
	return result;
}


PossibleValueSet LowLevelILInstructionBase::GetRawOperandAsPossibleValueSet(size_t operand) const
{
	return function->GetCachedPossibleValueSet(operands[operand]);
}


void LowLevelILInstructionBase::UpdateRawOperand(size_t operandIndex, ExprId value)
{
	operands[operandIndex] = value;
	function->UpdateInstructionOperand(exprIndex, operandIndex, value);
}


void LowLevelILInstructionBase::UpdateRawOperandAsSSARegisterList(size_t operandIndex, const vector<SSARegister>& regs)
{
	UpdateRawOperand(operandIndex, regs.size() * 2);
	UpdateRawOperand(operandIndex + 1, function->AddSSARegisterList(regs));
}


void LowLevelILInstructionBase::UpdateRawOperandAsSSARegisterOrFlagList(
    size_t operandIndex, const vector<SSARegisterOrFlag>& outputs)
{
	UpdateRawOperand(operandIndex, outputs.size() * 2);
	UpdateRawOperand(operandIndex + 1, function->AddSSARegisterOrFlagList(outputs));
}


RegisterValue LowLevelILInstructionBase::GetValue() const
{
	return function->GetExprValue(*(const LowLevelILInstruction*)this);
}


PossibleValueSet LowLevelILInstructionBase::GetPossibleValues(const set<BNDataFlowQueryOption>& options) const
{
	return function->GetPossibleExprValues(*(const LowLevelILInstruction*)this, options);
}


RegisterValue LowLevelILInstructionBase::GetRegisterValue(uint32_t reg)
{
	return function->GetRegisterValueAtInstruction(reg, instructionIndex);
}


RegisterValue LowLevelILInstructionBase::GetRegisterValueAfter(uint32_t reg)
{
	return function->GetRegisterValueAfterInstruction(reg, instructionIndex);
}


PossibleValueSet LowLevelILInstructionBase::GetPossibleRegisterValues(uint32_t reg)
{
	return function->GetPossibleRegisterValuesAtInstruction(reg, instructionIndex);
}


PossibleValueSet LowLevelILInstructionBase::GetPossibleRegisterValuesAfter(uint32_t reg)
{
	return function->GetPossibleRegisterValuesAfterInstruction(reg, instructionIndex);
}


RegisterValue LowLevelILInstructionBase::GetFlagValue(uint32_t flag)
{
	return function->GetFlagValueAtInstruction(flag, instructionIndex);
}


RegisterValue LowLevelILInstructionBase::GetFlagValueAfter(uint32_t flag)
{
	return function->GetFlagValueAfterInstruction(flag, instructionIndex);
}


PossibleValueSet LowLevelILInstructionBase::GetPossibleFlagValues(uint32_t flag)
{
	return function->GetPossibleFlagValuesAtInstruction(flag, instructionIndex);
}


PossibleValueSet LowLevelILInstructionBase::GetPossibleFlagValuesAfter(uint32_t flag)
{
	return function->GetPossibleFlagValuesAfterInstruction(flag, instructionIndex);
}


RegisterValue LowLevelILInstructionBase::GetStackContents(int32_t offset, size_t len)
{
	return function->GetStackContentsAtInstruction(offset, len, instructionIndex);
}


RegisterValue LowLevelILInstructionBase::GetStackContentsAfter(int32_t offset, size_t len)
{
	return function->GetStackContentsAfterInstruction(offset, len, instructionIndex);
}


PossibleValueSet LowLevelILInstructionBase::GetPossibleStackContents(int32_t offset, size_t len)
{
	return function->GetPossibleStackContentsAtInstruction(offset, len, instructionIndex);
}


PossibleValueSet LowLevelILInstructionBase::GetPossibleStackContentsAfter(int32_t offset, size_t len)
{
	return function->GetPossibleStackContentsAfterInstruction(offset, len, instructionIndex);
}


size_t LowLevelILInstructionBase::GetSSAInstructionIndex() const
{
	return function->GetSSAInstructionIndex(instructionIndex);
}


size_t LowLevelILInstructionBase::GetNonSSAInstructionIndex() const
{
	return function->GetNonSSAInstructionIndex(instructionIndex);
}


size_t LowLevelILInstructionBase::GetSSAExprIndex() const
{
	return function->GetSSAExprIndex(exprIndex);
}


size_t LowLevelILInstructionBase::GetNonSSAExprIndex() const
{
	return function->GetNonSSAExprIndex(exprIndex);
}


LowLevelILInstruction LowLevelILInstructionBase::GetSSAForm() const
{
	Ref<LowLevelILFunction> ssa = function->GetSSAForm().GetPtr();
	if (!ssa)
		return *this;
	size_t expr = GetSSAExprIndex();
	size_t instr = GetSSAInstructionIndex();
	return LowLevelILInstruction(ssa, ssa->GetRawExpr(expr), expr, instr);
}


LowLevelILInstruction LowLevelILInstructionBase::GetNonSSAForm() const
{
	Ref<LowLevelILFunction> nonSsa = function->GetNonSSAForm();
	if (!nonSsa)
		return *this;
	size_t expr = GetNonSSAExprIndex();
	size_t instr = GetNonSSAInstructionIndex();
	return LowLevelILInstruction(nonSsa, nonSsa->GetRawExpr(expr), expr, instr);
}


size_t LowLevelILInstructionBase::GetMediumLevelILInstructionIndex() const
{
	return function->GetMediumLevelILInstructionIndex(instructionIndex);
}


size_t LowLevelILInstructionBase::GetMediumLevelILExprIndex() const
{
	return function->GetMediumLevelILExprIndex(exprIndex);
}


size_t LowLevelILInstructionBase::GetMappedMediumLevelILInstructionIndex() const
{
	return function->GetMappedMediumLevelILInstructionIndex(instructionIndex);
}


size_t LowLevelILInstructionBase::GetMappedMediumLevelILExprIndex() const
{
	return function->GetMappedMediumLevelILExprIndex(exprIndex);
}


bool LowLevelILInstructionBase::HasMediumLevelIL() const
{
	Ref<MediumLevelILFunction> func = function->GetMediumLevelIL();
	if (!func)
		return false;
	return GetMediumLevelILExprIndex() < func->GetExprCount();
}


bool LowLevelILInstructionBase::HasMappedMediumLevelIL() const
{
	Ref<MediumLevelILFunction> func = function->GetMappedMediumLevelIL();
	if (!func)
		return false;
	return GetMappedMediumLevelILExprIndex() < func->GetExprCount();
}


MediumLevelILInstruction LowLevelILInstructionBase::GetMediumLevelIL() const
{
	Ref<MediumLevelILFunction> func = function->GetMediumLevelIL();
	if (!func)
		throw MediumLevelILInstructionAccessException();
	size_t expr = GetMediumLevelILExprIndex();
	if (expr >= func->GetExprCount())
		throw MediumLevelILInstructionAccessException();
	return func->GetExpr(expr);
}


MediumLevelILInstruction LowLevelILInstructionBase::GetMappedMediumLevelIL() const
{
	Ref<MediumLevelILFunction> func = function->GetMappedMediumLevelIL();
	if (!func)
		throw MediumLevelILInstructionAccessException();
	size_t expr = GetMappedMediumLevelILExprIndex();
	if (expr >= func->GetExprCount())
		throw MediumLevelILInstructionAccessException();
	return func->GetExpr(expr);
}


char* LowLevelILInstructionBase::Dump() const
{
	vector<InstructionTextToken> tokens;
#ifdef BINARYNINJACORE_LIBRARY
	bool success = function->GetExprText(function->GetFunction(), function->GetArchitecture(), *this, tokens);
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


void LowLevelILInstructionBase::Replace(ExprId expr)
{
	function->ReplaceExpr(exprIndex, expr);
}


void LowLevelILInstructionBase::SetAttributes(uint32_t attributes)
{
	function->SetExprAttributes(exprIndex, attributes);
}


void LowLevelILInstructionBase::SetAttribute(BNILInstructionAttribute attribute, bool state)
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


void LowLevelILInstructionBase::ClearAttribute(BNILInstructionAttribute attribute)
{
	SetAttribute(attribute, false);
}


// BEGIN GENERATED llil-visit: from api/il, do not edit
void LowLevelILInstruction::VisitExprs(bn::base::function_ref<bool(const LowLevelILInstruction& expr)> func) const
{
	if (!func(*this))
		return;
	switch (operation)
	{
	case LLIL_SET_REG:
		GetSourceExpr<LLIL_SET_REG>().VisitExprs(func);
		break;
	case LLIL_SET_REG_SPLIT:
		GetSourceExpr<LLIL_SET_REG_SPLIT>().VisitExprs(func);
		break;
	case LLIL_SET_FLAG:
		GetSourceExpr<LLIL_SET_FLAG>().VisitExprs(func);
		break;
	case LLIL_SET_REG_STACK_REL:
		GetDestExpr<LLIL_SET_REG_STACK_REL>().VisitExprs(func);
		GetSourceExpr<LLIL_SET_REG_STACK_REL>().VisitExprs(func);
		break;
	case LLIL_REG_STACK_PUSH:
		GetSourceExpr<LLIL_REG_STACK_PUSH>().VisitExprs(func);
		break;
	case LLIL_LOAD:
		GetSourceExpr<LLIL_LOAD>().VisitExprs(func);
		break;
	case LLIL_STORE:
		GetDestExpr<LLIL_STORE>().VisitExprs(func);
		GetSourceExpr<LLIL_STORE>().VisitExprs(func);
		break;
	case LLIL_PUSH:
		GetSourceExpr<LLIL_PUSH>().VisitExprs(func);
		break;
	case LLIL_REG_STACK_REL:
		GetSourceExpr<LLIL_REG_STACK_REL>().VisitExprs(func);
		break;
	case LLIL_REG_STACK_FREE_REL:
		GetDestExpr<LLIL_REG_STACK_FREE_REL>().VisitExprs(func);
		break;
	case LLIL_ADD:
		GetLeftExpr<LLIL_ADD>().VisitExprs(func);
		GetRightExpr<LLIL_ADD>().VisitExprs(func);
		break;
	case LLIL_ADC:
		GetLeftExpr<LLIL_ADC>().VisitExprs(func);
		GetRightExpr<LLIL_ADC>().VisitExprs(func);
		GetCarryExpr<LLIL_ADC>().VisitExprs(func);
		break;
	case LLIL_SUB:
		GetLeftExpr<LLIL_SUB>().VisitExprs(func);
		GetRightExpr<LLIL_SUB>().VisitExprs(func);
		break;
	case LLIL_SBB:
		GetLeftExpr<LLIL_SBB>().VisitExprs(func);
		GetRightExpr<LLIL_SBB>().VisitExprs(func);
		GetCarryExpr<LLIL_SBB>().VisitExprs(func);
		break;
	case LLIL_AND:
		GetLeftExpr<LLIL_AND>().VisitExprs(func);
		GetRightExpr<LLIL_AND>().VisitExprs(func);
		break;
	case LLIL_OR:
		GetLeftExpr<LLIL_OR>().VisitExprs(func);
		GetRightExpr<LLIL_OR>().VisitExprs(func);
		break;
	case LLIL_XOR:
		GetLeftExpr<LLIL_XOR>().VisitExprs(func);
		GetRightExpr<LLIL_XOR>().VisitExprs(func);
		break;
	case LLIL_LSL:
		GetLeftExpr<LLIL_LSL>().VisitExprs(func);
		GetRightExpr<LLIL_LSL>().VisitExprs(func);
		break;
	case LLIL_LSR:
		GetLeftExpr<LLIL_LSR>().VisitExprs(func);
		GetRightExpr<LLIL_LSR>().VisitExprs(func);
		break;
	case LLIL_ASR:
		GetLeftExpr<LLIL_ASR>().VisitExprs(func);
		GetRightExpr<LLIL_ASR>().VisitExprs(func);
		break;
	case LLIL_ROL:
		GetLeftExpr<LLIL_ROL>().VisitExprs(func);
		GetRightExpr<LLIL_ROL>().VisitExprs(func);
		break;
	case LLIL_RLC:
		GetLeftExpr<LLIL_RLC>().VisitExprs(func);
		GetRightExpr<LLIL_RLC>().VisitExprs(func);
		GetCarryExpr<LLIL_RLC>().VisitExprs(func);
		break;
	case LLIL_ROR:
		GetLeftExpr<LLIL_ROR>().VisitExprs(func);
		GetRightExpr<LLIL_ROR>().VisitExprs(func);
		break;
	case LLIL_RRC:
		GetLeftExpr<LLIL_RRC>().VisitExprs(func);
		GetRightExpr<LLIL_RRC>().VisitExprs(func);
		GetCarryExpr<LLIL_RRC>().VisitExprs(func);
		break;
	case LLIL_MUL:
		GetLeftExpr<LLIL_MUL>().VisitExprs(func);
		GetRightExpr<LLIL_MUL>().VisitExprs(func);
		break;
	case LLIL_MULU_DP:
		GetLeftExpr<LLIL_MULU_DP>().VisitExprs(func);
		GetRightExpr<LLIL_MULU_DP>().VisitExprs(func);
		break;
	case LLIL_MULS_DP:
		GetLeftExpr<LLIL_MULS_DP>().VisitExprs(func);
		GetRightExpr<LLIL_MULS_DP>().VisitExprs(func);
		break;
	case LLIL_DIVU:
		GetLeftExpr<LLIL_DIVU>().VisitExprs(func);
		GetRightExpr<LLIL_DIVU>().VisitExprs(func);
		break;
	case LLIL_DIVU_DP:
		GetLeftExpr<LLIL_DIVU_DP>().VisitExprs(func);
		GetRightExpr<LLIL_DIVU_DP>().VisitExprs(func);
		break;
	case LLIL_DIVS:
		GetLeftExpr<LLIL_DIVS>().VisitExprs(func);
		GetRightExpr<LLIL_DIVS>().VisitExprs(func);
		break;
	case LLIL_DIVS_DP:
		GetLeftExpr<LLIL_DIVS_DP>().VisitExprs(func);
		GetRightExpr<LLIL_DIVS_DP>().VisitExprs(func);
		break;
	case LLIL_MODU:
		GetLeftExpr<LLIL_MODU>().VisitExprs(func);
		GetRightExpr<LLIL_MODU>().VisitExprs(func);
		break;
	case LLIL_MODU_DP:
		GetLeftExpr<LLIL_MODU_DP>().VisitExprs(func);
		GetRightExpr<LLIL_MODU_DP>().VisitExprs(func);
		break;
	case LLIL_MODS:
		GetLeftExpr<LLIL_MODS>().VisitExprs(func);
		GetRightExpr<LLIL_MODS>().VisitExprs(func);
		break;
	case LLIL_MODS_DP:
		GetLeftExpr<LLIL_MODS_DP>().VisitExprs(func);
		GetRightExpr<LLIL_MODS_DP>().VisitExprs(func);
		break;
	case LLIL_NEG:
		GetSourceExpr<LLIL_NEG>().VisitExprs(func);
		break;
	case LLIL_NOT:
		GetSourceExpr<LLIL_NOT>().VisitExprs(func);
		break;
	case LLIL_SX:
		GetSourceExpr<LLIL_SX>().VisitExprs(func);
		break;
	case LLIL_ZX:
		GetSourceExpr<LLIL_ZX>().VisitExprs(func);
		break;
	case LLIL_LOW_PART:
		GetSourceExpr<LLIL_LOW_PART>().VisitExprs(func);
		break;
	case LLIL_JUMP:
		GetDestExpr<LLIL_JUMP>().VisitExprs(func);
		break;
	case LLIL_JUMP_TO:
		GetDestExpr<LLIL_JUMP_TO>().VisitExprs(func);
		break;
	case LLIL_CALL:
		GetDestExpr<LLIL_CALL>().VisitExprs(func);
		break;
	case LLIL_CALL_STACK_ADJUST:
		GetDestExpr<LLIL_CALL_STACK_ADJUST>().VisitExprs(func);
		break;
	case LLIL_TAILCALL:
		GetDestExpr<LLIL_TAILCALL>().VisitExprs(func);
		break;
	case LLIL_RET:
		GetDestExpr<LLIL_RET>().VisitExprs(func);
		break;
	case LLIL_IF:
		GetConditionExpr<LLIL_IF>().VisitExprs(func);
		break;
	case LLIL_CMP_E:
		GetLeftExpr<LLIL_CMP_E>().VisitExprs(func);
		GetRightExpr<LLIL_CMP_E>().VisitExprs(func);
		break;
	case LLIL_CMP_NE:
		GetLeftExpr<LLIL_CMP_NE>().VisitExprs(func);
		GetRightExpr<LLIL_CMP_NE>().VisitExprs(func);
		break;
	case LLIL_CMP_SLT:
		GetLeftExpr<LLIL_CMP_SLT>().VisitExprs(func);
		GetRightExpr<LLIL_CMP_SLT>().VisitExprs(func);
		break;
	case LLIL_CMP_ULT:
		GetLeftExpr<LLIL_CMP_ULT>().VisitExprs(func);
		GetRightExpr<LLIL_CMP_ULT>().VisitExprs(func);
		break;
	case LLIL_CMP_SLE:
		GetLeftExpr<LLIL_CMP_SLE>().VisitExprs(func);
		GetRightExpr<LLIL_CMP_SLE>().VisitExprs(func);
		break;
	case LLIL_CMP_ULE:
		GetLeftExpr<LLIL_CMP_ULE>().VisitExprs(func);
		GetRightExpr<LLIL_CMP_ULE>().VisitExprs(func);
		break;
	case LLIL_CMP_SGE:
		GetLeftExpr<LLIL_CMP_SGE>().VisitExprs(func);
		GetRightExpr<LLIL_CMP_SGE>().VisitExprs(func);
		break;
	case LLIL_CMP_UGE:
		GetLeftExpr<LLIL_CMP_UGE>().VisitExprs(func);
		GetRightExpr<LLIL_CMP_UGE>().VisitExprs(func);
		break;
	case LLIL_CMP_SGT:
		GetLeftExpr<LLIL_CMP_SGT>().VisitExprs(func);
		GetRightExpr<LLIL_CMP_SGT>().VisitExprs(func);
		break;
	case LLIL_CMP_UGT:
		GetLeftExpr<LLIL_CMP_UGT>().VisitExprs(func);
		GetRightExpr<LLIL_CMP_UGT>().VisitExprs(func);
		break;
	case LLIL_TEST_BIT:
		GetLeftExpr<LLIL_TEST_BIT>().VisitExprs(func);
		GetRightExpr<LLIL_TEST_BIT>().VisitExprs(func);
		break;
	case LLIL_BOOL_TO_INT:
		GetSourceExpr<LLIL_BOOL_TO_INT>().VisitExprs(func);
		break;
	case LLIL_ADD_OVERFLOW:
		GetLeftExpr<LLIL_ADD_OVERFLOW>().VisitExprs(func);
		GetRightExpr<LLIL_ADD_OVERFLOW>().VisitExprs(func);
		break;
	case LLIL_INTRINSIC:
		for (const auto& expr : GetParameterExprs<LLIL_INTRINSIC>())
			expr.VisitExprs(func);
		break;
	case LLIL_UNIMPL_MEM:
		GetSourceExpr<LLIL_UNIMPL_MEM>().VisitExprs(func);
		break;
	case LLIL_FADD:
		GetLeftExpr<LLIL_FADD>().VisitExprs(func);
		GetRightExpr<LLIL_FADD>().VisitExprs(func);
		break;
	case LLIL_FSUB:
		GetLeftExpr<LLIL_FSUB>().VisitExprs(func);
		GetRightExpr<LLIL_FSUB>().VisitExprs(func);
		break;
	case LLIL_FMUL:
		GetLeftExpr<LLIL_FMUL>().VisitExprs(func);
		GetRightExpr<LLIL_FMUL>().VisitExprs(func);
		break;
	case LLIL_FDIV:
		GetLeftExpr<LLIL_FDIV>().VisitExprs(func);
		GetRightExpr<LLIL_FDIV>().VisitExprs(func);
		break;
	case LLIL_FSQRT:
		GetSourceExpr<LLIL_FSQRT>().VisitExprs(func);
		break;
	case LLIL_FNEG:
		GetSourceExpr<LLIL_FNEG>().VisitExprs(func);
		break;
	case LLIL_FABS:
		GetSourceExpr<LLIL_FABS>().VisitExprs(func);
		break;
	case LLIL_FLOAT_TO_INT:
		GetSourceExpr<LLIL_FLOAT_TO_INT>().VisitExprs(func);
		break;
	case LLIL_INT_TO_FLOAT:
		GetSourceExpr<LLIL_INT_TO_FLOAT>().VisitExprs(func);
		break;
	case LLIL_FLOAT_CONV:
		GetSourceExpr<LLIL_FLOAT_CONV>().VisitExprs(func);
		break;
	case LLIL_ROUND_TO_INT:
		GetSourceExpr<LLIL_ROUND_TO_INT>().VisitExprs(func);
		break;
	case LLIL_FLOOR:
		GetSourceExpr<LLIL_FLOOR>().VisitExprs(func);
		break;
	case LLIL_CEIL:
		GetSourceExpr<LLIL_CEIL>().VisitExprs(func);
		break;
	case LLIL_FTRUNC:
		GetSourceExpr<LLIL_FTRUNC>().VisitExprs(func);
		break;
	case LLIL_FCMP_E:
		GetLeftExpr<LLIL_FCMP_E>().VisitExprs(func);
		GetRightExpr<LLIL_FCMP_E>().VisitExprs(func);
		break;
	case LLIL_FCMP_NE:
		GetLeftExpr<LLIL_FCMP_NE>().VisitExprs(func);
		GetRightExpr<LLIL_FCMP_NE>().VisitExprs(func);
		break;
	case LLIL_FCMP_LT:
		GetLeftExpr<LLIL_FCMP_LT>().VisitExprs(func);
		GetRightExpr<LLIL_FCMP_LT>().VisitExprs(func);
		break;
	case LLIL_FCMP_LE:
		GetLeftExpr<LLIL_FCMP_LE>().VisitExprs(func);
		GetRightExpr<LLIL_FCMP_LE>().VisitExprs(func);
		break;
	case LLIL_FCMP_GE:
		GetLeftExpr<LLIL_FCMP_GE>().VisitExprs(func);
		GetRightExpr<LLIL_FCMP_GE>().VisitExprs(func);
		break;
	case LLIL_FCMP_GT:
		GetLeftExpr<LLIL_FCMP_GT>().VisitExprs(func);
		GetRightExpr<LLIL_FCMP_GT>().VisitExprs(func);
		break;
	case LLIL_FCMP_O:
		GetLeftExpr<LLIL_FCMP_O>().VisitExprs(func);
		GetRightExpr<LLIL_FCMP_O>().VisitExprs(func);
		break;
	case LLIL_FCMP_UO:
		GetLeftExpr<LLIL_FCMP_UO>().VisitExprs(func);
		GetRightExpr<LLIL_FCMP_UO>().VisitExprs(func);
		break;
	case LLIL_SET_REG_SSA:
		GetSourceExpr<LLIL_SET_REG_SSA>().VisitExprs(func);
		break;
	case LLIL_SET_REG_SSA_PARTIAL:
		GetSourceExpr<LLIL_SET_REG_SSA_PARTIAL>().VisitExprs(func);
		break;
	case LLIL_SET_REG_SPLIT_SSA:
		GetSourceExpr<LLIL_SET_REG_SPLIT_SSA>().VisitExprs(func);
		break;
	case LLIL_SET_REG_STACK_REL_SSA:
		GetDestExpr<LLIL_SET_REG_STACK_REL_SSA>().VisitExprs(func);
		GetSourceExpr<LLIL_SET_REG_STACK_REL_SSA>().VisitExprs(func);
		break;
	case LLIL_SET_REG_STACK_ABS_SSA:
		GetSourceExpr<LLIL_SET_REG_STACK_ABS_SSA>().VisitExprs(func);
		break;
	case LLIL_REG_STACK_REL_SSA:
		GetSourceExpr<LLIL_REG_STACK_REL_SSA>().VisitExprs(func);
		break;
	case LLIL_REG_STACK_FREE_REL_SSA:
		GetDestExpr<LLIL_REG_STACK_FREE_REL_SSA>().VisitExprs(func);
		break;
	case LLIL_SET_FLAG_SSA:
		GetSourceExpr<LLIL_SET_FLAG_SSA>().VisitExprs(func);
		break;
	case LLIL_CALL_SSA:
		GetDestExpr<LLIL_CALL_SSA>().VisitExprs(func);
		for (const auto& expr : GetParameterExprs<LLIL_CALL_SSA>())
			expr.VisitExprs(func);
		break;
	case LLIL_SYSCALL_SSA:
		for (const auto& expr : GetParameterExprs<LLIL_SYSCALL_SSA>())
			expr.VisitExprs(func);
		break;
	case LLIL_TAILCALL_SSA:
		GetDestExpr<LLIL_TAILCALL_SSA>().VisitExprs(func);
		for (const auto& expr : GetParameterExprs<LLIL_TAILCALL_SSA>())
			expr.VisitExprs(func);
		break;
	case LLIL_SEPARATE_PARAM_LIST_SSA:
		for (const auto& expr : GetParameterExprs<LLIL_SEPARATE_PARAM_LIST_SSA>())
			expr.VisitExprs(func);
		break;
	case LLIL_SHARED_PARAM_SLOT_SSA:
		for (const auto& expr : GetParameterExprs<LLIL_SHARED_PARAM_SLOT_SSA>())
			expr.VisitExprs(func);
		break;
	case LLIL_LOAD_SSA:
		GetSourceExpr<LLIL_LOAD_SSA>().VisitExprs(func);
		break;
	case LLIL_STORE_SSA:
		GetDestExpr<LLIL_STORE_SSA>().VisitExprs(func);
		GetSourceExpr<LLIL_STORE_SSA>().VisitExprs(func);
		break;
	case LLIL_INTRINSIC_SSA:
		for (const auto& expr : GetParameterExprs<LLIL_INTRINSIC_SSA>())
			expr.VisitExprs(func);
		break;
	case LLIL_MEMORY_INTRINSIC_SSA:
		for (const auto& expr : GetParameterExprs<LLIL_MEMORY_INTRINSIC_SSA>())
			expr.VisitExprs(func);
		break;
	case LLIL_BSWAP:
		GetSourceExpr<LLIL_BSWAP>().VisitExprs(func);
		break;
	case LLIL_POPCNT:
		GetSourceExpr<LLIL_POPCNT>().VisitExprs(func);
		break;
	case LLIL_CLZ:
		GetSourceExpr<LLIL_CLZ>().VisitExprs(func);
		break;
	case LLIL_CTZ:
		GetSourceExpr<LLIL_CTZ>().VisitExprs(func);
		break;
	case LLIL_RBIT:
		GetSourceExpr<LLIL_RBIT>().VisitExprs(func);
		break;
	case LLIL_CLS:
		GetSourceExpr<LLIL_CLS>().VisitExprs(func);
		break;
	case LLIL_MINS:
		GetLeftExpr<LLIL_MINS>().VisitExprs(func);
		GetRightExpr<LLIL_MINS>().VisitExprs(func);
		break;
	case LLIL_MAXS:
		GetLeftExpr<LLIL_MAXS>().VisitExprs(func);
		GetRightExpr<LLIL_MAXS>().VisitExprs(func);
		break;
	case LLIL_MINU:
		GetLeftExpr<LLIL_MINU>().VisitExprs(func);
		GetRightExpr<LLIL_MINU>().VisitExprs(func);
		break;
	case LLIL_MAXU:
		GetLeftExpr<LLIL_MAXU>().VisitExprs(func);
		GetRightExpr<LLIL_MAXU>().VisitExprs(func);
		break;
	case LLIL_ABS:
		GetSourceExpr<LLIL_ABS>().VisitExprs(func);
		break;
	default:
		break;
	}
}
// END GENERATED llil-visit


ExprId LowLevelILInstruction::CopyTo(LowLevelILFunction* dest, const ILSourceLocation& sourceLocation) const
{
	return CopyTo(dest, [&](const LowLevelILInstruction& subExpr) { return subExpr.CopyTo(dest, sourceLocation); }, sourceLocation);
}


// Rebuilds a branch so it targets `dest`'s labels, because its targets are instruction indices in the source
// function.
static ExprId CopyBranchTo(const LowLevelILInstruction& instr, LowLevelILFunction* dest,
	bn::base::function_ref<ExprId(const LowLevelILInstruction& subExpr)> subExprHandler, const ILSourceLocation& loc)
{
	switch (instr.operation)
	{
	case LLIL_JUMP_TO:
	{
		map<uint64_t, BNLowLevelILLabel*> labels;
		for (auto target : instr.GetTargets<LLIL_JUMP_TO>())
		{
			BNLowLevelILLabel* label = dest->GetLabelForSourceInstruction(target.second);
			if (!label)
				return dest->Jump(subExprHandler(instr.GetDestExpr<LLIL_JUMP_TO>()), loc);
			labels[target.first] = label;
		}
		return dest->JumpTo(subExprHandler(instr.GetDestExpr<LLIL_JUMP_TO>()), labels, loc);
	}
	case LLIL_GOTO:
	{
		BNLowLevelILLabel* label = dest->GetLabelForSourceInstruction(instr.GetTarget<LLIL_GOTO>());
		if (!label)
		{
			return dest->Jump(dest->ConstPointer(instr.function->GetArchitecture()->GetAddressSize(),
				instr.function->GetInstruction(instr.GetTarget<LLIL_GOTO>()).address), loc);
		}
		return dest->Goto(*label, loc);
	}
	case LLIL_IF:
	{
		BNLowLevelILLabel* trueLabel = dest->GetLabelForSourceInstruction(instr.GetTrueTarget<LLIL_IF>());
		BNLowLevelILLabel* falseLabel = dest->GetLabelForSourceInstruction(instr.GetFalseTarget<LLIL_IF>());
		if (!trueLabel || !falseLabel)
			return dest->Undefined(loc);
		return dest->If(subExprHandler(instr.GetConditionExpr<LLIL_IF>()), *trueLabel, *falseLabel, loc);
	}
	default:
		throw LowLevelILInstructionAccessException();
	}
}

// BEGIN GENERATED llil-copy: from api/il, do not edit
static ExprId CopyOperandList(LowLevelILFunction* dest, const LowLevelILInstruction& instr, size_t operand)
{
	vector<uint64_t> items = instr.function->GetOperandList(instr.exprIndex, operand);
	return dest->AddIndexList(vector<size_t>(items.begin(), items.end()));
}


ExprId LowLevelILInstruction::CopyTo(LowLevelILFunction* dest,
    bn::base::function_ref<ExprId(const LowLevelILInstruction& subExpr)> subExprHandler,
    const ILSourceLocation& sourceLocation) const
{
	const auto& loc = sourceLocation.valid ? sourceLocation : ILSourceLocation{*this};
	switch (operation)
	{
	case LLIL_JUMP_TO:
	case LLIL_IF:
	case LLIL_GOTO:
		return CopyBranchTo(*this, dest, subExprHandler, loc);
	case LLIL_NOP:
		return dest->AddExprWithLocation(LLIL_NOP, loc, size, flags);
	case LLIL_SET_REG:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_SET_REG, loc, size, flags, GetRawOperandAsInteger(0), srcCopy);
	}
	case LLIL_SET_REG_SPLIT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    LLIL_SET_REG_SPLIT, loc, size, flags, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1), srcCopy);
	}
	case LLIL_SET_FLAG:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_SET_FLAG, loc, size, flags, GetRawOperandAsInteger(0), srcCopy);
	}
	case LLIL_SET_REG_STACK_REL:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    LLIL_SET_REG_STACK_REL, loc, size, flags, GetRawOperandAsInteger(0), destCopy, srcCopy);
	}
	case LLIL_REG_STACK_PUSH:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_REG_STACK_PUSH, loc, size, flags, GetRawOperandAsInteger(0), srcCopy);
	}
	case LLIL_ASSERT:
		return dest->AddExprWithLocation(LLIL_ASSERT, loc, size, flags, GetRawOperandAsInteger(0),
		    dest->CachePossibleValueSet(GetRawOperandAsPossibleValueSet(1)));
	case LLIL_FORCE_VER:
		return dest->AddExprWithLocation(LLIL_FORCE_VER, loc, size, flags, GetRawOperandAsInteger(0));
	case LLIL_LOAD:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_LOAD, loc, size, flags, srcCopy);
	}
	case LLIL_STORE:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_STORE, loc, size, flags, destCopy, srcCopy);
	}
	case LLIL_PUSH:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_PUSH, loc, size, flags, srcCopy);
	}
	case LLIL_POP:
		return dest->AddExprWithLocation(LLIL_POP, loc, size, flags);
	case LLIL_REG:
		return dest->AddExprWithLocation(LLIL_REG, loc, size, flags, GetRawOperandAsInteger(0));
	case LLIL_REG_SPLIT:
		return dest->AddExprWithLocation(
		    LLIL_REG_SPLIT, loc, size, flags, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case LLIL_REG_STACK_REL:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_REG_STACK_REL, loc, size, flags, GetRawOperandAsInteger(0), srcCopy);
	}
	case LLIL_REG_STACK_POP:
		return dest->AddExprWithLocation(LLIL_REG_STACK_POP, loc, size, flags, GetRawOperandAsInteger(0));
	case LLIL_REG_STACK_FREE_REG:
		return dest->AddExprWithLocation(LLIL_REG_STACK_FREE_REG, loc, size, flags, GetRawOperandAsInteger(0));
	case LLIL_REG_STACK_FREE_REL:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(
		    LLIL_REG_STACK_FREE_REL, loc, size, flags, GetRawOperandAsInteger(0), destCopy);
	}
	case LLIL_CONST:
		return dest->AddExprWithLocation(LLIL_CONST, loc, size, flags, GetRawOperandAsInteger(0));
	case LLIL_CONST_PTR:
		return dest->AddExprWithLocation(LLIL_CONST_PTR, loc, size, flags, GetRawOperandAsInteger(0));
	case LLIL_EXTERN_PTR:
		return dest->AddExprWithLocation(
		    LLIL_EXTERN_PTR, loc, size, flags, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case LLIL_FLOAT_CONST:
		return dest->AddExprWithLocation(LLIL_FLOAT_CONST, loc, size, flags, GetRawOperandAsInteger(0));
	case LLIL_FLAG:
		return dest->AddExprWithLocation(LLIL_FLAG, loc, size, flags, GetRawOperandAsInteger(0));
	case LLIL_FLAG_BIT:
		return dest->AddExprWithLocation(
		    LLIL_FLAG_BIT, loc, size, flags, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case LLIL_ADD:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_ADD, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_ADC:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(LLIL_ADC, loc, size, flags, leftCopy, rightCopy, carryCopy);
	}
	case LLIL_SUB:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_SUB, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_SBB:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(LLIL_SBB, loc, size, flags, leftCopy, rightCopy, carryCopy);
	}
	case LLIL_AND:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_AND, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_OR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_OR, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_XOR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_XOR, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_LSL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_LSL, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_LSR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_LSR, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_ASR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_ASR, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_ROL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_ROL, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_RLC:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(LLIL_RLC, loc, size, flags, leftCopy, rightCopy, carryCopy);
	}
	case LLIL_ROR:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_ROR, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_RRC:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		ExprId carryCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(LLIL_RRC, loc, size, flags, leftCopy, rightCopy, carryCopy);
	}
	case LLIL_MUL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_MUL, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_MULU_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_MULU_DP, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_MULS_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_MULS_DP, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_DIVU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_DIVU, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_DIVU_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_DIVU_DP, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_DIVS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_DIVS, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_DIVS_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_DIVS_DP, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_MODU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_MODU, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_MODU_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_MODU_DP, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_MODS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_MODS, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_MODS_DP:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_MODS_DP, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_NEG:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_NEG, loc, size, flags, srcCopy);
	}
	case LLIL_NOT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_NOT, loc, size, flags, srcCopy);
	}
	case LLIL_SX:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_SX, loc, size, flags, srcCopy);
	}
	case LLIL_ZX:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_ZX, loc, size, flags, srcCopy);
	}
	case LLIL_LOW_PART:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_LOW_PART, loc, size, flags, srcCopy);
	}
	case LLIL_JUMP:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_JUMP, loc, size, flags, destCopy);
	}
	case LLIL_CALL:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_CALL, loc, size, flags, destCopy);
	}
	case LLIL_CALL_STACK_ADJUST:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_CALL_STACK_ADJUST, loc, size, flags, destCopy, GetRawOperandAsInteger(1),
		    GetRawOperandAsInteger(2), CopyOperandList(dest, *this, 2));
	}
	case LLIL_TAILCALL:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_TAILCALL, loc, size, flags, destCopy);
	}
	case LLIL_RET:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_RET, loc, size, flags, destCopy);
	}
	case LLIL_NORET:
		return dest->AddExprWithLocation(LLIL_NORET, loc, size, flags);
	case LLIL_FLAG_COND:
		return dest->AddExprWithLocation(
		    LLIL_FLAG_COND, loc, size, flags, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case LLIL_FLAG_GROUP:
		return dest->AddExprWithLocation(LLIL_FLAG_GROUP, loc, size, flags, GetRawOperandAsInteger(0));
	case LLIL_CMP_E:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_CMP_E, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_CMP_NE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_CMP_NE, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_CMP_SLT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_CMP_SLT, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_CMP_ULT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_CMP_ULT, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_CMP_SLE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_CMP_SLE, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_CMP_ULE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_CMP_ULE, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_CMP_SGE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_CMP_SGE, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_CMP_UGE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_CMP_UGE, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_CMP_SGT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_CMP_SGT, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_CMP_UGT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_CMP_UGT, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_TEST_BIT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_TEST_BIT, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_BOOL_TO_INT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_BOOL_TO_INT, loc, size, flags, srcCopy);
	}
	case LLIL_ADD_OVERFLOW:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_ADD_OVERFLOW, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_SYSCALL:
		return dest->AddExprWithLocation(LLIL_SYSCALL, loc, size, flags);
	case LLIL_BP:
		return dest->AddExprWithLocation(LLIL_BP, loc, size, flags);
	case LLIL_TRAP:
		return dest->AddExprWithLocation(LLIL_TRAP, loc, size, flags, GetRawOperandAsInteger(0));
	case LLIL_INTRINSIC:
	{
		LowLevelILInstruction param = GetRawOperandAsExpr(3);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(0))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(LLIL_CALL_PARAM, loc, param.size, param.flags,
		    paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		return dest->AddExprWithLocation(LLIL_INTRINSIC, loc, size, flags, GetRawOperandAsInteger(0),
		    CopyOperandList(dest, *this, 0), GetRawOperandAsInteger(2), paramCopy);
	}
	case LLIL_UNDEF:
		return dest->AddExprWithLocation(LLIL_UNDEF, loc, size, flags);
	case LLIL_UNIMPL:
		return dest->AddExprWithLocation(LLIL_UNIMPL, loc, size, flags, GetRawOperandAsInteger(0));
	case LLIL_UNIMPL_MEM:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_UNIMPL_MEM, loc, size, flags, srcCopy, GetRawOperandAsInteger(1));
	}
	case LLIL_FADD:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FADD, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_FSUB:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FSUB, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_FMUL:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FMUL, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_FDIV:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FDIV, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_FSQRT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_FSQRT, loc, size, flags, srcCopy);
	}
	case LLIL_FNEG:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_FNEG, loc, size, flags, srcCopy);
	}
	case LLIL_FABS:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_FABS, loc, size, flags, srcCopy);
	}
	case LLIL_FLOAT_TO_INT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_FLOAT_TO_INT, loc, size, flags, srcCopy);
	}
	case LLIL_INT_TO_FLOAT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_INT_TO_FLOAT, loc, size, flags, srcCopy);
	}
	case LLIL_FLOAT_CONV:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_FLOAT_CONV, loc, size, flags, srcCopy);
	}
	case LLIL_ROUND_TO_INT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_ROUND_TO_INT, loc, size, flags, srcCopy);
	}
	case LLIL_FLOOR:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_FLOOR, loc, size, flags, srcCopy);
	}
	case LLIL_CEIL:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_CEIL, loc, size, flags, srcCopy);
	}
	case LLIL_FTRUNC:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_FTRUNC, loc, size, flags, srcCopy);
	}
	case LLIL_FCMP_E:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FCMP_E, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_FCMP_NE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FCMP_NE, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_FCMP_LT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FCMP_LT, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_FCMP_LE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FCMP_LE, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_FCMP_GE:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FCMP_GE, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_FCMP_GT:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FCMP_GT, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_FCMP_O:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FCMP_O, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_FCMP_UO:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_FCMP_UO, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_SET_REG_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    LLIL_SET_REG_SSA, loc, size, flags, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1), srcCopy);
	}
	case LLIL_SET_REG_SSA_PARTIAL:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(3));
		return dest->AddExprWithLocation(LLIL_SET_REG_SSA_PARTIAL, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), srcCopy);
	}
	case LLIL_SET_REG_SPLIT_SSA:
	{
		LowLevelILInstruction hi = GetRawOperandAsExpr(0);
		ExprId hiCopy = dest->AddExprWithLocation(LLIL_REG_SPLIT_DEST_SSA, loc, hi.size, hi.flags,
		    hi.GetRawOperandAsInteger(0), hi.GetRawOperandAsInteger(1));
		LowLevelILInstruction lo = GetRawOperandAsExpr(1);
		ExprId loCopy = dest->AddExprWithLocation(LLIL_REG_SPLIT_DEST_SSA, loc, lo.size, lo.flags,
		    lo.GetRawOperandAsInteger(0), lo.GetRawOperandAsInteger(1));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(LLIL_SET_REG_SPLIT_SSA, loc, size, flags, hiCopy, loCopy, srcCopy);
	}
	case LLIL_SET_REG_STACK_REL_SSA:
	{
		LowLevelILInstruction stack = GetRawOperandAsExpr(0);
		ExprId stackCopy = dest->AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, stack.size, stack.flags,
		    stack.GetRawOperandAsInteger(0), stack.GetRawOperandAsInteger(1), stack.GetRawOperandAsInteger(2));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(1));
		LowLevelILInstruction top = GetRawOperandAsExpr(2);
		ExprId topCopy = dest->AddExprWithLocation(
		    LLIL_REG_SSA, loc, top.size, top.flags, top.GetRawOperandAsInteger(0), top.GetRawOperandAsInteger(1));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(3));
		return dest->AddExprWithLocation(
		    LLIL_SET_REG_STACK_REL_SSA, loc, size, flags, stackCopy, destCopy, topCopy, srcCopy);
	}
	case LLIL_SET_REG_STACK_ABS_SSA:
	{
		LowLevelILInstruction stack = GetRawOperandAsExpr(0);
		ExprId stackCopy = dest->AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, stack.size, stack.flags,
		    stack.GetRawOperandAsInteger(0), stack.GetRawOperandAsInteger(1), stack.GetRawOperandAsInteger(2));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    LLIL_SET_REG_STACK_ABS_SSA, loc, size, flags, stackCopy, GetRawOperandAsInteger(1), srcCopy);
	}
	case LLIL_REG_SSA:
		return dest->AddExprWithLocation(
		    LLIL_REG_SSA, loc, size, flags, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case LLIL_REG_SSA_PARTIAL:
		return dest->AddExprWithLocation(LLIL_REG_SSA_PARTIAL, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	case LLIL_REG_SPLIT_SSA:
		return dest->AddExprWithLocation(LLIL_REG_SPLIT_SSA, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), GetRawOperandAsInteger(3));
	case LLIL_REG_STACK_REL_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		LowLevelILInstruction top = GetRawOperandAsExpr(3);
		ExprId topCopy = dest->AddExprWithLocation(
		    LLIL_REG_SSA, loc, top.size, top.flags, top.GetRawOperandAsInteger(0), top.GetRawOperandAsInteger(1));
		return dest->AddExprWithLocation(LLIL_REG_STACK_REL_SSA, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), srcCopy, topCopy);
	}
	case LLIL_REG_STACK_ABS_SSA:
		return dest->AddExprWithLocation(LLIL_REG_STACK_ABS_SSA, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	case LLIL_REG_STACK_FREE_REL_SSA:
	{
		LowLevelILInstruction stack = GetRawOperandAsExpr(0);
		ExprId stackCopy = dest->AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, stack.size, stack.flags,
		    stack.GetRawOperandAsInteger(0), stack.GetRawOperandAsInteger(1), stack.GetRawOperandAsInteger(2));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(1));
		LowLevelILInstruction top = GetRawOperandAsExpr(2);
		ExprId topCopy = dest->AddExprWithLocation(
		    LLIL_REG_SSA, loc, top.size, top.flags, top.GetRawOperandAsInteger(0), top.GetRawOperandAsInteger(1));
		return dest->AddExprWithLocation(LLIL_REG_STACK_FREE_REL_SSA, loc, size, flags, stackCopy, destCopy, topCopy);
	}
	case LLIL_REG_STACK_FREE_ABS_SSA:
	{
		LowLevelILInstruction stack = GetRawOperandAsExpr(0);
		ExprId stackCopy = dest->AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, stack.size, stack.flags,
		    stack.GetRawOperandAsInteger(0), stack.GetRawOperandAsInteger(1), stack.GetRawOperandAsInteger(2));
		return dest->AddExprWithLocation(
		    LLIL_REG_STACK_FREE_ABS_SSA, loc, size, flags, stackCopy, GetRawOperandAsInteger(1));
	}
	case LLIL_SET_FLAG_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(2));
		return dest->AddExprWithLocation(
		    LLIL_SET_FLAG_SSA, loc, size, flags, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1), srcCopy);
	}
	case LLIL_ASSERT_SSA:
		return dest->AddExprWithLocation(LLIL_ASSERT_SSA, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), dest->CachePossibleValueSet(GetRawOperandAsPossibleValueSet(2)));
	case LLIL_FORCE_VER_SSA:
		return dest->AddExprWithLocation(LLIL_FORCE_VER_SSA, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), GetRawOperandAsInteger(3));
	case LLIL_FLAG_SSA:
		return dest->AddExprWithLocation(
		    LLIL_FLAG_SSA, loc, size, flags, GetRawOperandAsInteger(0), GetRawOperandAsInteger(1));
	case LLIL_FLAG_BIT_SSA:
		return dest->AddExprWithLocation(LLIL_FLAG_BIT_SSA, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2));
	case LLIL_CALL_SSA:
	{
		LowLevelILInstruction outputExpr = GetRawOperandAsExpr(0);
		ExprId outputExprCopy = dest->AddExprWithLocation(LLIL_CALL_OUTPUT_SSA, loc, outputExpr.size, outputExpr.flags,
		    outputExpr.GetRawOperandAsInteger(0), outputExpr.GetRawOperandAsInteger(1),
		    CopyOperandList(dest, outputExpr, 1));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(1));
		LowLevelILInstruction stack = GetRawOperandAsExpr(2);
		ExprId stackCopy = dest->AddExprWithLocation(LLIL_CALL_STACK_SSA, loc, stack.size, stack.flags,
		    stack.GetRawOperandAsInteger(0), stack.GetRawOperandAsInteger(1), stack.GetRawOperandAsInteger(2));
		LowLevelILInstruction param = GetRawOperandAsExpr(3);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(0))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(LLIL_CALL_PARAM, loc, param.size, param.flags,
		    paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		return dest->AddExprWithLocation(
		    LLIL_CALL_SSA, loc, size, flags, outputExprCopy, destCopy, stackCopy, paramCopy);
	}
	case LLIL_SYSCALL_SSA:
	{
		LowLevelILInstruction outputExpr = GetRawOperandAsExpr(0);
		ExprId outputExprCopy = dest->AddExprWithLocation(LLIL_CALL_OUTPUT_SSA, loc, outputExpr.size, outputExpr.flags,
		    outputExpr.GetRawOperandAsInteger(0), outputExpr.GetRawOperandAsInteger(1),
		    CopyOperandList(dest, outputExpr, 1));
		LowLevelILInstruction stack = GetRawOperandAsExpr(1);
		ExprId stackCopy = dest->AddExprWithLocation(LLIL_CALL_STACK_SSA, loc, stack.size, stack.flags,
		    stack.GetRawOperandAsInteger(0), stack.GetRawOperandAsInteger(1), stack.GetRawOperandAsInteger(2));
		LowLevelILInstruction param = GetRawOperandAsExpr(2);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(0))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(LLIL_CALL_PARAM, loc, param.size, param.flags,
		    paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		return dest->AddExprWithLocation(LLIL_SYSCALL_SSA, loc, size, flags, outputExprCopy, stackCopy, paramCopy);
	}
	case LLIL_TAILCALL_SSA:
	{
		LowLevelILInstruction outputExpr = GetRawOperandAsExpr(0);
		ExprId outputExprCopy = dest->AddExprWithLocation(LLIL_CALL_OUTPUT_SSA, loc, outputExpr.size, outputExpr.flags,
		    outputExpr.GetRawOperandAsInteger(0), outputExpr.GetRawOperandAsInteger(1),
		    CopyOperandList(dest, outputExpr, 1));
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(1));
		LowLevelILInstruction stack = GetRawOperandAsExpr(2);
		ExprId stackCopy = dest->AddExprWithLocation(LLIL_CALL_STACK_SSA, loc, stack.size, stack.flags,
		    stack.GetRawOperandAsInteger(0), stack.GetRawOperandAsInteger(1), stack.GetRawOperandAsInteger(2));
		LowLevelILInstruction param = GetRawOperandAsExpr(3);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(0))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(LLIL_CALL_PARAM, loc, param.size, param.flags,
		    paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		return dest->AddExprWithLocation(
		    LLIL_TAILCALL_SSA, loc, size, flags, outputExprCopy, destCopy, stackCopy, paramCopy);
	}
	case LLIL_SEPARATE_PARAM_LIST_SSA:
	{
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(
		    LLIL_SEPARATE_PARAM_LIST_SSA, loc, size, flags, paramsCopy.size(), dest->AddOperandList(paramsCopy));
	}
	case LLIL_SHARED_PARAM_SLOT_SSA:
	{
		vector<ExprId> paramsCopy;
		for (const auto& expr : GetRawOperandAsExprList(0))
			paramsCopy.push_back(subExprHandler(expr));
		return dest->AddExprWithLocation(
		    LLIL_SHARED_PARAM_SLOT_SSA, loc, size, flags, paramsCopy.size(), dest->AddOperandList(paramsCopy));
	}
	case LLIL_LOAD_SSA:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_LOAD_SSA, loc, size, flags, srcCopy, GetRawOperandAsInteger(1));
	}
	case LLIL_STORE_SSA:
	{
		ExprId destCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(3));
		return dest->AddExprWithLocation(
		    LLIL_STORE_SSA, loc, size, flags, destCopy, GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), srcCopy);
	}
	case LLIL_INTRINSIC_SSA:
	{
		LowLevelILInstruction param = GetRawOperandAsExpr(3);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(0))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(LLIL_CALL_PARAM, loc, param.size, param.flags,
		    paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		return dest->AddExprWithLocation(LLIL_INTRINSIC_SSA, loc, size, flags, GetRawOperandAsInteger(0),
		    CopyOperandList(dest, *this, 0), GetRawOperandAsInteger(2), paramCopy);
	}
	case LLIL_MEMORY_INTRINSIC_SSA:
	{
		LowLevelILInstruction outputExpr = GetRawOperandAsExpr(0);
		ExprId outputExprCopy = dest->AddExprWithLocation(LLIL_MEMORY_INTRINSIC_OUTPUT_SSA, loc, outputExpr.size,
		    outputExpr.flags, outputExpr.GetRawOperandAsInteger(0), outputExpr.GetRawOperandAsInteger(1),
		    CopyOperandList(dest, outputExpr, 1));
		LowLevelILInstruction param = GetRawOperandAsExpr(2);
		vector<ExprId> paramParamsCopy;
		for (const auto& expr : param.GetRawOperandAsExprList(0))
			paramParamsCopy.push_back(subExprHandler(expr));
		ExprId paramCopy = dest->AddExprWithLocation(LLIL_CALL_PARAM, loc, param.size, param.flags,
		    paramParamsCopy.size(), dest->AddOperandList(paramParamsCopy));
		return dest->AddExprWithLocation(LLIL_MEMORY_INTRINSIC_SSA, loc, size, flags, outputExprCopy,
		    GetRawOperandAsInteger(1), paramCopy, GetRawOperandAsInteger(3));
	}
	case LLIL_REG_PHI:
		return dest->AddExprWithLocation(LLIL_REG_PHI, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), CopyOperandList(dest, *this, 2));
	case LLIL_REG_STACK_PHI:
		return dest->AddExprWithLocation(LLIL_REG_STACK_PHI, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), CopyOperandList(dest, *this, 2));
	case LLIL_FLAG_PHI:
		return dest->AddExprWithLocation(LLIL_FLAG_PHI, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), GetRawOperandAsInteger(2), CopyOperandList(dest, *this, 2));
	case LLIL_MEM_PHI:
		return dest->AddExprWithLocation(LLIL_MEM_PHI, loc, size, flags, GetRawOperandAsInteger(0),
		    GetRawOperandAsInteger(1), CopyOperandList(dest, *this, 1));
	case LLIL_BSWAP:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_BSWAP, loc, size, flags, srcCopy);
	}
	case LLIL_POPCNT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_POPCNT, loc, size, flags, srcCopy);
	}
	case LLIL_CLZ:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_CLZ, loc, size, flags, srcCopy);
	}
	case LLIL_CTZ:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_CTZ, loc, size, flags, srcCopy);
	}
	case LLIL_RBIT:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_RBIT, loc, size, flags, srcCopy);
	}
	case LLIL_CLS:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_CLS, loc, size, flags, srcCopy);
	}
	case LLIL_MINS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_MINS, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_MAXS:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_MAXS, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_MINU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_MINU, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_MAXU:
	{
		ExprId leftCopy = subExprHandler(GetRawOperandAsExpr(0));
		ExprId rightCopy = subExprHandler(GetRawOperandAsExpr(1));
		return dest->AddExprWithLocation(LLIL_MAXU, loc, size, flags, leftCopy, rightCopy);
	}
	case LLIL_ABS:
	{
		ExprId srcCopy = subExprHandler(GetRawOperandAsExpr(0));
		return dest->AddExprWithLocation(LLIL_ABS, loc, size, flags, srcCopy);
	}
	default:
		throw LowLevelILInstructionAccessException();
	}
}
// END GENERATED llil-copy


bool LowLevelILInstruction::GetOperandIndexForUsage(LowLevelILOperandUsage usage, size_t& operandIndex) const
{
	std::optional<LowLevelILOperandLocation> location = OperandLocationForUsage(operation, usage);
	if (!location)
		return false;

	operandIndex = location->partial && !location->field ? location->slot + 2 : location->slot;
	return true;
}


// BEGIN GENERATED llil-instruction-getters: from api/il, do not edit
size_t LowLevelILInstruction::GetBitIndex() const
{
	return OperandForUsages(*this, {BitIndexLowLevelOperandUsage}).GetIndex();
}


LowLevelILInstruction LowLevelILInstruction::GetCarryExpr() const
{
	return OperandForUsages(*this, {CarryExprLowLevelOperandUsage}).GetExpr();
}


LowLevelILInstruction LowLevelILInstruction::GetConditionExpr() const
{
	return OperandForUsages(*this, {ConditionExprLowLevelOperandUsage}).GetExpr();
}


int64_t LowLevelILInstruction::GetConstant() const
{
	return OperandForUsages(*this, {ConstantLowLevelOperandUsage}).GetInteger();
}


PossibleValueSet LowLevelILInstruction::GetConstraint() const
{
	return OperandForUsages(*this, {ConstraintLowLevelOperandUsage}).GetConstraint();
}


LowLevelILInstruction LowLevelILInstruction::GetDestExpr() const
{
	return OperandForUsages(*this, {DestExprLowLevelOperandUsage}).GetExpr();
}


uint32_t LowLevelILInstruction::GetDestFlag() const
{
	return OperandForUsages(*this, {DestFlagLowLevelOperandUsage}).GetFlag();
}


size_t LowLevelILInstruction::GetDestMemoryVersion() const
{
	return OperandForUsages(*this, {OutputMemoryVersionLowLevelOperandUsage, DestMemoryVersionLowLevelOperandUsage})
	    .GetIndex();
}


uint32_t LowLevelILInstruction::GetDestRegister() const
{
	return OperandForUsages(*this, {DestRegisterLowLevelOperandUsage}).GetRegister();
}


uint32_t LowLevelILInstruction::GetDestRegisterStack() const
{
	return OperandForUsages(*this, {DestRegisterStackLowLevelOperandUsage}).GetRegisterStack();
}


SSAFlag LowLevelILInstruction::GetDestSSAFlag() const
{
	return OperandForUsages(*this, {DestSSAFlagLowLevelOperandUsage}).GetSSAFlag();
}


SSARegister LowLevelILInstruction::GetDestSSARegister() const
{
	return OperandForUsages(*this, {DestSSARegisterLowLevelOperandUsage}).GetSSARegister();
}


SSARegisterStack LowLevelILInstruction::GetDestSSARegisterStack() const
{
	return OperandForUsages(*this, {DestSSARegisterStackLowLevelOperandUsage}).GetSSARegisterStack();
}


size_t LowLevelILInstruction::GetFalseTarget() const
{
	return OperandForUsages(*this, {FalseTargetLowLevelOperandUsage}).GetIndex();
}


BNLowLevelILFlagCondition LowLevelILInstruction::GetFlagCondition() const
{
	return OperandForUsages(*this, {FlagConditionLowLevelOperandUsage}).GetFlagCondition();
}


uint32_t LowLevelILInstruction::GetHighRegister() const
{
	return OperandForUsages(*this, {HighRegisterLowLevelOperandUsage}).GetRegister();
}


SSARegister LowLevelILInstruction::GetHighSSARegister() const
{
	return OperandForUsages(*this, {HighSSARegisterLowLevelOperandUsage}).GetSSARegister();
}


uint32_t LowLevelILInstruction::GetIntrinsic() const
{
	return OperandForUsages(*this, {IntrinsicLowLevelOperandUsage}).GetIntrinsic();
}


LowLevelILInstruction LowLevelILInstruction::GetLeftExpr() const
{
	return OperandForUsages(*this, {LeftExprLowLevelOperandUsage}).GetExpr();
}


uint32_t LowLevelILInstruction::GetLowRegister() const
{
	return OperandForUsages(*this, {LowRegisterLowLevelOperandUsage}).GetRegister();
}


SSARegister LowLevelILInstruction::GetLowSSARegister() const
{
	return OperandForUsages(*this, {LowSSARegisterLowLevelOperandUsage}).GetSSARegister();
}


uint64_t LowLevelILInstruction::GetOffset() const
{
	return OperandForUsages(*this, {OffsetLowLevelOperandUsage}).GetInteger();
}


LowLevelILRegisterOrFlagList LowLevelILInstruction::GetOutputRegisterOrFlagList() const
{
	return OperandForUsages(*this, {OutputRegisterOrFlagListLowLevelOperandUsage}).GetRegisterOrFlagList();
}


LowLevelILSSARegisterOrFlagList LowLevelILInstruction::GetOutputSSARegisterOrFlagList() const
{
	return OperandForUsages(
	    *this, {OutputSSARegisterOrFlagListLowLevelOperandUsage, OutputMemoryIntrinsicLowLevelOperandUsage})
	    .GetSSARegisterOrFlagList();
}


LowLevelILSSARegisterList LowLevelILInstruction::GetOutputSSARegisters() const
{
	return OperandForUsages(*this, {OutputSSARegistersLowLevelOperandUsage}).GetSSARegisterList();
}


LowLevelILInstructionList LowLevelILInstruction::GetParameterExprs() const
{
	return OperandForUsages(*this, {ParameterExprsLowLevelOperandUsage}).GetExprList();
}


uint32_t LowLevelILInstruction::GetPartialRegister() const
{
	return OperandForUsages(*this, {PartialRegisterLowLevelOperandUsage}).GetRegister();
}


map<uint32_t, int32_t> LowLevelILInstruction::GetRegisterStackAdjustments() const
{
	return OperandForUsages(*this, {RegisterStackAdjustmentsLowLevelOperandUsage}).GetRegisterStackAdjustments();
}


LowLevelILInstruction LowLevelILInstruction::GetRightExpr() const
{
	return OperandForUsages(*this, {RightExprLowLevelOperandUsage}).GetExpr();
}


uint32_t LowLevelILInstruction::GetSemanticFlagClass() const
{
	return OperandForUsages(*this, {SemanticFlagClassLowLevelOperandUsage}).GetSemanticFlagClass();
}


uint32_t LowLevelILInstruction::GetSemanticFlagGroup() const
{
	return OperandForUsages(*this, {SemanticFlagGroupLowLevelOperandUsage}).GetSemanticFlagGroup();
}


LowLevelILInstruction LowLevelILInstruction::GetSourceExpr() const
{
	return OperandForUsages(*this, {SourceExprLowLevelOperandUsage}).GetExpr();
}


uint32_t LowLevelILInstruction::GetSourceFlag() const
{
	return OperandForUsages(*this, {SourceFlagLowLevelOperandUsage}).GetFlag();
}


size_t LowLevelILInstruction::GetSourceMemoryVersion() const
{
	return OperandForUsages(*this, {StackMemoryVersionLowLevelOperandUsage, SourceMemoryVersionLowLevelOperandUsage})
	    .GetIndex();
}


LowLevelILIndexList LowLevelILInstruction::GetSourceMemoryVersions() const
{
	return OperandForUsages(*this, {SourceMemoryVersionsLowLevelOperandUsage}).GetIndexList();
}


uint32_t LowLevelILInstruction::GetSourceRegister() const
{
	return OperandForUsages(*this, {SourceRegisterLowLevelOperandUsage}).GetRegister();
}


uint32_t LowLevelILInstruction::GetSourceRegisterStack() const
{
	return OperandForUsages(*this, {SourceRegisterStackLowLevelOperandUsage}).GetRegisterStack();
}


SSAFlag LowLevelILInstruction::GetSourceSSAFlag() const
{
	return OperandForUsages(*this, {SourceSSAFlagLowLevelOperandUsage}).GetSSAFlag();
}


LowLevelILSSAFlagList LowLevelILInstruction::GetSourceSSAFlags() const
{
	return OperandForUsages(*this, {SourceSSAFlagsLowLevelOperandUsage}).GetSSAFlagList();
}


SSARegister LowLevelILInstruction::GetSourceSSARegister() const
{
	return OperandForUsages(*this, {SourceSSARegisterLowLevelOperandUsage}).GetSSARegister();
}


SSARegisterStack LowLevelILInstruction::GetSourceSSARegisterStack() const
{
	return OperandForUsages(
	    *this, {PartialSSARegisterStackSourceLowLevelOperandUsage, SourceSSARegisterStackLowLevelOperandUsage})
	    .GetSSARegisterStack();
}


LowLevelILSSARegisterStackList LowLevelILInstruction::GetSourceSSARegisterStacks() const
{
	return OperandForUsages(*this, {SourceSSARegisterStacksLowLevelOperandUsage}).GetSSARegisterStackList();
}


LowLevelILSSARegisterList LowLevelILInstruction::GetSourceSSARegisters() const
{
	return OperandForUsages(*this, {SourceSSARegistersLowLevelOperandUsage}).GetSSARegisterList();
}


int64_t LowLevelILInstruction::GetStackAdjustment() const
{
	return OperandForUsages(*this, {StackAdjustmentLowLevelOperandUsage}).GetInteger();
}


SSARegister LowLevelILInstruction::GetStackSSARegister() const
{
	return OperandForUsages(*this, {StackSSARegisterLowLevelOperandUsage}).GetSSARegister();
}


size_t LowLevelILInstruction::GetTarget() const
{
	return OperandForUsages(*this, {TargetLowLevelOperandUsage}).GetIndex();
}


LowLevelILIndexMap LowLevelILInstruction::GetTargets() const
{
	return OperandForUsages(*this, {TargetsLowLevelOperandUsage}).GetIndexMap();
}


SSARegister LowLevelILInstruction::GetTopSSARegister() const
{
	return OperandForUsages(*this, {TopSSARegisterLowLevelOperandUsage}).GetSSARegister();
}


size_t LowLevelILInstruction::GetTrueTarget() const
{
	return OperandForUsages(*this, {TrueTargetLowLevelOperandUsage}).GetIndex();
}


int64_t LowLevelILInstruction::GetVector() const
{
	return OperandForUsages(*this, {VectorLowLevelOperandUsage}).GetInteger();
}


bool LowLevelILInstruction::IsUnknown() const
{
	switch (operation)
	{
	case LLIL_UNIMPL:
		return IsUnknown<LLIL_UNIMPL>();
	case LLIL_UNIMPL_MEM:
		return IsUnknown<LLIL_UNIMPL_MEM>();
	default:
		throw LowLevelILInstructionAccessException();
	}
}
// END GENERATED llil-instruction-getters

// BEGIN GENERATED llil-builders: from api/il, do not edit
ExprId LowLevelILFunction::Nop(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_NOP, loc, 0, 0);
}


ExprId LowLevelILFunction::SetRegister(
    size_t size, uint32_t dest, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG, loc, size, flags, dest, src);
}


ExprId LowLevelILFunction::SetRegisterSplit(
    size_t size, uint32_t hi, uint32_t lo, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_SPLIT, loc, size, flags, hi, lo, src);
}


ExprId LowLevelILFunction::SetFlag(uint32_t dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_FLAG, loc, 0, 0, dest, src);
}


ExprId LowLevelILFunction::SetRegisterStackTopRelative(
    size_t size, uint32_t destStack, ExprId dest, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_STACK_REL, loc, size, flags, destStack, dest, src);
}


ExprId LowLevelILFunction::RegisterStackPush(
    size_t size, uint32_t destStack, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_PUSH, loc, size, flags, destStack, src);
}


ExprId LowLevelILFunction::Assert(
    size_t size, uint32_t src, const PossibleValueSet& constraint, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ASSERT, loc, size, 0, src, CachePossibleValueSet(constraint));
}


ExprId LowLevelILFunction::ForceVer(size_t size, uint32_t dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FORCE_VER, loc, size, 0, dest);
}


ExprId LowLevelILFunction::Load(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_LOAD, loc, size, flags, src);
}


ExprId LowLevelILFunction::Store(size_t size, ExprId dest, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_STORE, loc, size, flags, dest, src);
}


ExprId LowLevelILFunction::Push(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_PUSH, loc, size, flags, src);
}


ExprId LowLevelILFunction::Pop(size_t size, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_POP, loc, size, flags);
}


ExprId LowLevelILFunction::Register(size_t size, uint32_t src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG, loc, size, 0, src);
}


ExprId LowLevelILFunction::RegisterSplit(size_t size, uint32_t hi, uint32_t lo, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_SPLIT, loc, size, 0, hi, lo);
}


ExprId LowLevelILFunction::RegisterStackTopRelative(
    size_t size, uint32_t srcStack, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_REL, loc, size, 0, srcStack, src);
}


ExprId LowLevelILFunction::RegisterStackPop(size_t size, uint32_t srcStack, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_POP, loc, size, flags, srcStack);
}


ExprId LowLevelILFunction::RegisterStackFreeReg(uint32_t dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_FREE_REG, loc, 0, 0, dest);
}


ExprId LowLevelILFunction::RegisterStackFreeTopRelative(uint32_t destStack, ExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_FREE_REL, loc, 0, 0, destStack, dest);
}


ExprId LowLevelILFunction::Const(size_t size, uint64_t constant, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CONST, loc, size, 0, constant);
}


ExprId LowLevelILFunction::ConstPointer(size_t size, uint64_t constant, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CONST_PTR, loc, size, 0, constant);
}


ExprId LowLevelILFunction::ExternPointer(size_t size, uint64_t constant, uint64_t offset, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_EXTERN_PTR, loc, size, 0, constant, offset);
}


ExprId LowLevelILFunction::FloatConstRaw(size_t size, uint64_t constant, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLOAT_CONST, loc, size, 0, constant);
}


ExprId LowLevelILFunction::Flag(uint32_t src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG, loc, 0, 0, src);
}


ExprId LowLevelILFunction::FlagBit(size_t size, uint32_t src, size_t bit, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG_BIT, loc, size, 0, src, bit);
}


ExprId LowLevelILFunction::Add(size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ADD, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::AddCarry(
    size_t size, ExprId left, ExprId right, ExprId carry, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ADC, loc, size, flags, left, right, carry);
}


ExprId LowLevelILFunction::Sub(size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SUB, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::SubBorrow(
    size_t size, ExprId left, ExprId right, ExprId carry, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SBB, loc, size, flags, left, right, carry);
}


ExprId LowLevelILFunction::And(size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_AND, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::Or(size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_OR, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::Xor(size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_XOR, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::ShiftLeft(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_LSL, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::LogicalShiftRight(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_LSR, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::ArithShiftRight(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ASR, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::RotateLeft(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ROL, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::RotateLeftCarry(
    size_t size, ExprId left, ExprId right, ExprId carry, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_RLC, loc, size, flags, left, right, carry);
}


ExprId LowLevelILFunction::RotateRight(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ROR, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::RotateRightCarry(
    size_t size, ExprId left, ExprId right, ExprId carry, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_RRC, loc, size, flags, left, right, carry);
}


ExprId LowLevelILFunction::Mult(size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MUL, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::MultDoublePrecUnsigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MULU_DP, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::MultDoublePrecSigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MULS_DP, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::DivUnsigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_DIVU, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::DivDoublePrecUnsigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_DIVU_DP, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::DivSigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_DIVS, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::DivDoublePrecSigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_DIVS_DP, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::ModUnsigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MODU, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::ModDoublePrecUnsigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MODU_DP, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::ModSigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MODS, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::ModDoublePrecSigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MODS_DP, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::Neg(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_NEG, loc, size, flags, src);
}


ExprId LowLevelILFunction::Not(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_NOT, loc, size, flags, src);
}


ExprId LowLevelILFunction::SignExtend(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SX, loc, size, flags, src);
}


ExprId LowLevelILFunction::ZeroExtend(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ZX, loc, size, flags, src);
}


ExprId LowLevelILFunction::LowPart(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_LOW_PART, loc, size, flags, src);
}


ExprId LowLevelILFunction::Jump(ExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_JUMP, loc, 0, 0, dest);
}


ExprId LowLevelILFunction::JumpTo(
    ExprId dest, const map<uint64_t, BNLowLevelILLabel*>& targets, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_JUMP_TO, loc, 0, 0, dest, targets.size() * 2, AddLabelMap(targets));
}


ExprId LowLevelILFunction::Call(ExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CALL, loc, 0, 0, dest);
}


ExprId LowLevelILFunction::CallStackAdjust(ExprId dest, int64_t stackAdjustment,
    const map<uint32_t, int32_t>& regStackAdjustments, const ILSourceLocation& loc)
{
	vector<size_t> regStackAdjustmentsList;
	regStackAdjustmentsList.reserve(regStackAdjustments.size() * 2);
	for (auto& i : regStackAdjustments)
	{
		regStackAdjustmentsList.push_back(i.first);
		regStackAdjustmentsList.push_back(i.second);
	}
	return AddExprWithLocation(LLIL_CALL_STACK_ADJUST, loc, 0, 0, dest, stackAdjustment, regStackAdjustmentsList.size(),
	    AddIndexList(regStackAdjustmentsList));
}


ExprId LowLevelILFunction::TailCall(ExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_TAILCALL, loc, 0, 0, dest);
}


ExprId LowLevelILFunction::Return(ExprId dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_RET, loc, 0, 0, dest);
}


ExprId LowLevelILFunction::NoReturn(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_NORET, loc, 0, 0);
}


ExprId LowLevelILFunction::FlagCondition(
    BNLowLevelILFlagCondition flagCondition, uint32_t semanticClass, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG_COND, loc, 0, 0, flagCondition, semanticClass);
}


ExprId LowLevelILFunction::FlagGroup(uint32_t semanticGroup, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG_GROUP, loc, 0, 0, semanticGroup);
}


ExprId LowLevelILFunction::CompareEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_E, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::CompareNotEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_NE, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::CompareSignedLessThan(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_SLT, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::CompareUnsignedLessThan(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_ULT, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::CompareSignedLessEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_SLE, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::CompareUnsignedLessEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_ULE, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::CompareSignedGreaterEqual(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_SGE, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::CompareUnsignedGreaterEqual(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_UGE, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::CompareSignedGreaterThan(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_SGT, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::CompareUnsignedGreaterThan(
    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CMP_UGT, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::TestBit(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_TEST_BIT, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::BoolToInt(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_BOOL_TO_INT, loc, size, 0, src);
}


ExprId LowLevelILFunction::AddOverflow(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ADD_OVERFLOW, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::SystemCall(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SYSCALL, loc, 0, 0);
}


ExprId LowLevelILFunction::Breakpoint(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_BP, loc, 0, 0);
}


ExprId LowLevelILFunction::Trap(int64_t vector, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_TRAP, loc, 0, 0, vector);
}


ExprId LowLevelILFunction::Intrinsic(const vector<RegisterOrFlag>& output, uint32_t intrinsic,
    const vector<ExprId>& params, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_INTRINSIC, loc, 0, flags, output.size(), AddRegisterOrFlagList(output), intrinsic,
	    AddExprWithLocation(LLIL_CALL_PARAM, loc, 0, 0, params.size(), AddOperandList(params)));
}


ExprId LowLevelILFunction::Undefined(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_UNDEF, loc, 0, 0);
}


ExprId LowLevelILFunction::Unimplemented(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_UNIMPL, loc, 0, 0, 0);
}


ExprId LowLevelILFunction::Unknown(const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_UNIMPL, loc, 0, 0, 1);
}


ExprId LowLevelILFunction::UnimplementedMemoryRef(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_UNIMPL_MEM, loc, size, 0, src, 0);
}


ExprId LowLevelILFunction::UnknownMemoryRef(size_t size, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_UNIMPL_MEM, loc, size, 0, src, 1);
}


ExprId LowLevelILFunction::FloatAdd(size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FADD, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::FloatSub(size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FSUB, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::FloatMult(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FMUL, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::FloatDiv(size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FDIV, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::FloatSqrt(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FSQRT, loc, size, flags, src);
}


ExprId LowLevelILFunction::FloatNeg(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FNEG, loc, size, flags, src);
}


ExprId LowLevelILFunction::FloatAbs(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FABS, loc, size, flags, src);
}


ExprId LowLevelILFunction::FloatToInt(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLOAT_TO_INT, loc, size, flags, src);
}


ExprId LowLevelILFunction::IntToFloat(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_INT_TO_FLOAT, loc, size, flags, src);
}


ExprId LowLevelILFunction::FloatConvert(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLOAT_CONV, loc, size, flags, src);
}


ExprId LowLevelILFunction::RoundToInt(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ROUND_TO_INT, loc, size, flags, src);
}


ExprId LowLevelILFunction::Floor(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLOOR, loc, size, flags, src);
}


ExprId LowLevelILFunction::Ceil(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CEIL, loc, size, flags, src);
}


ExprId LowLevelILFunction::FloatTrunc(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FTRUNC, loc, size, flags, src);
}


ExprId LowLevelILFunction::FloatCompareEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_E, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::FloatCompareNotEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_NE, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::FloatCompareLessThan(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_LT, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::FloatCompareLessEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_LE, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::FloatCompareGreaterEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_GE, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::FloatCompareGreaterThan(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_GT, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::FloatCompareOrdered(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_O, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::FloatCompareUnordered(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FCMP_UO, loc, size, 0, left, right);
}


ExprId LowLevelILFunction::SetRegisterSSA(size_t size, const SSARegister& dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_SSA, loc, size, 0, dest.reg, dest.version, src);
}


ExprId LowLevelILFunction::SetRegisterSSAPartial(
    size_t size, const SSARegister& dest, uint32_t partial, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_SSA_PARTIAL, loc, size, 0, dest.reg, dest.version, partial, src);
}


ExprId LowLevelILFunction::SetRegisterSplitSSA(
    size_t size, const SSARegister& hiReg, const SSARegister& loReg, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_SPLIT_SSA, loc, size, 0,
	    AddExprWithLocation(LLIL_REG_SPLIT_DEST_SSA, loc, size, 0, hiReg.reg, hiReg.version),
	    AddExprWithLocation(LLIL_REG_SPLIT_DEST_SSA, loc, size, 0, loReg.reg, loReg.version), src);
}


ExprId LowLevelILFunction::SetRegisterStackTopRelativeSSA(size_t size, uint32_t stack, size_t destVersion,
    size_t srcVersion, ExprId dest, const SSARegister& topReg, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_STACK_REL_SSA, loc, size, 0,
	    AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, size, 0, stack, destVersion, srcVersion), dest,
	    AddExprWithLocation(LLIL_REG_SSA, loc, 0, 0, topReg.reg, topReg.version), src);
}


ExprId LowLevelILFunction::SetRegisterStackAbsoluteSSA(size_t size, uint32_t stack, size_t destVersion,
    size_t srcVersion, uint32_t dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_REG_STACK_ABS_SSA, loc, size, 0,
	    AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, size, 0, stack, destVersion, srcVersion), dest, src);
}


ExprId LowLevelILFunction::RegisterSSA(size_t size, const SSARegister& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_SSA, loc, size, 0, src.reg, src.version);
}


ExprId LowLevelILFunction::RegisterSSAPartial(
    size_t size, const SSARegister& src, uint32_t partial, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_SSA_PARTIAL, loc, size, 0, src.reg, src.version, partial);
}


ExprId LowLevelILFunction::RegisterSplitSSA(
    size_t size, const SSARegister& hi, const SSARegister& lo, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_SPLIT_SSA, loc, size, 0, hi.reg, hi.version, lo.reg, lo.version);
}


ExprId LowLevelILFunction::RegisterStackTopRelativeSSA(
    size_t size, const SSARegisterStack& srcStack, ExprId src, const SSARegister& topReg, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_REL_SSA, loc, size, 0, srcStack.regStack, srcStack.version, src,
	    AddExprWithLocation(LLIL_REG_SSA, loc, 0, 0, topReg.reg, topReg.version));
}


ExprId LowLevelILFunction::RegisterStackAbsoluteSSA(
    size_t size, const SSARegisterStack& srcStack, uint32_t src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_ABS_SSA, loc, size, 0, srcStack.regStack, srcStack.version, src);
}


ExprId LowLevelILFunction::RegisterStackFreeTopRelativeSSA(uint32_t stack, size_t destVersion, size_t srcVersion,
    ExprId dest, const SSARegister& topReg, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_FREE_REL_SSA, loc, 0, 0,
	    AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, 0, 0, stack, destVersion, srcVersion), dest,
	    AddExprWithLocation(LLIL_REG_SSA, loc, 0, 0, topReg.reg, topReg.version));
}


ExprId LowLevelILFunction::RegisterStackFreeAbsoluteSSA(
    uint32_t stack, size_t destVersion, size_t srcVersion, uint32_t dest, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_REG_STACK_FREE_ABS_SSA, loc, 0, 0,
	    AddExprWithLocation(LLIL_REG_STACK_DEST_SSA, loc, 0, 0, stack, destVersion, srcVersion), dest);
}


ExprId LowLevelILFunction::SetFlagSSA(const SSAFlag& dest, ExprId src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SET_FLAG_SSA, loc, 0, 0, dest.flag, dest.version, src);
}


ExprId LowLevelILFunction::AssertSSA(
    size_t size, const SSARegister& src, const PossibleValueSet& constraint, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ASSERT_SSA, loc, size, 0, src.reg, src.version, CachePossibleValueSet(constraint));
}


ExprId LowLevelILFunction::ForceVerSSA(
    size_t size, const SSARegister& dest, const SSARegister& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FORCE_VER_SSA, loc, size, 0, dest.reg, dest.version, src.reg, src.version);
}


ExprId LowLevelILFunction::FlagSSA(const SSAFlag& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG_SSA, loc, 0, 0, src.flag, src.version);
}


ExprId LowLevelILFunction::FlagBitSSA(size_t size, const SSAFlag& src, size_t bit, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG_BIT_SSA, loc, size, 0, src.flag, src.version, bit);
}


ExprId LowLevelILFunction::CallSSA(const vector<SSARegister>& output, ExprId dest, const vector<ExprId>& params,
    const SSARegister& stackReg, size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CALL_SSA, loc, 0, 0,
	    AddExprWithLocation(LLIL_CALL_OUTPUT_SSA, loc, 0, 0, destMemory, output.size() * 2, AddSSARegisterList(output)),
	    dest, AddExprWithLocation(LLIL_CALL_STACK_SSA, loc, 0, 0, stackReg.reg, stackReg.version, srcMemory),
	    AddExprWithLocation(LLIL_CALL_PARAM, loc, 0, 0, params.size(), AddOperandList(params)));
}


ExprId LowLevelILFunction::SystemCallSSA(const vector<SSARegister>& output, const vector<ExprId>& params,
    const SSARegister& stackReg, size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SYSCALL_SSA, loc, 0, 0,
	    AddExprWithLocation(LLIL_CALL_OUTPUT_SSA, loc, 0, 0, destMemory, output.size() * 2, AddSSARegisterList(output)),
	    AddExprWithLocation(LLIL_CALL_STACK_SSA, loc, 0, 0, stackReg.reg, stackReg.version, srcMemory),
	    AddExprWithLocation(LLIL_CALL_PARAM, loc, 0, 0, params.size(), AddOperandList(params)));
}


ExprId LowLevelILFunction::TailCallSSA(const vector<SSARegister>& output, ExprId dest, const vector<ExprId>& params,
    const SSARegister& stackReg, size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_TAILCALL_SSA, loc, 0, 0,
	    AddExprWithLocation(LLIL_CALL_OUTPUT_SSA, loc, 0, 0, destMemory, output.size() * 2, AddSSARegisterList(output)),
	    dest, AddExprWithLocation(LLIL_CALL_STACK_SSA, loc, 0, 0, stackReg.reg, stackReg.version, srcMemory),
	    AddExprWithLocation(LLIL_CALL_PARAM, loc, 0, 0, params.size(), AddOperandList(params)));
}


ExprId LowLevelILFunction::SeparateParamListSSA(const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SEPARATE_PARAM_LIST_SSA, loc, 0, 0, params.size(), AddOperandList(params));
}


ExprId LowLevelILFunction::SharedParamSlotSSA(const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_SHARED_PARAM_SLOT_SSA, loc, 0, 0, params.size(), AddOperandList(params));
}


ExprId LowLevelILFunction::LoadSSA(size_t size, ExprId src, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_LOAD_SSA, loc, size, 0, src, srcMemory);
}


ExprId LowLevelILFunction::StoreSSA(
    size_t size, ExprId dest, ExprId src, size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_STORE_SSA, loc, size, 0, dest, destMemory, srcMemory, src);
}


ExprId LowLevelILFunction::IntrinsicSSA(const vector<SSARegisterOrFlag>& output, uint32_t intrinsic,
    const vector<ExprId>& params, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_INTRINSIC_SSA, loc, 0, 0, output.size() * 2, AddSSARegisterOrFlagList(output),
	    intrinsic, AddExprWithLocation(LLIL_CALL_PARAM, loc, 0, 0, params.size(), AddOperandList(params)));
}


ExprId LowLevelILFunction::MemoryIntrinsicSSA(const vector<SSARegisterOrFlag>& output, uint32_t intrinsic,
    const vector<ExprId>& params, size_t destMemory, size_t srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MEMORY_INTRINSIC_SSA, loc, 0, 0,
	    AddExprWithLocation(LLIL_MEMORY_INTRINSIC_OUTPUT_SSA, loc, 0, 0, destMemory, output.size() * 2,
	        AddSSARegisterOrFlagList(output)),
	    intrinsic, AddExprWithLocation(LLIL_CALL_PARAM, loc, 0, 0, params.size(), AddOperandList(params)), srcMemory);
}


ExprId LowLevelILFunction::RegisterPhi(
    const SSARegister& dest, const vector<SSARegister>& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    LLIL_REG_PHI, loc, 0, 0, dest.reg, dest.version, src.size() * 2, AddSSARegisterList(src));
}


ExprId LowLevelILFunction::RegisterStackPhi(
    const SSARegisterStack& dest, const vector<SSARegisterStack>& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(
	    LLIL_REG_STACK_PHI, loc, 0, 0, dest.regStack, dest.version, src.size() * 2, AddSSARegisterStackList(src));
}


ExprId LowLevelILFunction::FlagPhi(const SSAFlag& dest, const vector<SSAFlag>& src, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_FLAG_PHI, loc, 0, 0, dest.flag, dest.version, src.size() * 2, AddSSAFlagList(src));
}


ExprId LowLevelILFunction::MemoryPhi(size_t destMemory, const vector<size_t>& srcMemory, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MEM_PHI, loc, 0, 0, destMemory, srcMemory.size(), AddIndexList(srcMemory));
}


ExprId LowLevelILFunction::ByteSwap(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_BSWAP, loc, size, flags, src);
}


ExprId LowLevelILFunction::PopulationCount(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_POPCNT, loc, size, flags, src);
}


ExprId LowLevelILFunction::CountLeadingZeros(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CLZ, loc, size, flags, src);
}


ExprId LowLevelILFunction::CountTrailingZeros(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CTZ, loc, size, flags, src);
}


ExprId LowLevelILFunction::ReverseBits(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_RBIT, loc, size, flags, src);
}


ExprId LowLevelILFunction::CountLeadingSigns(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_CLS, loc, size, flags, src);
}


ExprId LowLevelILFunction::MinSigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MINS, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::MaxSigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MAXS, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::MinUnsigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MINU, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::MaxUnsigned(
    size_t size, ExprId left, ExprId right, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_MAXU, loc, size, flags, left, right);
}


ExprId LowLevelILFunction::AbsoluteValue(size_t size, ExprId src, uint32_t flags, const ILSourceLocation& loc)
{
	return AddExprWithLocation(LLIL_ABS, loc, size, flags, src);
}
// END GENERATED llil-builders

ExprId LowLevelILFunction::FloatConstSingle(float val, const ILSourceLocation& loc)
{
	union
	{
		float f;
		uint32_t i;
	} bits;
	bits.f = val;
	return AddExprWithLocation(LLIL_FLOAT_CONST, loc, 4, 0, bits.i);
}


ExprId LowLevelILFunction::FloatConstDouble(double val, const ILSourceLocation& loc)
{
	union
	{
		double f;
		uint64_t i;
	} bits;
	bits.f = val;
	return AddExprWithLocation(LLIL_FLOAT_CONST, loc, 8, 0, bits.i);
}

fmt::format_context::iterator fmt::formatter<LowLevelILInstruction>::format(const LowLevelILInstruction& obj, format_context& ctx) const
{
	if (!obj.function)
		return fmt::format_to(ctx.out(), "<uninit>");

	vector<InstructionTextToken> tokens;
#ifdef BINARYNINJACORE_LIBRARY
	bool success = obj.function->GetExprText(obj.function->GetFunction(), obj.function->GetArchitecture(), obj, tokens);
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
